from __future__ import annotations

import json
import logging
import socket
import time

_log = logging.getLogger("patchi.debug.dap_client")


class DAPError(Exception):
    """A DAP request returned success=false."""


class DAPClient:
    """Minimal Debug Adapter Protocol client over TCP.

    Drives any DAP-compliant debug adapter (debugpy, dlv dap, codelldb, …)
    through the same code path.  This is *not* a full DAP implementation —
    only the subset needed to capture post-exception state.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 5678):
        self._host = host
        self._port = port
        self._sock: socket.socket | None = None
        self._seq = 0
        self._buffer = b""

    # ── connection lifecycle ────────────────────────────────────────────

    def connect(self, timeout: float = 15) -> None:
        deadline = time.monotonic() + timeout
        last_err = None
        while time.monotonic() < deadline:
            try:
                self._sock = socket.create_connection(
                    (self._host, self._port), timeout=min(5.0, deadline - time.monotonic())
                )
                self._sock.settimeout(timeout)
                return
            except (ConnectionRefusedError, OSError) as e:
                last_err = e
                time.sleep(0.5)
        raise ConnectionError(f"Could not connect to {self._host}:{self._port} after {timeout}s") from last_err

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._buffer = b""

    # ── low-level I/O ───────────────────────────────────────────────────

    def _send(self, body: str) -> None:
        raw = f"Content-Length: {len(body)}\r\n\r\n{body}".encode()
        self._sock.sendall(raw)

    def _recv(self, size: int = 8192) -> bytes:
        chunk = self._sock.recv(size)
        if not chunk:
            raise ConnectionError("debug adapter closed the connection")
        return chunk

    def read_message(self) -> dict:
        self._buffer += self._recv()
        # peel off one complete DAP message
        while True:
            idx = self._buffer.find(b"\r\n\r\n")
            if idx == -1:
                self._buffer += self._recv()
                continue
            header = self._buffer[:idx].decode("ascii", errors="replace")
            length = 0
            for line in header.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":", 1)[1].strip())
                    break
            body_start = idx + 4
            if len(self._buffer) < body_start + length:
                self._buffer += self._recv()
                continue
            body = self._buffer[body_start : body_start + length]
            self._buffer = self._buffer[body_start + length :]
            return json.loads(body.decode("utf-8"))

    # ── high-level wire helpers ─────────────────────────────────────────

    def send_request(self, command: str, arguments: dict | None = None) -> int:
        self._seq += 1
        body = json.dumps(
            {
                "seq": self._seq,
                "type": "request",
                "command": command,
                "arguments": arguments or {},
            }
        )
        self._send(body)
        return self._seq

    def read_response(self, expected_seq: int) -> dict:
        while True:
            msg = self.read_message()
            if msg["type"] == "response" and msg.get("request_seq") == expected_seq:
                if not msg.get("success", False):
                    err = msg.get("message", msg.get("body", {}).get("error", {}).get("format", "unknown"))
                    raise DAPError(f"{msg.get('command', '?')} failed: {err}")
                return msg.get("body", {})
            if msg["type"] == "event":
                _log.debug("DAP event during response wait: %s", msg.get("event"))

    def request(self, command: str, arguments: dict | None = None) -> dict:
        seq = self.send_request(command, arguments)
        return self.read_response(seq)

    def wait_for_event(self, event: str) -> dict:
        while True:
            msg = self.read_message()
            if msg["type"] == "event" and msg.get("event") == event:
                return msg.get("body", {})

    # ── standard DAP requests ──────────────────────────────────────────

    def initialize(self) -> dict:
        return self.request(
            "initialize",
            {
                "clientID": "patchi-debug",
                "clientName": "Patchi Debugger",
                "adapterID": "python",
                "pathFormat": "path",
                "linesStartAt1": True,
                "columnsStartAt1": True,
                "supportsVariableType": True,
                "supportsRunInTerminalRequest": False,
            },
        )

    def launch(
        self,
        program: str,
        args: list[str] | None = None,
        *,
        type: str = "python",
        console: str = "none",
        sourceLanguages: list[str] | None = None,
    ) -> dict:
        args_body = {
            "type": type,
            "request": "launch",
            "name": "Patchi Debug",
            "program": program,
            "args": args or [],
            "console": console,
        }
        if sourceLanguages is not None:
            args_body["sourceLanguages"] = sourceLanguages
        return self.request("launch", args_body)

    def set_exception_breakpoints(self, filters: list[str] | None = None) -> dict:
        return self.request(
            "setExceptionBreakpoints",
            {
                "filters": filters or ["uncaught"],
            },
        )

    def set_function_breakpoints(self, names: list[str]) -> dict:
        return self.request(
            "setFunctionBreakpoints",
            {
                "breakpoints": [{"name": n} for n in names],
            },
        )

    def set_breakpoints(self, source_path: str, lines: list[int]) -> dict:
        return self.request(
            "setBreakpoints",
            {
                "source": {"path": source_path},
                "breakpoints": [{"line": ln} for ln in lines],
            },
        )

    def configuration_done(self) -> dict:
        return self.request("configurationDone")

    def continue_req(self, thread_id: int = 1) -> dict:
        return self.request("continue", {"threadId": thread_id})

    def stack_trace(self, thread_id: int, levels: int = 30) -> dict:
        return self.request(
            "stackTrace",
            {
                "threadId": thread_id,
                "levels": levels,
            },
        )

    def scopes(self, frame_id: int) -> dict:
        return self.request("scopes", {"frameId": frame_id})

    def variables(self, var_ref: int) -> dict:
        return self.request("variables", {"variablesReference": var_ref})

    def disconnect(self) -> dict:
        return self.request("disconnect")

    # ── non-blocking launch flow ───────────────────────────────────────

    def launch_no_wait(
        self,
        program: str,
        args: list[str] | None = None,
        *,
        type: str = "python",
        console: str = "none",
        sourceLanguages: list[str] | None = None,
    ) -> int:
        """Send ``launch`` + ``configurationDone`` without waiting for the
        launch response.

        Some adapters (codelldb) defer the ``launch`` response until
        ``configurationDone`` has been processed.  Blocking on the response
        before sending ``configurationDone`` deadlocks, so this sends both
        back-to-back and returns the launch request seq.
        """
        body = {
            "type": type,
            "request": "launch",
            "name": "Patchi Debug",
            "program": program,
            "args": args or [],
            "console": console,
        }
        if sourceLanguages is not None:
            body["sourceLanguages"] = sourceLanguages
        launch_seq = self.send_request("launch", body)
        self.send_request("configurationDone", {})
        return launch_seq

    def wait_for_stopped(self, timeout: float) -> dict:
        """Read messages until a ``stopped`` event arrives (within *timeout*).

        Other events and responses (including the deferred ``launch``
        response) are consumed and discarded.  Raises ``TimeoutError`` if no
        stop happens in time.
        """
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for 'stopped' event")
            try:
                self._sock.settimeout(min(max(remaining, 0.5), 5.0))
                msg = self.read_message()
            except (ConnectionError, OSError, TimeoutError) as exc:
                raise TimeoutError("timed out waiting for 'stopped' event") from exc
            if msg.get("type") == "event" and msg.get("event") == "stopped":
                return msg.get("body", {})
