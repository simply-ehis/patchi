from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import time
from pathlib import Path

from patchi.core.debug.dap_client import DAPClient, DAPError

_log = logging.getLogger("patchi.debug.adapters.codelldb")

# Well-known installation paths for CodeLLDB
_CODELDB_CANDIDATES: list[str] = []

_vscode_base = Path(os.environ.get("USERPROFILE", "~")) / ".vscode" / "extensions"
if _vscode_base.is_dir():
    for entry in _vscode_base.iterdir():
        if entry.name.startswith("vadimcn.vscode-lldb"):
            _CODELDB_CANDIDATES.append(str(entry / "codelldb.exe"))
            _CODELDB_CANDIDATES.append(str(entry / "codelldb"))
            _CODELDB_CANDIDATES.append(str(entry / "adapter" / "codelldb.exe"))
            _CODELDB_CANDIDATES.append(str(entry / "lldb" / "bin" / "lldb-vscode.exe"))

_vscode_insiders = Path(os.environ.get("USERPROFILE", "~")) / ".vscode-insiders" / "extensions"
if _vscode_insiders.is_dir():
    for entry in _vscode_insiders.iterdir():
        if entry.name.startswith("vadimcn.vscode-lldb"):
            _CODELDB_CANDIDATES.append(str(entry / "codelldb.exe"))
            _CODELDB_CANDIDATES.append(str(entry / "codelldb"))
            _CODELDB_CANDIDATES.append(str(entry / "adapter" / "codelldb.exe"))

# Also check PATH / common standalone installs
_PATH_CANDIDATES = ["codelldb", "codelldb.exe", "lldb-vscode", "lldb-vscode.exe"]

# Symbol reached for every Rust panic (unwinding and abort alike).
_PANIC_SYMBOL = "__rustc::__rust_start_panic"

# ``frame #N: 0xADDR module`func(args) at file:line[:col]`` (line may carry
# trailing markers like "[inlined]"). The location group is lazy so Windows
# drive-letter colons in absolute paths don't truncate it.
_FRAME_RE = re.compile(
    r"frame #(\d+): 0x[0-9a-f]+ [^`]+`([^ ]+)"
    r"(?: at (.+?):(\d+)(?::(\d+))?)?"
)


def find_codelldb() -> str | None:
    for p in _CODELDB_CANDIDATES:
        if Path(p).is_file():
            return p
    for name in _PATH_CANDIDATES:
        which = Path(name)
        if which.is_file():
            return str(which.resolve())
        import shutil

        found = shutil.which(name)
        if found:
            return found
    return None


def _find_lldb_cli(exe: str) -> str | None:
    """Bundled LLDB command-line binary that ships inside the extension."""
    root = Path(exe).resolve()
    candidates = [
        root.parent.parent / "lldb" / "bin" / "lldb.exe",  # adapter\codelldb.exe
        root.parent / "lldb" / "bin" / "lldb.exe",  # extension-root codelldb.exe
        root.parent.parent / "lldb" / "bin" / "lldb",  # non-Windows
        root.parent / "lldb" / "bin" / "lldb",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


class CodeLLDBAdapter:
    """Drives CodeLLDB (LLDB debugger for Rust / C++) to capture post-crash state.

    Uses the DAP server first (richer data: locals per frame), then falls back
    to the bundled LLDB command line, which is deterministic.  Usage::

        adapter = CodeLLDBAdapter("/path/to/binary")
        capture = adapter.capture_crash(timeout=60)
        print(capture.get("exception", ""))
    """

    def __init__(self, binary: str | Path, args: list[str] | None = None):
        self._binary = Path(binary).resolve()
        self._args = args or []

    def available(self) -> bool:
        """Check if a usable codelldb binary can be found."""
        return find_codelldb() is not None

    def capture_crash(self, timeout: float = 60) -> dict | None:
        """Return a structured capture dict if the target crashes, else *None*."""
        exe = find_codelldb()
        if not exe:
            _log.info("codelldb not found — skipping Rust/C++ debug capture")
            return None

        deadline = time.monotonic() + max(timeout, 1)
        cap = self._capture_dap(exe, min(6.0, max(3.0, timeout / 4)))
        if cap is not None:
            return cap
        if time.monotonic() < deadline:
            cap = self._capture_cli(exe, deadline - time.monotonic())
        return cap

    # ── DAP attempt (best effort, bounded) ──────────────────────────────

    def _capture_dap(self, exe: str, budget: float) -> dict | None:
        port = self._pick_port()
        client = DAPClient(port=port)
        proc = self._start_server(exe, port)
        deadline = time.monotonic() + budget
        try:
            client.connect(timeout=min(10.0, budget))
            client.initialize()
            client.send_request(
                "launch",
                {
                    "type": "lldb",
                    "request": "launch",
                    "name": "Patchi Debug",
                    "program": str(self._binary),
                    "args": self._args or [],
                    "console": "internalConsole",
                    "sourceLanguages": ["rust"],
                    # Deterministic entry stop; stopOnEntry alone is racy on Windows.
                    "processCreateCommands": ["process launch -s"],
                },
            )
            # Set the panic breakpoint before configurationDone so its
            # response is not starved by the deferred launch response.
            client.send_request(
                "setFunctionBreakpoints",
                {
                    "breakpoints": [{"name": _PANIC_SYMBOL}],
                },
            )
            client.send_request("configurationDone", {})

            entry = _pump_until(client, deadline, "stopped")
            if entry is None:
                _log.info("DAP: no entry stop")
                return None
            entry_desc = entry.get("description") or entry.get("reason") or ""
            # Launch/configDone responses are deferred until the process is
            # resumed — continue first, then pump everything.
            client.send_request("continue", {"threadId": entry.get("threadId", 1)})
            stop = _pump_until(client, deadline, "stopped")
            if stop is None:
                _log.info("DAP: no panic stop after continue")
                return None
            desc = stop.get("description") or stop.get("text") or stop.get("reason") or "rust panic"
            # codelldb sometimes re-delivers the entry int3 stop instead of
            # the breakpoint hit — treat that as a failed attempt.
            if desc == entry_desc:
                _log.info("DAP: duplicate entry stop, not the panic")
                return None

            time.sleep(0.5)  # let the stop state settle before querying
            tid = stop.get("threadId", 1)
            if tid <= 0:
                tids = _try_threads(client)
                tid = tids[0] if tids else 1
            frames = self._capture_frames_retry(client, tid)
            if not frames:
                _log.info("DAP: stackTrace failed on tid %s", tid)
                return None
            return {"thread_id": tid, "exception": desc, "frames": frames}
        except (ConnectionError, DAPError, OSError, TimeoutError, KeyError) as exc:
            _log.info("codelldb DAP capture attempt failed: %s", exc)
            return None
        finally:
            client.close()
            _kill_after(proc)

    # ── CLI fallback (deterministic) ────────────────────────────────────

    def _capture_cli(self, exe: str, budget: float) -> dict | None:
        cli = _find_lldb_cli(exe)
        if not cli:
            _log.info("no bundled lldb CLI next to codelldb — skipping CLI capture")
            return None
        cmd = [
            cli,
            "-b",
            "-o",
            f"break set -n {_PANIC_SYMBOL}",
            "-o",
            "run",
            "-o",
            "bt 30",
            "--",
            str(self._binary),
            *self._args,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=budget,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _log.warning("lldb CLI capture failed: %s", exc)
            return None
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        frames = _parse_cli_frames(out)
        if not frames:
            # Clean exit or no breakpoint hit — nothing to capture.
            return None
        return {
            "thread_id": 0,
            "exception": _parse_cli_exception(out),
            "frames": frames,
        }

    # ── internals ────────────────────────────────────────────────────────

    def _pick_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _start_server(self, exe: str, port: int) -> subprocess.Popen:
        cmd = [exe, "--port", str(port)]
        _log.debug("launching codelldb: %s", " ".join(cmd))
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def _capture_frames_retry(self, client: DAPClient, thread_id: int) -> list[dict]:
        for _ in range(3):
            try:
                frames = self._capture_frames(client, thread_id)
                if frames:
                    return frames
            except (DAPError, ConnectionError, OSError, TimeoutError, KeyError):
                time.sleep(1.0)
        return []

    def _capture_frames(self, client: DAPClient, thread_id: int) -> list[dict]:
        try:
            st = client.stack_trace(thread_id)
        except Exception:
            return []
        frames = []
        for sf in st.get("stackFrames", []):
            try:
                locals_vars = self._frame_locals(client, sf["id"])
            except Exception:
                locals_vars = {}
            frames.append(
                {
                    "id": sf["id"],
                    "name": sf.get("name", ""),
                    "path": (sf.get("source") or {}).get("path", ""),
                    "line": sf.get("line", 0),
                    "locals": locals_vars,
                }
            )
        return frames

    def _frame_locals(self, client: DAPClient, frame_id: int) -> dict:
        scope_list = client.scopes(frame_id)
        for sc in scope_list.get("scopes", []):
            if sc.get("name") in ("Local", "Locals"):
                return _resolve_variables(client, sc["variablesReference"])
        return {}


# ── helpers ──────────────────────────────────────────────────────────────


def _pump_until(client: DAPClient, deadline: float, event: str) -> dict | None:
    """Read messages until *event* arrives or *deadline* passes."""
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            client._sock.settimeout(min(max(remaining, 0.1), 3.0))
            msg = client.read_message()
        except TimeoutError:
            continue
        except (ConnectionError, OSError):
            break
        if msg.get("type") == "event" and msg.get("event") == event:
            return msg.get("body", {})
    return None


def _try_threads(client: DAPClient) -> list[int]:
    try:
        body = client.request("threads", {})
        return [t.get("id", 0) for t in body.get("threads", []) if t.get("id", 0) > 0]
    except Exception:
        return []


def _resolve_variables(client: DAPClient, var_ref: int, max_depth: int = 2, depth: int = 0) -> dict:
    if depth >= max_depth or var_ref <= 0:
        return {"__depth_limit__": True}
    try:
        vars_list = client.variables(var_ref)
    except Exception:
        return {"__error__": "variables request failed"}
    result = {}
    for v in vars_list.get("variables", []):
        name = v.get("name", "")
        value = v.get("value", "")
        ref = v.get("variablesReference", 0)
        if ref > 0:
            value = _resolve_variables(client, ref, max_depth, depth + 1)
        result[name] = value
    return result


def _parse_cli_exception(out: str) -> str:
    """Extract the Rust panic message from lldb batch output."""
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "panicked at " in line:
            msg = line.split("panicked at ", 1)[1].strip()
            # Rust prints the message on the next line when it contains
            # backticks / spaces.
            for nxt in lines[i + 1 :]:
                nxt = nxt.strip()
                if not nxt:
                    continue
                if nxt.startswith(("note:", "warning:", "Process ", "thread ", "(lldb)")):
                    break
                msg += " " + nxt
                break
            return "panicked at " + msg
    return "rust panic"


def _parse_cli_frames(out: str) -> list[dict]:
    """Parse ``bt`` output into the same frame dict shape as the DAP path."""
    frames = []
    for m in _FRAME_RE.finditer(out):
        name = m.group(2)
        name = re.sub(r"\(.*\)$", "", name)  # strip argument lists
        frames.append(
            {
                "id": int(m.group(1)),
                "name": name,
                "path": m.group(3) or "",
                "line": int(m.group(4) or 0),
                "locals": {},
            }
        )
    return frames


def _kill_after(proc: subprocess.Popen, timeout: float = 3) -> None:
    """Kill the codelldb server (and its child tree on Windows)."""
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
            )
        else:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
