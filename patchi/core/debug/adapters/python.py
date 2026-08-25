from __future__ import annotations

import json
import logging
import subprocess
import sys
import textwrap
from pathlib import Path

_LOG = logging.getLogger("patchi.debug.adapters.python")


class PythonDebugAdapter:
    def __init__(self, script: str | Path, args: list[str] | None = None):
        self._script = Path(script).resolve()
        self._args = args or []

    def capture_exception(self, timeout: float = 60) -> dict | None:
        # 1) Standalone exec harness — catches module-level crashes in plain
        #    scripts (the fast, dependency-free path).
        cap = self._capture_standalone(timeout)
        if cap is not None:
            return cap

        # 2) Pytest harness — a real test file imports cleanly but only fails
        #    *inside* a test function, which the standalone harness can't see.
        if _looks_like_test_file(self._script):
            cap = self._capture_pytest(timeout)
            if cap is not None:
                return cap

        return None

    def _capture_standalone(self, timeout: float) -> dict | None:
        harness = _build_harness(self._script)
        cmd = [sys.executable, "-Xfrozen_modules=off", "-c", harness, *self._args]
        _LOG.debug("running python harness: %s …", " ".join(cmd[:4]))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            _LOG.warning("python harness timed out after %s seconds", timeout)
            return None
        except OSError as e:
            _LOG.warning("python harness failed to start: %s", e)
            return None
        if proc.returncode == 0:
            return None

        for stream in (proc.stdout, proc.stderr):
            for line in stream.splitlines():
                stripped = line.strip()
                prefix = "PATCHI_DEBUG_CAPTURE:"
                if stripped.startswith(prefix):
                    try:
                        return json.loads(stripped[len(prefix) :])
                    except json.JSONDecodeError:
                        _LOG.warning("PATCHI_DEBUG_CAPTURE JSON parse error: %.200s", stripped)
                        return None

        _LOG.debug("python exited code=%d but no capture token", proc.returncode)
        return None

    def _capture_pytest(self, timeout: float) -> dict | None:
        harness = _build_pytest_harness(self._script)
        cmd = [sys.executable, "-Xfrozen_modules=off", "-c", harness, *self._args]
        _LOG.debug("running pytest harness: %s …", " ".join(cmd[:4]))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            _LOG.warning("pytest harness timed out after %s seconds", timeout)
            return None

        for stream in (proc.stderr, proc.stdout):
            for line in stream.splitlines():
                stripped = line.strip()
                prefix = "PATCHI_DEBUG_CAPTURE:"
                if stripped.startswith(prefix):
                    try:
                        return json.loads(stripped[len(prefix) :])
                    except json.JSONDecodeError:
                        _LOG.warning("PATCHI_DEBUG_CAPTURE JSON parse error: %.200s", stripped)
                        return None

        _LOG.debug("pytest exited code=%d but no capture token", proc.returncode)
        return None

    def _resolve_variables(self, var_ref: int, max_depth: int = 2, depth: int = 0) -> dict:
        raise NotImplementedError("Python adapter uses harness, not DAP protocol")


def _looks_like_test_file(script: Path) -> bool:
    """Heuristic: does the file look like a pytest/unittest test module?"""
    try:
        text = script.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return False
    if "pytest" in text or "unittest" in text:
        return True
    if "def test_" in text or "class Test" in text:
        return True
    return False


def _build_harness(script: Path) -> str:
    """Generate a Python script that wraps the target in an exception hook
    that captures local variables and prints them as JSON on stdout.

    ``__file__`` and ``__name__`` are injected so scripts that read them at
    module level don't blow up (``python -c`` otherwise has no ``__file__``).
    """
    script_code = script.read_text(encoding="utf-8-sig", errors="replace")
    return textwrap.dedent(f"""\
        import json, sys

        def _patchi_capture(exc_type, exc_value, exc_tb):
            frames = []
            tb = exc_tb
            while tb:
                frame = tb.tb_frame
                fname = frame.f_code.co_name
                fpath = frame.f_code.co_filename
                lineno = tb.tb_lineno
                # Only include user frames, not the harness itself
                if '<string>' not in fpath:
                    # Capture locals for every user frame, redacting secrets
                    # so credentials never reach the AI prompt.
                    locals_ = {{k: _patchi_redact(k, v) for k, v in frame.f_locals.items()
                                if not k.startswith('_')}}
                    frames.append({{
                        "name": fname,
                        "path": fpath,
                        "line": lineno,
                        "locals": locals_,
                    }})
                tb = tb.tb_next
            frames.reverse()
            data = {{
                "exception": f"{{exc_type.__name__}}: {{exc_value}}",
                "thread_id": 1,
                "frames": frames,
            }}
            # stderr + token prefix: the target script may print to stdout
            # before crashing, so a bare JSON dump would be polluted.
            print("PATCHI_DEBUG_CAPTURE:" + json.dumps(data), file=sys.stderr, flush=True)

        import re as _re
        _SECRET_NAMES = _re.compile(
            r"(password|passwd|secret|token|api[_-]?key|apikey|credential|authorization|private[_-]?key|access[_-]?key|session[_-]?id|aws[_-]?secret)", _re.I)

        def _patchi_redact(k, v):
            if _SECRET_NAMES.search(k):
                return "{{REDACTED}}"
            return repr(v)

        sys.excepthook = _patchi_capture

        _globals = {{'__name__': '__main__', '__file__': {str(script)!r}, '__builtins__': __builtins__}}
        exec(compile({script_code!r}, {str(script)!r}, "exec"), _globals)
        """)


def _build_pytest_harness(script: Path) -> str:
    """Generate a harness that runs the target file under pytest and captures
    the first test failure's traceback + locals via a small in-process plugin.

    The plugin serializes the capture and prints a single line prefixed with
    ``PATCHI_DEBUG_CAPTURE:`` so the adapter can parse it reliably.
    """
    return textwrap.dedent(f"""\
        import json, sys
        import pytest

        _captured = {{}}

        def _patchi_capture_frames(exc_tb):
            import re as _re
            import sys as _sys
            _SECRET_NAMES = _re.compile(
                r"(password|passwd|secret|token|api[_-]?key|apikey|credential|authorization|private[_-]?key|access[_-]?key|session[_-]?id|aws[_-]?secret)", _re.I)

            def _redact(k, v):
                if _SECRET_NAMES.search(k):
                    return "{{REDACTED}}"
                return repr(v)

            frames = []
            tb = exc_tb
            while tb:
                frame = tb.tb_frame
                fname = frame.f_code.co_name
                fpath = frame.f_code.co_filename
                lineno = tb.tb_lineno
                # Keep user frames only: skip the harness and Python internals.
                norm = fpath.replace("\\\\", "/")
                is_stdlib = norm.startswith(_sys.prefix.replace("\\\\", "/") + "/")
                if "<string>" not in fpath and "site-packages" not in norm and not is_stdlib:
                    locals_ = {{k: _redact(k, v) for k, v in frame.f_locals.items()
                                if not k.startswith('_')}}
                    frames.append({{
                        "name": fname,
                        "path": fpath,
                        "line": lineno,
                        "locals": locals_,
                    }})
                tb = tb.tb_next
            frames.reverse()
            return frames

        class _CapturePlugin:
            def pytest_runtest_makereport(self, item, call):
                global _captured
                if _captured:
                    return
                if call.when == "call" and call.excinfo is not None:
                    exc = call.excinfo
                    _captured = {{
                        "exception": f"{{exc.type.__name__}}: {{exc.value}}",
                        "thread_id": 1,
                        "frames": _patchi_capture_frames(exc.tb),
                    }}

            def pytest_sessionfinish(self, session, exitstatus):
                if _captured:
                    # stderr: pytest writes its own progress chars to stdout,
                    # so a token on stdout would be prefixed with them.
                    print("PATCHI_DEBUG_CAPTURE:" + json.dumps(_captured), file=sys.stderr, flush=True)

        sys.exit(pytest.main([{str(script)!r}, "-x", "-q", "-s", "--no-header", "--tb=short"],
                             plugins=[_CapturePlugin()]))
        """)
