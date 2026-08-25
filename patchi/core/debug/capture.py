from __future__ import annotations

import logging
from pathlib import Path

from patchi.core.debug.adapters.codelldb import CodeLLDBAdapter
from patchi.core.debug.adapters.node import NodeDebugAdapter
from patchi.core.debug.adapters.powershell import PowerShellDebugAdapter
from patchi.core.debug.adapters.python import PythonDebugAdapter

_log = logging.getLogger("patchi.core.debug.capture")

# File types the harnesses can actually run. Anything else is refused so a
# finding pointing at, say, a log file can never be executed as code.
_CAPTURE_EXTENSIONS = frozenset({".py", ".js", ".ts", ".ps1"})


class DebugCapture:
    """Structured capture of runtime state at the moment of an exception.

    Designed for AI fix-agent consumption — compact, information-dense,
    variable-oriented.  Every method returns plain dicts / lists so the
    caller can serialize or format however it likes.
    """

    def __init__(self, raw: dict) -> None:
        self._raw = raw

    @property
    def exception(self) -> str:
        return self._raw.get("exception", "")

    @property
    def thread_id(self) -> int:
        return self._raw.get("thread_id", 0)

    @property
    def frames(self) -> list[dict]:
        return self._raw.get("frames", [])

    @property
    def trigger_frame(self) -> int:
        """Index of the deepest non-library frame (the 'real' crash site)."""
        for i, f in enumerate(self.frames):
            if f.get("path") and "site-packages" not in f["path"].replace("\\", "/"):
                return i
        return 0

    def variable_summary(self, max_var_len: int = 80) -> str:
        """Human- and AI-readable one-line-per-frame summary.

        Example output::

            #1  process_order  myapp/orders.py:42
                total -> None  (expected int)
                user -> User(id=123, name='Alice')
                items -> [<list: 3 items>]
        """
        lines: list[str] = []
        for i, f in enumerate(self.frames):
            marker = " <-- trigger" if i == self.trigger_frame else ""
            lines.append(f"#{i}  {f['name']}  {_short_path(f.get('path',''))}:{f.get('line',0)}{marker}")
            for k, v in f.get("locals", {}).items():
                val = _short_value(v, max_var_len)
                lines.append(f"    {k} -> {val}")
        return "\n".join(lines)

    def to_dict(self, max_vars: int = 15) -> dict:
        """Compact dict ready for JSON serialisation.

        ``max_vars`` limits the total number of variable entries across all
        frames to keep the payload small for LLM context windows.
        """
        capped = []
        remaining = max_vars
        for f in self.frames:
            frame: dict = {
                "name": f["name"],
                "path": _short_path(f.get("path", "")),
                "line": f.get("line", 0),
            }
            if remaining > 0:
                locals_capped = {}
                for k, v in list(f.get("locals", {}).items())[:remaining]:
                    locals_capped[k] = _short_value(v, 60)
                frame["locals"] = locals_capped
                remaining -= len(locals_capped)
            capped.append(frame)
        return {
            "exception": self.exception,
            "trigger_frame": self.trigger_frame,
            "frames": capped,
        }


def capture_exception(
    script: str | Path,
    args: list[str] | None = None,
    timeout: float = 60,
) -> DebugCapture | None:
    """Convenience: run *script* under the debugger and return a
    :class:`DebugCapture` or *None* if it exited cleanly.

    This is the primary entry point for Patchi fix agents.
    """
    ext = Path(script).suffix.lower()

    if ext == ".py":
        adapter = PythonDebugAdapter(script, args)
    elif ext == ".ps1":
        adapter = PowerShellDebugAdapter(script, args)
    elif ext in (".js", ".ts"):
        adapter = NodeDebugAdapter(script, args)
    else:
        _log.warning("unsupported file extension %s – defaulting to Python harness", ext)
        adapter = PythonDebugAdapter(script, args)

    raw = adapter.capture_exception(timeout=timeout)
    if raw is None:
        return None
    return DebugCapture(raw)


def capture_rust_crash(
    binary: str | Path,
    args: list[str] | None = None,
    timeout: float = 60,
) -> DebugCapture | None:
    """Run a compiled Rust (or C++) binary under CodeLLDB and return a
    :class:`DebugCapture` if it crashes, or *None* if it exits cleanly.

    If codelldb is not installed, returns *None* gracefully.
    """
    adapter = CodeLLDBAdapter(binary, args)
    raw = adapter.capture_crash(timeout=timeout)
    if raw is None:
        return None
    return DebugCapture(raw)


def capture_powershell_crash(
    script: str | Path,
    args: list[str] | None = None,
    timeout: float = 60,
) -> DebugCapture | None:
    """Run a PowerShell script under the debug harness and return a
    :class:`DebugCapture` if it crashes, or *None* if it exits cleanly.

    If pwsh is not installed, returns *None* gracefully.
    """
    adapter = PowerShellDebugAdapter(script, args)
    raw = adapter.capture_exception(timeout=timeout)
    if raw is None:
        return None
    return DebugCapture(raw)


def debug_context_from_finding(finding: dict, root: Path) -> dict | None:
    """Return a debug-context dict if *finding* is a test failure, else *None*.

    Runs the failing test file under the debugger harness and returns compact
    runtime-state data for the AI prompt.
    """
    if finding.get("type") != "test_failure":
        return None
    test_file = finding.get("file", "")
    if not test_file:
        return None
    # The finding path comes from the scanned repo — never let it escape the
    # project root: an absolute path or "../" traversal would make us execute
    # an arbitrary file outside the project as code.
    root_resolved = Path(root).resolve()
    test_path = (root_resolved / test_file).resolve()
    try:
        test_path.relative_to(root_resolved)
    except ValueError:
        _log.warning("refusing to capture outside project root: %s", test_file)
        return None
    if not test_path.is_file():
        return None
    if test_path.suffix.lower() not in _CAPTURE_EXTENSIONS:
        _log.warning("refusing to capture unsupported file type: %s", test_file)
        return None

    cap = capture_exception(test_path, timeout=30)
    if cap is None:
        return None
    return cap.to_dict(max_vars=15)


def _short_path(p: str) -> str:
    try:
        return str(Path(p).relative_to(Path.cwd()))
    except ValueError:
        return p


def _short_value(val, max_len: int) -> str:
    if isinstance(val, dict):
        if val.get("__depth_limit__"):
            return "{...}"
        if val.get("__error__"):
            return "{?}"
        return f"{{{', '.join(_short_value(v, 20) for v in list(val.values())[:3])}{'…' if len(val) > 3 else ''}}}"
    s = str(val)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s
