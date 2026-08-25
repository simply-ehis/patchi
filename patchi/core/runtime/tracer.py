"""
Runtime Tracer — AST-guided execution tracing for Python target code.

Runs a Python file in a fresh subprocess under a sys.settrace-based tracer
that records:
  - every function call/return (name, file, line, duration)
  - raised exceptions with full argument snapshot
  - total wall time

Bounded by design: wall-clock timeout kills the child; trace buffer is
capped; output is a single JSON blob on a pipe — never interleaved with
program stdout.

This closes the gap between "scanner found it" and "reproduced it":
RuntimeCrashScanner findings can be fed here for a reproduction trace.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger("patchi.core.runtime.tracer")

# The child-side tracer source. Injected as a file so we don't fight
# shell quoting; kept as one string so it stays reviewable.
_CHILD_TRACER = r"""
import json
import sys
import time
import tracemalloc

MAX_CALLS = int(sys.argv[1]) if len(sys.argv) > 1 else 5000

calls = []          # completed call records
exceptions = []     # captured exceptions
order = [0]
tracemalloc.start()

def _tracer(frame, event, arg):
    if len(calls) >= MAX_CALLS and event != "exception":
        return None
    co = frame.f_code
    rec = {
        "fn": co.co_name,
        "file": co.co_filename,
        "line": co.co_firstlineno,
    }
    if event == "call":
        order[0] += 1
        rec["seq"] = order[0]
        rec["event"] = "call"
        calls.append(rec)
        return _tracer
    if event == "return":
        rec["event"] = "return"
        calls.append(rec)
        return None
    if event == "exception":
        exc_type, exc_val, _ = arg
        tb = exc_val.__traceback__
        exceptions.append({
            "type": exc_type.__name__,
            "message": str(exc_val)[:300],
            "file": tb.tb_frame.f_code.co_filename if tb else co.co_filename,
            "line": tb.tb_lineno if tb else 0,
            "locals": {
                k: repr(v)[:120]
                for k, v in list(frame.f_locals.items())[:15]
                if not k.startswith("__")
            },
        })
        return _tracer
    return None


def main():
    target = sys.argv[2]
    out_path = sys.argv[3]
    sys.argv = [target] + sys.argv[4:]
    sys.settrace(_tracer)
    t0 = time.perf_counter()
    exit_code = 0
    try:
        with open(target, encoding="utf-8") as fh:
            code = compile(fh.read(), target, "exec")
        g = {"__name__": "__main__", "__file__": target}
        exec(code, g)
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 0
    except BaseException as e:
        exit_code = 1
        exceptions.append({
            "type": type(e).__name__,
            "message": str(e)[:300],
            "file": target,
            "line": getattr(getattr(e, "__traceback__", None), "tb_lineno", 0),
            "locals": {},
            "fatal": True,
        })
    finally:
        sys.settrace(None)
    duration = time.perf_counter() - t0
    current, peak = tracemalloc.get_traced_memory()
    out = {
        "exit_code": exit_code,
        "duration_s": round(duration, 4),
        "peak_memory_bytes": peak,
        "call_count": len(calls),
        "truncated": len(calls) >= MAX_CALLS,
        "calls": calls[-200:],       # tail: most recent activity
        "exceptions": exceptions,
    }
    # Dedicated file, NOT stdout: the traced program owns stdout.
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, default=str)

main()
"""


@dataclass
class TraceReport:
    """Structured result of one traced run."""

    exit_code: int = -1
    duration_s: float = 0.0
    peak_memory_bytes: int = 0
    call_count: int = 0
    truncated: bool = False
    calls: list[dict] = field(default_factory=list)
    exceptions: list[dict] = field(default_factory=list)
    error: str = ""

    @property
    def crashed(self) -> bool:
        return bool(self.exceptions) or self.exit_code not in (0, None)

    def hot_functions(self, top_n: int = 10) -> list[tuple[str, int]]:
        """Most-called functions — N+1 query / loop-hotspot candidates."""
        counts: dict[str, int] = {}
        for c in self.calls:
            if c.get("event") == "call":
                key = f"{c['fn']} ({Path(c['file']).name}:{c['line']})"
                counts[key] = counts.get(key, 0) + 1
        return sorted(counts.items(), key=lambda kv: -kv[1])[:top_n]

    def to_dict(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "duration_s": self.duration_s,
            "peak_memory_bytes": self.peak_memory_bytes,
            "call_count": self.call_count,
            "truncated": self.truncated,
            "crashed": self.crashed,
            "hot_functions": [{"fn": fn, "calls": n} for fn, n in self.hot_functions()],
            "exceptions": self.exceptions,
            "error": self.error,
        }


def trace_file(
    script: str | Path,
    timeout: float = 60.0,
    max_calls: int = 5000,
    args: list[str] | None = None,
) -> TraceReport:
    """
    Run *script* under the tracer; returns a TraceReport.

    Never raises for program behavior — crashes are captured data. Raises
    only for infrastructure failures (missing file, bad extension).
    """
    path = Path(script).resolve()
    if path.suffix.lower() != ".py":
        raise ValueError(f"tracer supports .py only, got {path.suffix}")
    if not path.is_file():
        raise FileNotFoundError(str(path))

    with tempfile.TemporaryDirectory() as td:
        tracer_path = Path(td) / "_patchi_tracer.py"
        tracer_path.write_text(_CHILD_TRACER, encoding="utf-8")
        out_path = Path(td) / "trace_out.json"

        cmd = [
            sys.executable,
            str(tracer_path),
            str(max_calls),
            str(path),
            str(out_path),
            *(args or []),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                cwd=str(path.parent),
            )
        except subprocess.TimeoutExpired:
            return TraceReport(error=f"timed out after {timeout}s")

        if not out_path.is_file():
            return TraceReport(
                error=f"tracer failed rc={proc.returncode}: {proc.stderr.decode(errors='replace')[:300]}"
            )

        try:
            raw = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return TraceReport(error=f"unparseable trace output: {e}")

        report = TraceReport(
            exit_code=raw.get("exit_code", -1),
            duration_s=raw.get("duration_s", 0.0),
            peak_memory_bytes=raw.get("peak_memory_bytes", 0),
            call_count=raw.get("call_count", 0),
            truncated=raw.get("truncated", False),
            calls=raw.get("calls", []),
            exceptions=raw.get("exceptions", []),
        )
        # A fatal exception means exit handler captured it but exit stayed 1.
        if any(x.get("fatal") for x in report.exceptions):
            report.exit_code = 1
        return report
