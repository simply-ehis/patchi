from __future__ import annotations

import json
import logging
import subprocess
import tempfile
import textwrap
from pathlib import Path

_LOG = logging.getLogger("patchi.debug.adapters.node")

_BUILTIN_VARS = frozenset({
    "arguments", "console", "process", "require", "module", "__filename",
    "__dirname", "global", "Buffer", "clearTimeout", "setTimeout",
    "setInterval", "clearInterval", "setImmediate", "Promise",
    "JSON", "Object", "String", "Number", "Boolean", "Function", "Array",
    "Date", "Math", "RegExp", "Error", "SyntaxError", "TypeError",
    "ReferenceError", "RangeError", "URIError", "EvalError", "Symbol",
    "Map", "Set", "WeakMap", "WeakSet", "Proxy", "Reflect",
})


class NodeDebugAdapter:
    def __init__(self, script: str | Path, args: list[str] | None = None):
        self._script = Path(script).resolve()
        self._args = args or []

    def available(self) -> bool:
        return _find_node() is not None

    def capture_exception(self, timeout: float = 60) -> dict | None:
        node_path = _find_node()
        if node_path is None:
            _LOG.warning("node not found on PATH")
            return None

        harness_code = _build_harness(self._script, self._args)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False, encoding="utf-8"
        ) as f:
            f.write(harness_code)
            tmp_path = Path(f.name)

        try:
            proc = subprocess.run(
                [str(node_path), "--no-warnings", str(tmp_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self._script.parent,
            )
        except subprocess.TimeoutExpired:
            _LOG.warning("node harness timed out after %s seconds", timeout)
            return None
        finally:
            tmp_path.unlink(missing_ok=True)

        if proc.returncode == 0:
            return None

        for line in (proc.stderr + "\n" + proc.stdout).splitlines():
            stripped = line.strip()
            prefix = "PATCHI_DEBUG_CAPTURE:"
            if stripped.startswith(prefix):
                try:
                    return json.loads(stripped[len(prefix):])
                except json.JSONDecodeError:
                    _LOG.warning("PATCHI_DEBUG_CAPTURE JSON parse error: %.200s", stripped)
                    return None

        _LOG.debug(
            "node exited code=%d but no PATCHI_DEBUG_CAPTURE token in stderr/stdout",
            proc.returncode,
        )
        return None

    def _resolve_variables(self, var_ref: int, max_depth: int = 2, depth: int = 0) -> dict:
        raise NotImplementedError("Node adapter uses harness, not DAP protocol")


def _find_node() -> Path | None:
    try:
        result = subprocess.run(
            ["where", "node"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                p = Path(line.strip())
                if p.is_file():
                    return p
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def _js_quote(s: str) -> str:
    """JavaScript double-quoted string with proper escaping.

    Backslash must be escaped FIRST — escaping `"` before `\\` turns the
    generated `\"` into `\\"`, leaving the quote unescaped and allowing
    arbitrary JS injection via a script path or argument containing a quote.
    """
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _build_harness(script: Path, args: list[str] | None) -> str:
    script_quoted = _js_quote(str(script))
    args_repr = ", ".join(_js_quote(a) for a in (args or []))

    return textwrap.dedent(f"""\
        'use strict';

        const $script = {script_quoted};
        const $args = [{args_repr}];

        // Route process.argv through the target script so scripts that read
        // process.argv[2..] see their real arguments, not the harness's.
        process.argv = [process.argv[0], $script].concat($args);

        let $capture = {{
            exception: null,
            thread_id: 1,
            frames: [],
            stack: null
        }};

        function $parseStack(stack) {{
            if (!stack) return [];
            const lines = stack.split('\\n');
            const frames = [];
            for (const line of lines) {{
                const match = line.match(/^\\s+at\\s+(.+?)\\s+\\((.+?):(\\d+):(\\d+)\\)/);
                if (match) {{
                    frames.push({{
                        name: match[1],
                        path: match[2],
                        line: parseInt(match[3]),
                        lineEnd: parseInt(match[4]),
                        locals: {{}}
                    }});
                }} else {{
                    const match2 = line.match(/^\\s+at\\s+(.+?):(\\d+):(\\d+)/);
                    if (match2) {{
                        frames.push({{
                            name: '<anonymous>',
                            path: match2[1],
                            line: parseInt(match2[2]),
                            lineEnd: parseInt(match2[3]),
                            locals: {{}}
                        }});
                    }}
                }}
            }}
            return frames;
        }}

        function $emit(capture) {{
            console.error('PATCHI_DEBUG_CAPTURE:' + JSON.stringify(capture));
            process.exit(1);
        }}

        process.on('uncaughtException', (exc) => {{
            $capture.exception = exc.message || String(exc);
            $capture.frames = $parseStack(exc.stack);
            $emit($capture);
        }});

        process.on('unhandledRejection', (reason, promise) => {{
            const exc = reason instanceof Error ? reason : new Error(String(reason));
            $capture.exception = exc.message || String(exc);
            $capture.frames = $parseStack(exc.stack);
            $emit($capture);
        }});

        try {{
            require($script);
        }} catch (exc) {{
            $capture.exception = exc.message || String(exc);
            $capture.frames = $parseStack(exc.stack);
            $emit($capture);
        }}
        """)