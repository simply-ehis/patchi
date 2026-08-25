"""
AST utilities — per-language node type configs and common sink sets.

Centralized configuration used by security agents, type checkers, and route
detectors when walking tree-sitter parse trees or the Python `ast` module.
"""

from __future__ import annotations

from patchi.core.brain.languages import Lang

# ── Per-language node type config ─────────────────────────────────────────────

# Languages in this codebase use tree-sitter (except Python which uses ast)
CALL_NODE_TYPES: dict[Lang, set[str]] = {
    Lang.PYTHON: set(),  # handled by ast
    Lang.JAVASCRIPT: {"call_expression"},
    Lang.TYPESCRIPT: {"call_expression"},
    Lang.RUST: {"call_expression"},
    Lang.JAVA: {"method_invocation"},
    Lang.GO: {"call_expression"},
    Lang.C: {"call_expression"},
    Lang.CPP: {"call_expression"},
    Lang.SWIFT: {"function_call_expression"},
    Lang.RUBY: {"call"},
    Lang.PHP: {"function_call_expression", "scoped_call_expression"},
    Lang.C_SHARP: {"invocation_expression"},
    Lang.KOTLIN: {"call_expression"},
    Lang.DART: {"function_expression"},
}

IMPORT_NODE_TYPES: dict[Lang, set[str]] = {
    Lang.PYTHON: set(),  # handled by ast
    Lang.JAVASCRIPT: {"import_statement", "import_require_clause"},
    Lang.TYPESCRIPT: {"import_statement", "import_require_clause"},
    Lang.RUST: {"use_declaration"},
    Lang.JAVA: {"import_declaration"},
    Lang.GO: {"import_declaration"},
    Lang.C: {"preproc_include"},
    Lang.CPP: {"preproc_include"},
    Lang.SWIFT: {"import_declaration"},
    Lang.RUBY: {"call"},  # require/include are calls with specific names
    Lang.PHP: {"namespace_use_declaration", "use_declaration"},
    Lang.C_SHARP: {"using_directive"},
    Lang.KOTLIN: {"import"},
    Lang.DART: {"import"},
}

DECORATOR_NODE_TYPES: dict[Lang, set[str]] = {
    Lang.PYTHON: set(),  # handled by ast
    Lang.JAVA: {"marker_annotation", "annotation"},
    Lang.C_SHARP: {"attribute"},
    Lang.KOTLIN: {"annotation"},
    Lang.PHP: {"attribute_group"},
}

# ── Common function names used across agents ─────────────────────────────────

EXEC_SINKS = {
    "execute",
    "exec",
    "eval",
    "execScript",
    "Runtime.getRuntime().exec",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
    "ProcessBuilder",
    "shell_exec",
    "system",
    "passthru",
    "exec_",
    "child_process.exec",
    "child_process.execSync",
    "child_process.spawnSync",
    "child_process.spawn",
    "child_process.execFile",
    "execSync",
    "spawnSync",
}

SQL_SINKS = {
    "execute",
    "execute_query",
    "executeQuery",
    "executeUpdate",
    "exec",
    "query",
    "raw_query",
    "prepare",
    "preparedStatement",
    "cursor.execute",
    "cursor.executemany",
    "db.execute",
    "session.execute",
    "EntityManager.createQuery",
    "entityManager.createQuery",
    "JdbcTemplate.query",
    "jdbcTemplate.query",
}

HTTP_CLIENTS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.patch",
    "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post",
    "urllib.request.urlopen",
    "urllib.request.Request",
    "urllib3.request",
    "curl",
    "wget",
    "fetch",
    "axios.get",
    "axios.post",
    "axios.put",
    "axios.delete",
    "got",
    "node-fetch",
    "superagent",
}
