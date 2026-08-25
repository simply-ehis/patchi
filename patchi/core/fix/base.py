"""
Base functionality for fix agents.
"""

import os
import re
from pathlib import Path

from patchi.core.fix.patch import (
    FileChange,
    Patch,
    PatchState,
    PatchType,
    compute_confidence,
    compute_risk_score,
)


def _call_ai(prompt: str, config: dict, max_tokens: int = 1500, system_prompt: str = "") -> str:
    if os.environ.get("PATCHI_OFFLINE"):
        return ""
    """
    Call the configured AI model with a prompt.
    Delegates to the canonical client. Uses skill-specific system prompt when provided.
    """
    from patchi.core.ai.client import call_ai

    sys_prompt = system_prompt or "You are a helpful coding assistant."
    result = call_ai(config, sys_prompt, prompt, max_tokens)
    return result or ""


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _extract_code_block(text: str) -> str:
    """Extract the first ```...``` block from an AI response."""
    m = re.search(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    return m.group(1) if m else text.strip()


def _make_patch(
    agent_name: str,
    patch_type: PatchType,
    changes: list[FileChange],
    description: str,
    ai_explanation: str,
    finding_id: str = "",
    blast_radius: int = 0,
    agent_certainty: float = 0.9,
    has_test_coverage: bool = True,
    scanner_agent: str = "",
    source_finding: dict | None = None,
) -> Patch:
    risk = compute_risk_score(changes, blast_radius)
    conf = compute_confidence(changes, agent_certainty, has_test_coverage=has_test_coverage)
    return Patch(
        agent=agent_name,
        patch_type=patch_type,
        finding_id=finding_id,
        changes=changes,
        description=description,
        ai_explanation=ai_explanation,
        risk_score=risk,
        confidence=conf,
        blast_radius=blast_radius,
        state=PatchState.PROPOSED,
        scanner_agent=scanner_agent,
        source_finding=source_finding or {},
        verify_retries=2,
    )


_SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts",
    ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php",
    ".cs", ".swift", ".dart", ".c", ".cpp", ".cxx", ".cc",
    ".h", ".hpp", ".scala", ".svelte", ".vue",
}


def compute_blast_radius(file_path: str, root: Path) -> int:
    """Count how many files in the project import this file."""
    rel = file_path
    stem = Path(rel).stem
    count = 0
    for src in root.rglob("*"):
        if src.suffix not in _SOURCE_EXTENSIONS or not src.is_file():
            continue
        try:
            content = src.read_text(encoding="utf-8", errors="ignore")
            if rel in content or stem in content:
                count += 1
        except OSError:
            pass
    return count


# Domain-specific fix patterns: finding_type → (search_regex, replacement)
_FIX_PATTERNS: list[tuple[str, str, str]] = [
    # Secrets
    (r'(?:password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']',
     "hardcoded_secret",
     "Use os.environ.get() or a secrets manager instead of hardcoded values"),
    # Debug mode
    (r'DEBUG\s*=\s*True',
     "debug_mode",
     "DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'"),
    # SQL injection
    (r'execute\(.*%s.*\%',
     "sqli",
     "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"),
    # Missing HTTPS redirect
    (r'@app\.route.*methods.*GET',
     "missing_header",
     "Add @app.before_request to redirect HTTP to HTTPS"),
    # Weak hash
    (r'hashlib\.(md5|sha1)\(',
     "weak_hash",
     "Use hashlib.sha256() or hashlib.sha3_256() instead"),
    # Eval/exec
    (r'\b(eval|exec)\s*\(',
     "injection",
     "Avoid eval()/exec(); use ast.literal_eval() or safe parsing"),
    # Pickle deserialization
    (r'pickle\.loads?\s*\(',
     "injection",
     "Use json.loads() or a safe serialization format instead of pickle"),
    # CORS wildcard
    (r'Access-Control-Allow-Origin.*\*',
     "cors_wildcard",
     "Restrict CORS to specific trusted origins instead of wildcard (*)"),
    # Missing rate limiting
    (r'@app\.route',
     "missing_rate_limit",
     "Add Flask-Limiter or similar rate limiting middleware"),
]


def _find_vulnerable_line(content: str, finding_type: str, file_path: str) -> tuple[int, str] | None:
    """Find the specific line that needs fixing based on finding type."""
    import re
    lines = content.splitlines()
    for search_re, ftype, _ in _FIX_PATTERNS:
        if ftype == finding_type or ftype in finding_type:
            for i, line in enumerate(lines):
                if re.search(search_re, line):
                    return (i, line)
    return None


def _apply_fix_pattern(line: str, finding_type: str) -> str | None:
    """Apply a fix pattern to a specific line."""
    import re

    if "hardcoded_secret" in finding_type or "password" in finding_type:
        # Replace hardcoded value with env var lookup
        m = re.search(r'(\w+)\s*=\s*["\']([^"\']+)["\']', line)
        if m:
            var_name = m.group(1)
            indent = line[: len(line) - len(line.lstrip())]
            return f'{indent}{var_name} = os.environ.get("{var_name.upper()}", "")'

    elif "debug_mode" in finding_type:
        indent = line[: len(line) - len(line.lstrip())]
        return f"{indent}DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'"

    elif "weak_hash" in finding_type:
        return line.replace("hashlib.md5(", "hashlib.sha256(").replace("hashlib.sha1(", "hashlib.sha256(")

    elif "eval" in finding_type or "exec" in finding_type:
        indent = line[: len(line) - len(line.lstrip())]
        return f"{indent}# SECURITY: Replaced eval/exec with safe alternative\n{line}"

    elif "pickle" in finding_type:
        return line.replace("pickle.loads(", "json.loads(").replace("pickle.load(", "json.load(")

    elif "cors_wildcard" in finding_type:
        return line.replace("*", "os.environ.get('ALLOWED_ORIGINS', '').split(',')")

    return None


def generate_fix(
    root: Path,
    finding_dict: dict,
    config: dict | None = None,
) -> Patch | None:
    """Generate a fix patch for a finding.

    Reads the actual file, finds the vulnerable line, and applies a
    domain-specific fix pattern. Falls back to suggestion-based patch
    if no pattern matches.
    """

    suggestion = finding_dict.get("suggestion", "")
    file_path = finding_dict.get("file", "")
    finding_type = finding_dict.get("type", "unknown")
    line_num = finding_dict.get("line", 0)
    playbook = finding_dict.get("playbook")

    if not file_path:
        return None

    target = root / file_path
    if not target.is_file():
        return None

    try:
        original = target.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    lines = original.splitlines()
    changes: list[FileChange] = []

    # Strategy 1: Use playbook template if available
    if playbook and playbook.get("llm_template"):
        # Find the relevant line using the playbook's control_id
        control_id = playbook.get("control_id", finding_type)
        found = _find_vulnerable_line(original, control_id, file_path)
        if found:
            line_idx, old_line = found
            fixed_line = _apply_fix_pattern(old_line, control_id)
            if fixed_line and fixed_line != old_line:
                changes.append(FileChange(
                    path=file_path,
                    original=old_line,
                    proposed=fixed_line,
                ))

    # Strategy 2: Pattern-based fix
    if not changes:
        found = _find_vulnerable_line(original, finding_type, file_path)
        if found:
            line_idx, old_line = found
            fixed_line = _apply_fix_pattern(old_line, finding_type)
            if fixed_line and fixed_line != old_line:
                changes.append(FileChange(
                    path=file_path,
                    original=old_line,
                    proposed=fixed_line,
                ))

    # Strategy 3: Line-number targeted fix
    if not changes and line_num and 0 < line_num <= len(lines):
        old_line = lines[line_num - 1]
        fixed_line = _apply_fix_pattern(old_line, finding_type)
        if fixed_line and fixed_line != old_line:
            changes.append(FileChange(
                path=file_path,
                original=old_line,
                proposed=fixed_line,
            ))

    # Strategy 4: Suggestion-based fallback (add comment)
    if not changes and suggestion:
        # Add a TODO comment at the top of the file
        changes.append(FileChange(
            path=file_path,
            original=lines[0] if lines else "",
            proposed=f"# TODO: {suggestion}\n{lines[0] if lines else ''}",
        ))

    if not changes:
        return None

    return _make_patch(
        agent_name="auto_fixer",
        patch_type=PatchType.SECURITY,
        changes=changes,
        description=f"Auto-fix for {finding_type}",
        ai_explanation=suggestion or f"Fixed {finding_type} in {file_path}",
        finding_id=finding_type,
        blast_radius=compute_blast_radius(file_path, root),
        agent_certainty=0.6,
        source_finding=finding_dict,
    )
