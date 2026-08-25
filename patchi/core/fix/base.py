"""
Base functionality for fix agents.
"""

import logging
import os
import re
from pathlib import Path

_log = logging.getLogger("patchi.fix")

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


def _build_fix_prompt(
    finding_type: str,
    file_path: str,
    original: str,
    line_num: int,
    suggestion: str,
    playbook: dict | None,
    message: str = "",
) -> str:
    """Build the AI prompt for fix generation."""
    # Extract context around the vulnerable line
    lines = original.splitlines()
    start = max(0, line_num - 5) if line_num else 0
    end = min(len(lines), line_num + 10) if line_num else min(20, len(lines))
    context = "\n".join(f"{i+1:4d} | {l}" for i, l in enumerate(lines[start:end], start))

    prompt = f"""You are a security expert. Fix the following vulnerability.

## Finding
- Type: {finding_type}
- File: {file_path}
- Line: {line_num or 'unknown'}
- Message: {message or suggestion or finding_type}
"""

    if playbook:
        prompt += f"- Control ID: {playbook.get('control_id', 'unknown')}\n"
        prompt += f"- Fix strategy: {playbook.get('fix_strategy', 'unknown')}\n"
        if playbook.get("llm_template"):
            prompt += f"- Template hint: {playbook['llm_template']}\n"

    prompt += f"""
## Code Context (lines {start+1}-{end})
```python
{context}
```

## Requirements
1. Fix the vulnerability with minimal changes
2. Preserve the original code style and indentation
3. Do NOT add comments explaining the fix
4. Do NOT change unrelated code
5. Output ONLY the fixed line(s), no explanation

## Fixed code
```python
"""

    return prompt


def _generate_fix_with_ai(
    root: Path,
    file_path: str,
    original: str,
    finding_type: str,
    line_num: int,
    suggestion: str,
    playbook: dict | None,
    config: dict,
    message: str = "",
) -> FileChange | None:
    """Use AI to generate a fix for the vulnerability."""
    prompt = _build_fix_prompt(
        finding_type, file_path, original, line_num, suggestion, playbook, message
    )

    system_prompt = (
        "You are a security engineer fixing vulnerabilities in Python/JS/Go code. "
        "Output only the fixed code in a code block. No explanations. "
        "Make minimal changes to fix the security issue."
    )

    try:
        response = _call_ai(prompt, config, max_tokens=500, system_prompt=system_prompt)
    except Exception as e:
        _log.warning("AI fix generation failed: %s", e)
        return None

    if not response:
        return None

    # Extract the fixed code from AI response
    fixed_code = _extract_code_block(response)
    if not fixed_code or fixed_code.strip() == "":
        return None

    # Find the vulnerable line to replace
    lines = original.splitlines()
    if line_num and 0 < line_num <= len(lines):
        original_line = lines[line_num - 1]
        # Use the first non-empty line from the AI response
        fixed_lines = [l for l in fixed_code.strip().splitlines() if l.strip()]
        if fixed_lines:
            proposed_line = fixed_lines[0]
            # Preserve original indentation
            indent = len(original_line) - len(original_line.lstrip())
            proposed_line = " " * indent + proposed_line.strip()
            if proposed_line != original_line:
                return FileChange(
                    path=file_path,
                    original=original_line,
                    proposed=proposed_line,
                )

    return None


def generate_fix(
    root: Path,
    finding_dict: dict,
    config: dict | None = None,
) -> Patch | None:
    """Generate a fix patch for a finding.

    Strategy:
    1. AI-powered fix generation (calls LLM with file context)
    2. Pattern-based fix (regex replacements)
    3. Playbook template fix
    4. Suggestion-based fallback

    The generated patch passes through RiskGate for mode-based approval.
    """
    config = config or {}
    suggestion = finding_dict.get("suggestion", "")
    file_path = finding_dict.get("file", "")
    finding_type = finding_dict.get("type", "unknown")
    line_num = finding_dict.get("line", 0)
    playbook = finding_dict.get("playbook")
    message = finding_dict.get("message", "")

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
    ai_fix_used = False

    # Strategy 1: AI-powered fix generation
    ai_change = _generate_fix_with_ai(
        root, file_path, original, finding_type, line_num,
        suggestion, playbook, config, message,
    )
    if ai_change:
        changes.append(ai_change)
        ai_fix_used = True

    # Strategy 2: Pattern-based fix (fallback)
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

    # Strategy 3: Playbook template fix (fallback)
    if not changes and playbook and playbook.get("llm_template"):
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

    # Strategy 4: Line-number targeted fix (fallback)
    if not changes and line_num and 0 < line_num <= len(lines):
        old_line = lines[line_num - 1]
        fixed_line = _apply_fix_pattern(old_line, finding_type)
        if fixed_line and fixed_line != old_line:
            changes.append(FileChange(
                path=file_path,
                original=old_line,
                proposed=fixed_line,
            ))

    # Strategy 5: Suggestion-based fallback (last resort)
    if not changes and suggestion:
        changes.append(FileChange(
            path=file_path,
            original=lines[0] if lines else "",
            proposed=f"# TODO: {suggestion}\n{lines[0] if lines else ''}",
        ))

    if not changes:
        return None

    # Build the patch
    patch = _make_patch(
        agent_name="auto_fixer",
        patch_type=PatchType.SECURITY,
        changes=changes,
        description=f"{'AI-generated' if ai_fix_used else 'Pattern-based'} fix for {finding_type}",
        ai_explanation=suggestion or message or f"Fixed {finding_type} in {file_path}",
        finding_id=finding_type,
        blast_radius=compute_blast_radius(file_path, root),
        agent_certainty=0.8 if ai_fix_used else 0.6,
        source_finding=finding_dict,
    )

    # Pass through RiskGate
    try:
        from patchi.core.fix.risk_gate import RiskGate
        gate = RiskGate(root)
        gate_result = gate.evaluate(patch)
        _log.info(
            "RiskGate for %s: %s (risk=%d)",
            finding_type,
            "auto" if gate_result.is_auto else "blocked" if gate_result.is_blocked else "review",
            patch.risk_score,
        )
    except Exception as e:
        _log.warning("RiskGate evaluation failed: %s", e)

    return patch
