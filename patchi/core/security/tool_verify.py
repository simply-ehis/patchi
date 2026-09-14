"""
Tool verification — close the fix loop with the same SAST tools that found the bug.

After the AutoFixer writes a patch, we want real evidence the vulnerability is
gone, not a simulated "True". This module runs Bandit or Semgrep against the
*patched* file and reports whether the original finding still appears.

Both tools are invoked through their existing Patchi agents so we inherit the
exact same severity/confidence/CWE normalization the scanner uses elsewhere.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path

from patchi.core.agents.base import AgentInput, Finding, Severity

_log = logging.getLogger("patchi.security.tool_verify")

# Map the playbook `deterministic_tool` name -> registered agent name.
_TOOL_AGENT = {
    "bandit": "BanditAgent",
    "semgrep": "SemgrepAgent",
}


def _extract_identity(finding: Finding | object) -> tuple[str, str]:
    """Return (cwe, type) for a Finding or CorrelatedFinding-like object."""
    cwe = ""
    ftype = ""
    for attr in ("cwe", "type"):
        if hasattr(finding, attr):
            val = getattr(finding, attr)
            if attr == "cwe":
                cwe = str(val or "")
            else:
                ftype = str(val or "")
        elif hasattr(finding, "finding"):
            val = getattr(finding.finding, attr, "")
            if attr == "cwe":
                cwe = str(val or "")
            else:
                ftype = str(val or "")
    return cwe, ftype


def is_tool_ready(tool: str) -> tuple[bool, str]:
    """Unified availability check (Part 3 §2): the shared tool registry
    decides, not a hardcoded per-module list. Returns (ready, reason)."""
    try:
        from patchi.core.agents.tool_health import install_hint, is_available
    except ImportError:
        return False, "tool registry unavailable"
    if is_available(tool):
        return True, ""
    hint = install_hint(tool)
    return False, f"{tool} not available" + (f" — {hint}" if hint else "")


def run_tool_on_file(tool: str, file_path: Path) -> list[Finding]:
    """Run one SAST tool against a single file via an isolated temp copy.

    Copying the file into a temp dir keeps the scan scoped to just that file
    (fast, no project-wide noise) while still exercising the real tool binary
    through its Patchi agent wrapper.
    """
    import patchi.core.security.security_agents  # noqa: F401  (registers agents)
    from patchi.core.agents.base import list_agents

    agent_name = _TOOL_AGENT.get(tool.lower())
    if not agent_name:
        raise ValueError(f"tool_verify: unsupported tool {tool!r}")

    ready, reason = is_tool_ready(tool)
    if not ready:
        _log.warning("tool_verify: skipping %s on %s: %s", tool, file_path, reason)
        return []

    agents = {a.name: a for a in list_agents("security")}
    cls = agents.get(agent_name)
    if not cls:
        _log.warning("tool_verify: agent %s not available", agent_name)
        return []

    src = Path(file_path)
    if not src.exists():
        return []

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dest = tmp_path / src.name
        shutil.copy2(src, dest)
        res = cls().run(AgentInput(root=tmp_path, scope=[], brain={}, config={}, extra={}))
        return list(res.findings or [])


def finding_resolved(tool: str, file_path: Path, original: Finding | object) -> bool:
    """True if `original` no longer appears in the tool's output for the file.

    Matching prefers CWE (most specific). When the tool reports no findings at
    all we treat the issue as resolved.
    """
    findings = run_tool_on_file(tool, file_path)
    if not findings:
        return True

    orig_cwe, orig_type = _extract_identity(original)
    orig_short = orig_type.split(".")[-1] if orig_type else ""

    for f in findings:
        if orig_cwe and f.cwe and f.cwe.upper() == orig_cwe.upper():
            return False
        if orig_short and f.type and orig_short in f.type:
            return False
    return True


def high_findings_on_file(file_path: Path) -> list[Finding]:
    """Run Bandit + Semgrep on a single file; return only HIGH/CRITICAL findings.

    Used to verify that an applied proactive fix did not introduce or leave a
    serious vulnerability. Returns an empty list on tool failure (fail-open) so
    a slow/missing tool never blocks the watch loop. The returned findings carry
    the real (non-temp) file path.
    """
    out: list[Finding] = []
    real = str(file_path)
    for tool in ("bandit", "semgrep"):
        try:
            findings = run_tool_on_file(tool, file_path)
        except Exception as e:
            _log.warning("high_findings_on_file: %s failed on %s: %s", tool, file_path, e)
            continue
        for f in findings:
            if f.severity in (Severity.HIGH, Severity.CRITICAL):
                try:
                    f.file = real
                except Exception as _exc:
                    _log.warning("high_findings_on_file failed: %s", _exc)
                out.append(f)
    return out


def verify_proactive_fixes(
    root: Path,
    applied_files: list[str],
    pre_highs: dict[str, set],
) -> list[dict]:
    """Diff SAST HIGH/CRITICAL findings before vs after applied proactive fixes.

    For each file a proactive fix touched, re-runs Bandit + Semgrep and reports
    only findings that are NEW relative to ``pre_highs`` (so pre-existing
    findings are never re-flagged on every save). Returns a list of issue dicts
    ready for ``mem.save_issue``. Fail-open: any tool failure yields no issue.
    """
    issues: list[dict] = []
    for vf in sorted(set(applied_files)):
        vpath = Path(root) / vf
        if not vpath.exists() or vpath.suffix != ".py":
            continue
        try:
            post_findings = high_findings_on_file(vpath)
        except Exception as e:
            _log.warning("verify_proactive_fixes skipped %s: %s", vf, e)
            continue
        post = {(h.type, h.cwe) for h in post_findings}
        new_sigs = post - pre_highs.get(vf, set())
        if not new_sigs:
            continue
        for hf in post_findings:
            if (hf.type, hf.cwe) not in new_sigs:
                continue
            issues.append(
                {
                    "source": "proactive_sast_verify",
                    "fix_type": "sast_regression",
                    "file": vf,
                    "name": hf.cwe or hf.type,
                    "line": hf.line,
                    "description": (
                        f"Proactive fix introduced a HIGH/CRITICAL SAST "
                        f"finding ({hf.type}{' ' + hf.cwe if hf.cwe else ''}) "
                        f"at line {hf.line}"
                    ),
                    "severity": "high",
                }
            )
    return issues
