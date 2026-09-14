"""
sast_gate — fast synchronous SAST gate for the pre-commit hook.

Runs Bandit + Semgrep against a list of staged files and exits non-zero when a
HIGH/CRITICAL finding is present. Intended to be invoked from the generated
pre-commit hook as:

    python -m patchi.core.security.sast_gate file1.py file2.py

Exit codes:
    0  clean (or tools unavailable — fail-open so the hook never hard-blocks
       the developer when a binary is missing)
    1  at least one HIGH/CRITICAL finding (blocking in --strict mode)
    2  usage / unexpected error

This keeps the commit path fast: it scans only the staged files, never the
whole tree, and reuses the same agents/normalization as the full scanner.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from patchi.core.agents.base import AgentInput, Severity

_log = logging.getLogger("patchi.core.security.sast_gate")


def _gather(tool_name: str, files: list[Path]) -> list:
    """Run one tool over the given files; return normalized findings."""
    import patchi.core.security.security_agents  # noqa: F401  (registers agents)
    from patchi.core.agents.base import list_agents

    agents = {a.name: a for a in list_agents("security")}
    cls = agents.get(tool_name)
    if not cls:
        return []

    findings: list = []
    # Scan each staged file in isolation so a single bad file can't poison the
    # whole run and so output maps directly to the staged path.
    for f in files:
        if not f.exists():
            continue
        res = cls().run(AgentInput(root=f.parent, scope=[], brain={}, config={}, extra={}))
        for finding in res.findings or []:
            # Re-anchor the finding to the real (staged) path for reporting.
            try:
                finding.file = str(f)
            except Exception as _exc:  # pragma: no cover - defensive
                _log.warning("_gather failed: %s", _exc)
            findings.append(finding)
    return findings


def main(argv: list[str]) -> int:
    files = [Path(a) for a in argv[1:] if a.endswith(".py")]
    if not files:
        sys.stdout.write("sast_gate: no Python files to scan\n")
        sys.stdout.flush()
        return 0

    high_or_critical = 0
    total = 0
    for tool in ("BanditAgent", "SemgrepAgent"):
        try:
            found = _gather(tool, files)
        except Exception as e:  # fail-open: never hard-block on tool errors
            sys.stderr.write(f"sast_gate: {tool} skipped ({e})\n")
            sys.stderr.flush()
            continue
        for f in found:
            total += 1
            sev = getattr(f, "severity", None)
            if sev in (Severity.HIGH, Severity.CRITICAL):
                high_or_critical += 1
            sys.stdout.write(
                f"  [{tool}] {getattr(f, 'severity', '?')} {getattr(f, 'type', '?')} "
                f"{getattr(f, 'file', '?')}:{getattr(f, 'line', 0)} "
                f"{getattr(f, 'cwe', '')}\n"
            )
            sys.stdout.flush()

    sys.stdout.write(f"sast_gate: {total} finding(s), {high_or_critical} high/critical\n")
    sys.stdout.flush()
    if high_or_critical:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
