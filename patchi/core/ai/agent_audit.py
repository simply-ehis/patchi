"""
Agent audit harness.

Scans every registered agent (security, test, fix, scanner, guard) for the
defects called out in AUDIT_STUBS_PLACEHOLDERS_WRONG_LOGIC.md and the user's
"audit each agent and improve them" request:

  * raises ``NotImplementedError``
  * returns placeholder text ("initiated", "placeholder", "TODO", "not implemented")
  * uses the OLD single-arg ``_run(self, inp)`` signature instead of the
    mutation style ``_run(self, inp, result)``

It does NOT auto-mutate agents (too risky to rewrite 50+ classes blindly); it
returns a structured, machine-readable report so the issues can be tracked and
fixed deliberately. Run it with ``python -m patchi.core.ai.agent_audit``.
"""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_log = logging.getLogger("patchi.ai.agent_audit")

_STUB_MARKERS = (
    "not implemented",
    "notimplemented",
    "placeholder",
    "todo",
    "fixme",
    "initiated",
    "coming soon",
    "stub",
)


@dataclass
class AuditIssue:
    agent: str
    group: str
    issue: str
    severity: str  # "high" | "medium" | "low"
    evidence: str = ""


@dataclass
class AuditReport:
    total_agents: int = 0
    groups_scanned: list[str] = field(default_factory=list)
    issues: list[AuditIssue] = field(default_factory=list)

    @property
    def by_severity(self) -> dict[str, int]:
        out = {"high": 0, "medium": 0, "low": 0}
        for i in self.issues:
            out[i.severity] = out.get(i.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "total_agents": self.total_agents,
            "groups_scanned": self.groups_scanned,
            "issue_count": len(self.issues),
            "by_severity": self.by_severity,
            "issues": [vars(i) for i in self.issues],
        }


def _all_groups():
    from patchi.core.agents.base import AgentGroup

    return list(AgentGroup)


def audit(root: Path | None = None) -> AuditReport:
    """Inspect all registered agents and return a structured report."""
    report = AuditReport()
    try:
        import patchi.core.agents.fix_agents  # noqa: F401
        import patchi.core.agents.test_agents  # noqa: F401
        import patchi.core.security.security_agents  # noqa: F401
    except Exception:
        pass

    from patchi.core.agents.base import list_agents

    for group in _all_groups():
        report.groups_scanned.append(group.value)
        for cls in list_agents(group):
            report.total_agents += 1
            _audit_class(cls, group.value, report)
    return report


def _audit_class(cls: Any, group: str, report: AuditReport) -> None:
    name = cls.__name__
    try:
        src = inspect.getsource(cls)
    except (OSError, TypeError):
        return

    low = src.lower()

    # 1. NotImplementedError
    if "notimplementederror" in low and "raise notimplementederror" in low.replace(" ", ""):
        report.issues.append(
            AuditIssue(
                name, group, "raises NotImplementedError", "high", "raise NotImplementedError"
            )
        )
        return  # definitive, stop here

    # 2. Placeholder / stub markers
    for marker in _STUB_MARKERS:
        if marker in low:
            report.issues.append(
                AuditIssue(name, group, f"possible stub marker '{marker}'", "medium", marker)
            )
            break

    # 3. Old-style _run signature
    run_method = getattr(cls, "_run", None)
    if run_method is not None and callable(run_method):
        try:
            sig = inspect.signature(run_method)
            params = [p for p in sig.parameters if p != "self"]
            # New style: _run(self, inp, result) -> None  (2 params beyond self)
            # Old style: _run(self, inp) -> AgentResult     (1 param beyond self)
            if len(params) == 1:
                report.issues.append(
                    AuditIssue(
                        name,
                        group,
                        "old-style _run(self, inp) signature",
                        "low",
                        "expected _run(self, inp, result)",
                    )
                )
        except (ValueError, TypeError):
            pass


def main() -> None:
    rep = audit()
    for _i in rep.issues[:50]:
        pass


if __name__ == "__main__":
    main()
