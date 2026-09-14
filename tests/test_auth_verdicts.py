"""AuthenticationAuditAgent verdict policy (Part 7)."""

from pathlib import Path

from patchi.core.agents.base import AgentInput, AgentResult, Severity
from patchi.core.security.auth_audit_agent import AuthenticationAuditAgent


class _Agent(AuthenticationAuditAgent):
    """Relevance gate bypassed: these tests pin verdict logic, not gating."""

    def _run(self, inp, result):
        from patchi.core.agents.base import AgentStatus

        findings = []
        findings.extend(self._check_password_hashing(inp.extra["content"], "src/auth.py", None))
        findings.extend(self._check_session_security(inp.extra["content"], "src/auth.py"))
        findings.extend(self._check_oauth(inp.extra["content"], "src/auth.py"))
        findings.extend(self._check_rate_limiting(inp.extra["content"], "src/auth.py"))
        result.status = AgentStatus.DONE
        result.findings = findings
        return result


def _run(rel: str, content: str):

    res = AgentResult(agent_name="AuthenticationAuditAgent")
    _Agent()._run(
        AgentInput(root=Path("."), scope=[], brain={}, config={}, extra={"content": content}),
        res,
    )
    return res


def test_weak_secret_value_rejected():
    res = _run("src/auth.py", 'SECRET_KEY = "abc"\n')
    assert res.finding_count == 0


def test_strong_secret_value_high_not_critical():
    res = _run("src/auth.py", 'SECRET_KEY = "9f8eD2xQ7vB4mK1wZ6aB3cD5eF7"\n')
    assert res.finding_count == 1
    assert res.findings[0].severity == Severity.HIGH


def test_rate_limit_absence_is_medium():
    res = _run("src/auth.py", "def login(user, pw):\n    return check(user, pw)\n")
    rl = [f for f in res.findings if f.type == "missing_rate_limit"]
    assert rl and all(f.severity == Severity.MEDIUM for f in rl)


def test_md5_password_context_critical():
    # Proven weak hash in a password flow: CRITICAL is honest here.
    res = _run("src/auth.py", "import hashlib\nh = hashlib.md5(password.encode())\n")
    assert Severity.CRITICAL in [f.severity for f in res.findings]


def test_md5_without_password_context_demoted():
    res = _run("src/util.py", "import hashlib\netag = hashlib.md5(content).hexdigest()\n")
    assert Severity.CRITICAL not in [f.severity for f in res.findings]
    assert Severity.HIGH not in [f.severity for f in res.findings]
