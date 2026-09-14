"""SensitiveDataAgent verdict policy (Part 7): structure verdicts, gate values."""

import tempfile
from pathlib import Path

from patchi.core.agents.base import AgentInput, AgentResult, Severity
from patchi.core.security.sensitive_data_agent import SensitiveDataAgent

_REAL_AWS = "AKIAIOSFODNN7XKQ9MWB2DT8FV4HJ6"


def _run_file(rel: str, content: str) -> AgentResult:
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    res = AgentResult(agent_name="SensitiveDataAgent")
    SensitiveDataAgent()._run(
        AgentInput(root=root, scope=[], brain={}, config={}), res
    )
    return res


def _sevs(res):
    return [f.severity for f in res.findings]


def test_real_aws_key_critical():
    res = _run_file("src/config.py", f"KEY = '{_REAL_AWS}\n'".replace("\n'", "'\n"))
    assert Severity.CRITICAL in _sevs(res)


def test_example_aws_key_rejected():
    res = _run_file("src/config.py", "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    assert res.finding_count == 0


def test_lowercase_akia_rejected():
    res = _run_file("src/config.py", "key = 'akiaiosfodnn7xkq9mwb2dt8fv4hj6'\n")
    assert res.finding_count == 0


def test_weak_password_value_rejected():
    res = _run_file("src/config.py", 'password = "abc"\n')
    assert res.finding_count == 0


def test_strong_password_value_high_not_critical():
    res = _run_file("src/config.py", 'password = "9f8eD2xQ7vB4mK1wZ6"\n')
    assert res.finding_count == 1
    assert res.findings[0].severity == Severity.HIGH


def test_placeholder_uri_rejected():
    res = _run_file(
        "src/db.py", 'URL = "postgres://user:changeme@localhost/db"\n'
    )
    assert res.finding_count == 0


def test_real_uri_high():
    res = _run_file(
        "src/db.py", 'URL = "postgres://svc:9f8eD2xQ7vB4mK1wZ6@db.internal/app"\n'
    )
    assert res.finding_count == 1
    assert res.findings[0].severity == Severity.HIGH


def test_pem_header_without_body_rejected():
    res = _run_file(
        "src/docs.py", '"see -----BEGIN RSA PRIVATE KEY----- in the manual"\n'
    )
    assert res.finding_count == 0


def test_pem_with_body_critical():
    body = "MIIB" * 40
    res = _run_file(
        "src/keys.py",
        "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\n",
    )
    assert Severity.CRITICAL in _sevs(res)


def test_invalid_ssn_rejected():
    res = _run_file("src/data.py", 'x = "000-12-3456"\n')
    assert res.finding_count == 0


def test_valid_ssn_shape_high():
    res = _run_file("src/data.py", 'x = "219-09-9999"\n')
    assert Severity.HIGH in _sevs(res)


def test_luhn_invalid_cc_rejected():
    res = _run_file("src/data.py", 'x = "1234-5678-9012-3456"\n')
    assert res.finding_count == 0


def test_luhn_valid_cc_high():
    res = _run_file("src/data.py", 'x = "4539-1488-0343-6467"\n')
    assert Severity.HIGH in _sevs(res)


def test_example_email_rejected():
    res = _run_file("src/data.py", 'x = "admin@example.com"\n')
    assert res.finding_count == 0


def test_fixture_pii_silenced():
    res = _run_file("tests/test_data.py", 'x = "219-09-9999"\n')
    assert res.finding_count == 0
