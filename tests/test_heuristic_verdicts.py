"""Cross-agent verdict policy spot checks (Part 7).

Each test pins one fixed heuristic: the exact input that used to produce a
false-as-fact verdict, and what it produces now.
"""

import tempfile
from pathlib import Path

from patchi.core.agents.base import AgentInput, Severity


def _run_agent(cls, files: dict[str, str]):
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return cls().run(AgentInput(root=root, scope=[], brain={}, config={}, extra={}))


def _types(res):
    return [(f.type, f.severity) for f in res.findings]


def test_mobile_bare_storage_demoted():
    from patchi.core.security.mobile_security_agent import MobileSecurityAgent

    res = _run_agent(
        MobileSecurityAgent,
        {"app/src/main/java/A.java": "SharedPreferences prefs = getPrefs();\n"},
    )
    assert ("nsuserdefaults_sensitive", Severity.MEDIUM) not in _types(res)
    assert ("sharedprefs_sensitive", Severity.MEDIUM) in _types(res)
    assert ("sharedprefs_sensitive", Severity.HIGH) not in _types(res)


def test_mobile_cbc_is_info():
    from patchi.core.security.mobile_security_agent import MobileSecurityAgent

    res = _run_agent(
        MobileSecurityAgent,
        {"app/src/main/java/C.java": 'Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'},
    )
    assert ("aes_cbc", Severity.INFO) in _types(res)
    assert ("aes_ecb", Severity.HIGH) not in _types(res)


def test_network_tls12_silent_tls10_high():
    from patchi.core.security.network_agent import NetworkAgent

    res = _run_agent(
        NetworkAgent,
        {"src/t.py": 'ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)\n'},
    )
    assert not [f for f in res.findings if "TLS" in f.title or "TLS" in f.type]
    res = _run_agent(
        NetworkAgent, {"src/t.py": "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"}
    )
    assert any("TLS" in (f.title + f.type) and f.severity == Severity.HIGH for f in res.findings)


def test_network_aes128_dropped():
    from patchi.core.security.network_agent import NetworkAgent

    res = _run_agent(NetworkAgent, {"src/t.py": "cipher = 'aes-128-gcm'\n"})
    assert not [f for f in res.findings if "Cipher" in f.title]


def test_privacy_identifier_without_sink_low():
    from patchi.core.security.privacy_agent import PrivacyAgent

    res = _run_agent(PrivacyAgent, {"src/a.py": "email = get_default()\n"})
    assert ("Email Handling", Severity.LOW) in [(f.title, f.severity) for f in res.findings]
    assert ("Email Handling", Severity.MEDIUM) not in [(f.title, f.severity) for f in res.findings]


def test_authz_english_pair_capped():
    # Relevance gate bypassed: pins verdict logic, not gating.
    from patchi.core.security.authz_agent import AuthZAgent

    agent = AuthZAgent()
    findings = agent._scan_general_authz(
        "def delete_user(uid):\n    db.remove(uid)\n", "src/a.py"
    )
    hits = [f for f in findings if "Authorization" in f.title]
    assert hits and all(f.severity == Severity.MEDIUM for f in hits)


def test_business_idor_medium():
    from patchi.core.security.business_logic_agent import BusinessLogicAgent

    res = _run_agent(
        BusinessLogicAgent,
        {"routes/api.py": "@app.get('/items/{id}')\ndef get_item(id):\n    return db.get(id)\n"},
    )
    assert ("idor_missing_ownership_check", Severity.MEDIUM) in _types(res)
    assert ("idor_missing_ownership_check", Severity.HIGH) not in _types(res)


def test_redteam_safeloader_silent():
    from patchi.core.security.red_team_agent import RedTeamAgent

    res = _run_agent(
        RedTeamAgent, {"src/a.py": "import yaml\ndata = yaml.load(f, Loader=yaml.SafeLoader)\n"}
    )
    assert not [f for f in res.findings if "yaml" in f.title.lower()]


def test_framework_package_boundaries():
    from patchi.core.brain.framework import FrameworkDetector

    root = Path(tempfile.mkdtemp())
    (root / "requirements.txt").write_text("deflasker==1.0\n", encoding="utf-8")
    stack = FrameworkDetector(root).detect() if hasattr(FrameworkDetector(root), "detect") else None
    names = [f.name for f in (stack.frameworks if stack else [])]
    assert "Flask" not in names
    (root / "requirements.txt").write_text("flask-cors==1.0\n", encoding="utf-8")
    stack = FrameworkDetector(root).detect() if hasattr(FrameworkDetector(root), "detect") else None
    names = [f.name for f in (stack.frameworks if stack else [])]
    assert "Flask" in names
