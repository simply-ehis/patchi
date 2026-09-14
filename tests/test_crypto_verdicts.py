"""CryptoAgent verdict policy (Part 7): call context, gated values, no line-absence proofs."""

import tempfile
from pathlib import Path

from patchi.core.agents.base import Severity
from patchi.core.security.crypto_agent import CryptoAgent


def _scan(rel: str, content: str):
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    agent = CryptoAgent()
    # Run the per-area scanners directly for unit precision
    from patchi.core.security.crypto_agent import CryptoAgent as CA

    out = []
    out += CA._scan_weak_hashing(agent, content, rel)
    out += CA._scan_weak_encryption(agent, content, rel)
    out += CA._scan_hardcoded_keys(agent, content, rel)
    out += CA._scan_salt_issues(agent, content, rel)
    out += CA._scan_random_generation(agent, content, rel)
    out += CA._scan_other_crypto_issues(agent, content, rel)
    return out


def _sevs(findings):
    return [f.severity for f in findings]


def test_md5_call_site_high():
    fs = _scan("src/h.py", "import hashlib\nh = hashlib.md5(data)\n")
    assert Severity.HIGH in _sevs(fs)


def test_md5_mention_demoted():
    fs = _scan("src/h.py", "# we migrated away from md5 last year\nx = 1\n")
    assert Severity.HIGH not in _sevs(fs)
    assert all(s in (Severity.MEDIUM, Severity.LOW, Severity.INFO) for s in _sevs(fs))


def test_des_bare_word_demoted():
    fs = _scan("src/d.py", "# describes the new design\n")
    assert all(s in (Severity.MEDIUM, Severity.LOW, Severity.INFO) for s in _sevs(fs))


def test_bcrypt_rule_gone():
    fs = _scan("src/a.py", "import bcrypt\nhashed = bcrypt.hashpw(pw, bcrypt.gensalt())\n")
    assert not [f for f in fs if "bcrypt" in f.title.lower()]


def test_salt_absence_is_medium_not_high():
    fs = _scan("src/a.py", "h = hash_password(pw)\n")
    sal = [f for f in fs if "Salt" in f.title]
    assert sal and all(f.severity == Severity.MEDIUM for f in sal)


def test_weak_key_value_rejected():
    fs = _scan("src/k.py", 'API_KEY = "test123"\n')
    assert fs == []


def test_strong_key_value_high():
    fs = _scan("src/k.py", 'API_KEY = "9f8eD2xQ7vB4mK1wZ6aB3cD5"\n')
    assert Severity.HIGH in _sevs(fs)


def test_math_random_without_sink_demoted():
    fs = _scan("src/a.js", "const x = Math.random() * 100;\n")
    rnd = [f for f in fs if "Random" in f.title]
    assert rnd and all(f.severity == Severity.MEDIUM for f in rnd)


def test_math_random_with_sink_high():
    fs = _scan("src/a.js", "const token = Math.random().toString(36);\n")
    assert Severity.HIGH in _sevs(fs)


def test_bare_number_not_a_key_size():
    fs = _scan("src/a.py", "BUFFER = 1024\nPORT = 512\n")
    assert not [f for f in fs if "Key Size" in f.title]


def test_keygen_with_weak_size_flagged():
    fs = _scan("src/a.py", "key = generate_rsa_key(key_size=512)\n")
    assert Severity.HIGH in _sevs(fs)
