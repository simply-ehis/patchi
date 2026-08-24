"""Tests for the secrets detection sweep (p audit / p watch)."""

from pathlib import Path

from patchi.core.brain.secrets import scan_secrets


def _proj(tmp_path: Path) -> Path:
    (tmp_path / ".patchi").mkdir()
    return tmp_path


def test_finds_aws_key(tmp_path):
    r = _proj(tmp_path)
    f = r / "config.py"
    f.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    hits = scan_secrets(r)
    assert any(h.rule == "aws_access_key_id" for h in hits)
    assert hits[0].path.endswith("config.py")


def test_finds_private_key(tmp_path):
    r = _proj(tmp_path)
    f = r / "key.pem"
    f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n")
    hits = scan_secrets(r)
    assert any(h.rule == "private_key" for h in hits)


def test_clean_file_no_hits(tmp_path):
    r = _proj(tmp_path)
    (r / "app.py").write_text("def add(a, b):\n    return a + b\n")
    assert scan_secrets(r) == []


def test_paths_limit_scan(tmp_path):
    r = _proj(tmp_path)
    (r / "secret.py").write_text('TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUV"\n')
    (r / "clean.py").write_text('x = 1\n')
    # Scanning only clean.py should yield no hits.
    hits = scan_secrets(r, paths=["clean.py"])
    assert hits == []
    # Scanning the secret file yields a hit.
    hits2 = scan_secrets(r, paths=["secret.py"])
    assert any(h.rule == "github_pat" for h in hits2)


def test_skip_dirs(tmp_path):
    r = _proj(tmp_path)
    skip = r / ".venv" / "lib"
    skip.mkdir(parents=True)
    (skip / "leak.py").write_text('K = "sk-abcdefghijklmnopqrstuvwxyz"\n')
    assert scan_secrets(r) == []
