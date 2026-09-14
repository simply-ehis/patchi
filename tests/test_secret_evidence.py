"""Shared secret-evidence helper (Part 7 §4: measured, not trusted)."""

from patchi.core.security.secret_evidence import (
    is_fixture_path,
    is_placeholder,
    is_public_key_material,
    looks_like_secret,
    private_key_body_present,
    shannon_entropy,
)


def test_placeholders_rejected():
    for v in ["changeme", "xxx", "AKIAIOSFODNN7EXAMPLE", "password123", "test", "x", "", "  "]:
        assert is_placeholder(v), v


def test_realistic_tokens_accepted_as_candidates():
    # No placeholder substrings: real leaked keys don't say "example".
    assert not is_placeholder("AKIAIOSFODNN7XKQ9MWB2DT8FV4HJ6")
    assert not is_placeholder("ghp_cJYq0B4vK9mN2pL7xQ5wE8rT1yU3i")


def test_shannon_entropy_orders_correctly():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0
    assert shannon_entropy("hello-world123") < 3.5
    assert shannon_entropy("AKIAIOSFODNN7XKQ9MWB2DT8FV4HJ6") >= 3.5


def test_looks_like_secret_gate():
    assert not looks_like_secret("abc")  # too short
    assert not looks_like_secret("changeme1234567890")  # placeholder
    assert not looks_like_secret("hello-world1234567890")  # low entropy
    assert looks_like_secret("AKIAIOSFODNN7XKQ9MWB2DT8FV4HJ6")
    assert not looks_like_secret("AKIAIOSFODNN7EXAMPLE", min_length=32)


def test_base64_encoded_english_rejected():
    import base64

    fake = base64.b64encode(b"secretvaluewithentropy12345678").decode()
    assert not looks_like_secret(fake)
    # Real random bytes stay candidates (may fail base64 shape, still gated
    # on entropy, not rejected by the decoder).
    assert looks_like_secret("Q7ZmK2vX9pL4wN8cR3tY6uI1oP5aS0dF")


def test_fixture_paths():
    assert is_fixture_path("tests/test_auth.py")
    assert is_fixture_path("src/__tests__/a.js")
    assert is_fixture_path("docs/example.md")
    assert is_fixture_path("src/test_helper.py")
    assert not is_fixture_path("src/auth.py")
    assert not is_fixture_path("backend/routes/login.py")


def test_public_key_not_secret():
    assert is_public_key_material("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== user@host")
    assert is_public_key_material("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAB user@host")
    assert not is_public_key_material("-----BEGIN RSA PRIVATE KEY-----\nMIIabc")


def test_pem_header_needs_body():
    assert not private_key_body_present("-----BEGIN RSA PRIVATE KEY-----\nsee docs\n-----END RSA PRIVATE KEY-----")
    assert private_key_body_present(
        "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIB" * 40 + "\n-----END RSA PRIVATE KEY-----"
    )
