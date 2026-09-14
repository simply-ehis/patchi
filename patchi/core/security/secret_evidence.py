"""Shared secret-evidence helpers (Part 7).

Every secret scanner in the repo used to re-derive "is this string a real
secret" from keyword proximity alone, each with different (usually absent)
placeholder handling, no entropy math, and no fixture awareness. That is how
`password="changeme"` in a test fixture became a CRITICAL finding.

This module is the single place that answers the question. Rules:
- Placeholders, examples, and obvious non-secrets are NEVER secrets,
  regardless of which keyword sits next to them.
- Test/fixture/doc paths are NEVER secret-bearing for verdict purposes
  (fixtures intentionally contain dangerous-looking strings).
- Randomness is measured with real Shannon entropy, not character diversity.
- Public key material is not secret material (separate predicate).

KEEP-AND-HARDEN justification (§4): no structural proof exists that an
opaque string is an API key — pattern + entropy + context is the actual
right approach here. What makes it honest is shared thresholds, measured
behavior (tests/test_secret_evidence.py), and never verdicting on a
bare keyword match.
"""

from __future__ import annotations

import math
from pathlib import PurePosixPath

# Values that are documentation, not credentials — matched case-insensitively
# as substrings, plus exact matches for short sentinels.
_PLACEHOLDER_SUBSTRINGS = frozenset(
    {
        "example",
        "sample",
        "placeholder",
        "changeme",
        "your-",
        "your_",
        "xxx",
        "testkey",
        "fake",
        "dummy",
        "todo",
        "fixme",
        "***",
        "aaa",
        "abcdef",
        "123456",
        "password123",
        "pass123",
        "admin123",
        "qwerty",
        "letmein",
        "p@ssw0rd",
        "redacted",
        "[redacted]",
        "<redacted>",
        "none",
        "null",
        "undefined",
        "empty",
    }
)

_PLACEHOLDER_EXACT = frozenset(
    {
        "",
        "x",
        "xx",
        "test",
        "testing",
        "secret",
        "password",
        "pass",
        "pwd",
        "token",
        "key",
        "changeme",
        "default",
        "1234",
        "12345",
        "abcd",
    }
)

# Path markers that mean "this file intentionally looks dangerous".
_FIXTURE_MARKERS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "__tests__",
        "spec",
        "specs",
        "fixture",
        "fixtures",
        "testdata",
        "test_data",
        "mock",
        "mocks",
        "fake",
        "fakes",
        "stub",
        "stubs",
        "example",
        "examples",
        "docs",
        "doc",
        "sample",
        "samples",
        "demo",
    }
)


def is_placeholder(value: str) -> bool:
    """True if the string is documentation-shaped, not credential-shaped."""
    v = (value or "").strip()
    if not v:
        return True
    low = v.lower()
    if low in _PLACEHOLDER_EXACT:
        return True
    return any(marker in low for marker in _PLACEHOLDER_SUBSTRINGS)


def is_fixture_path(path: str) -> bool:
    """True if the path intentionally contains dangerous-looking strings."""
    try:
        parts = {seg.lower() for seg in PurePosixPath((path or "").replace("\\", "/")).parts}
    except Exception:
        return False
    if parts & _FIXTURE_MARKERS:
        return True
    name = (path or "").lower()
    return "test_" in name or "_test." in name or name.endswith((".spec.ts", ".spec.js", ".test.ts", ".test.js"))


def shannon_entropy(value: str) -> float:
    """Real Shannon entropy in bits per character (0.0 for empty)."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _decoded_placeholder(value: str) -> bool:
    """Base64-encoded fakes (`c2VjcmV0...` decodes to English): decode and
    re-check. Real secrets decode to non-textual bytes and pass through."""
    import base64
    import re as _re

    v = (value or "").strip()
    if len(v) < 16 or len(v) % 4 != 0:
        return False
    if not _re.fullmatch(r"[A-Za-z0-9+/=]+", v):
        return False
    try:
        raw = base64.b64decode(v, validate=True)
    except Exception:
        return False
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    if not text or sum(32 <= ord(c) < 127 for c in text) / len(text) < 0.7:
        return False
    return is_placeholder(text)


def looks_like_secret(
    value: str, min_length: int = 16, min_entropy: float = 3.5, allow_spaces: bool = True
) -> bool:
    """Shared gate: long + random + not a placeholder.

    Defaults (16 chars, 3.5 bits/char) reject `password="changeme"`,
    `token="abc"`, sequential/repeated strings, and prose, while keeping
    real tokens (base64/hex IDs typically score 4.0–6.0 bits/char).
    Base64-encoded English fakes are decoded and re-checked.
    allow_spaces=False for keyword-assignment tiers: a quoted value with
    spaces (`"Steal Credentials / Secrets"`) is a description, never a
    credential. Real API keys/tokens/passwords in code have no spaces.
    """
    import re as _re

    v = (value or "").strip().strip("\"'").strip()
    if len(v) < min_length:
        return False
    if not allow_spaces and any(ch.isspace() for ch in v):
        return False
    # Regex character classes ([^@], [A-Z...]) are pattern source, never
    # credentials — this silences scanners flagging their own patterns.
    if _re.search(r"\[[^\]]+\]", v):
        return False
    if is_placeholder(v):
        return False
    if _decoded_placeholder(v):
        return False
    return shannon_entropy(v) >= min_entropy


def is_public_key_material(text: str) -> bool:
    """True for PUBLIC key blocks (ssh-rsa/ssh-ed25519, *.pub content).

    Public keys are published by design — flagging them as hardcoded
    *secrets* is false-as-fact. Private key headers (BEGIN ... PRIVATE
    KEY) are NOT matched here; they stay secret-evidence.
    """
    t = (text or "").strip()
    low = t.lower()
    if low.startswith(("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-", "sk-ssh-")):
        return True
    if "private" not in low and "public" in low and "key" in low:
        return True
    return False


def private_key_body_present(text: str) -> bool:
    """A PEM header alone can be a doc snippet — require base64 body."""
    import re

    if "-----BEGIN" not in (text or ""):
        return False
    body = re.sub(r"-----(BEGIN|END)[^-]*-----", "", text)
    b64 = re.sub(r"\s+", "", body)
    return len(b64) >= 64 and bool(re.fullmatch(r"[A-Za-z0-9+/=\n\r]+", b64 or "x"))
