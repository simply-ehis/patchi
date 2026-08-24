"""
Admin token management for Patchi hosted mode.

Tokens are generated as random 32-byte hex strings.
Only the HMAC-SHA256 hash is ever stored — plaintext is shown once on generation.

Storage: .patchi/hosted/tokens.json
Format: [{id, name, hash, created_at, last_used}]
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path

_TOKENS_FILE = ".patchi/hosted/tokens.json"
_SECRET_FILE = ".patchi/hosted/.secret"
_HMAC_KEY_LEN = 32


def _tokens_path(root: Path) -> Path:
    return root / _TOKENS_FILE


def _secret_path(root: Path) -> Path:
    return root / _SECRET_FILE


def _get_hmac_key(root: Path) -> bytes:
    """Load or generate a per-installation HMAC key."""
    path = _secret_path(root)
    if path.exists():
        try:
            return bytes.fromhex(path.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            pass
    # Generate and persist a new key
    key = os.urandom(_HMAC_KEY_LEN)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key.hex(), encoding="utf-8")
    return key


def _load(root: Path) -> list[dict]:
    path = _tokens_path(root)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save(root: Path, tokens: list[dict]) -> None:
    path = _tokens_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tokens, indent=2), encoding="utf-8")


def _hash(plaintext: str, root: Path) -> str:
    """HMAC-SHA256 hash of the token using per-installation key."""
    key = _get_hmac_key(root)
    return hmac.new(key, plaintext.encode(), hashlib.sha256).hexdigest()


def generate(root: Path, name: str) -> str:
    """
    Generate a new admin token. Stores the hash, returns the plaintext once.
    The caller must display this to the user — it cannot be recovered later.
    """
    plaintext = os.urandom(32).hex()
    token_id = str(uuid.uuid4())[:8]
    tokens = _load(root)
    tokens.append(
        {
            "id": token_id,
            "name": name,
            "hash": _hash(plaintext, root),
            "created_at": time.time(),
            "last_used": None,
        }
    )
    _save(root, tokens)
    return plaintext


def validate(root: Path, plaintext: str) -> dict | None:
    """
    Check if a plaintext token matches any stored hash.
    Returns the token record (without hash) on match, None otherwise.
    Updates last_used timestamp on success.
    """
    candidate_hash = _hash(plaintext, root)
    tokens = _load(root)

    for token in tokens:
        if hmac.compare_digest(token["hash"], candidate_hash):
            token["last_used"] = time.time()
            _save(root, tokens)
            return {k: v for k, v in token.items() if k != "hash"}

    return None


def list_tokens(root: Path) -> list[dict]:
    """Return all tokens without hash field."""
    return [{k: v for k, v in t.items() if k != "hash"} for t in _load(root)]


def revoke(root: Path, token_id: str) -> bool:
    """Remove a token by ID. Returns True if found and removed."""
    tokens = _load(root)
    before = len(tokens)
    tokens = [t for t in tokens if t["id"] != token_id]
    if len(tokens) == before:
        return False
    _save(root, tokens)
    return True


def count(root: Path) -> int:
    return len(_load(root))
