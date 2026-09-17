"""
Testing authorization — the legal shield for active testing.

Active tools (nuclei/sqlmap/dalfox/ffuf/zap, DAST) send real traffic to real
hosts. Against a customer's system that is only defensible with a recorded,
scoped, time-boxed approval: who approved what host, which paths, until when.

- Localhost/loopback stays frictionless (dev velocity untouched).
- Any other host needs a grant (`p authorize`) OR a charter/--target entry.
- Every grant, denial, and active-tool invocation is audit-logged
  (append-only JSONL) — "here's exactly what we did" is the deliverable
  that separates professionals from vandals.

Storage: .patchi/memory/authorization.json (grants),
         .patchi/audit/active_requests.jsonl (invocation log).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from urllib.parse import urlparse

from patchi.core.testing.gate import is_loopback_host

_log = logging.getLogger("patchi.testing.authorization")

_AUTH_FILE = ".patchi/memory/authorization.json"
_AUDIT_FILE = ".patchi/audit/active_requests.jsonl"


def normalize_host(target: str) -> str:
    """Bare lowercase hostname: scheme/port/path/query stripped.

    Accepts full URLs or bare hosts. Empty input → "".
    """
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        host = (urlparse(raw).hostname or "").lower()
    except ValueError:
        host = ""
    return host


def is_loopback_url(url: str | None) -> bool:
    """True for localhost/loopback targets (frictionless dev testing)."""
    if not url:
        return False
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return is_loopback_host(host)


def _auth_path(root: Path) -> Path:
    return root / _AUTH_FILE


def _read_store(root: Path) -> dict:
    path = _auth_path(root)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _log.warning("authorization store unreadable, treating as empty: %s", exc)
        return {}
    return data if isinstance(data, dict) else {}


def _write_store(root: Path, data: dict) -> None:
    path = _auth_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def grant(
    root: Path,
    target: str,
    approved_by: str,
    scope_paths: list[str] | None = None,
    window_hours: float = 24.0,
    purpose: str = "",
) -> dict:
    """Record approval to actively test `target`. Returns the grant record.

    Raises ValueError on empty host/approver or non-positive window.
    Overwrites any prior grant for the same host (re-approval extends).
    """
    host = normalize_host(target)
    if not host:
        raise ValueError("no host in target")
    if not (approved_by or "").strip():
        raise ValueError("approver name required (who authorized this?)")
    if window_hours <= 0:
        raise ValueError("window_hours must be positive")
    now = time.time()
    record = {
        "host": host,
        "approved_by": approved_by.strip(),
        "scope_paths": list(scope_paths or ["/"]),
        "granted_at": now,
        "expires_at": now + window_hours * 3600,
        "purpose": purpose or "",
    }
    store = _read_store(root)
    store[host] = record
    _write_store(root, store)
    log_active_request(
        root,
        tool="authorize",
        target=host,
        action="grant",
        safe_mode=True,
        authorized_via=f"approved_by={record['approved_by']}",
    )
    return record


def revoke(root: Path, target: str) -> bool:
    """Delete the grant for `target`. Returns True if one existed."""
    host = normalize_host(target)
    store = _read_store(root)
    if host not in store:
        return False
    del store[host]
    _write_store(root, store)
    log_active_request(
        root, tool="authorize", target=host, action="revoke",
        safe_mode=True, authorized_via="manual",
    )
    return True


def list_authorizations(root: Path) -> list[dict]:
    """All grants with live expired/authorizer status attached."""
    now = time.time()
    out = []
    for record in _read_store(root).values():
        view = dict(record)
        view["expired"] = now >= float(record.get("expires_at", 0))
        out.append(view)
    return sorted(out, key=lambda r: r["host"])


def authorization_for(root: Path, url: str | None) -> dict | None:
    """Valid (unexpired) grant for url's host, or None.

    Expired grants are kept for the audit trail but never authorize.
    """
    host = normalize_host(url or "")
    if not host:
        return None
    record = _read_store(root).get(host)
    if not record:
        return None
    if time.time() >= float(record.get("expires_at", 0)):
        return None
    return record


def log_active_request(
    root: Path,
    *,
    tool: str,
    target: str,
    action: str,
    safe_mode: bool,
    authorized_via: str,
    extra: dict | None = None,
) -> None:
    """Append one audit row. Never raises — a broken audit trail must not
    break scans (the failure itself is logged)."""
    try:
        path = root / _AUDIT_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": tool,
            "target": target,
            "action": action,
            "safe_mode": bool(safe_mode),
            "authorized_via": authorized_via,
        }
        if extra:
            row["extra"] = extra
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
    except OSError as exc:
        _log.warning("audit log write failed: %s", exc)
