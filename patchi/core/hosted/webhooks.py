"""
Hosted Webhooks — Outbound alert forwarding for Patchi hosted mode.

Stores webhook subscriptions in .patchi/hosted/webhooks.json and delivers
finding/anomaly alerts via signed POST requests. Delivery failures are
logged to the audit log; repeated failures auto-disable a webhook.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from pathlib import Path

_log = logging.getLogger("patchi.hosted.webhooks")

MAX_FAILURES = 5  # consecutive failures before auto-disable


def _path(root: Path) -> Path:
    return root / ".patchi" / "hosted" / "webhooks.json"


def _load(root: Path) -> list[dict]:
    p = _path(root)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        _log.warning("webhook load failed: %s", e)
        return []


def _save(root: Path, hooks: list[dict]) -> None:
    p = _path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(hooks, indent=2), encoding="utf-8")
    tmp.replace(p)


def list_webhooks(root: Path) -> list[dict]:
    """All webhooks with secret redacted."""
    out = []
    for h in _load(root):
        out.append(
            {k: v for k, v in h.items() if k != "secret"} | {"has_secret": bool(h.get("secret"))}
        )
    return out


def add_webhook(
    root: Path, url: str, events: list[str] | None = None, name: str = "", secret: str = ""
) -> dict:
    """Register a webhook. Returns its record (with id)."""
    hooks = _load(root)
    record = {
        "id": uuid.uuid4().hex[:10],
        "url": url,
        "events": events or ["finding", "anomaly", "scan_completed"],
        "name": name or url[:40],
        "secret": secret,
        "enabled": True,
        "consecutive_failures": 0,
        "last_delivery": None,
        "created_at": time.time(),
    }
    hooks.append(record)
    _save(root, hooks)
    return {k: v for k, v in record.items() if k != "secret"}


def remove_webhook(root: Path, hook_id: str) -> bool:
    hooks = _load(root)
    before = len(hooks)
    hooks = [h for h in hooks if h.get("id") != hook_id]
    if len(hooks) < before:
        _save(root, hooks)
        return True
    return False


def _sign(payload_bytes: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def dispatch_event(root: Path, event: str, data: dict) -> int:
    """Fan an event out to matching enabled webhooks. Returns delivery count.

    Never raises — delivery issues are logged and counted per-hook.
    """
    delivered = 0
    hooks = _load(root)
    dirty = False

    for h in hooks:
        if not h.get("enabled"):
            continue
        if event not in h.get("events", []) and "*" not in h.get("events", []):
            continue

        body = json.dumps({"event": event, "data": data, "ts": time.time()}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if h.get("secret"):
            headers["X-Patchi-Signature"] = _sign(body, h["secret"])

        ok = False
        try:
            import urllib.request

            req = urllib.request.Request(h["url"], data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                ok = 200 <= resp.status < 300
        except Exception as e:
            _log.debug("webhook %s delivery failed: %s", h["id"], e)

        if ok:
            h["consecutive_failures"] = 0
            h["last_delivery"] = time.time()
            delivered += 1
        else:
            h["consecutive_failures"] = h.get("consecutive_failures", 0) + 1
            if h["consecutive_failures"] >= MAX_FAILURES:
                h["enabled"] = False
                try:
                    from patchi.core.hosted.audit_log import write as audit_write

                    audit_write(
                        root,
                        "webhook.disabled",
                        data={
                            "id": h["id"],
                            "reason": f"{MAX_FAILURES} consecutive delivery failures",
                        },
                    )
                except Exception:
                    pass
        dirty = True

    if dirty:
        _save(root, hooks)

    try:
        from patchi.core.hosted.audit_log import write as audit_write

        if delivered:
            audit_write(root, "webhook.delivered", data={"event": event, "count": delivered})
    except Exception:
        pass

    return delivered
