"""
IP Reputation database for hosted mode.

Maintains a local database of known-bad IPs from public blocklists.
Supports:
  - Loading public blocklists (abuse.ch, firehol, etc.)
  - Fast O(1) lookup via set
  - Periodic refresh (daily)
  - Auto-blocking for high-threat IPs

All data stored locally in .patchi/hosted/ip_reputation.json.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

_REPUTATION_FILE = ".patchi/hosted/ip_reputation.json"
_BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
]

# IPs from these lists are automatically blocked
_AUTO_BLOCK_THRESHOLD = 3  # IPs seen on 3+ lists


import logging

_log = logging.getLogger("patchi.core.ip_reputation")


def _load(root: Path) -> dict:
    path = root / _REPUTATION_FILE
    if not path.exists():
        return {"bad_ips": {}, "last_refresh": 0, "blocked": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        _log.warning("_load failed: %s", e)
        return {"bad_ips": {}, "last_refresh": 0, "blocked": []}


def _save(root: Path, data: dict) -> None:
    path = root / _REPUTATION_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def lookup(ip: str, root: Path) -> dict:
    """
    Look up an IP's reputation.
    Returns {"known_bad": bool, "threat_level": str, "lists_hit": int, "blocked": bool}
    """
    data = _load(root)
    bad_ips = data.get("bad_ips", {})
    blocked = set(data.get("blocked", []))

    if ip in bad_ips:
        info = bad_ips[ip]
        return {
            "known_bad": True,
            "threat_level": _threat_level(info.get("lists_hit", 0)),
            "lists_hit": info.get("lists_hit", 0),
            "sources": info.get("sources", []),
            "blocked": ip in blocked,
        }

    return {
        "known_bad": False,
        "threat_level": "clean",
        "lists_hit": 0,
        "sources": [],
        "blocked": ip in blocked,
    }


def record_hit(ip: str, source: str, root: Path) -> None:
    """Record that an IP was flagged by a detector."""
    data = _load(root)
    bad_ips = data.setdefault("bad_ips", {})

    if ip not in bad_ips:
        bad_ips[ip] = {"lists_hit": 0, "sources": [], "first_seen": time.time()}

    entry = bad_ips[ip]
    if source not in entry["sources"]:
        entry["sources"].append(source)
        entry["lists_hit"] = len(entry["sources"])
    entry["last_seen"] = time.time()

    # Auto-block if threshold crossed
    if entry["lists_hit"] >= _AUTO_BLOCK_THRESHOLD:
        blocked = data.setdefault("blocked", [])
        if ip not in blocked:
            blocked.append(ip)

    _save(root, data)


def is_blocked(ip: str, root: Path) -> bool:
    """Check if an IP is auto-blocked."""
    data = _load(root)
    return ip in data.get("blocked", [])


def block(ip: str, root: Path) -> None:
    """Manually block an IP."""
    data = _load(root)
    blocked = data.setdefault("blocked", [])
    if ip not in blocked:
        blocked.append(ip)
    _save(root, data)


def unblock(ip: str, root: Path) -> bool:
    """Unblock an IP. Returns True if it was blocked."""
    data = _load(root)
    blocked = data.get("blocked", [])
    if ip in blocked:
        blocked.remove(ip)
        data["blocked"] = blocked
        _save(root, data)
        return True
    return False


def needs_refresh(root: Path, max_age_hours: int = 24) -> bool:
    """Check if the reputation database needs refreshing."""
    data = _load(root)
    last_refresh = data.get("last_refresh", 0)
    age_hours = (time.time() - last_refresh) / 3600
    return age_hours > max_age_hours


def get_top_threats(root: Path, limit: int = 20) -> list[dict]:
    """Get the top threatening IPs sorted by lists_hit."""
    data = _load(root)
    bad_ips = data.get("bad_ips", {})

    sorted_ips = sorted(
        bad_ips.items(),
        key=lambda x: x[1].get("lists_hit", 0),
        reverse=True,
    )[:limit]

    return [
        {
            "ip": ip,
            "lists_hit": info.get("lists_hit", 0),
            "sources": info.get("sources", []),
            "threat_level": _threat_level(info.get("lists_hit", 0)),
            "first_seen": info.get("first_seen", 0),
            "last_seen": info.get("last_seen", 0),
        }
        for ip, info in sorted_ips
    ]


def _threat_level(lists_hit: int) -> str:
    if lists_hit >= 5:
        return "critical"
    if lists_hit >= 3:
        return "high"
    if lists_hit >= 1:
        return "medium"
    return "clean"
