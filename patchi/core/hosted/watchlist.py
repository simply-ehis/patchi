"""
IP watchlist for Patchi hosted mode.

Tracks per-IP threat scores over time. Scores decay with TTL.
Escalates to Notifier when an IP crosses the configured threshold.

Storage: .patchi/hosted/watchlist.json
"""

from __future__ import annotations

import json
import time
from pathlib import Path

_WATCHLIST_FILE = ".patchi/hosted/watchlist.json"
_SCORE_TTL_SECS = 3600  # scores decay to 0 after 1 hour of silence
_ESCALATE_HIGH = 50  # score threshold → HIGH alert
_ESCALATE_CRITICAL = 100  # score threshold → CRITICAL alert

# Score increments per finding type
_SCORE_MAP: dict[str, int] = {
    "brute_force": 40,
    "injection_probe": 30,
    "scanner_sweep": 20,
    "rate_spike": 10,
    "error_spike": 5,
    "ml_outlier": 15,
}


def _path(root: Path) -> Path:
    return root / _WATCHLIST_FILE


def _load(root: Path) -> dict[str, dict]:
    p = _path(root)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(root: Path, data: dict[str, dict]) -> None:
    p = _path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(p)


def _decay(entry: dict, now: float) -> float:
    """Linear decay to 0 over TTL since last_seen."""
    age = now - entry.get("last_seen", now)
    ratio = max(0.0, 1.0 - age / _SCORE_TTL_SECS)
    return entry.get("score", 0.0) * ratio


class WatchlistTracker:
    """
    Tracks IP threat scores and fires escalation callbacks when thresholds cross.

    escalation_fn(ip, score, severity) is called when an IP crosses a threshold.
    """

    def __init__(self, root: Path, escalation_fn=None) -> None:
        self._root = root
        self._escalation_fn = escalation_fn or (lambda *a: None)

    def record(self, ip: str, detector: str, note: str = "") -> float:
        """
        Add score for a detector hit on this IP.
        Returns the new effective score after decay + increment.
        """
        if not ip:
            return 0.0

        now = time.time()
        data = _load(self._root)
        entry = data.get(
            ip,
            {
                "ip": ip,
                "score": 0.0,
                "last_seen": now,
                "hit_count": 0,
                "escalated_high": False,
                "escalated_critical": False,
                "notes": [],
            },
        )

        # Apply decay since last event
        decayed = _decay(entry, now)
        increment = _SCORE_MAP.get(detector, 10)
        new_score = decayed + increment

        entry["score"] = new_score
        entry["last_seen"] = now
        entry["hit_count"] = entry.get("hit_count", 0) + 1
        if note:
            entry["notes"] = (entry.get("notes", []) + [note])[-20:]

        data[ip] = entry

        # Check escalation before saving so we use in-memory data (no re-read race)
        should_escalate_critical = new_score >= _ESCALATE_CRITICAL and not entry.get("escalated_critical")
        should_escalate_high = (
            new_score >= _ESCALATE_HIGH and not should_escalate_critical and not entry.get("escalated_high")
        )

        if should_escalate_critical:
            entry["escalated_critical"] = True
        elif should_escalate_high:
            entry["escalated_high"] = True

        _save(self._root, data)

        if should_escalate_critical:
            self._escalation_fn(ip, new_score, "critical")
        elif should_escalate_high:
            self._escalation_fn(ip, new_score, "high")

        return new_score

    def score(self, ip: str) -> float:
        """Current decayed score for an IP."""
        data = _load(self._root)
        entry = data.get(ip)
        if not entry:
            return 0.0
        return _decay(entry, time.time())

    def top(self, n: int = 10) -> list[dict]:
        """Return top-n IPs by current decayed score."""
        now = time.time()
        data = _load(self._root)
        scored = [{**entry, "current_score": _decay(entry, now)} for entry in data.values()]
        return sorted(scored, key=lambda e: e["current_score"], reverse=True)[:n]

    def clear_ip(self, ip: str) -> bool:
        """Remove an IP from the watchlist. Returns True if found."""
        data = _load(self._root)
        if ip not in data:
            return False
        del data[ip]
        _save(self._root, data)
        return True

    def purge_expired(self) -> int:
        """Remove IPs whose score has fully decayed. Returns count removed."""
        now = time.time()
        data = _load(self._root)
        keep = {ip: e for ip, e in data.items() if _decay(e, now) > 0}
        removed = len(data) - len(keep)
        if removed:
            _save(self._root, keep)
        return removed
