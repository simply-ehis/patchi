"""
Digest queue for Patchi notifications.

MEDIUM, LOW, and INFO alerts are batched here instead of firing immediately.
The queue persists to .patchi/digest.json so alerts survive restarts.
Flushing sends all queued alerts as a single digest notification per channel.

Flush is triggered either:
  - Manually via `p notify flush`
  - Automatically when Notifier.send() is called and the digest window has elapsed
"""

from __future__ import annotations

import json
import time as _time
from pathlib import Path
from typing import Any

# Severities that feed the digest queue (not immediate)
DIGEST_SEVERITIES: frozenset[str] = frozenset({"medium", "low", "info"})

# Frequency → seconds mapping
_FREQUENCY_SECONDS: dict[str, int] = {
    "hourly": 3600,
    "6h": 21600,
    "daily": 86400,
    "weekly": 604800,
}

_DIGEST_FILE = ".patchi/digest.json"


def _load_queue(root: Path) -> dict:
    path = root / _DIGEST_FILE
    if not path.exists():
        return {"items": [], "last_flushed": 0.0}
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"items": [], "last_flushed": 0.0}


def _save_queue(root: Path, data: dict) -> None:
    path = root / _DIGEST_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _frequency_to_seconds(frequency: str) -> int:
    return _FREQUENCY_SECONDS.get(frequency, _FREQUENCY_SECONDS["daily"])


class DigestQueue:
    """
    Persistent queue for batched (MEDIUM/LOW/INFO) notifications.

    Usage:
        dq = DigestQueue(project_root)
        dq.enqueue("medium", "Title", "Body text")
        if dq.should_flush(digest_frequency):
            items = dq.flush(channels)   # returns list of (channel, message) tuples
    """

    def __init__(self, root: Path) -> None:
        self._root = root

    def enqueue(self, severity: str, title: str, body: str, data: dict | None = None) -> None:
        """Add one alert to the persistent queue."""
        queue = _load_queue(self._root)
        queue["items"].append(
            {
                "severity": severity,
                "title": title,
                "body": body,
                "data": data or {},
                "queued_at": _time.time(),
            }
        )
        _save_queue(self._root, queue)

    def should_flush(self, frequency: str) -> bool:
        """Return True if enough time has elapsed since the last flush."""
        queue = _load_queue(self._root)
        elapsed = _time.time() - queue.get("last_flushed", 0.0)
        interval = _frequency_to_seconds(frequency)
        return elapsed >= interval

    def flush(self) -> list[dict[str, Any]]:
        """
        Drain the queue and return all pending items.
        Resets the queue and updates last_flushed timestamp.
        Returns an empty list if nothing was queued.
        """
        queue = _load_queue(self._root)
        items = queue.get("items", [])
        if not items:
            return []
        _save_queue(self._root, {"items": [], "last_flushed": _time.time()})
        return items

    def peek(self) -> list[dict[str, Any]]:
        """Return queued items without draining."""
        return _load_queue(self._root).get("items", [])

    def clear(self) -> int:
        """Remove all queued items without sending. Returns count cleared."""
        queue = _load_queue(self._root)
        count = len(queue.get("items", []))
        _save_queue(self._root, {"items": [], "last_flushed": _time.time()})
        return count

    @staticmethod
    def build_digest_body(items: list[dict]) -> str:
        """
        Render a human-readable digest body from a list of queued items.
        Groups by severity, most critical first.
        """
        if not items:
            return "No alerts."

        order = ["medium", "low", "info"]
        grouped: dict[str, list[dict]] = {s: [] for s in order}
        for item in items:
            sev = item.get("severity", "info")
            if sev in grouped:
                grouped[sev].append(item)

        lines: list[str] = [f"Patchi digest — {len(items)} alert(s)\n"]
        labels = {"medium": "⚠ Medium", "low": "✓ Low", "info": "ℹ Info"}
        for sev in order:
            group = grouped[sev]
            if not group:
                continue
            lines.append(f"\n{labels[sev]} ({len(group)})")
            for item in group:
                lines.append(f"  • {item['title']}: {item['body']}")

        return "\n".join(lines)
