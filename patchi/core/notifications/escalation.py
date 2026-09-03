"""
Escalation tracking for CRITICAL and HIGH Patchi alerts.

When an alert fires, it is registered here with a unique ID.
If the user does not acknowledge it within the configured window,
escalation fires to the next channel in the notification list.

Ack store persists to .patchi/escalation.json.
`p notify ack [id]` calls EscalationTracker.acknowledge(id).
"""
from __future__ import annotations

import json
import logging
import threading
import time as _time
from pathlib import Path
from typing import Any

# Severities that require acknowledgement tracking
ESCALATION_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})

_ESCALATION_FILE = ".patchi/escalation.json"
_DEFAULT_ESCALATION_MINS = 30  # escalate after 30 min if unacknowledged
_POLL_INTERVAL_SECS = 60  # check every 60 seconds


_log = logging.getLogger("patchi.core.escalation")


def _load_store(root: Path) -> dict:
    path = root / _ESCALATION_FILE
    if not path.exists():
        return {"alerts": {}}
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"alerts": {}}


def _save_store(root: Path, data: dict) -> None:
    path = root / _ESCALATION_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


class EscalationTracker:
    """
    Tracks unacknowledged CRITICAL/HIGH alerts and escalates them.

    The background thread polls every 60 seconds and fires escalation
    callbacks for overdue unacknowledged alerts.

    escalation_fn signature: (alert_id: str, alert: dict, channels: list) -> None
    """

    def __init__(
        self,
        root: Path,
        escalation_fn: Any,
        escalation_minutes: int = _DEFAULT_ESCALATION_MINS,
    ) -> None:
        self._root = root
        self._escalation_fn = escalation_fn
        self._escalation_secs = escalation_minutes * 60
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def register(self, alert_id: str, severity: str, title: str, body: str) -> None:
        """Register a new alert as requiring acknowledgement."""
        if severity not in ESCALATION_SEVERITIES:
            return
        store = _load_store(self._root)
        store["alerts"][alert_id] = {
            "severity": severity,
            "title": title,
            "body": body,
            "fired_at": _time.time(),
            "acked": False,
            "escalated": False,
        }
        _save_store(self._root, store)

    def acknowledge(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged. Returns True if the ID was found."""
        store = _load_store(self._root)
        if alert_id not in store["alerts"]:
            return False
        store["alerts"][alert_id]["acked"] = True
        _save_store(self._root, store)
        return True

    def pending(self) -> list[dict]:
        """Return all alerts that are unacknowledged and not yet escalated."""
        store = _load_store(self._root)
        return [
            {"id": aid, **alert}
            for aid, alert in store["alerts"].items()
            if not alert.get("acked") and not alert.get("escalated")
        ]

    def list_all(self) -> list[dict]:
        """Return all tracked alerts (acked and unacked)."""
        store = _load_store(self._root)
        return [{"id": aid, **alert} for aid, alert in store["alerts"].items()]

    def start(self) -> None:
        """Start the background escalation polling thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the background polling thread."""
        self._stop_event.set()

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            self._check_overdue()
            self._stop_event.wait(timeout=_POLL_INTERVAL_SECS)

    def _check_overdue(self) -> None:
        """Fire escalation for any alert past the window."""
        store = _load_store(self._root)
        now = _time.time()
        changed = False

        for alert_id, alert in store["alerts"].items():
            if alert.get("acked") or alert.get("escalated"):
                continue
            age = now - alert.get("fired_at", now)
            if age >= self._escalation_secs:
                alert["escalated"] = True
                changed = True
                try:
                    self._escalation_fn(alert_id, alert)
                except Exception as e:
                    _log.warning("EscalationTracker._check_overdue failed: %s", e)

        if changed:
            _save_store(self._root, store)

    def purge_old(self, max_age_hours: int = 72) -> int:
        """Remove acked/escalated alerts older than max_age_hours. Returns count removed."""
        store = _load_store(self._root)
        cutoff = _time.time() - (max_age_hours * 3600)
        before = len(store["alerts"])
        store["alerts"] = {
            aid: a
            for aid, a in store["alerts"].items()
            if not (a.get("acked") or a.get("escalated")) or a.get("fired_at", 0) >= cutoff
        }
        _save_store(self._root, store)
        return before - len(store["alerts"])
