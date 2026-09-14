"""
Central notification dispatcher for Patchi.

Single entry point: Notifier.send(severity, title, body, data)

Routing rules:
  CRITICAL  → immediate, all channels, bypass quiet hours, start escalation
  HIGH      → immediate, bypass quiet hours, start escalation
  MEDIUM    → digest queue unless quiet hours bypassed, respects quiet hours
  LOW/INFO  → digest queue only, respects quiet hours

Usage:
    notifier = Notifier(project_root)
    notifier.send("critical", "SQL injection found", "in routes/user.py:44")
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import apprise
from apprise import NotifyType

from patchi.core.notifications.channels import ChannelConfig, load_channels
from patchi.core.notifications.digest import DIGEST_SEVERITIES, DigestQueue
from patchi.core.notifications.escalation import ESCALATION_SEVERITIES, EscalationTracker
from patchi.core.notifications.quiet_hours import should_suppress

# Severity → Apprise NotifyType mapping
_APPRISE_TYPE: dict[str, str] = {
    "critical": NotifyType.FAILURE,
    "high": NotifyType.WARNING,
    "medium": NotifyType.INFO,
    "low": NotifyType.SUCCESS,
    "info": NotifyType.SUCCESS,
}


class Notifier:
    """
    Dispatch Patchi alerts to configured channels.

    Instantiate once per command invocation or keep alive in watch mode.
    Thread-safe for the escalation background thread.
    """

    def __init__(self, root: Path, config: dict) -> None:
        self._root = root
        self._config = config
        self._channels = load_channels(config)
        self._digest = DigestQueue(root)
        self._tracker = EscalationTracker(
            root,
            escalation_fn=self._escalate,
            escalation_minutes=config.get("escalation_minutes", 30),
        )

    def send(
        self,
        severity: str,
        title: str,
        body: str,
        data: dict[str, Any] | None = None,
    ) -> int:
        """
        Route one alert by severity.
        Returns the number of channels that received the alert immediately.
        """
        data = data or {}
        channels = self._eligible_channels(severity)

        if not channels:
            return 0

        in_digest_mode = severity in DIGEST_SEVERITIES
        suppressed = should_suppress(severity, self._config.get("quiet_hours", {}))

        if suppressed or in_digest_mode:
            self._digest.enqueue(severity, title, body, data)
            return 0

        # Immediate fire
        sent = self._fire(channels, severity, title, body)

        # Register for escalation if CRITICAL or HIGH
        if severity in ESCALATION_SEVERITIES and sent > 0:
            alert_id = str(uuid.uuid4())[:8]
            self._tracker.register(alert_id, severity, title, body)

        # Auto-flush digest if window has elapsed
        freq = self._config.get("digest_frequency", "daily")
        if self._digest.should_flush(freq):
            self.flush_digest()

        return sent

    def flush_digest(self) -> int:
        """
        Flush the digest queue to all channels configured with in_digest=True
        or that accept MEDIUM severity. Returns number of channels notified.
        """
        items = self._digest.flush()
        if not items:
            return 0

        body = DigestQueue.build_digest_body(items)
        title = f"Patchi digest — {len(items)} alert(s)"
        channels = [ch for ch in self._channels if ch.accepts_severity("medium")]
        return self._fire(channels, "medium", title, body)

    def test(self, channel_name: str | None = None) -> list[tuple[str, bool]]:
        """
        Send a test alert to one or all channels.
        Returns list of (channel_name, success) tuples.
        """
        targets = [ch for ch in self._channels if ch.name == channel_name] if channel_name else self._channels
        results: list[tuple[str, bool]] = []
        for ch in targets:
            ok = _apprise_send(
                ch.apprise_url,
                "info",
                "Patchi test alert",
                "If you see this, the channel is working.",
            )
            results.append((ch.name, ok))
        return results

    def acknowledge(self, alert_id: str) -> bool:
        """Acknowledge a CRITICAL/HIGH alert by its short ID."""
        return self._tracker.acknowledge(alert_id)

    def pending_escalations(self) -> list[dict]:
        """Return all unacknowledged, unescalated alerts."""
        return self._tracker.pending()

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _eligible_channels(self, severity: str) -> list[ChannelConfig]:
        return [ch for ch in self._channels if ch.accepts_severity(severity)]

    def _fire(
        self,
        channels: list[ChannelConfig],
        severity: str,
        title: str,
        body: str,
    ) -> int:
        notify_type = _APPRISE_TYPE.get(severity, NotifyType.INFO)
        sent = 0
        for ch in channels:
            if _apprise_send(ch.apprise_url, notify_type, title, body):
                sent += 1
        return sent

    def _escalate(self, alert_id: str, alert: dict) -> None:
        """
        Escalation callback — fires remaining channels that haven't received the alert.
        Called by EscalationTracker on the background thread.
        """
        channels = self._eligible_channels(alert.get("severity", "high"))
        # Skip first channel (already fired) — escalate to the rest
        escalation_targets = channels[1:] if len(channels) > 1 else channels
        if escalation_targets:
            self._fire(
                escalation_targets,
                alert.get("severity", "high"),
                f"[ESCALATED] {alert.get('title', 'Alert')}",
                alert.get("body", ""),
            )


def _apprise_send(url: str, notify_type: str, title: str, body: str) -> bool:
    """Send one notification via Apprise. Returns True on success."""
    ap = apprise.Apprise()
    ap.add(url)
    return bool(ap.notify(title=title, body=body, notify_type=notify_type))
