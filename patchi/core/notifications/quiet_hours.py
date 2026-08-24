"""
Quiet hours enforcement for Patchi notifications.

Quiet hours block non-urgent alerts during the configured window.
CRITICAL and HIGH severity always bypass quiet hours.
MEDIUM, LOW, INFO are suppressed during the window.
"""

from __future__ import annotations

from datetime import datetime, time

# Severities that always fire regardless of quiet hours
_BYPASS_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})


def _parse_time(value: str) -> time:
    """Parse HH:MM string to a time object. Raises ValueError on bad format."""
    try:
        h, m = value.split(":")
        return time(int(h), int(m))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"Invalid time format '{value}' — expected HH:MM") from exc


def is_quiet_now(quiet_config: dict) -> bool:
    """
    Return True if the current moment falls inside the configured quiet window.

    quiet_config shape (from config.json):
        {
            "enabled": bool,
            "start":   "22:00",
            "end":     "08:00",
            "timezone": "UTC"   # currently ignored — uses system local time
        }

    Handles overnight windows (e.g. 22:00 → 08:00 wraps past midnight).
    """
    if not quiet_config.get("enabled", False):
        return False

    try:
        start = _parse_time(quiet_config.get("start", "22:00"))
        end = _parse_time(quiet_config.get("end", "08:00"))
    except ValueError:
        # Misconfigured quiet hours — treat as off to avoid silent notification loss
        return False

    now = datetime.now().time()

    if start <= end:
        # Same-day window: e.g. 09:00 → 17:00
        return start <= now < end
    else:
        # Overnight window: e.g. 22:00 → 08:00
        return now >= start or now < end


def should_suppress(severity: str, quiet_config: dict) -> bool:
    """
    Return True if this alert should be suppressed due to quiet hours.

    CRITICAL and HIGH always fire.
    MEDIUM/LOW/INFO are suppressed during the quiet window.
    """
    if severity in _BYPASS_SEVERITIES:
        return False
    return is_quiet_now(quiet_config)
