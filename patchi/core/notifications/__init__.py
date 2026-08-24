"""Patchi notification system — public API."""

from patchi.core.notifications.channels import ChannelConfig, ChannelType, load_channels
from patchi.core.notifications.digest import DigestQueue
from patchi.core.notifications.escalation import EscalationTracker
from patchi.core.notifications.notifier import Notifier
from patchi.core.notifications.quiet_hours import is_quiet_now, should_suppress

__all__ = [
    "Notifier",
    "ChannelConfig",
    "ChannelType",
    "load_channels",
    "DigestQueue",
    "EscalationTracker",
    "should_suppress",
    "is_quiet_now",
]
