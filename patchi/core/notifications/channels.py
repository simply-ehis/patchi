"""
Channel configuration models and Apprise URL builders for Patchi notifications.

Each channel type stores its config in the project's config.json under the
`notifications` list as a plain dict. This module converts those dicts to
validated models and builds the Apprise URL strings required to send alerts.

Supported types: email, slack, discord, webhook, telegram
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import quote


class ChannelType(StrEnum):
    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    WEBHOOK = "webhook"
    TELEGRAM = "telegram"


# Severity levels that each channel is willing to receive.
# Channels with min_severity="high" skip MEDIUM/LOW alerts.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class ChannelConfig:
    """Parsed, validated representation of one entry in config `notifications`."""

    name: str
    channel_type: ChannelType
    apprise_url: str  # ready-to-use Apprise URL
    min_severity: str = "medium"  # alerts below this rank are skipped
    in_digest: bool = False  # if True, always batch regardless of severity

    def accepts_severity(self, severity: str) -> bool:
        """Return True if this channel should receive an alert at the given severity."""
        channel_rank = _SEVERITY_RANK.get(self.min_severity, 2)
        alert_rank = _SEVERITY_RANK.get(severity, 4)
        return alert_rank <= channel_rank


# ── Apprise URL builders ───────────────────────────────────────────────────────


def _build_email_url(cfg: dict) -> str:
    """
    Build an Apprise mailto:// URL from email config dict.
    Required keys: user, password, host
    Optional: port, to, from_addr, secure (bool)
    """
    user = cfg["user"]
    password = quote(cfg["password"], safe="")
    host = cfg["host"]
    port = cfg.get("port", "")
    to = cfg.get("to", user)
    secure = cfg.get("secure", True)
    schema = "mailtos" if secure else "mailto"
    port_str = f":{port}" if port else ""
    return f"{schema}://{user}:{password}@{host}{port_str}?to={quote(to, safe='@.')}"


def _build_slack_url(cfg: dict) -> str:
    """
    Build an Apprise slack:// URL.
    Accepts either a raw webhook URL (webhook_url key) or
    tokenA/tokenB/tokenC format (token_a, token_b, token_c keys).
    """
    if "webhook_url" in cfg:
        # Slack incoming webhook — extract path tokens from URL
        # Format: https://hooks.slack.com/services/T.../B.../xxx
        path = cfg["webhook_url"].split("hooks.slack.com/services/")[-1]
        parts = path.strip("/").split("/")
        if len(parts) == 3:
            return f"slack://{parts[0]}/{parts[1]}/{parts[2]}"
        # Non-standard — pass raw URL through Apprise's https:// handler
        return cfg["webhook_url"]
    return "slack://{token_a}/{token_b}/{token_c}".format(**cfg)


def _build_discord_url(cfg: dict) -> str:
    """
    Build an Apprise discord:// URL.
    Required: webhook_id, webhook_token
    (Discord webhook URL format: .../webhooks/{id}/{token})
    """
    if "webhook_url" in cfg:
        parts = cfg["webhook_url"].rstrip("/").split("/")
        # Last two segments are id and token
        return f"discord://{parts[-2]}/{parts[-1]}"
    return "discord://{webhook_id}/{webhook_token}".format(**cfg)


def _build_webhook_url(cfg: dict) -> str:
    """
    Custom HTTP webhook — just pass the URL through directly.
    Apprise supports json:// and xml:// schemas; plain https:// also works.
    """
    url = cfg["url"]
    # If already an apprise-style schema, use as-is
    if any(url.startswith(s) for s in ("json://", "xml://", "form://")):
        return url
    # Convert plain https:// to json:// so Apprise sends JSON body
    return url.replace("https://", "json://", 1).replace("http://", "json://", 1)


def _build_telegram_url(cfg: dict) -> str:
    """
    Build an Apprise tgram:// URL.
    Required: bot_token, chat_id
    """
    return "tgram://{bot_token}/{chat_id}".format(**cfg)


_URL_BUILDERS = {
    ChannelType.EMAIL: _build_email_url,
    ChannelType.SLACK: _build_slack_url,
    ChannelType.DISCORD: _build_discord_url,
    ChannelType.WEBHOOK: _build_webhook_url,
    ChannelType.TELEGRAM: _build_telegram_url,
}


# ── Public API ─────────────────────────────────────────────────────────────────


def from_config(raw: dict) -> ChannelConfig:
    """
    Parse one raw dict from config `notifications` list into a ChannelConfig.
    Raises ValueError for missing required fields or unknown channel type.
    """
    try:
        channel_type = ChannelType(raw["type"])
    except (KeyError, ValueError) as exc:
        valid = ", ".join(t.value for t in ChannelType)
        raise ValueError(f"Channel type must be one of: {valid}") from exc

    if "name" not in raw:
        raise ValueError("Channel config missing required key: name")

    builder = _URL_BUILDERS[channel_type]
    try:
        apprise_url = builder(raw.get("credentials", raw))
    except KeyError as exc:
        raise ValueError(f"Channel '{raw['name']}' ({channel_type.value}) missing required field: {exc}") from exc

    return ChannelConfig(
        name=raw["name"],
        channel_type=channel_type,
        apprise_url=apprise_url,
        min_severity=raw.get("min_severity", "medium"),
        in_digest=raw.get("in_digest", False),
    )


def load_channels(config: dict) -> list[ChannelConfig]:
    """
    Load and validate all channels from a config dict.
    Skips entries that fail validation (logs name for debugging).
    """
    channels: list[ChannelConfig] = []
    for raw in config.get("notifications", []):
        try:
            channels.append(from_config(raw))
        except ValueError:
            # Corrupt/incomplete entry — skip silently in runtime, surface in `p notify list`
            pass
    return channels


def channel_to_dict(ch: ChannelConfig) -> dict[str, Any]:
    """Serialise a ChannelConfig back for display (never exposes the full apprise_url)."""
    return {
        "name": ch.name,
        "type": ch.channel_type.value,
        "min_severity": ch.min_severity,
        "in_digest": ch.in_digest,
    }
