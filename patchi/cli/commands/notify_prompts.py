"""
Prompt field definitions for `p notify add` interactive setup.
Kept separate so notify_cmd.py stays under 200 lines.
"""

CHANNEL_SETUP_FIELDS: dict[str, list[tuple[str, str]]] = {
    "email": [
        ("user", "SMTP username (your email address)"),
        ("password", "SMTP password or app password"),
        ("host", "SMTP host (e.g. smtp.gmail.com)"),
        ("port", "SMTP port [leave blank for default]"),
        ("to", "Recipient address [blank = same as username]"),
    ],
    "slack": [
        ("webhook_url", "Slack incoming webhook URL"),
    ],
    "discord": [
        ("webhook_url", "Discord webhook URL"),
    ],
    "webhook": [
        ("url", "Webhook URL (https://...)"),
    ],
    "telegram": [
        ("bot_token", "Telegram bot token"),
        ("chat_id", "Chat ID (your chat or channel ID)"),
    ],
}

SEVERITY_CHOICES: list[str] = ["critical", "high", "medium", "low", "info"]
