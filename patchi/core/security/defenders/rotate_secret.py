"""Adapter: rotate_secret — generate new secret and update .env."""

from __future__ import annotations

import logging
import re
import secrets as sec

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.rotate_secret")


class RotateSecretAdapter(BaseAdapter):
    """Generate a new secret and update the code."""

    action_type = "rotate_secret"

    def execute(self, action: DefenseAction) -> DefendResult:
        new_secret = sec.token_urlsafe(32)
        env_path = self.root / ".env"
        if env_path.exists():
            try:
                content = env_path.read_text(encoding="utf-8")
                var_name = (
                    action.target if action.target and "=" not in action.target else "SECRET_KEY"
                )
                if var_name in content:
                    content = re.sub(
                        rf"^{re.escape(var_name)}=.*$",
                        f"{var_name}={new_secret}",
                        content,
                        count=1,
                        flags=re.MULTILINE,
                    )
                else:
                    content = f"{content.rstrip()}\n{var_name}={new_secret}\n"
                env_path.write_text(content, encoding="utf-8")
                return DefendResult(
                    action="applied",
                    reason=f"Rotated {var_name} in .env — new 256-bit secret generated",
                    defense_action=action,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Failed to rotate secret: {e}",
                    defense_action=action,
                )
        return DefendResult(
            action="queued",
            reason="No .env file found — create one and add the rotated secret manually",
            defense_action=action,
        )
