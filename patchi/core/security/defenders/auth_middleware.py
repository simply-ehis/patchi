"""Adapter: auth_middleware — add authentication middleware / decorator to an endpoint."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from patchi.core.fix.patch import FileChange, Patch

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.auth_middleware")


class AuthMiddlewareAdapter(BaseAdapter):
    """Add authentication middleware / decorator to an endpoint."""

    action_type = "auth_middleware"

    def execute(self, action: DefenseAction) -> DefendResult:
        if not action.target or not Path(action.target).exists():
            return DefendResult(
                action="skipped",
                reason=f"File does not exist: {action.target}",
                defense_action=action,
            )
        fpath = Path(action.target)
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            return DefendResult(action="blocked", reason=f"Read error: {e}", defense_action=action)

        changes = []
        if "flask" in content.lower() or "from flask" in content:
            if (
                "from flask_login import login_required" not in content
                and "from flask_login import" not in content
            ):
                lines = content.splitlines()
                insert_at = 0
                for i, line in enumerate(lines):
                    if line.startswith("#!") or line.startswith("# -*-"):
                        insert_at = i + 1
                    else:
                        break
                lines.insert(insert_at, "from flask_login import login_required")
                modified = "\n".join(lines)
                changes.append(FileChange(path=str(fpath), original=content, proposed=modified))
        elif "django" in content.lower() or "from django" in content:
            if "from django.contrib.auth.decorators import login_required" not in content:
                changes.append(
                    FileChange(
                        path=str(fpath),
                        original=content,
                        proposed="from django.contrib.auth.decorators import login_required\n"
                        + content,
                    )
                )
        elif "fastapi" in content.lower() or "from fastapi" in content:
            if "Depends" not in content and "get_current_user" not in content:
                changes.append(
                    FileChange(
                        path=str(fpath),
                        original=content,
                        proposed="from fastapi import Depends\nfrom .auth import get_current_user\n"
                        + content,
                    )
                )

        if not changes:
            return DefendResult(
                action="skipped",
                reason="No recognizable framework found for auth middleware insertion",
                defense_action=action,
            )

        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="SECURITY",
            changes=changes,
            description="Add authentication middleware",
            risk_score=30,
            confidence=70,
            blast_radius=2,
        )
        gate_result = self.risk_gate.evaluate(patch)
        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason="Auth middleware template added",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Apply failed: {e}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
        else:
            return DefendResult(
                action="queued" if not gate_result.is_blocked else "blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )
