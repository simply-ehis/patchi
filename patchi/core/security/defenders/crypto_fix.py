"""Adapter: crypto_fix — replace weak crypto with modern algorithms."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from patchi.core.fix.patch import FileChange, Patch

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.crypto_fix")

# Known bad → good replacements (in order of specificity)
_CRYPTO_REPLACEMENTS: list[tuple[str, str]] = [
    ("hashlib.md5(", "hashlib.sha256("),
    ("hashlib.sha1(", "hashlib.sha256("),
    (
        "from cryptography.hazmat.primitives.ciphers.algorithms import ARC4",
        "from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20",
    ),
    ("ARC4.new(", "ChaCha20.new("),
    ("DES.new(", "AES.new("),
    ("DES3.new(", "AES.new("),
    ("RSA.generate(1024", "RSA.generate(2048"),
    ("RSA.generate(512", "RSA.generate(2048"),
    ("DSA.generate(512", "RSA.generate(2048"),
    ("DSA.generate(1024", "RSA.generate(2048"),
    ("PBKDF2", "PBKDF2HMAC"),
]


class CryptoFixAdapter(BaseAdapter):
    """Replace weak crypto with modern algorithms."""

    action_type = "crypto_fix"

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
        for old, new in _CRYPTO_REPLACEMENTS:
            if old in content:
                lines = content.splitlines()
                for _i, line in enumerate(lines):
                    if old in line:
                        change = FileChange(
                            path=str(fpath),
                            original=line,
                            proposed=line.replace(old, new),
                        )
                        changes.append(change)
                        break

        if not changes:
            return DefendResult(
                action="skipped",
                reason="No weak crypto patterns found in file",
                defense_action=action,
            )

        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="SECURITY",
            changes=changes,
            description="Replace weak cryptography with modern algorithms",
            risk_score=20,
            confidence=90,
            blast_radius=1,
        )
        gate_result = self.risk_gate.evaluate(patch)
        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason="Crypto fix auto-applied",
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
        elif gate_result.is_blocked:
            return DefendResult(
                action="blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )
        else:
            return DefendResult(
                action="queued",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )
