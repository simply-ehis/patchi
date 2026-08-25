"""Defenders package — adapter registry for defense actions.

Usage::

    from patchi.core.security.defenders import ADAPTER_REGISTRY, get_adapter
    from patchi.core.security.defenders.base import DefenseAction

    adapter = get_adapter("fix_code", root=path, risk_gate=gate)
    result = adapter.execute(action)
"""

from __future__ import annotations

from pathlib import Path

from .auth_middleware import AuthMiddlewareAdapter
from .base import BaseAdapter, DefendResult, DefenseAction
from .block_ip import BlockIpAdapter
from .block_ws_origin import BlockWsOriginAdapter
from .crypto_fix import CryptoFixAdapter
from .enforce_rate_limit import EnforceRateLimitAdapter
from .fix_code import FixCodeAdapter
from .invalidate_session import InvalidateSessionAdapter
from .patch_config import PatchConfigAdapter
from .rotate_secret import RotateSecretAdapter
from .suspend_account import SuspendAccountAdapter
from .update_dependency import UpdateDependencyAdapter

# Registry: action_type string → adapter class
ADAPTER_REGISTRY: dict[str, type[BaseAdapter]] = {
    "fix_code": FixCodeAdapter,
    "update_dependency": UpdateDependencyAdapter,
    "block_ip": BlockIpAdapter,
    "rotate_secret": RotateSecretAdapter,
    "patch_config": PatchConfigAdapter,
    "crypto_fix": CryptoFixAdapter,
    "auth_middleware": AuthMiddlewareAdapter,
    "invalidate_session": InvalidateSessionAdapter,
    "enforce_rate_limit": EnforceRateLimitAdapter,
    "suspend_account": SuspendAccountAdapter,
    "block_ws_origin": BlockWsOriginAdapter,
}

__all__ = [
    "ADAPTER_REGISTRY",
    "BaseAdapter",
    "DefenseAction",
    "DefendResult",
    "get_adapter",
]


def get_adapter(action_type: str, root: Path, risk_gate) -> BaseAdapter:
    """Get an adapter instance for the given action type.

    Falls back to a no-op adapter if the type is unknown.
    """
    cls = ADAPTER_REGISTRY.get(action_type)
    if cls is not None:
        return cls(root=root, risk_gate=risk_gate)

    # Fallback: return a stub that queues for human review
    class _FallbackAdapter(BaseAdapter):
        action_type = ""  # overridden below

        def execute(self, _action: DefenseAction) -> DefendResult:
            return DefendResult(
                action="queued",
                reason=f"No auto-defense available for '{_action.type}' — queued for human review",
                defense_action=_action,
            )

    adapter = _FallbackAdapter(root=root, risk_gate=risk_gate)
    adapter.action_type = action_type
    return adapter
