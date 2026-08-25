"""Tool executor — public entry point.

The implementation lives in :mod:`patchi.core.ai.tools.executor`; this shim
keeps the historical import path ``patchi.core.ai.tool_executor`` working for
the council, dashboard, and CLI integrations.
"""

from patchi.core.ai.tools.executor import (
    CLIConfirmationProvider,
    ConfirmationProvider,
    ExecutionResult,
    ToolExecutor,
    ToolInvocation,
    execute_tool_sync,
)

__all__ = [
    "CLIConfirmationProvider",
    "ConfirmationProvider",
    "ExecutionResult",
    "ToolExecutor",
    "ToolInvocation",
    "execute_tool_sync",
]
