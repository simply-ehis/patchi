"""
Tool Executor — Executes AI tool calls with validation, confirmation, and error handling.

Handles:
- Parameter validation against JSON schemas
- User confirmation for destructive operations
- Execution with timeout and error recovery
- Result formatting for AI consumption
- Audit logging of all tool invocations
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from patchi.core.ai.tools.registry import ToolRegistry, get_tool_registry

_log = logging.getLogger("patchi.ai.tool_executor")


@dataclass
class ToolInvocation:
    """A single tool invocation record for audit logging."""
    id: str
    tool_name: str
    parameters: dict
    invoked_by: str  # "council", "persona", "cli", "user"
    persona_name: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: float = 0
    completed_at: float = 0
    success: bool = False
    result: dict | None = None
    error: str | None = None
    confirmation_given: bool = False


@dataclass
class ExecutionResult:
    """Result of a tool execution."""
    success: bool
    result: Any = None
    error: str | None = None
    invocation_id: str = ""
    duration_ms: int = 0


class ConfirmationProvider:
    """Interface for getting user confirmation."""
    
    async def confirm(self, tool_name: str, parameters: dict, side_effects: str, description: str) -> bool:
        """Return True if user confirms, False otherwise."""
        raise NotImplementedError


class CLIConfirmationProvider(ConfirmationProvider):
    """CLI-based confirmation using rich prompts."""
    
    def __init__(self, auto_confirm: bool = False):
        self.auto_confirm = auto_confirm
    
    async def confirm(self, tool_name: str, parameters: dict, side_effects: str, description: str) -> bool:
        if self.auto_confirm:
            return True
        
        try:
            from rich.console import Console
            from rich.prompt import Confirm
            
            console = Console()
            console.print(f"\n[yellow]⚠ Tool requires confirmation:[/yellow] {tool_name}")
            console.print(f"  Description: {description}")
            console.print(f"  Parameters: {json.dumps(parameters, indent=2)}")
            if side_effects:
                console.print(f"  [red]Side effects:[/red] {side_effects}")
            
            return Confirm.ask("  Proceed?", default=False)
        except Exception:
            # Fallback to simple input
            print(f"\n⚠ Tool requires confirmation: {tool_name}")
            print(f"  Description: {description}")
            print(f"  Parameters: {json.dumps(parameters, indent=2)}")
            if side_effects:
                print(f"  Side effects: {side_effects}")
            response = input("  Proceed? (y/N): ").strip().lower()
            return response in ("y", "yes")


class ToolExecutor:
    """
    Executes tool calls with full validation, confirmation, and error handling.
    
    Features:
    - JSON schema validation for parameters
    - Confirmation gates for destructive operations
    - Timeout enforcement
    - Structured error handling
    - Audit logging
    - Result normalization for AI consumption
    """
    
    def __init__(
        self,
        root: Path,
        confirmation_provider: ConfirmationProvider | None = None,
        default_timeout: float = 120.0,
        on_progress: Optional[Callable[[str], None]] = None,
    ):
        self.root = root
        self.registry = get_tool_registry()
        self.confirmation_provider = confirmation_provider or CLIConfirmationProvider()
        self.default_timeout = default_timeout
        self.on_progress = on_progress or (lambda _: None)
        
        # Audit log
        self.invocation_log: list[ToolInvocation] = []
        self._log_path = root / ".patchi" / "logs" / "tool_invocations.jsonl"
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
    
    async def execute(
        self,
        tool_name: str,
        parameters: dict,
        invoked_by: str = "user",
        persona_name: str | None = None,
        timeout: float | None = None,
        skip_confirmation: bool = False,
    ) -> ExecutionResult:
        """
        Execute a tool call with full validation and safety checks.
        
        Args:
            tool_name: Name of the tool to execute
            parameters: Parameters for the tool
            invoked_by: Who is invoking ("council", "persona", "cli", "user")
            persona_name: Name of the persona if invoked by one
            timeout: Custom timeout in seconds
            skip_confirmation: Skip confirmation even if required (for testing)
        
        Returns:
            ExecutionResult with success status, result, or error
        """
        invocation_id = str(uuid.uuid4())[:8]
        start_time = time.monotonic()
        
        # Create invocation record
        invocation = ToolInvocation(
            id=invocation_id,
            tool_name=tool_name,
            parameters=parameters,
            invoked_by=invoked_by,
            persona_name=persona_name,
            started_at=start_time,
        )
        
        self.on_progress(f"🔧 Executing tool: {tool_name}")
        _log.info(f"Tool invocation {invocation_id}: {tool_name}({parameters}) by {invoked_by}")
        
        try:
            # 1. Validate tool exists
            tool_def = self.registry.get_tool(tool_name)
            if not tool_def:
                raise ValueError(f"Unknown tool: {tool_name}")
            
            handler = self.registry.get_handler(tool_name)
            if not handler:
                raise ValueError(f"No handler for tool: {tool_name}")
            
            # 2. Validate parameters against schema
            validated_params = self._validate_parameters(tool_def, parameters)
            
            # 3. Confirmation gate
            if tool_def.requires_confirmation and not skip_confirmation:
                confirmed = await self.confirmation_provider.confirm(
                    tool_name=tool_name,
                    parameters=validated_params,
                    side_effects=tool_def.side_effects,
                    description=tool_def.description,
                )
                invocation.confirmation_given = confirmed
                if not confirmed:
                    return ExecutionResult(
                        success=False,
                        error="User declined confirmation",
                        invocation_id=invocation_id,
                        duration_ms=int((time.monotonic() - start_time) * 1000),
                    )
            
            # 4. Execute with timeout
            exec_timeout = timeout or self.default_timeout
            result = await self._execute_with_timeout(
                handler, validated_params, exec_timeout
            )
            
            # 5. Normalize result
            normalized = self._normalize_result(result)
            
            invocation.success = True
            invocation.result = normalized
            invocation.completed_at = time.monotonic()
            
            self._log_invocation(invocation)
            
            self.on_progress(f"✅ {tool_name} completed in {invocation.duration_ms}ms")
            
            return ExecutionResult(
                success=True,
                result=normalized,
                invocation_id=invocation_id,
                duration_ms=invocation.duration_ms,
            )
            
        except Exception as e:
            _log.error(f"Tool {tool_name} failed: {e}", exc_info=True)
            invocation.success = False
            invocation.error = str(e)
            invocation.completed_at = time.monotonic()
            self._log_invocation(invocation)
            
            return ExecutionResult(
                success=False,
                error=str(e),
                invocation_id=invocation_id,
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )
    
    def _validate_parameters(self, tool_def: "ToolDefinition", parameters: dict) -> dict:
        """Validate and coerce parameters against tool schema."""
        validated = {}
        
        for param in tool_def.parameters:
            if param.name in parameters:
                value = parameters[param.name]
                validated[param.name] = self._coerce_value(value, param)
            elif param.required:
                raise ValueError(f"Missing required parameter: {param.name}")
            elif param.default is not None:
                validated[param.name] = param.default
        
        # Check for unknown parameters
        known_params = {p.name for p in tool_def.parameters}
        unknown = set(parameters.keys()) - known_params
        if unknown:
            _log.warning(f"Tool {tool_def.name} received unknown parameters: {unknown}")
        
        return validated
    
    def _coerce_value(self, value: Any, param: "ToolParameter") -> Any:
        """Coerce a value to the expected type."""
        if param.type == "string":
            return str(value)
        elif param.type == "integer":
            return int(value)
        elif param.type == "number":
            return float(value)
        elif param.type == "boolean":
            if isinstance(value, str):
                return value.lower() in ("true", "1", "yes", "on")
            return bool(value)
        elif param.type == "array":
            if isinstance(value, list):
                return value
            return [value]
        elif param.type == "object":
            if isinstance(value, dict):
                return value
            return {}
        return value
    
    async def _execute_with_timeout(
        self,
        handler: Callable,
        parameters: dict,
        timeout: float,
    ) -> Any:
        """Execute handler with timeout."""
        # Add root to parameters if handler expects it
        sig = inspect.signature(handler)
        if "root" in sig.parameters:
            parameters["root"] = self.root
        
        # Check if handler is async
        if inspect.iscoroutinefunction(handler):
            return await asyncio.wait_for(handler(**parameters), timeout=timeout)
        else:
            # Run sync handler in thread pool
            loop = asyncio.get_event_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(None, lambda: handler(**parameters)),
                timeout=timeout,
            )
    
    def _normalize_result(self, result: Any) -> dict:
        """Normalize tool result to a standard dict format."""
        if isinstance(result, dict):
            # Ensure success field
            if "success" not in result:
                result = {"success": True, "data": result}
            return result
        elif isinstance(result, (list, str, int, float, bool)):
            return {"success": True, "data": result}
        else:
            return {"success": True, "data": str(result)}
    
    def _log_invocation(self, invocation: ToolInvocation) -> None:
        """Log invocation to audit trail."""
        self.invocation_log.append(invocation)
        
        # Write to JSONL file
        try:
            log_entry = {
                "id": invocation.id,
                "tool": invocation.tool_name,
                "parameters": invocation.parameters,
                "invoked_by": invocation.invoked_by,
                "persona": invocation.persona_name,
                "timestamp": invocation.timestamp,
                "duration_ms": int((invocation.completed_at - invocation.started_at) * 1000),
                "success": invocation.success,
                "error": invocation.error,
                "confirmed": invocation.confirmation_given,
            }
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            _log.warning(f"Failed to write invocation log: {e}")
    
    def get_invocation_history(self, limit: int = 100) -> list[ToolInvocation]:
        """Get recent invocation history."""
        return self.invocation_log[-limit:]
    
    def get_tool_schemas(self, category: str = None) -> list[dict]:
        """Get JSON schemas for tools (for AI consumption)."""
        return self.registry.get_schemas(category)
    
    def list_available_tools(self, category: str = None) -> list[dict]:
        """List available tools with metadata."""
        tools = self.registry.list_tools(category)
        return [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "requires_confirmation": t.requires_confirmation,
                "side_effects": t.side_effects,
            }
            for t in tools
        ]


# Convenience function for synchronous execution (for non-async contexts)
def execute_tool_sync(
    root: Path,
    tool_name: str,
    parameters: dict,
    invoked_by: str = "cli",
    timeout: float = 120.0,
) -> ExecutionResult:
    """Synchronous tool execution for CLI use."""
    executor = ToolExecutor(root)
    
    # Run async executor in event loop
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(
        executor.execute(tool_name, parameters, invoked_by, timeout=timeout)
    )