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
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchi.core.ai.tools.registry import get_tool_registry

_log = logging.getLogger("patchi.ai.tool_executor")


@dataclass
class ToolInvocation:
    """A single tool invocation record for audit logging."""

    id: str
    tool_name: str
    parameters: dict
    invoked_by: str  # "council", "persona", "cli", "user"
    persona_name: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    started_at: float = 0
    completed_at: float = 0
    success: bool = False
    result: dict | None = None
    error: str | None = None
    confirmation_given: bool = False

    @property
    def duration_ms(self) -> int:
        """Wall-clock duration of the invocation in milliseconds."""
        if not self.completed_at:
            return 0
        return int((self.completed_at - self.started_at) * 1000)


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

    async def confirm(
        self, tool_name: str, parameters: dict, side_effects: str, description: str
    ) -> bool:
        """Return True if user confirms, False otherwise."""
        raise NotImplementedError


class CLIConfirmationProvider(ConfirmationProvider):
    """CLI-based confirmation using rich prompts."""

    def __init__(self, auto_confirm: bool = False):
        self.auto_confirm = auto_confirm

    async def confirm(
        self, tool_name: str, parameters: dict, side_effects: str, description: str
    ) -> bool:
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
            if side_effects:
                pass
            response = input("  Proceed? (y/N): ").strip().lower()
            return response in ("y", "yes")


@dataclass
class StateSnapshot:
    """Snapshot of file system state for rollback."""

    id: str
    files: dict[str, bytes] = field(default_factory=dict)  # path -> content
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


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
    - State snapshots and rollback on failure
    - Tool chain execution with automatic rollback
    """

    def __init__(
        self,
        root: Path,
        confirmation_provider: ConfirmationProvider | None = None,
        default_timeout: float = 120.0,
        on_progress: Callable[[str], None] | None = None,
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

        # Rollback state
        self._snapshots: dict[str, StateSnapshot] = {}
        self._snapshot_dir = root / ".patchi" / "snapshots"
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)

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

        self.on_progress(f"[EXEC] Executing tool: {tool_name}")
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
            result = await self._execute_with_timeout(handler, validated_params, exec_timeout)

            # 5. Normalize result
            normalized = self._normalize_result(result)

            invocation.success = True
            invocation.result = normalized
            invocation.completed_at = time.monotonic()

            self._log_invocation(invocation)

            self.on_progress(f"[OK] {tool_name} completed in {invocation.duration_ms}ms")

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

    def _validate_parameters(self, tool_def: ToolDefinition, parameters: dict) -> dict:
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

    def _coerce_value(self, value: Any, param: ToolParameter) -> Any:
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
            if value is None:
                return None
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
            # Run sync handlers directly in the event loop's thread.
            #
            # We deliberately do NOT use loop.run_in_executor here: many security
            # agents call signal.signal() / rely on main-thread-only behavior, and
            # tools like scan_vulnerabilities spawn their own thread pools — both
            # break or deadlock when the handler runs in a worker thread (every
            # agent raises -> the scan reports 0 findings). The agent loop is
            # single-purpose, so blocking it briefly is acceptable; per-tool
            # internal timeouts (e.g. realize's PATCHI_AGENT_TIMEOUT) still bound
            # any individual tool that would otherwise hang.
            return handler(**parameters)

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

    # ── Snapshot & Rollback ─────────────────────────────────────────────────

    def create_snapshot(self, description: str = "") -> str:
        """Create a snapshot of files that might be modified.

        Snapshots key project files (config, source, etc.) so they can be
        restored if a tool chain fails.

        Returns:
            Snapshot ID for later rollback.
        """
        snapshot_id = str(uuid.uuid4())[:8]
        files: dict[str, bytes] = {}

        # Snapshot common tool targets
        patterns = [
            "**/*.py",
            "**/*.yaml",
            "**/*.yml",
            "**/*.json",
            "**/*.toml",
            "**/*.cfg",
            "**/*.ini",
        ]

        for pattern in patterns:
            for path in self.root.glob(pattern):
                # Skip .patchi, .git, __pycache__, node_modules, venv
                rel = path.relative_to(self.root)
                parts = rel.parts
                if any(
                    p.startswith(".") or p in ("__pycache__", "node_modules", ".venv", "venv")
                    for p in parts
                ):
                    continue
                try:
                    content = path.read_bytes()
                    # Only snapshot small files (< 100KB)
                    if len(content) < 100_000:
                        files[str(rel)] = content
                except Exception:
                    pass

        snapshot = StateSnapshot(id=snapshot_id, files=files)
        self._snapshots[snapshot_id] = snapshot

        # Persist to disk for cross-session rollback
        snapshot_path = self._snapshot_dir / f"{snapshot_id}.json"
        try:
            import base64

            data = {
                "id": snapshot_id,
                "description": description,
                "created_at": snapshot.created_at,
                "files": {k: base64.b64encode(v).decode() for k, v in files.items()},
            }
            snapshot_path.write_text(json.dumps(data), encoding="utf-8")
        except Exception as e:
            _log.warning(f"Failed to persist snapshot: {e}")

        self.on_progress(f"[SNAP] Snapshot {snapshot_id} created ({len(files)} files)")
        return snapshot_id

    def rollback(self, snapshot_id: str) -> bool:
        """Restore files from a snapshot.

        Returns:
            True if rollback succeeded.
        """
        snapshot = self._snapshots.get(snapshot_id)
        if not snapshot:
            # Try loading from disk
            snapshot = self._load_snapshot(snapshot_id)

        if not snapshot:
            _log.error(f"Snapshot {snapshot_id} not found")
            return False

        restored = 0
        for rel_path, content in snapshot.files.items():
            full_path = self.root / rel_path
            try:
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_bytes(content)
                restored += 1
            except Exception as e:
                _log.warning(f"Failed to restore {rel_path}: {e}")

        self.on_progress(f"↩️ Rollback {snapshot_id} restored {restored} files")
        _log.info(f"Rollback {snapshot_id}: restored {restored}/{len(snapshot.files)} files")
        return True

    def _load_snapshot(self, snapshot_id: str) -> StateSnapshot | None:
        """Load a snapshot from disk."""
        snapshot_path = self._snapshot_dir / f"{snapshot_id}.json"
        if not snapshot_path.exists():
            return None

        try:
            import base64

            data = json.loads(snapshot_path.read_text(encoding="utf-8"))
            files = {k: base64.b64decode(v) for k, v in data["files"].items()}
            return StateSnapshot(
                id=data["id"],
                files=files,
                created_at=data["created_at"],
            )
        except Exception as e:
            _log.warning(f"Failed to load snapshot {snapshot_id}: {e}")
            return None

    async def execute_with_rollback(
        self,
        tool_name: str,
        parameters: dict,
        invoked_by: str = "user",
        persona_name: str | None = None,
    ) -> ExecutionResult:
        """Execute a tool with automatic snapshot and rollback on failure.

        Creates a state snapshot before execution, and rolls back if the
        tool fails.
        """
        # Create snapshot before execution
        snapshot_id = self.create_snapshot(f"pre-{tool_name}")

        # Execute the tool
        result = await self.execute(tool_name, parameters, invoked_by, persona_name)

        # Rollback on failure
        if not result.success:
            self.on_progress(f"⚠️ {tool_name} failed, rolling back...")
            self.rollback(snapshot_id)
        else:
            # Clean up old snapshot on success
            self._cleanup_snapshot(snapshot_id)

        return result

    def _cleanup_snapshot(self, snapshot_id: str) -> None:
        """Remove a snapshot after successful use."""
        self._snapshots.pop(snapshot_id, None)
        snapshot_path = self._snapshot_dir / f"{snapshot_id}.json"
        try:
            snapshot_path.unlink(missing_ok=True)
        except Exception:
            pass

    async def execute_chain(
        self,
        steps: list[dict],
        invoked_by: str = "user",
        stop_on_failure: bool = True,
    ) -> list[ExecutionResult]:
        """Execute a chain of tools with rollback on failure.

        Args:
            steps: List of {"tool": name, "parameters": {...}} dicts
            invoked_by: Who is invoking the chain
            stop_on_failure: If True, stop and rollback on first failure

        Returns:
            List of ExecutionResult for each step
        """
        results = []
        snapshot_id = self.create_snapshot("chain-pre-execution")

        for i, step in enumerate(steps):
            tool_name = step.get("tool")
            parameters = step.get("parameters", {})

            self.on_progress(f"[CHAIN] Chain step {i + 1}/{len(steps)}: {tool_name}")

            result = await self.execute(tool_name, parameters, invoked_by)
            results.append(result)

            if not result.success and stop_on_failure:
                self.on_progress(f"[FAIL] Chain failed at step {i + 1}, rolling back...")
                self.rollback(snapshot_id)
                # Mark remaining steps as skipped
                for _j in range(i + 1, len(steps)):
                    results.append(
                        ExecutionResult(
                            success=False,
                            error=f"Skipped: chain stopped at step {i + 1}",
                        )
                    )
                break

        # Clean up snapshot if chain succeeded
        all_success = all(r.success for r in results)
        if all_success:
            self._cleanup_snapshot(snapshot_id)

        return results


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
