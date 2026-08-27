"""
Patchi Orchestrator — The central brain that turns p chat into an orchestra.

The chat IS the brain. It uses LLM-powered reasoning to:
  1. Understand natural language requests (no keyword matching)
  2. Decide what tools/agents to use
  3. Execute them with full control
  4. Report results with context

The orchestrator gives the chat direct access to:
  - Read/write any file in the project
  - Run any CLI command
  - Spawn any agent (security, testing, fixing, etc.)
  - Access the full brain/memory state
  - Make decisions based on context
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

_log = logging.getLogger("patchi.ai.orchestrator")


# ── Pydantic Models ───────────────────────────────────────────────────

class ToolCall(BaseModel):
    """A single tool invocation with validated parameters."""
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    timeout_seconds: float = 120.0


class StepResult(BaseModel):
    """Result of executing a single step."""
    tool: str
    success: bool
    result: Any = None
    error: str | None = None
    duration_ms: int = 0
    output_summary: str = ""


class Plan(BaseModel):
    """A multi-step execution plan."""
    goal: str
    steps: list[ToolCall] = Field(default_factory=list)
    reasoning: str = ""  # LLM's reasoning for why these steps
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class PlanResult(BaseModel):
    """Complete result of executing a plan."""
    plan: Plan
    steps: list[StepResult] = Field(default_factory=list)
    success: bool = False
    total_duration_ms: int = 0
    findings_count: int = 0
    summary: str = ""


class IntentType(str, Enum):
    """Types of intent — but this is just for categorization, not routing."""
    CHAT = "chat"  # General conversation
    ACTION = "action"  # User wants to DO something
    QUESTION = "question"  # User wants to KNOW something
    COMPLEX = "complex"  # Multi-step task


class Intent(BaseModel):
    """Parsed user intent — determined by LLM, not keywords."""
    type: IntentType
    goal: str  # What the user wants to achieve
    needs_tools: bool = False  # Whether tools are needed
    needs_files: bool = False  # Whether file access is needed
    needs_agents: bool = False  # Whether agent spawning is needed
    context: dict[str, Any] = Field(default_factory=dict)  # Additional context


# ── Brain: The Core Intelligence ──────────────────────────────────────

class Brain:
    """
    The Brain — direct access to everything.

    This is what makes the chat the central orchestrator.
    It can read files, run commands, spawn agents, and make decisions.
    """

    def __init__(self, root: Path, on_progress: Callable[[str], None] | None = None):
        self.root = root
        self.on_progress = on_progress or (lambda _: None)

    # ── File Operations ───────────────────────────────────────────────

    def read_file(self, path: str) -> str:
        """Read a file's contents."""
        target = Path(path)
        if not target.is_absolute():
            target = self.root / target
        try:
            return target.read_text(encoding="utf-8")
        except Exception as e:
            return f"ERROR: Could not read {path}: {e}"

    def write_file(self, path: str, content: str) -> dict:
        """Write content to a file."""
        target = Path(path)
        if not target.is_absolute():
            target = self.root / target
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            return {"success": True, "path": str(target), "size": len(content)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_files(self, pattern: str = "**/*.py", max_files: int = 100) -> list[str]:
        """List files matching a pattern."""
        files = []
        for f in self.root.glob(pattern):
            if f.is_file() and ".patchi" not in str(f) and "node_modules" not in str(f):
                files.append(str(f.relative_to(self.root)))
                if len(files) >= max_files:
                    break
        return files

    # ── Command Execution ─────────────────────────────────────────────

    def run_command(self, command: str, timeout: int = 60) -> dict:
        """Run a shell command and return the result."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Command timed out after {timeout}s"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Agent Spawning ────────────────────────────────────────────────

    def spawn_agent(self, agent_type: str, **kwargs) -> dict:
        """Spawn a specialized agent for a specific task."""
        self.on_progress(f"Spawning {agent_type} agent...")

        try:
            if agent_type == "security":
                from patchi.core.security.orchestrator import SecurityOrchestrator
                orchestrator = SecurityOrchestrator(self.root)
                result = orchestrator.run()
                return {"success": True, "result": result}

            elif agent_type == "scanner":
                from patchi.core.scanner import scan_project
                result = scan_project(self.root)
                return {"success": True, "result": result}

            elif agent_type == "proactive":
                from patchi.core.brain.proactive import run_proactive
                files = kwargs.get("files", [])
                apply = kwargs.get("apply", False)
                result = run_proactive(self.root, files, apply=apply)
                return {"success": True, "result": result}

            elif agent_type == "council":
                from patchi.core.brain.council import Council

                async def _deliberate():
                    council = Council(self.root, on_progress=self.on_progress)
                    session = await council.deliberate(kwargs.get("goal", ""), {})
                    return {
                        "synthesis": session.synthesis,
                        "action_plan": [
                            {"tool": s.get("tool", ""), "params": s.get("parameters", {})}
                            for s in (session.action_plan or [])
                        ],
                        "consensus": session.consensus_reached,
                        "personas": [d.persona_name for d in (session.persona_decisions or [])],
                    }

                return asyncio.run(_deliberate())

            elif agent_type == "smart":
                from patchi.core.ai.smart import run_smart_agent
                result = run_smart_agent(
                    self.root,
                    kwargs.get("goal", ""),
                    max_steps=kwargs.get("max_steps", 6),
                )
                return {"success": True, "result": result}

            else:
                return {"success": False, "error": f"Unknown agent type: {agent_type}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Brain Access ──────────────────────────────────────────────────

    def get_brain_state(self) -> dict:
        """Get the current brain/memory state."""
        from patchi.core import memory as mem
        return mem.get_brain(self.root)

    def get_findings(self, severity: str | None = None) -> list[dict]:
        """Get security findings."""
        from patchi.core import memory as mem
        results = mem.get_scan_results(self.root)
        findings = []
        for agent_name, data in results.items():
            for f in data.get("findings", []):
                f["agent"] = agent_name
                if severity and f.get("severity") != severity:
                    continue
                findings.append(f)
        return findings

    def get_layers(self) -> dict:
        """Get the layered brain data."""
        from patchi.core import memory as mem
        return mem.get_layers(self.root)

    # ── Tool Execution ────────────────────────────────────────────────

    def execute_tool(self, tool_name: str, params: dict) -> StepResult:
        """Execute a tool via the ToolExecutor."""
        start = time.monotonic()
        self.on_progress(f"Executing {tool_name}...")

        try:
            from patchi.core.ai.tools.executor import ToolExecutor, CLIConfirmationProvider

            async def _run():
                executor = ToolExecutor(
                    self.root,
                    confirmation_provider=CLIConfirmationProvider(auto_confirm=True),
                    on_progress=self.on_progress,
                )
                return await executor.execute(tool_name, params, invoked_by="brain", skip_confirmation=True)

            result = asyncio.run(_run())
            duration = int((time.monotonic() - start) * 1000)

            return StepResult(
                tool=tool_name,
                success=getattr(result, "success", False),
                result=getattr(result, "result", None),
                error=getattr(result, "error", None),
                duration_ms=duration,
                output_summary=self._summarize(tool_name, getattr(result, "result", None)),
            )
        except Exception as e:
            duration = int((time.monotonic() - start) * 1000)
            return StepResult(
                tool=tool_name,
                success=False,
                error=str(e),
                duration_ms=duration,
                output_summary=f"ERROR: {e}",
            )

    def _summarize(self, tool: str, data: Any) -> str:
        """Summarize tool output for display."""
        if not isinstance(data, dict):
            return str(data)[:200] if data else "Done"

        if tool == "scan_vulnerabilities":
            sev = data.get("by_severity", {})
            return f"{data.get('agent_count', 0)} agents, {data.get('total_findings', 0)} findings (C={sev.get('critical', 0)} H={sev.get('high', 0)} M={sev.get('medium', 0)})"
        elif tool == "run_tests":
            return f"passed={data.get('passed', 0)} failed={data.get('failed', 0)}"
        elif tool == "attack_simulate":
            return f"{data.get('total_findings', 0)} offensive findings"
        elif tool == "stress_test":
            return f"{data.get('requests', 0)} reqs @ {data.get('rps', 0)} rps"
        elif tool == "analyze_project":
            return f"{data.get('file_count', 0)} files, {data.get('route_count', 0)} routes"
        elif tool == "write_file":
            return f"Wrote {data.get('size', 0)} bytes to {data.get('path', '?')}"
        return (data.get("message") or data.get("error") or str(data))[:200]


# ── LLM-Powered Intent Parser ─────────────────────────────────────────

def parse_intent_llm(message: str, brain: Brain, config: dict) -> Intent:
    """
    Use the LLM to parse natural language into structured intent.

    This is NOT keyword matching — the LLM understands context and nuance.
    """
    from patchi.core.ai.client import call_ai

    # Get brain context for the LLM
    brain_state = brain.get_brain_state()
    findings = brain.get_findings()[:10]  # Top 10 findings
    files = brain.list_files(max_files=20)

    # Build the parsing prompt
    system_prompt = """You are Patchi's intent parser. Analyze the user's message and determine:

1. intent_type: "chat" (general conversation), "action" (user wants to DO something), "question" (user wants to KNOW something), or "complex" (multi-step task)
2. goal: What the user wants to achieve (one sentence)
3. needs_tools: Whether tool execution is needed (scan, test, fix, etc.)
4. needs_files: Whether file reading/writing is needed
5. needs_agents: Whether agent spawning is needed (security, council, etc.)
6. context: Any relevant context (file paths, severity, etc.)

Respond with ONLY a JSON object, no other text."""

    user_prompt = f"""User message: "{message}"

Project context:
- {len(files)} files in project
- {len(findings)} security findings
- Brain state available

Respond with JSON:
{{
  "intent_type": "action|question|chat|complex",
  "goal": "what the user wants",
  "needs_tools": true/false,
  "needs_files": true/false,
  "needs_agents": true/false,
  "context": {{}}
}}"""

    response = call_ai(config, system_prompt, user_prompt)

    if not response:
        # Fallback to keyword-based parsing if LLM unavailable
        return _parse_intent_fallback(message)

    try:
        # Parse LLM response
        # Handle markdown code blocks
        cleaned = response.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1])
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]

        data = json.loads(cleaned)
        return Intent(
            type=IntentType(data.get("intent_type", "chat")),
            goal=data.get("goal", message),
            needs_tools=data.get("needs_tools", False),
            needs_files=data.get("needs_files", False),
            needs_agents=data.get("needs_agents", False),
            context=data.get("context", {}),
        )
    except Exception as e:
        _log.info("LLM intent parsing failed: %s, using fallback", e)
        return _parse_intent_fallback(message)


def _parse_intent_fallback(message: str) -> Intent:
    """Simple fallback intent parsing when LLM is unavailable."""
    msg = message.lower().strip()

    # Action words
    action_words = ["scan", "test", "fix", "run", "execute", "build", "create", "write", "generate", "attack", "stress"]
    is_action = any(w in msg for w in action_words)

    # Question words
    question_words = ["what", "how", "why", "where", "which", "who", "when", "is", "are", "does", "do"]
    is_question = any(msg.startswith(w) for w in question_words)

    # Multi-step indicators
    multi_step_words = ["and then", "also", "plus", "after that", "first.*then"]
    is_complex = any(w in msg for w in multi_step_words)

    if is_complex:
        return Intent(type=IntentType.COMPLEX, goal=message, needs_tools=True)
    elif is_action:
        return Intent(type=IntentType.ACTION, goal=message, needs_tools=True)
    elif is_question:
        return Intent(type=IntentType.QUESTION, goal=message, needs_files=True)
    else:
        return Intent(type=IntentType.CHAT, goal=message)


# ── LLM-Powered Planner ───────────────────────────────────────────────

def plan_with_llm(intent: Intent, brain: Brain, config: dict) -> Plan:
    """
    Use the LLM to create an execution plan.

    The LLM decides which tools to use based on the intent and context.
    """
    from patchi.core.ai.client import call_ai

    # Get available tools
    try:
        from patchi.core.ai.tools.registry import get_tool_registry
        registry = get_tool_registry()
        tools = [t.name for t in registry.list_tools()]
    except Exception:
        tools = []

    # Get brain context
    brain_state = brain.get_brain_state()
    findings = brain.get_findings()[:5]

    system_prompt = f"""You are Patchi's planner. Given a user goal, create an execution plan.

Available tools: {', '.join(tools)}

For each step, specify:
- tool: tool name from the available list
- params: parameters for the tool
- reason: why this step is needed

Respond with ONLY a JSON object:
{{
  "reasoning": "why these steps achieve the goal",
  "steps": [
    {{"tool": "tool_name", "params": {{}}, "reason": "why"}}
  ]
}}"""

    user_prompt = f"""Goal: {intent.goal}

Context:
- {len(findings)} security findings
- Brain state: {json.dumps(brain_state, default=str)[:500]}

Create a plan to achieve this goal."""

    response = call_ai(config, system_prompt, user_prompt)

    if not response:
        # Fallback to default plan
        return _plan_fallback(intent)

    try:
        cleaned = response.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1])
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]

        data = json.loads(cleaned)
        steps = [
            ToolCall(
                tool=s["tool"],
                params=s.get("params", {}),
                reason=s.get("reason", ""),
            )
            for s in data.get("steps", [])
            if s.get("tool") in tools  # Only valid tools
        ]
        return Plan(
            goal=intent.goal,
            steps=steps,
            reasoning=data.get("reasoning", ""),
        )
    except Exception as e:
        _log.info("LLM planning failed: %s, using fallback", e)
        return _plan_fallback(intent)


def _plan_fallback(intent: Intent) -> Plan:
    """Simple fallback plan when LLM is unavailable."""
    steps = []

    if intent.needs_tools:
        # Default to scan + test
        steps.append(ToolCall(tool="scan_vulnerabilities", params={"domains": None}, reason="Security scan"))
        steps.append(ToolCall(tool="run_tests", params={"test_types": ["unit"]}, reason="Run tests"))

    if intent.needs_files:
        # Just analyze the project
        steps.append(ToolCall(tool="analyze_project", params={}, reason="Analyze project"))

    if not steps:
        steps.append(ToolCall(tool="analyze_project", params={}, reason="Analyze project"))

    return Plan(goal=intent.goal, steps=steps, reasoning="Fallback plan")


# ── Orchestrator ───────────────────────────────────────────────────────

class Orchestrator:
    """
    The central brain of Patchi.

    The chat IS the orchestrator. It uses LLM reasoning to understand
    requests and has direct control over everything.
    """

    def __init__(
        self,
        root: Path,
        on_progress: Callable[[str], None] | None = None,
        on_event: Callable[[dict], None] | None = None,
    ):
        self.root = root
        self.on_progress = on_progress or (lambda _: None)
        self.on_event = on_event or (lambda _: None)
        self.brain = Brain(root, on_progress=on_progress)
        self._config: dict | None = None

    @property
    def config(self) -> dict:
        """Lazy-load config."""
        if self._config is None:
            from patchi.core import config as cfg
            self._config = cfg.load(self.root)
        return self._config

    async def run(self, message: str, max_steps: int = 10) -> PlanResult:
        """
        Process a natural language message using LLM-powered reasoning.

        This is the main entry point. The LLM decides:
        1. What the user wants (intent parsing)
        2. What tools to use (planning)
        3. How to execute them (orchestration)
        """
        start = time.monotonic()

        # Step 1: Parse intent with LLM
        self.on_progress("Understanding your request...")
        intent = parse_intent_llm(message, self.brain, self.config)

        # Step 2: Plan with LLM
        self.on_progress("Planning execution...")
        plan = plan_with_llm(intent, self.brain, self.config)
        plan.steps = plan.steps[:max_steps]

        self.on_event({
            "event": "orchestrator.planned",
            "data": {
                "goal": intent.goal,
                "steps": len(plan.steps),
                "reasoning": plan.reasoning,
            },
        })

        # Step 3: Execute plan
        plan_result = PlanResult(plan=plan)
        for i, step in enumerate(plan.steps):
            self.on_progress(f"Step {i+1}/{len(plan.steps)}: {step.tool}")
            result = self.brain.execute_tool(step.tool, step.params)
            plan_result.steps.append(result)

            if result.tool == "scan_vulnerabilities" and result.result:
                plan_result.findings_count += int(result.result.get("total_findings", 0) or 0)

        # Step 4: Summarize
        plan_result.total_duration_ms = int((time.monotonic() - start) * 1000)
        successes = sum(1 for s in plan_result.steps if s.success)
        plan_result.success = successes == len(plan_result.steps)
        plan_result.summary = f"{successes}/{len(plan_result.steps)} steps succeeded"

        self.on_event({
            "event": "orchestrator.completed",
            "data": {
                "goal": intent.goal,
                "steps": len(plan_result.steps),
                "success": plan_result.success,
                "findings": plan_result.findings_count,
            },
        })

        return plan_result

    def read_file(self, path: str) -> str:
        """Direct file access from chat."""
        return self.brain.read_file(path)

    def write_file(self, path: str, content: str) -> dict:
        """Direct file writing from chat."""
        return self.brain.write_file(path, content)

    def run_command(self, command: str, timeout: int = 60) -> dict:
        """Direct command execution from chat."""
        return self.brain.run_command(command, timeout)

    def spawn_agent(self, agent_type: str, **kwargs) -> dict:
        """Direct agent spawning from chat."""
        return self.brain.spawn_agent(agent_type, **kwargs)

    def get_findings(self, severity: str | None = None) -> list[dict]:
        """Get security findings."""
        return self.brain.get_findings(severity)

    def get_brain_state(self) -> dict:
        """Get brain state."""
        return self.brain.get_brain_state()

    def get_tools(self) -> list[dict]:
        """Get all available tools."""
        try:
            from patchi.core.ai.tools.registry import get_tool_registry
            registry = get_tool_registry()
            return [t.to_schema() for t in registry.list_tools()]
        except Exception:
            return []
