"""
Base Persona Class — Foundation for all Council personas.

Each persona is a specialized AI agent with:
- Unique system prompt defining expertise and perspective
- Tool access permissions (which tools it can call)
- Decision-making style (cautious, aggressive, balanced, etc.)
- Memory of past decisions for learning
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from patchi.core.ai.client import call_ai_structured
from patchi.core.ai.prompts import Skill, get_system_prompt
from patchi.core.brain.layered_brain import Layer

_log = logging.getLogger("patchi.brain.personas")


class PersonaStyle(Enum):
    """Decision-making style of the persona."""
    CAUTIOUS = "cautious"          # Prefers safe, proven approaches
    AGGRESSIVE = "aggressive"      # Pushes boundaries, finds edge cases
    BALANCED = "balanced"          # Weighs tradeoffs carefully
    INNOVATIVE = "innovative"      # Seeks novel solutions
    PRAGMATIC = "pragmatic"        # Focuses on practical outcomes


@dataclass
class PersonaDecision:
    """A single decision from a persona."""
    persona_name: str
    issue: str
    analysis: str
    recommendation: str
    confidence: float  # 0.0 - 1.0
    tools_needed: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reasoning_trace: list[str] = field(default_factory=list)


@dataclass
class PersonaMemory:
    """Long-term memory for a persona."""
    decisions: list[PersonaDecision] = field(default_factory=list)
    patterns_learned: dict[str, Any] = field(default_factory=dict)
    success_rates: dict[str, float] = field(default_factory=dict)
    last_updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BasePersona(ABC):
    """
    Abstract base class for all Council personas.
    
    Each persona must implement:
    - analyze(): Core analysis logic
    - get_tool_permissions(): Which tools this persona can call
    - get_style(): Decision-making style
    """

    def __init__(
        self,
        name: str,
        root: Path,
        brain_layers: dict[str, Layer],
        project_context: dict,
        config: dict,
        on_progress: Optional[Callable[[str], None]] = None,
    ):
        self.name = name
        self.root = root
        self.layers = brain_layers
        self.project_context = project_context
        self.config = config
        self.on_progress = on_progress or (lambda _: None)
        self.memory = self._load_memory()
        self._decision_count = 0

    @abstractmethod
    def get_expertise_areas(self) -> list[str]:
        """Return list of domains this persona specializes in."""
        pass

    @abstractmethod
    def get_style(self) -> PersonaStyle:
        """Return the persona's decision-making style."""
        pass

    @abstractmethod
    def get_system_prompt_additions(self) -> str:
        """Additional system prompt content specific to this persona."""
        pass

    def get_tool_permissions(self) -> list[str]:
        """Return list of tool names this persona is allowed to call."""
        # Default: all tools. Override to restrict.
        return ["*"]

    def _load_memory(self) -> PersonaMemory:
        """Load persona memory from disk."""
        mem_path = self.root / ".patchi" / "memory" / f"persona_{self.name.lower()}.json"
        if mem_path.exists():
            try:
                data = json.loads(mem_path.read_text(encoding="utf-8"))
                return PersonaMemory(
                    decisions=[PersonaDecision(**d) for d in data.get("decisions", [])],
                    patterns_learned=data.get("patterns_learned", {}),
                    success_rates=data.get("success_rates", {}),
                    last_updated=data.get("last_updated", ""),
                )
            except Exception as e:
                _log.warning(f"Failed to load memory for {self.name}: {e}")
        return PersonaMemory()

    def _save_memory(self) -> None:
        """Save persona memory to disk."""
        mem_path = self.root / ".patchi" / "memory" / f"persona_{self.name.lower()}.json"
        mem_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "decisions": [d.__dict__ for d in self.memory.decisions[-100:]],  # Keep last 100
            "patterns_learned": self.memory.patterns_learned,
            "success_rates": self.memory.success_rates,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
        try:
            mem_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            _log.warning(f"Failed to save memory for {self.name}: {e}")

    def _build_context(self, issue: str, additional_context: dict = None) -> str:
        """Build context string for AI analysis."""
        ctx_parts = [
            "=== PROJECT CONTEXT ===",
            f"Project: {self.project_context.get('project_purpose', 'Unknown')}",
            f"Domain: {self.project_context.get('project_domain', 'Unknown')}",
            f"Frameworks: {', '.join(f.get('name', '') for f in self.project_context.get('frameworks', []))}",
            f"Active Security Domains: {', '.join(self.project_context.get('active_security_domains', []))}",
            "",
            "=== LAYERED BRAIN SUMMARY ===",
        ]

        # Add relevant layer summaries
        for layer_name, layer in self.layers.items():
            if layer.level <= 2:  # Project and subsystem levels
                ctx_parts.append(f"[{layer.name}] {layer.summary}")

        if additional_context:
            ctx_parts.append("\n=== ADDITIONAL CONTEXT ===")
            ctx_parts.append(json.dumps(additional_context, indent=2))

        ctx_parts.append("\n=== CURRENT ISSUE ===")
        ctx_parts.append(issue)

        return "\n".join(ctx_parts)

    def _call_ai_with_persona(
        self,
        prompt: str,
        system_prompt: str = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
    ) -> dict | None:
        """Call AI with persona-specific system prompt."""
        if system_prompt is None:
            base_prompt = get_system_prompt(Skill.DEEP_ANALYSIS)
            system_prompt = f"{base_prompt}\n\n{self.get_system_prompt_additions()}"

        try:
            result = call_ai_structured(
                config=self.config,
                system_prompt=system_prompt,
                user_prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return result
        except Exception as e:
            _log.warning(f"{self.name} AI call failed: {e}")
            return None

    def analyze(self, issue: str, context: dict = None) -> PersonaDecision:
        """
        Analyze an issue and produce a decision.
        
        This is the main entry point called by the Council.
        """
        self._decision_count += 1
        self.on_progress(f"[{self.name}] Analyzing: {issue[:80]}...")

        # Build context
        full_context = self._build_context(issue, context)

        # Create analysis prompt
        analysis_prompt = f"""
Analyze the following issue from your perspective as {self.name}.

Your expertise: {', '.join(self.get_expertise_areas())}
Your style: {self.get_style().value}

Issue: {issue}

Provide your analysis in this JSON format:
{{
    "analysis": "Your detailed analysis of the issue",
    "recommendation": "Your specific recommendation for action",
    "confidence": 0.85,
    "tools_needed": ["tool1", "tool2"],
    "risks": ["risk1", "risk2"],
    "reasoning_trace": ["step 1", "step 2", "step 3"]
}}
"""

        result = self._call_ai_with_persona(analysis_prompt, max_tokens=3000)

        if result:
            decision = PersonaDecision(
                persona_name=self.name,
                issue=issue,
                analysis=result.get("analysis", ""),
                recommendation=result.get("recommendation", ""),
                confidence=float(result.get("confidence", 0.5)),
                tools_needed=result.get("tools_needed", []),
                risks=result.get("risks", []),
                reasoning_trace=result.get("reasoning_trace", []),
            )
        else:
            # Fallback heuristic decision
            decision = self._heuristic_decision(issue, context)

        # Store in memory
        self.memory.decisions.append(decision)
        self._save_memory()

        self.on_progress(f"[{self.name}] Decision: {decision.recommendation[:80]}... (confidence: {decision.confidence:.0%})")
        return decision

    def _heuristic_decision(self, issue: str, context: dict = None) -> PersonaDecision:
        """Fallback heuristic decision when AI is unavailable."""
        return PersonaDecision(
            persona_name=self.name,
            issue=issue,
            analysis=f"Heuristic analysis for: {issue}",
            recommendation="Run standard scan and review findings manually",
            confidence=0.4,
            tools_needed=["scan_project"],
            risks=["AI unavailable - limited analysis"],
            reasoning_trace=["AI call failed, using fallback"],
        )

    def record_outcome(self, decision: PersonaDecision, success: bool, details: str = "") -> None:
        """Record the outcome of a decision for learning."""
        key = decision.issue[:50]
        current = self.memory.success_rates.get(key, 0.5)
        # Exponential moving average
        self.memory.success_rates[key] = current * 0.7 + (1.0 if success else 0.0) * 0.3
        self.memory.patterns_learned[key] = {
            "last_outcome": "success" if success else "failure",
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._save_memory()

    def get_relevant_context(self, issue: str) -> dict:
        """Extract relevant context from brain layers for this issue."""
        # Use reasoning engine to find relevant layers
        from patchi.core.brain.reasoning import ReasoningEngine

        engine = ReasoningEngine(self.root)
        relevant = {}

        # Find layers matching issue keywords
        issue_lower = issue.lower()
        for name, layer in self.layers.items():
            layer_text = f"{name} {layer.summary} {layer.purpose}".lower()
            # Simple keyword matching
            if any(word in layer_text for word in issue_lower.split() if len(word) > 3):
                relevant[name] = {
                    "level": layer.level,
                    "summary": layer.summary,
                    "purpose": layer.purpose,
                    "depends_on": layer.depends_on,
                    "dependents": layer.dependents,
                }

        return relevant


# ── Persona Registry ────────────────────────────────────────────────────────────

PERSONA_REGISTRY: dict[str, type[BasePersona]] = {}


def register_persona(cls: type[BasePersona]) -> type[BasePersona]:
    """Decorator to register a persona class."""
    PERSONA_REGISTRY[cls.__name__] = cls
    return cls


def get_persona_class(name: str) -> type[BasePersona] | None:
    """Get a persona class by name."""
    return PERSONA_REGISTRY.get(name)


def list_personas() -> list[str]:
    """List all registered persona names."""
    return list(PERSONA_REGISTRY.keys())


def create_persona(
    name: str,
    root: Path,
    brain_layers: dict[str, Layer],
    project_context: dict,
    config: dict,
    on_progress: Callable[[str], None] = None,
) -> BasePersona | None:
    """Factory function to create a persona instance."""
    cls = get_persona_class(name)
    if cls is None:
        _log.warning(f"Unknown persona: {name}")
        return None
    try:
        return cls(
            name=name,
            root=root,
            brain_layers=brain_layers,
            project_context=project_context,
            config=config,
            on_progress=on_progress,
        )
    except Exception as e:
        _log.error(f"Failed to create persona {name}: {e}")
        return None
