"""
Cost-Aware Model Router — Selects the best AI model based on task requirements.

Routes requests to the optimal model considering:
- Task complexity (simple → cheap model, complex → expensive model)
- Budget constraints (hard limit, soft warning)
- Quality requirements (accuracy vs speed tradeoff)
- Model availability (fallback chain)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from patchi.core.ai import cost_tracker

_log = logging.getLogger("patchi.ai.model_router")


@dataclass
class ModelProfile:
    """Profile for an AI model with cost and quality metrics."""
    name: str
    provider: str  # "openai", "anthropic", "local", "ollama"
    cost_per_1k_input: float
    cost_per_1k_output: float
    quality_score: float  # 0-1, relative quality
    speed_score: float  # 0-1, relative speed
    max_tokens: int = 4096
    supports_tools: bool = False
    supports_vision: bool = False
    available: bool = True


# ── Model Profiles ───────────────────────────────────────────────────────────

MODEL_PROFILES: dict[str, ModelProfile] = {
    # OpenAI
    "gpt-4o-mini": ModelProfile(
        name="gpt-4o-mini", provider="openai",
        cost_per_1k_input=0.00015, cost_per_1k_output=0.00060,
        quality_score=0.7, speed_score=0.9, max_tokens=16384,
        supports_tools=True,
    ),
    "gpt-4o": ModelProfile(
        name="gpt-4o", provider="openai",
        cost_per_1k_input=0.00250, cost_per_1k_output=0.01000,
        quality_score=0.95, speed_score=0.7, max_tokens=16384,
        supports_tools=True, supports_vision=True,
    ),
    "gpt-4o-mini-ft": ModelProfile(
        name="gpt-4o-mini", provider="openai",
        cost_per_1k_input=0.00015, cost_per_1k_output=0.00060,
        quality_score=0.75, speed_score=0.9, max_tokens=16384,
        supports_tools=True,
    ),
    # Anthropic
    "claude-haiku": ModelProfile(
        name="claude-3-5-haiku-20241022", provider="anthropic",
        cost_per_1k_input=0.00025, cost_per_1k_output=0.00125,
        quality_score=0.75, speed_score=0.95, max_tokens=8192,
    ),
    "claude-sonnet": ModelProfile(
        name="claude-sonnet-4-20250514", provider="anthropic",
        cost_per_1k_input=0.00300, cost_per_1k_output=0.01500,
        quality_score=0.92, speed_score=0.6, max_tokens=8192,
    ),
    # Local / Ollama
    "llama3-8b": ModelProfile(
        name="llama3:8b", provider="local",
        cost_per_1k_input=0.0, cost_per_1k_output=0.0,
        quality_score=0.5, speed_score=0.8, max_tokens=4096,
    ),
    "mistral-small": ModelProfile(
        name="mistral-small", provider="local",
        cost_per_1k_input=0.0, cost_per_1k_output=0.0,
        quality_score=0.55, speed_score=0.85, max_tokens=4096,
    ),
}


# ── Task Complexity Levels ───────────────────────────────────────────────────

class TaskComplexity:
    """Task complexity classification for model routing."""
    SIMPLE = "simple"      # Formatting, summaries, simple Q&A
    MODERATE = "moderate"  # Code analysis, explanations, refactoring suggestions
    COMPLEX = "complex"    # Security analysis, architecture decisions, multi-step reasoning
    CRITICAL = "critical"  # Fix generation, exploit analysis, production decisions


# ── Model Router ─────────────────────────────────────────────────────────────

class ModelRouter:
    """Routes AI requests to the optimal model based on cost and requirements."""

    def __init__(self, config: dict | None = None, root: Path | None = None):
        self.config = config or {}
        self._root = root
        self._budget_limit = self.config.get("ai", {}).get("cost_limit", 0)
        self._prefer_local = self.config.get("ai", {}).get("prefer_local", False)
        self._default_model = self.config.get("ai", {}).get("default_model", "gpt-4o-mini")
        self._profiler_cache: dict[str, dict] | None = None

    def select_model(
        self,
        complexity: str = TaskComplexity.MODERATE,
        require_tools: bool = False,
        require_vision: bool = False,
        max_cost_per_1k: float | None = None,
    ) -> str:
        """Select the best model for the given requirements.

        Args:
            complexity: Task complexity level
            require_tools: Whether the model needs function calling
            require_vision: Whether the model needs vision capabilities
            max_cost_per_1k: Maximum cost per 1k tokens (input + output averaged)

        Returns:
            Model name string
        """
        # Check budget first
        budget_msg = cost_tracker.check_budget(self.config)
        if budget_msg:
            _log.warning("Budget constraint: %s — using cheapest model", budget_msg)
            return self._cheapest_available(require_tools, require_vision)

        # Filter by requirements
        candidates = []
        for name, profile in MODEL_PROFILES.items():
            if not profile.available:
                continue
            if require_tools and not profile.supports_tools:
                continue
            if require_vision and not profile.supports_vision:
                continue
            if max_cost_per_1k is not None:
                avg_cost = (profile.cost_per_1k_input + profile.cost_per_1k_output) / 2
                if avg_cost > max_cost_per_1k:
                    continue
            candidates.append((name, profile))

        if not candidates:
            # Fallback to default
            return self._default_model

        # Score each candidate based on complexity
        scored = []
        for name, profile in candidates:
            score = self._score_model(profile, complexity)
            scored.append((score, name))

        # Sort by score descending
        scored.sort(reverse=True)

        selected = scored[0][1]
        _log.info(
            "Model router: selected %s for complexity=%s (score=%.2f)",
            selected, complexity, scored[0][0],
        )
        return selected

    def _load_profiler_stats(self) -> dict[str, dict]:
        """Load and aggregate profiler data per model."""
        if self._profiler_cache is not None:
            return self._profiler_cache
        if not self._root:
            self._profiler_cache = {}
            return self._profiler_cache
        try:
            from patchi.core.ai.agent_profiler import get_all_profiles
            profiles = get_all_profiles(self._root)
            if not profiles:
                self._profiler_cache = {}
                return self._profiler_cache
            model_stats: dict[str, dict] = {}
            for agent_name, profile in profiles.items():
                if profile.run_count == 0 or not profile.most_used_model:
                    continue
                m = profile.most_used_model
                if m not in model_stats:
                    model_stats[m] = {"accuracy": [], "p95_ms": [], "cost": 0.0, "runs": 0}
                if profile.run_count >= 3:
                    model_stats[m]["accuracy"].append(profile.accuracy)
                model_stats[m]["p95_ms"].append(profile.p95_wall_ms)
                model_stats[m]["cost"] += profile.total_cost_usd
                model_stats[m]["runs"] += profile.run_count
            result = {}
            for m, s in model_stats.items():
                accs = s["accuracy"]
                p95s = s["p95_ms"]
                result[m] = {
                    "accuracy": sum(accs) / len(accs) if accs else 0.5,
                    "avg_p95_ms": sum(p95s) / len(p95s) if p95s else 0,
                    "total_cost": s["cost"],
                    "total_runs": s["runs"],
                }
            self._profiler_cache = result
        except Exception as exc:
            _log.debug("Profiler load failed: %s", exc)
            self._profiler_cache = {}
        return self._profiler_cache

    def _score_model(self, profile: ModelProfile, complexity: str) -> float:
        """Score a model based on complexity + historical profiler data."""
        weights = {
            TaskComplexity.SIMPLE: {"cost": 0.6, "quality": 0.2, "speed": 0.2},
            TaskComplexity.MODERATE: {"cost": 0.3, "quality": 0.5, "speed": 0.2},
            TaskComplexity.COMPLEX: {"cost": 0.1, "quality": 0.8, "speed": 0.1},
            TaskComplexity.CRITICAL: {"cost": 0.05, "quality": 0.9, "speed": 0.05},
        }
        w = weights.get(complexity, weights[TaskComplexity.MODERATE])
        avg_cost = (profile.cost_per_1k_input + profile.cost_per_1k_output) / 2
        max_cost = 0.02
        cost_score = 1.0 - min(avg_cost / max_cost, 1.0)
        if self._prefer_local and profile.provider == "local":
            cost_score = min(cost_score + 0.3, 1.0)
        # Blend with profiler data
        quality = profile.quality_score
        speed = profile.speed_score
        profiler = self._load_profiler_stats().get(profile.name)
        if profiler and profiler["total_runs"] >= 3:
            n = profiler["total_runs"]
            weight = min(n / 20, 0.4)
            quality = quality * (1 - weight) + profiler["accuracy"] * weight
            if profiler["avg_p95_ms"] > 0:
                hist_speed = max(0, 1.0 - (profiler["avg_p95_ms"] - 500) / 4500)
                speed = speed * (1 - weight) + hist_speed * weight
        score = w["cost"] * cost_score + w["quality"] * quality + w["speed"] * speed
        return score

    def _cheapest_available(self, require_tools: bool, require_vision: bool) -> str:
        """Find the cheapest available model."""
        cheapest = None
        cheapest_cost = float("inf")

        for name, profile in MODEL_PROFILES.items():
            if not profile.available:
                continue
            if require_tools and not profile.supports_tools:
                continue
            if require_vision and not profile.supports_vision:
                continue
            avg_cost = (profile.cost_per_1k_input + profile.cost_per_1k_output) / 2
            if avg_cost < cheapest_cost:
                cheapest_cost = avg_cost
                cheapest = name

        return cheapest or self._default_model

    def get_routing_stats(self) -> dict:
        """Get routing statistics."""
        stats = cost_tracker.get_stats()
        return {
            "total_cost": stats.get("cost_estimate", 0),
            "total_calls": stats.get("calls", 0),
            "total_tokens": stats.get("total_tokens", 0),
            "budget_limit": self._budget_limit,
            "budget_used_pct": (
                (stats.get("cost_estimate", 0) / self._budget_limit * 100)
                if self._budget_limit > 0 else 0
            ),
            "models_used": list(stats.get("by_model", {}).keys()),
            "prefer_local": self._prefer_local,
        }


# ── Global Router Instance ───────────────────────────────────────────────────

_router: ModelRouter | None = None


def get_model_router(config: dict | None = None) -> ModelRouter:
    """Get the global model router."""
    global _router
    if _router is None:
        _router = ModelRouter(config)
    return _router
