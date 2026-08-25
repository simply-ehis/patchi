"""
Council Orchestration — Multi-persona decision making for Patchi.

The Council coordinates multiple specialized personas to analyze issues,
deliberate, and reach consensus on action plans.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from patchi.core.brain.layered_brain import Layer, layers_from_dict
# Import the personas package (not just base) so @register_persona decorators run
import patchi.core.brain.personas as _persona_registry  # noqa: F401
from patchi.core.brain.personas.base import (
    BasePersona,
    PersonaDecision,
    PersonaStyle,
    create_persona,
    list_personas,
)
from patchi.core.brain.reasoning import ReasoningEngine
from patchi.core import config as cfg
from patchi.core import memory as mem

_log = logging.getLogger("patchi.brain.council")


@dataclass
class CouncilSession:
    """A single council deliberation session."""
    issue: str
    context: dict = field(default_factory=dict)
    persona_decisions: list[PersonaDecision] = field(default_factory=list)
    synthesis: str = ""
    action_plan: list[dict] = field(default_factory=list)
    consensus_reached: bool = False
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = ""
    duration_ms: int = 0


@dataclass
class ActionStep:
    """A single step in the council's action plan."""
    tool: str
    parameters: dict
    priority: int  # 1=highest
    rationale: str
    assigned_persona: str
    depends_on: list[str] = field(default_factory=list)
    estimated_duration_ms: int = 0


class Council:
    """
    The Council — orchestrates multi-persona deliberation.
    
    Flow:
    1. Receive issue + context
    2. Select relevant personas
    3. Parallel analysis by each persona
    4. Synthesis & debate (if conflicts)
    5. Consensus action plan
    6. Execute & learn
    """
    
    # Persona selection rules: issue keywords -> persona names
    PERSONA_SELECTION_RULES = {
        "architect": [
            "architecture", "structure", "dependency", "module", "layer",
            "refactor", "blast radius", "circular", "dead code", "coupling",
            "cohesion", "boundary", "interface", "contract",
        ],
        "security_officer": [
            "security", "vulnerability", "attack", "threat", "exploit",
            "injection", "xss", "csrf", "ssrf", "auth", "authorization",
            "secrets", "compliance", "encryption", "owasp", "cve",
        ],
        "test_engineer": [
            "test", "testing", "coverage", "flaky", "regression", "e2e",
            "integration", "unit test", "visual", "accessibility", "browser",
            "stress", "load", "contract", "api",
        ],
        "performance_analyst": [
            "performance", "slow", "latency", "throughput", "bottleneck",
            "memory", "cpu", "profiling", "benchmark", "optimization",
            "scalability", "cache", "async", "concurrent",
        ],
        "devops_engineer": [
            "deploy", "ci", "cd", "pipeline", "infrastructure", "kubernetes",
            "docker", "container", "monitoring", "observability", "logging",
            "secrets", "supply chain", "rollback", "feature flag",
        ],
        "code_reviewer": [
            "code quality", "readability", "maintainability", "pattern",
            "anti-pattern", "complexity", "duplication", "naming",
            "documentation", "style", "error handling",
        ],
        "product_owner": [
            "business", "user", "requirement", "acceptance", "flow",
            "journey", "feature", "priority", "compliance", "regulation",
            "risk", "value",
        ],
        "incident_responder": [
            "crash", "error", "incident", "anomaly", "debug", "root cause",
            "runtime", "alert", "outage", "recovery", "postmortem",
        ],
    }
    
    def __init__(
        self,
        root: Path,
        on_progress: Optional[Callable[[str], None]] = None,
    ):
        self.root = root
        self.on_progress = on_progress or (lambda _: None)
        self.config = cfg.load(root)
        self.brain_layers = self._load_brain_layers()
        self.project_context = self._load_project_context()
        self.personas: dict[str, BasePersona] = {}
        self.session_history: list[CouncilSession] = []
        self._initialize_personas()
    
    def _load_brain_layers(self) -> dict[str, Layer]:
        """Load layered brain from memory."""
        layers_data = mem.get_layers(self.root)
        if layers_data and layers_data.get("layers"):
            return layers_from_dict(layers_data)
        return {}
    
    def _load_project_context(self) -> dict:
        """Load project context from brain memory."""
        brain = mem.get_brain(self.root)
        return {
            "project_purpose": brain.get("project_purpose", ""),
            "project_domain": brain.get("project_domain", ""),
            "frameworks": brain.get("frameworks", []),
            "active_security_domains": brain.get("active_security_domains", []),
            "file_count": brain.get("file_count", 0),
            "route_count": brain.get("route_count", 0),
        }
    
    def _initialize_personas(self) -> None:
        """Create all persona instances, keyed by short rule names."""
        # Map registered class names (e.g. "SecurityOfficerPersona") to the
        # short rule keys used in PERSONA_SELECTION_RULES ("security_officer").
        short_name = {
            "ArchitectPersona": "architect",
            "SecurityOfficerPersona": "security_officer",
            "TestEngineerPersona": "test_engineer",
            "PerformanceAnalystPersona": "performance_analyst",
            "DevOpsEngineerPersona": "devops_engineer",
            "CodeReviewerPersona": "code_reviewer",
            "ProductOwnerPersona": "product_owner",
            "IncidentResponderPersona": "incident_responder",
        }
        for cls_name in list_personas():
            key = short_name.get(cls_name, cls_name.lower())
            persona = create_persona(
                name=cls_name,
                root=self.root,
                brain_layers=self.brain_layers,
                project_context=self.project_context,
                config=self.config,
                on_progress=self.on_progress,
            )
            if persona:
                self.personas[key] = persona
                _log.info(f"Initialized persona: {key} ({cls_name})")
            else:
                _log.warning(f"Failed to initialize persona: {cls_name}")
    
    def _select_personas(self, issue: str, context: dict = None) -> list[str]:
        """Select relevant personas using domain relevance scoring.
        
        Scoring factors:
        1. Keyword match (0-5 points per persona)
        2. Expertise area alignment (0-3 points)
        3. Historical success rate for similar issues (0-2 points)
        4. Context-based relevance (file types, code patterns)
        """
        context = context or {}
        issue_lower = issue.lower()
        scores: dict[str, float] = {}
        
        for persona_name, keywords in self.PERSONA_SELECTION_RULES.items():
            if persona_name not in self.personas:
                continue
            
            score = 0.0
            
            # Factor 1: Keyword match (0-5 points)
            keyword_hits = sum(1 for kw in keywords if kw in issue_lower)
            score += min(keyword_hits, 5)
            
            # Factor 2: Expertise area alignment (0-3 points)
            persona = self.personas[persona_name]
            expertise = persona.get_expertise_areas()
            expertise_overlap = sum(1 for e in expertise if e.lower() in issue_lower)
            score += min(expertise_overlap * 1.5, 3.0)
            
            # Factor 3: Historical success rate (0-2 points)
            if hasattr(persona, 'memory') and persona.memory.success_rates:
                # Get success rate for similar issue types
                rates = persona.memory.success_rates
                avg_success = sum(rates.values()) / len(rates)
                score += avg_success * 2.0
            
            # Factor 4: Context-based relevance
            # Check if issue mentions files/types this persona handles
            context_files = context.get('files', [])
            if context_files:
                # Security persona gets bonus for security-related files
                if persona_name == 'security_officer':
                    sec_kws = ['auth', 'crypto', 'secret', 'token']
                    sec_files = [f for f in context_files
                                 if any(k in f.lower() for k in sec_kws)]
                    score += min(len(sec_files) * 0.5, 2.0)
                # DevOps for infrastructure files
                elif persona_name == 'devops_engineer':
                    infra_kws = ['docker', 'ci', 'deploy', 'k8s']
                    infra_files = [f for f in context_files
                                   if any(k in f.lower() for k in infra_kws)]
                    score += min(len(infra_files) * 0.5, 2.0)
            
            if score > 0:
                scores[persona_name] = score
        
        # Always include Architect for structural perspective (bonus +2)
        if "architect" in self.personas:
            scores["architect"] = scores.get("architect", 0) + 2.0
        
        # Sort by score descending
        selected = sorted(scores.keys(), key=lambda p: scores[p], reverse=True)
        
        # Minimum 3, maximum 5 personas for balanced deliberation
        if len(selected) < 3:
            defaults = ["architect", "security_officer", "test_engineer"]
            for d in defaults:
                if d in self.personas and d not in selected:
                    selected.append(d)
        
        return selected[:5]
    
    async def deliberate(self, issue: str, context: dict = None) -> CouncilSession:
        """
        Run a full council deliberation on an issue.
        
        Returns a CouncilSession with decisions, synthesis, and action plan.
        """
        start_time = time.monotonic()
        context = context or {}
        
        self.on_progress(f"🏛️ Council convened for: {issue[:80]}...")
        
        # Select personas with domain relevance scoring
        selected_names = self._select_personas(issue, context)
        self.on_progress(f"👥 Selected personas: {', '.join(selected_names)}")
        
        session = CouncilSession(issue=issue, context=context)
        
        # Phase 1: Parallel Analysis
        self.on_progress("📋 Phase 1: Individual Analysis")
        analysis_tasks = []
        for name in selected_names:
            persona = self.personas[name]
            analysis_tasks.append(self._run_persona_analysis(persona, issue, context))
        
        decisions = await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        for name, decision in zip(selected_names, decisions):
            if isinstance(decision, Exception):
                _log.error(f"Persona {name} failed: {decision}")
                continue
            session.persona_decisions.append(decision)
        
        # Phase 2: Synthesis & Debate
        self.on_progress("🤝 Phase 2: Synthesis & Debate")
        session.synthesis = await self._synthesize(session)
        
        # Phase 3: Action Plan
        self.on_progress("📋 Phase 3: Action Plan")
        session.action_plan = await self._create_action_plan(session)
        
        # Phase 4: Consensus Check
        session.consensus_reached = self._check_consensus(session)
        
        session.completed_at = datetime.now(timezone.utc).isoformat()
        session.duration_ms = int((time.monotonic() - start_time) * 1000)
        
        self.session_history.append(session)
        self.on_progress(f"✅ Council complete in {session.duration_ms}ms. Consensus: {session.consensus_reached}")
        
        return session
    
    async def _run_persona_analysis(
        self,
        persona: BasePersona,
        issue: str,
        context: dict,
    ) -> PersonaDecision:
        """Run analysis for a single persona (in thread pool for sync AI calls)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, persona.analyze, issue, context)
    
    async def _synthesize(self, session: CouncilSession) -> str:
        """Synthesize persona decisions into a unified analysis."""
        if not session.persona_decisions:
            return "No persona decisions to synthesize."
        
        # Build synthesis prompt
        decisions_text = "\n\n".join([
            f"=== {d.persona_name.upper()} ===\n"
            f"Analysis: {d.analysis}\n"
            f"Recommendation: {d.recommendation}\n"
            f"Confidence: {d.confidence:.0%}\n"
            f"Tools: {', '.join(d.tools_needed) if d.tools_needed else 'none'}\n"
            f"Risks: {', '.join(d.risks) if d.risks else 'none'}"
            for d in session.persona_decisions
        ])
        
        synthesis_prompt = f"""
Synthesize the following persona analyses into a unified assessment.

ORIGINAL ISSUE: {session.issue}

PERSONA DECISIONS:
{decisions_text}

Provide synthesis in this JSON format:
{{
    "unified_analysis": "Synthesized analysis combining all perspectives",
    "key_agreements": ["agreement1", "agreement2"],
    "key_disagreements": ["disagreement1", "disagreement2"],
    "risk_assessment": "Overall risk level and key risks",
    "priority": "critical|high|medium|low",
    "recommended_approach": "High-level approach summary"
}}
"""
        
        # Use Architect persona for synthesis (or first available)
        synthesizer = self.personas.get("architect") or list(self.personas.values())[0]
        result = synthesizer._call_ai_with_persona(
            synthesis_prompt,
            max_tokens=2000,
            temperature=0.2,
        )
        
        if result:
            return result.get("unified_analysis", "Synthesis failed")
        return "AI synthesis unavailable; see individual decisions above."
    
    async def _create_action_plan(self, session: CouncilSession) -> list[dict]:
        """Create prioritized action plan from decisions."""
        # Collect all tools needed
        all_tools = []
        for d in session.persona_decisions:
            for tool in d.tools_needed:
                all_tools.append({
                    "tool": tool,
                    "persona": d.persona_name,
                    "confidence": d.confidence,
                    "rationale": d.recommendation,
                })
        
        # Deduplicate and prioritize
        tool_map: dict[str, dict] = {}
        for t in all_tools:
            key = t["tool"]
            if key not in tool_map or t["confidence"] > tool_map[key]["confidence"]:
                tool_map[key] = t
        
        # Build action steps
        steps = []
        for i, (tool_name, info) in enumerate(tool_map.items()):
            steps.append({
                "tool": tool_name,
                "parameters": {},  # Will be filled by executor
                "priority": i + 1,
                "rationale": info["rationale"],
                "assigned_persona": info["persona"],
                "confidence": info["confidence"],
            })
        
        return steps
    
    def _check_consensus(self, session: CouncilSession) -> bool:
        """Check if personas reached weighted consensus.
        
        Uses weighted confidence based on:
        1. Persona expertise relevance to the issue
        2. Historical accuracy of each persona
        3. Style-based weight adjustments
        """
        if len(session.persona_decisions) < 2:
            return True
        
        # Calculate weights for each persona
        weights = []
        weighted_confidences = []
        
        for decision in session.persona_decisions:
            weight = self._calculate_persona_weight(decision, session.issue)
            weights.append(weight)
            weighted_confidences.append(decision.confidence * weight)
        
        total_weight = sum(weights)
        if total_weight == 0:
            return False
        
        # Weighted average confidence
        weighted_avg = sum(weighted_confidences) / total_weight
        
        # Weighted standard deviation (measures agreement)
        weighted_variance = sum(
            w * (c - weighted_avg) ** 2 
            for w, c in zip(weights, [d.confidence for d in session.persona_decisions])
        ) / total_weight
        weighted_std = weighted_variance ** 0.5
        
        # Check for semantic agreement (recommendations align)
        semantic_agreement = self._check_semantic_agreement(session)
        
        # Consensus criteria:
        # 1. Weighted confidence > 0.6
        # 2. Weighted std < 0.25 (low disagreement)
        # 3. At least 60% semantic agreement on recommendations
        consensus = (
            weighted_avg > 0.6 and
            weighted_std < 0.25 and
            semantic_agreement >= 0.6
        )
        
        return consensus
    
    def _calculate_persona_weight(self, decision: 'PersonaDecision', issue: str) -> float:
        """Calculate weight for a persona based on expertise and history."""
        weight = 1.0  # Base weight
        
        persona = self.personas.get(decision.persona_name)
        if not persona:
            return weight
        
        # Factor 1: Expertise relevance (0-1 bonus)
        expertise = persona.get_expertise_areas()
        issue_lower = issue.lower()
        expertise_matches = sum(1 for e in expertise if e.lower() in issue_lower)
        if expertise_matches > 0:
            weight += min(expertise_matches * 0.25, 1.0)
        
        # Factor 2: Historical accuracy (0-1 bonus)
        if hasattr(persona, 'memory') and persona.memory.success_rates:
            rates = persona.memory.success_rates
            avg_success = sum(rates.values()) / len(rates)
            weight += avg_success * 1.0
        
        # Factor 3: Style-based adjustments
        style = persona.get_style()
        if style == PersonaStyle.CAUTIOUS:
            # Cautious personas get bonus for risk-related issues
            if any(kw in issue_lower for kw in ['risk', 'safety', 'security', 'regression']):
                weight += 0.3
        elif style == PersonaStyle.AGGRESSIVE:
            # Aggressive personas get bonus for edge cases
            if any(kw in issue_lower for kw in ['edge case', 'boundary', '极限', 'corner']):
                weight += 0.3
        elif style == PersonaStyle.PRAGMATIC:
            # Pragmatic personas get bonus for implementation issues
            if any(kw in issue_lower for kw in ['implement', 'fix', 'deploy', 'ship']):
                weight += 0.3
        
        return weight
    
    def _check_semantic_agreement(self, session: CouncilSession) -> float:
        """Check if persona recommendations semantically agree."""
        if len(session.persona_decisions) < 2:
            return 1.0
        
        recommendations = [d.recommendation.lower() for d in session.persona_decisions]
        
        # Simple semantic check: count common action keywords
        action_keywords = ['fix', 'refactor', 'test', 'deploy', 'monitor', 'review', 'audit']
        
        keyword_counts = {}
        for rec in recommendations:
            for kw in action_keywords:
                if kw in rec:
                    keyword_counts[kw] = keyword_counts.get(kw, 0) + 1
        
        if not keyword_counts:
            return 0.5  # Neutral if no clear actions
        
        # Agreement is max keyword count / total personas
        max_agreement = max(keyword_counts.values()) / len(session.persona_decisions)
        return max_agreement
    
    async def execute_action_plan(
        self,
        session: CouncilSession,
        tool_executor: "ToolExecutor",
        max_steps: int = 10,
    ) -> list[dict]:
        """Execute the council's action plan using the tool executor."""
        results = []
        executed_tools = set()
        
        for step in session.action_plan[:max_steps]:
            tool_name = step["tool"]
            
            # Check dependencies
            deps_met = all(dep in executed_tools for dep in step.get("depends_on", []))
            if not deps_met:
                self.on_progress(f"⏳ Skipping {tool_name}: dependencies not met")
                continue
            
            self.on_progress(f"⚡ Executing: {tool_name} (by {step['assigned_persona']})")
            
            try:
                result = await tool_executor.execute(tool_name, step["parameters"])
                results.append({
                    "tool": tool_name,
                    "success": result.get("success", False),
                    "result": result,
                    "step": step,
                })
                executed_tools.add(tool_name)
                
                # Record outcome for learning
                for decision in session.persona_decisions:
                    if decision.persona_name == step["assigned_persona"]:
                        decision.record_outcome(decision, result.get("success", False))
                
            except Exception as e:
                _log.error(f"Tool {tool_name} failed: {e}")
                results.append({
                    "tool": tool_name,
                    "success": False,
                    "error": str(e),
                    "step": step,
                })
        
        return results
    
    def get_session_history(self, limit: int = 10) -> list[CouncilSession]:
        """Get recent council sessions."""
        return self.session_history[-limit:]
    
    def get_persona_stats(self) -> dict:
        """Get statistics for all personas."""
        stats = {}
        for name, persona in self.personas.items():
            decisions = persona.memory.decisions
            stats[name] = {
                "total_decisions": len(decisions),
                "avg_confidence": sum(d.confidence for d in decisions) / len(decisions) if decisions else 0,
                "success_rates": persona.memory.success_rates,
                "style": persona.get_style().value,
            }
        return stats


class CouncilMode:
    """Council operation modes."""
    
    AUTO = "auto"          # Full autonomous: deliberate -> execute -> learn
    CONFIRM = "confirm"    # Deliberate -> present plan -> wait for confirmation -> execute
    ADVISORY = "advisory"  # Deliberate only -> present recommendations


# Convenience function for CLI integration
async def run_council(
    root: Path,
    issue: str,
    context: dict = None,
    mode: str = CouncilMode.CONFIRM,
    on_progress: Callable[[str], None] = None,
) -> CouncilSession:
    """Run a council session on an issue."""
    council = Council(root, on_progress)
    session = await council.deliberate(issue, context)
    
    if mode == CouncilMode.AUTO:
        from patchi.core.ai.tool_executor import ToolExecutor
        executor = ToolExecutor(root)
        await council.execute_action_plan(session, executor)
    elif mode == CouncilMode.CONFIRM:
        # Would present plan and wait for user confirmation
        pass
    # ADVISORY: just return session
    
    return session