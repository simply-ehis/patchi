"""
BrainContext — the single bridge that connects all brain knowledge.

Assembles:
  - Enriched context (AI project understanding)
  - Project insight (README, package.json, tech stack)
  - Layer summaries (architectural knowledge)
  - Reasoning engine (impact analysis, explain, why)
  - Import graph (dependencies, circular deps)
  - Active security domains
  - Recent findings (for false-positive learning)

Used by:
  - DetectionPipeline: context-aware finding classification
  - Chat: full brain state injection
  - ReasoningEngine: enriched question answering
  - Web dashboard: brain state for all pages

Design: Lazy-loaded, cacheable, offline-safe.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path

_log = logging.getLogger("patchi.brain.context")


@dataclass
class BrainContext:
    """Assembled brain knowledge for a project scan."""

    root: Path = field(default_factory=lambda: Path("."))

    # Enriched context (from enriched_context.py)
    enriched: dict = field(default_factory=dict)
    purpose: str = ""
    domain: str = ""
    domain_confidence: float = 0.0
    tech_stack: list[str] = field(default_factory=list)
    critical_dirs: list[dict] = field(default_factory=list)
    top_risks: list[dict] = field(default_factory=list)
    scan_focus: str = ""

    # Project insight (from project_reader.py)
    project_name: str = ""
    project_type: str = ""
    framework: str = ""
    language: str = ""
    entry_points: list[str] = field(default_factory=list)
    readme_summary: str = ""

    # Layer summaries (from layered_brain.py)
    layers: dict = field(default_factory=dict)
    layer_count: int = 0

    # Import graph
    import_graph: dict = field(default_factory=dict)
    circular_deps: list = field(default_factory=list)
    dead_files: list[str] = field(default_factory=list)

    # Active domains
    active_domains: list[str] = field(default_factory=list)

    # Recent findings (for FP learning)
    recent_findings: list[dict] = field(default_factory=list)
    known_fps: set = field(default_factory=set)

    # File corpus (for code context)
    file_count: int = 0
    file_criticality_ranking: list[dict] = field(default_factory=list)
    language_breakdown: dict = field(default_factory=dict)
    route_count: int = 0

    # Health
    health_score: float = 0.0
    health_grade: str = "?"

    # Build metadata
    built_at: str = ""
    build_duration_ms: int = 0
    source: str = "heuristic"

    def is_loaded(self) -> bool:
        """Whether the context has been populated with real data."""
        return self.purpose or self.project_name or self.file_count > 0

    def get_summary(self) -> str:
        """One-paragraph summary for AI prompts."""
        parts = []
        if self.purpose:
            parts.append(self.purpose)
        if self.project_type:
            parts.append(f"Project type: {self.project_type}")
        if self.framework:
            parts.append(f"Framework: {self.framework}")
        if self.language:
            parts.append(f"Language: {self.language}")
        if self.file_count:
            parts.append(f"{self.file_count} files")
        if self.route_count:
            parts.append(f"{self.route_count} routes")
        if self.active_domains:
            parts.append(f"Security domains: {', '.join(self.active_domains[:5])}")
        if self.top_risks:
            parts.append(f"Top risks: {'; '.join(r.get('risk', '') for r in self.top_risks[:3])}")
        return ". ".join(parts) + "." if parts else "No project context available."

    def get_finding_context(self, file_path: str, finding_type: str, message: str) -> dict:
        """Build contextual information for a specific finding.

        Returns a dict with:
        - is_test_fixture: True if file is in tests/
        - is_docs: True if file is documentation
        - is_generated: True if file appears generated
        - project_relevance: how relevant this finding is to the project
        - related_layers: which architectural layers are affected
        - domain_matches: which security domains apply
        """
        result = {
            "is_test_fixture": False,
            "is_docs": False,
            "is_generated": False,
            "project_relevance": "unknown",
            "related_layers": [],
            "domain_matches": [],
        }

        fp = file_path.lower() if file_path else ""

        # Test fixture detection
        if any(seg in fp for seg in ("test", "spec", "fixture", "mock", "__test__")):
            result["is_test_fixture"] = True
            result["project_relevance"] = "low"

        # Documentation detection
        if any(seg in fp for seg in (".md", ".rst", ".txt", "doc", "readme")):
            result["is_docs"] = True
            result["project_relevance"] = "low"

        # Generated code detection
        _gen_segs = (".generated", "auto-generated", "__pycache__", "node_modules")
        if any(seg in fp for seg in _gen_segs):
            result["is_generated"] = True
            result["project_relevance"] = "low"

        # Relevance scoring based on critical dirs
        if self.critical_dirs:
            for cd in self.critical_dirs:
                dir_path = cd.get("dir", "").lower()
                if dir_path and dir_path in fp:
                    result["project_relevance"] = "high"
                    break

        # Layer matching
        if self.layers:
            for layer_name, layer_data in self.layers.items():
                files = layer_data.get("files", []) if isinstance(layer_data, dict) else []
                if any(file_path.endswith(f) or f in file_path for f in files):
                    result["related_layers"].append(layer_name)

        # Domain matching (lightweight keyword check)
        if self.active_domains:
            msg_lower = message.lower()
            type_lower = finding_type.lower()
            for domain in self.active_domains:
                domain_words = domain.replace("-", " ").split()
                if any(w in msg_lower or w in type_lower for w in domain_words if len(w) > 3):
                    result["domain_matches"].append(domain)

        return result

    def get_context_for_prompt(self, max_chars: int = 4000) -> str:
        """Build a context block for AI prompts (chat, reasoning, detection)."""
        lines = []

        # Project identity
        if self.project_name:
            lines.append(f"PROJECT: {self.project_name} ({self.project_type or 'unknown'})")
        if self.purpose:
            lines.append(f"PURPOSE: {self.purpose}")
        if self.framework or self.language:
            lines.append(f"STACK: {self.framework or ''} {self.language or ''}")
        if self.tech_stack:
            lines.append(f"TECH: {', '.join(self.tech_stack[:8])}")

        # Stats
        lines.append(
            f"FILES: {self.file_count} | ROUTES: {self.route_count}"
            f" | HEALTH: {self.health_score}/100"
        )

        # Critical dirs
        if self.critical_dirs:
            lines.append("CRITICAL_DIRS:")
            for cd in self.critical_dirs[:4]:
                lines.append(f"  - {cd.get('dir', '?')}: {cd.get('why', '?')}")

        # Risks
        if self.top_risks:
            lines.append("TOP_RISKS:")
            for r in self.top_risks[:3]:
                lines.append(f"  - {r.get('risk', '?')}: {r.get('why', '?')}")

        # Layers
        if self.layers:
            lines.append(f"LAYERS: {len(self.layers)} architectural layers")
            for name in list(self.layers.keys())[:6]:
                lines.append(f"  - {name}")

        # Domains
        if self.active_domains:
            lines.append(f"SECURITY_DOMAINS: {', '.join(self.active_domains[:8])}")

        # Scan focus
        if self.scan_focus:
            lines.append(f"SCAN_FOCUS: {self.scan_focus}")

        result = "\n".join(lines)
        if len(result) > max_chars:
            result = result[:max_chars] + "\n... (truncated)"
        return result


def build_brain_context(root: Path, config: dict | None = None) -> BrainContext:
    """Build a BrainContext from all available brain sources.

    This is the main entry point. It assembles context from:
    1. brain.json (enriched context, layers, file count, etc.)
    2. project_reader (README, package.json, tech stack)
    3. memory (recent findings, known FPs)
    4. domain_loader (active domains)
    """
    import time as _time
    t0 = _time.monotonic()
    ctx = BrainContext(root=root)


    # 1. Load brain.json (enriched context + scan results)
    try:
        from patchi.core import memory as mem
        brain = mem.get_brain(root)
        if brain:
            ctx.file_count = brain.get("file_count", 0)
            ctx.route_count = brain.get("route_count", 0)
            ctx.framework = brain.get("framework", "")
            ctx.language_breakdown = brain.get("languages", {})
            hs = brain.get("health_score")
            ctx.health_score = (
                hs.get("total", 0) if isinstance(hs, dict) else (hs or 0)
            )
            ctx.health_grade = brain.get("health_grade", "?")

            # Enriched context
            ec = brain.get("enriched_context", {})
            if ec:
                ctx.enriched = ec
                ctx.purpose = ec.get("purpose_1sent", "")
                ctx.domain = ec.get("domain", "")
                ctx.domain_confidence = ec.get("domain_confidence", 0)
                ctx.tech_stack = ec.get("tech_stack_confirmed", [])
                ctx.critical_dirs = ec.get("critical_dirs_reasoned", [])
                ctx.top_risks = ec.get("top_risks", [])
                ctx.scan_focus = ec.get("scan_focus", "")
                ctx.source = ec.get("source", "unknown")

            # Layers
            layers = brain.get("layers", {})
            if layers and isinstance(layers, dict):
                ctx.layers = layers.get("layers", layers)
                ctx.layer_count = len(ctx.layers)

            # Project context
            pc = brain.get("project_context", {})
            if pc:
                ctx.project_name = pc.get("name", "")
                ctx.project_type = pc.get("project_type", "")
                ctx.entry_points = pc.get("entry_points", [])
    except Exception as exc:
        _log.debug("brain.json load failed: %s", exc)

    # 2. Project reader (README, package.json, etc.)
    try:
        from patchi.core.brain.project_reader import read_project_insight
        insight = read_project_insight(root)
        if insight:
            ctx.project_name = ctx.project_name or insight.name
            ctx.project_type = ctx.project_type or insight.project_type
            ctx.framework = ctx.framework or insight.framework
            ctx.language = insight.language
            ctx.entry_points = ctx.entry_points or insight.entry_points
            ctx.readme_summary = insight.readme_summary
            if insight.tech_stack and not ctx.tech_stack:
                ctx.tech_stack = insight.tech_stack
    except Exception as exc:
        _log.debug("project_reader failed: %s", exc)

    # 2b. File criticality ranking via body_tags + understander
    try:
        from patchi.core.brain.body_tags import build_body_tags
        file_infos = []
        try:
            from patchi.core.agents.discovery import discover_project
            disc = discover_project(root)
            file_infos = getattr(disc, 'file_infos', [])
        except Exception as _exc:
            _log.debug('suppressed: %s', _exc)
        body_tags = build_body_tags(root, file_infos)
        if body_tags:
            ranked = sorted(
                body_tags.items(),
                key=lambda kv: (-int(kv[1].get("score", 0)), -int(kv[1].get("fan_in", 0)), kv[0]),
            )
            ctx.file_criticality_ranking = [
                {"path": path, "score": tag.get("score", 0), "role": tag.get("role", ""),
                 "system": tag.get("system", ""), "criticality": tag.get("criticality", "low")}
                for path, tag in ranked[:30]
            ]
    except Exception as exc:
        _log.debug("body_tags ranking failed: %s", exc)

    # 3. Active domains
    try:
        from patchi.core.security.domain_loader import DomainLoader
        dl = DomainLoader(root)
        dl._load_all()
        ctx.active_domains = list(dl._domains.keys())[:20]
    except Exception as exc:
        _log.debug("domain_loader failed: %s", exc)

    # 4. Known false positives
    try:
        fp_file = root / ".patchi/memory/known_false_positives.json"
        if fp_file.exists():
            import json
            fps = json.loads(fp_file.read_text(encoding="utf-8"))
            if isinstance(fps, list):
                ctx.known_fps = {tuple(fp) if isinstance(fp, list) else fp for fp in fps}
            elif isinstance(fps, dict):
                ctx.known_fps = set(fps.keys())
    except Exception as _exc:
        _log.debug('suppressed: %s', _exc)

    # 5. Recent findings
    try:
        from patchi.core import memory as mem
        scan_results = mem.get_scan_results(root)
        for _scanner, data in scan_results.items():
            for finding in data.get("findings", [])[-50:]:
                if isinstance(finding, dict):
                    ctx.recent_findings.append(finding)
    except Exception as _exc:
        _log.debug('suppressed: %s', _exc)

    from datetime import datetime as _dtnow
    ctx.built_at = _dtnow.now(UTC).isoformat()
    ctx.build_duration_ms = int((_time.monotonic() - t0) * 1000)

    _log.info(
        "BrainContext built in %dms: %d files, %d domains, %d layers, purpose=%s",
        ctx.build_duration_ms,
        ctx.file_count,
        len(ctx.active_domains),
        ctx.layer_count,
        ctx.purpose[:50] if ctx.purpose else "?",
    )

    return ctx


# ── Singleton cache ────────────────────────────────────────────────────────────
_cached: BrainContext | None = None
_cached_root: Path | None = None


def get_brain_context(root: Path, config: dict | None = None, force: bool = False) -> BrainContext:
    """Get (or build and cache) the BrainContext for a project."""
    global _cached, _cached_root
    if _cached is not None and _cached_root == root.resolve() and not force:
        return _cached
    _cached = build_brain_context(root, config)
    _cached_root = root.resolve()
    return _cached


def invalidate_brain_context() -> None:
    """Clear the cached BrainContext (call after a scan completes)."""
    global _cached, _cached_root
    _cached = None
    _cached_root = None
