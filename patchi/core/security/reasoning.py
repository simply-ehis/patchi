"""
Reasoning Engine — queries the Layered Brain for structured impact analysis.

Answers questions like:
  - "What changed?" → reads git diff, maps to layers, lists affected subsystems
  - "What does auth do?" → reads layer summaries, shows public API + dependencies
  - "What imports X?" → traces dependency graph through layers
  - "What are the security hotspots?" → cross-references charter rules with layers

No AI tokens required — pure heuristic reasoning over the layered brain.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from patchi.core.brain.layered_brain import (
    Layer,
    find_layers_for_file,
    get_layer_context,
    layers_from_dict,
)


@dataclass
class ReasoningResult:
    """Structured answer from the reasoning engine."""

    question: str
    answer: str  # human-readable summary
    layers: list[str] = field(default_factory=list)  # affected layer names
    files: list[str] = field(default_factory=list)  # affected files
    details: dict[str, Any] = field(default_factory=dict)  # structured data

    def to_dict(self) -> dict:
        return {
            "question": self.question,
            "answer": self.answer,
            "layers": self.layers,
            "files": self.files,
            "details": self.details,
        }


# ── Layered Brain loader ─────────────────────────────────────────────────────


def _load_layers(root: Path) -> dict[str, Layer]:
    """Load cached layers from .patchi/memory/layers.json."""
    path = root / ".patchi" / "memory" / "layers.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return layers_from_dict(data)
    except Exception:
        return {}


# ── Question classifiers ──────────────────────────────────────────────────────

_WHAT_CHANGED_RE = re.compile(
    r"what(?:'s| is| are)?\s+(?:changed|new|modified|different)", re.I
)
_WHAT_DOES_RE = re.compile(
    r"what\s+(?:does|is|are)\s+(?:the\s+)?['\"]?(\w+)['\"]?\s+(?:module|service|function|class)?\s*(?:do|about)",
    re.I,
)
_WHAT_IMPORTS_RE = re.compile(
    r"what\s+(?:imports?|uses?|depends?\s+on)\s+['\"]?([\w./]+)['\"]?",
    re.I,
)
_HOTSPOTS_RE = re.compile(r"(?:security|hotspot|vuln|risk|dangerous)", re.I)
_ROUTE_RE = re.compile(r"(?:route|endpoint|api|handler)", re.I)
_LAYER_RE = re.compile(r"(?:layer|subsystem|module|component)", re.I)


def classify_question(question: str) -> str:
    """Classify a question into a category."""
    q = question.lower().strip()
    if _WHAT_CHANGED_RE.search(q):
        return "what_changed"
    if _WHAT_DOES_RE.search(q):
        return "what_does"
    if _WHAT_IMPORTS_RE.search(q):
        return "what_imports"
    if _HOTSPOTS_RE.search(q):
        return "hotspots"
    if _ROUTE_RE.search(q):
        return "routes"
    if _LAYER_RE.search(q):
        return "layers"
    return "general"


# ── Answer generators ─────────────────────────────────────────────────────────


def _answer_what_changed(root: Path, layers: dict[str, Layer]) -> ReasoningResult:
    """Answer 'what changed?' by checking git diff and mapping to layers."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1"],
            capture_output=True, text=True, cwd=str(root), timeout=10,
        )
        changed_files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except Exception:
        changed_files = []

    if not changed_files:
        return ReasoningResult(
            question="what changed",
            answer="No recent changes detected (or not a git repo).",
            layers=[],
            files=[],
        )

    # Map files to layers
    affected_layers: set[str] = set()
    affected_files: list[str] = []
    layer_details: dict[str, list[str]] = {}

    for fp in changed_files:
        layer_names = find_layers_for_file(layers, fp)
        for ln in layer_names:
            affected_layers.add(ln)
            layer_details.setdefault(ln, []).append(fp)
        affected_files.append(fp)

    # Build answer
    parts = [f"Changed {len(changed_files)} file(s) across {len(affected_layers)} layer(s):"]
    for ln in sorted(affected_layers):
        layer = layers.get(ln)
        summary = layer.summary if layer else "unknown"
        files_in = layer_details.get(ln, [])
        parts.append(f"  {ln}: {summary}")
        for f in files_in[:5]:
            parts.append(f"    - {f}")
        if len(files_in) > 5:
            parts.append(f"    ... and {len(files_in) - 5} more")

    # Check for boundary violations
    if affected_layers:
        parts.append("")
        parts.append("Dependency analysis:")
        for ln in sorted(affected_layers):
            layer = layers.get(ln)
            if layer and layer.dependents:
                cross = [d for d in layer.dependents if d not in affected_layers]
                if cross:
                    parts.append(f"  {ln} is imported by: {', '.join(cross[:5])}")

    return ReasoningResult(
        question="what changed",
        answer="\n".join(parts),
        layers=sorted(affected_layers),
        files=affected_files,
        details={"layer_files": layer_details},
    )


def _answer_what_does(root: Path, layers: dict[str, Layer], module_name: str) -> ReasoningResult:
    """Answer 'what does X do?' by reading layer summaries."""
    # Try exact match first
    layer = layers.get(module_name)

    # Try partial match
    if not layer:
        for name, lay in layers.items():
            if module_name.lower() in name.lower():
                layer = lay
                module_name = name
                break

    if not layer:
        return ReasoningResult(
            question=f"what does {module_name} do",
            answer=f"Layer '{module_name}' not found in the layered brain.",
            layers=[],
        )

    parts = [f"=== {layer.name} (Level {layer.level}) ==="]
    parts.append(f"Summary: {layer.summary}")
    parts.append(f"Purpose: {layer.purpose}")
    if layer.files:
        parts.append(f"Files: {len(layer.files)}")
        for f in layer.files[:10]:
            parts.append(f"  - {f}")
    if layer.public_api:
        parts.append(f"Public API: {len(layer.public_api)} symbols")
        for api in layer.public_api[:15]:
            parts.append(f"  - {api}")
    if layer.depends_on:
        parts.append(f"Depends on: {', '.join(layer.depends_on[:10])}")
    if layer.dependents:
        parts.append(f"Used by: {', '.join(layer.dependents[:10])}")

    # Get context from dependencies
    context = get_layer_context(layers, module_name, max_depth=1)
    if len(context) > 1:
        parts.append(f"\nDirect dependencies ({len(context) - 1}):")
        for name, summary in context.items():
            if name != module_name:
                parts.append(f"  {name}: {summary[:100]}")

    return ReasoningResult(
        question=f"what does {module_name} do",
        answer="\n".join(parts),
        layers=[module_name] + layer.depends_on,
        files=layer.files,
        details={
            "api": layer.public_api,
            "depends": layer.depends_on,
            "dependents": layer.dependents,
        },
    )


def _answer_what_imports(root: Path, layers: dict[str, Layer], module_name: str) -> ReasoningResult:
    """Answer 'what imports X?' by tracing dependency graph."""
    # Find all layers that depend on the target
    importers: list[str] = []
    for name, layer in layers.items():
        if module_name in layer.depends_on:
            importers.append(name)

    if not importers:
        return ReasoningResult(
            question=f"what imports {module_name}",
            answer=f"No layers import '{module_name}'.",
            layers=[module_name] if module_name in layers else [],
        )

    parts = [f"Layers that import '{module_name}':"]
    for imp in importers:
        layer = layers.get(imp)
        summary = layer.summary[:80] if layer else "unknown"
        parts.append(f"  {imp}: {summary}")

    # Check for circular dependencies
    if module_name in layers and module_name in layers[module_name].dependents:
        parts.append(f"\n⚠ Circular dependency detected: {module_name} imports itself!")

    return ReasoningResult(
        question=f"what imports {module_name}",
        answer="\n".join(parts),
        layers=importers + [module_name],
        details={"importers": importers},
    )


def _answer_hotspots(root: Path, layers: dict[str, Layer]) -> ReasoningResult:
    """Answer 'what are the security hotspots?' by analyzing layer properties."""
    hotspots: list[dict] = []

    for name, layer in layers.items():
        if name.startswith("__"):
            continue
        risk_score = 0
        reasons: list[str] = []

        # High dependency count = more attack surface
        if len(layer.dependents) > 5:
            risk_score += 2
            reasons.append(f"imported by {len(layer.dependents)} modules (high attack surface)")

        # Auth/security layers are critical
        if any(kw in name.lower() for kw in ("auth", "security", "session", "crypto")):
            risk_score += 3
            reasons.append("security-critical layer")

        # Large layers with many files are harder to audit
        if len(layer.files) > 20:
            risk_score += 1
            reasons.append(f"{len(layer.files)} files (large layer)")

        # API layers accept external input
        if any(kw in name.lower() for kw in ("api", "route", "endpoint", "handler", "view")):
            risk_score += 2
            reasons.append("accepts external input")

        if risk_score > 0:
            hotspots.append({
                "name": name,
                "risk_score": risk_score,
                "reasons": reasons,
                "summary": layer.summary[:100],
            })

    hotspots.sort(key=lambda h: -h["risk_score"])

    parts = ["Security hotspots (sorted by risk):"]
    for h in hotspots[:10]:
        parts.append(f"  [{h['risk_score']}] {h['name']}: {', '.join(h['reasons'])}")

    return ReasoningResult(
        question="security hotspots",
        answer="\n".join(parts),
        layers=[h["name"] for h in hotspots],
        details={"hotspots": hotspots},
    )


def _answer_general(root: Path, layers: dict[str, Layer], question: str) -> ReasoningResult:
    """Generic answer — list all layers with summaries."""
    project = layers.get("__project__")
    parts = ["Project overview:"]
    if project:
        parts.append(f"  {project.summary}")

    parts.append(f"\nLayers ({len(layers)}):")
    for name, layer in sorted(layers.items()):
        if name.startswith("__"):
            continue
        parts.append(f"  [{layer.level}] {name}: {layer.summary[:80]}")

    return ReasoningResult(
        question=question,
        answer="\n".join(parts),
        layers=list(layers.keys()),
    )


# ── Main entry point ─────────────────────────────────────────────────────────


def answer_question(question: str, root: Path | None = None) -> ReasoningResult:
    """Answer a question about the codebase using the layered brain."""
    r = root or Path.cwd()
    layers = _load_layers(r)

    if not layers:
        return ReasoningResult(
            question=question,
            answer="No layered brain found. Run 'p scan' first to build the layer cache.",
        )

    category = classify_question(question)

    if category == "what_changed":
        return _answer_what_changed(r, layers)

    if category == "what_does":
        m = _WHAT_DOES_RE.search(question)
        module_name = m.group(1) if m else ""
        return _answer_what_does(r, layers, module_name)

    if category == "what_imports":
        m = _WHAT_IMPORTS_RE.search(question)
        module_name = m.group(1) if m else ""
        return _answer_what_imports(r, layers, module_name)

    if category == "hotspots":
        return _answer_hotspots(r, layers)

    return _answer_general(r, layers, question)
