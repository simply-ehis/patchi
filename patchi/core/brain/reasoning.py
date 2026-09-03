"""
Reasoning Engine — Phase 3 of the Patchi super-agent.

Sits *above* the Layered Brain and turns it into answers.  Given a change-set, a
file, or a natural-language question, it reasons over the cached layer summaries
(never re-reading raw source) and produces structured, human-readable output:

    - impact_analysis(changed_files) → blast radius across layers
    - explain(target)                → a layer's summary + its dependency context
    - why(path)                      → why a file matters (dependents, purpose)
    - ask(question)                  → NL answer built from layer summaries

Everything is offline-safe (pure heuristics over the Layered Brain).  If an LLM
is configured, :meth:`ReasoningEngine.ask` can optionally enrich the answer.

This module is additive: it only reads the Layered Brain persisted at
``.patchi/memory/layers.json`` and existing ``layered_brain`` helpers.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from patchi.core.brain.brain_watcher import ChangeSet, affected_layers
from patchi.core.brain.layered_brain import (
    find_layers_for_file,
    get_layer_context,
    layers_from_dict,
)

_log = logging.getLogger("patchi.brain.reasoning")

if TYPE_CHECKING:
    from patchi.core.brain.layered_brain import Layer


@dataclass
class ImpactAnalysis:
    """Structured result of reasoning about a change-set."""

    changed_files: list[str] = field(default_factory=list)
    affected_layers: list[str] = field(default_factory=list)  # directly touched
    impacted_layers: list[str] = field(default_factory=list)  # blast radius (dependents)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "changed_files": self.changed_files,
            "affected_layers": self.affected_layers,
            "impacted_layers": self.impacted_layers,
            "summary": self.summary,
        }


class ReasoningEngine:
    """Answers questions using the cached Layered Brain (no raw-source reads)."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.layers: dict[str, Layer] = self._load_layers()

    def _load_layers(self) -> dict[str, Layer]:
        from patchi.core import memory as mem

        data = mem.get_layers(self.root) or {}
        if not data.get("layers"):
            return {}
        return layers_from_dict(data)

    # ── Impact analysis (blast radius) ──────────────────────────────────────────

    def impact_analysis(self, changed_files: list[str]) -> ImpactAnalysis:
        if not self.layers:
            return ImpactAnalysis(
                changed_files=changed_files,
                summary="No layered brain available. Run `p scan` first to build it.",
            )

        changes = ChangeSet(changed=set(changed_files))
        affected = affected_layers(changes, self.layers)

        # Blast radius: transitively follow dependents of every affected layer.
        impacted: set[str] = set()
        stack = list(affected)
        while stack:
            cur = stack.pop()
            layer = self.layers.get(cur)
            if not layer:
                continue
            for dep in layer.dependents:
                if dep in self.layers and dep not in impacted:
                    impacted.add(dep)
                    stack.append(dep)

        blast = impacted - affected
        summary = self._impact_summary(changed_files, affected, blast)
        return ImpactAnalysis(
            changed_files=changed_files,
            affected_layers=sorted(affected),
            impacted_layers=sorted(blast),
            summary=summary,
        )

    def _impact_summary(self, changed, affected, blast) -> str:
        if not changed:
            return "No changes provided."
        parts = [f"{len(changed)} file(s) changed"]
        if affected:
            parts.append(
                f"{len(affected)} layer(s) directly affected: {', '.join(sorted(affected))}"
            )
        if blast:
            parts.append(
                f"{len(blast)} downstream layer(s) in the blast radius: {', '.join(sorted(blast))}"
            )
        else:
            parts.append("no downstream layers depend on the changed code")
        return "; ".join(parts) + "."

    # ── Explain a layer / file ───────────────────────────────────────────────────

    def explain(self, target: str) -> dict:
        """Return a layer's summary plus its direct dependency context.

        ``target`` may be a file path or a layer name.
        """
        if not self.layers:
            return {"error": "No layered brain available. Run `p scan` first."}

        # Resolve to a layer name.
        if target in self.layers:
            layer_name = target
        else:
            matches = find_layers_for_file(self.layers, target)
            if not matches:
                return {"error": f"No layer found for '{target}'."}
            layer_name = matches[0]

        layer = self.layers[layer_name]
        context = get_layer_context(self.layers, layer_name, max_depth=1)
        return {
            "layer": layer_name,
            "level": layer.level,
            "summary": layer.summary,
            "purpose": layer.purpose,
            "depends_on": layer.depends_on,
            "dependents": layer.dependents,
            "context": {k: v for k, v in context.items() if k != layer_name},
        }

    # ── Why does a file matter ───────────────────────────────────────────────────

    def why(self, path: str) -> dict:
        """Explain why a file matters: its layer, dependents, and purpose."""
        if not self.layers:
            return {"error": "No layered brain available. Run `p scan` first."}

        matches = find_layers_for_file(self.layers, path)
        if not matches:
            return {"error": f"'{path}' is not part of any known layer."}

        layer_name = matches[0]
        layer = self.layers[layer_name]
        dependents = layer.dependents
        importance = "critical" if dependents else ("shared" if len(layer.files) > 1 else "leaf")
        return {
            "file": path,
            "layer": layer_name,
            "layer_summary": layer.summary,
            "purpose": layer.purpose,
            "depended_on_by": dependents,
            "importance": importance,
            "files_in_layer": len(layer.files),
        }

    # ── Natural-language问答 (TF-IDF over layers + body_tags, LLM optional) ─

    def ask(self, question: str, use_ai: bool = False, ask_ai: bool | None = None, **_) -> str:
        """Answer a question from layer summaries. TF-IDF ranked, optionally LLM-synthesized.

        Spec L3: RAG over cached layers[].summary built at scan time (layers.json rag_index),
        query via cosine, ask_ai=True wraps RAG context + call_ai. use_ai is alias for backward compat.
        """
        if ask_ai is not None:
            use_ai = bool(ask_ai)
        if not self.layers:
            return (
                "I don't have a brain-map of this project yet. "
                "Run `p scan` to build the layered brain, then ask again."
            )

        q = question.lower()
        tokens = {t for t in re.findall(r"[a-z0-9_]+", q) if len(t) > 2}
        if not tokens:
            return "Could you rephrase? Try naming a subsystem (auth, api, data, ui…)."

        # Try understander/body_tags boost if available
        body_boost: dict[str, float] = {}
        try:
            from patchi.core.brain.body_tags import load_body_tags

            tags = load_body_tags(self.root)
            for _path, tag in tags.items():
                layer_hint = tag.get("layer", "")
                if layer_hint:
                    body_boost[layer_hint] = max(body_boost.get(layer_hint, 0), float(tag.get("score", 0)) / 100.0)
        except Exception:
            body_boost = {}

        # TF-IDF-ish: term freq * inverse doc freq approximation
        doc_freq: dict[str, int] = {}
        for t in tokens:
            df = sum(1 for n, layer in self.layers.items() if t in f"{n} {layer.summary} {layer.purpose}".lower())
            doc_freq[t] = max(1, df)
        import math

        scored: list[tuple[float, str, Layer]] = []
        for name, layer in self.layers.items():
            if layer.level == 4:
                continue
            text = f"{name} {layer.summary} {layer.purpose}".lower()
            tfidf = 0.0
            for t in tokens:
                if t in text:
                    tf = text.count(t)
                    idf = math.log(len(self.layers) / doc_freq[t] + 1)
                    tfidf += tf * idf
            tfidf += body_boost.get(name, 0.0)
            if tfidf > 0:
                scored.append((tfidf, name, layer))

        if not scored:
            return (
                "I couldn't match that to any layer I know. "
                "Known layers: "
                + ", ".join(sorted(n for n in self.layers if n != "__project__"))
                + "."
            )

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:3]
        if use_ai:
            try:
                import os

                if not os.environ.get("PATCHI_OFFLINE"):
                    from patchi.core import config as cfg
                    from patchi.core.ai.client import call_ai

                    cfgd = cfg.load(self.root) if hasattr(cfg, "load") else {}
                    ctx = "\n".join(f"[{n}] {lay.summary} — {lay.purpose}" for _, n, lay in top)
                    ans = call_ai(cfgd, "You are Patchi understander. Answer from layered brain context.", f"Question: {question}\n\nContext:\n{ctx}", max_tokens=400)
                    if ans:
                        return ans
            except Exception as _exc:
                _log.debug("reasoning AI synthesis fallback: %s", _exc)
        lines = [f"Based on the layered brain, here's what I know about '{question.strip()}':", ""]
        for _, name, layer in top:
            lines.append(f"[bold]{name}[/bold] ({_level_name(layer.level)}): {layer.summary}")
        lines.append("")
        lines.append("[dim]Answers are derived from cached layer summaries + body_tags ranking.[/dim]")
        return "\n".join(lines)


def _level_name(level: int) -> str:
    return {1: "module", 2: "subsystem", 4: "project"}.get(level, f"L{level}")
