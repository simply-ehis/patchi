"""
Layered Brain — the "complex brain system" for Patchi.

Breaks a codebase into persistent **layers** so the agent can retrieve context
for one part without re-reading the whole repository:

    Layer 4: PROJECT    → purpose, stack, conventions
    Layer 3: FLOWS      → critical paths (contract flows)
    Layer 2: SUBSYSTEMS → "auth", "data", "api", "ui" (semantic groups)
    Layer 1: MODULES    → directory-level units (cached summaries)
    Layer 0: FILES      → FileInfo (handled elsewhere)

Each layer carries a cached heuristic summary, its inter-layer dependencies
(derived from the import graph), its public API, and a validity hash.  When a
single file changes, only its module summary is recomputed and the change
propagates up one level — sibling layers are never touched.

This module is **additive**: it builds on the existing FileInfo / ImportGraph /
RouteInfo structures and serialises to `.patchi/memory/layers.json`.  No rewrite
of the scan pipeline is required.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from patchi.core.brain.framework import StackInfo
    from patchi.core.brain.import_graph import ImportGraph
    from patchi.core.brain.route_mapper import RouteInfo
    from patchi.core.brain.scanner import FileInfo


# ── Subsystem classification ──────────────────────────────────────────────────

# Maps a keyword (matched against module path) to a semantic subsystem name.
_SUBSYSTEM_RULES: list[tuple[str, str]] = [
    (r"auth|login|session|security|oauth|jwt|token|passwd|permission", "auth"),
    (r"api|route|router|controller|endpoint|view|handler|resource", "api"),
    (r"model|db|data|repo|repository|orm|migration|schema|query|sql", "data"),
    (r"test|spec|__tests__|e2e|fixture", "tests"),
    (r"ui|component|page|frontend|web|dom|css|react|vue|svelte", "ui"),
    (r"agent|scanner|fix|brain|analy|guard|detect", "agents"),
    (r"core|util|common|lib|shared|helper|internal", "core"),
    (r"config|deploy|infra|ci|docker|k8s|pipeline|script", "infra"),
]


def _classify_subsystem(module_name: str) -> str:
    """Map a module path to a semantic subsystem name."""
    low = module_name.lower()
    for pattern, name in _SUBSYSTEM_RULES:
        if re.search(pattern, low):
            return name
    # Fall back to the top-level directory name
    return module_name.split("/")[0] or "root"


# ── Layer dataclass ───────────────────────────────────────────────────────────


@dataclass
class Layer:
    """A single layer in the Layered Brain."""

    name: str
    level: int  # 1=module, 2=subsystem, 4=project
    path: str = ""  # relative path (modules) or logical name (subsystems/project)
    language: str = ""  # primary language of the layer
    summary: str = ""  # cached heuristic description
    purpose: str = ""  # one-line purpose (heuristic)
    files: list[str] = field(default_factory=list)  # child file paths
    child_layers: list[str] = field(default_factory=list)  # child layer names
    parent_layer: str | None = None
    depends_on: list[str] = field(default_factory=list)  # layer names this imports
    dependents: list[str] = field(default_factory=list)  # layer names importing this
    public_api: list[str] = field(default_factory=list)  # exported symbols
    validity_hash: str = ""  # hash of public_api + summary + files
    stale: bool = False  # True when a parent/child change invalidated this layer

    def compute_hash(self) -> str:
        payload = (
            self.name
            + "|"
            + self.summary
            + "|"
            + ",".join(sorted(self.public_api))
            + "|"
            + ",".join(sorted(self.files))
        )
        return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "level": self.level,
            "path": self.path,
            "language": self.language,
            "summary": self.summary,
            "purpose": self.purpose,
            "files": self.files,
            "child_layers": self.child_layers,
            "parent_layer": self.parent_layer,
            "depends_on": self.depends_on,
            "dependents": self.dependents,
            "public_api": self.public_api,
            "validity_hash": self.validity_hash,
            "stale": self.stale,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Layer:
        return cls(
            name=d["name"],
            level=d["level"],
            path=d.get("path", ""),
            language=d.get("language", ""),
            summary=d.get("summary", ""),
            purpose=d.get("purpose", ""),
            files=d.get("files", []),
            child_layers=d.get("child_layers", []),
            parent_layer=d.get("parent_layer"),
            depends_on=d.get("depends_on", []),
            dependents=d.get("dependents", []),
            public_api=d.get("public_api", []),
            validity_hash=d.get("validity_hash", ""),
            stale=d.get("stale", False),
        )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _module_of(file_path: str) -> str:
    """Return the module (parent directory) for a file path."""
    parts = file_path.split("/")
    if len(parts) <= 1:
        return file_path  # root-level file is its own module
    return "/".join(parts[:-1])


def _lang_value(lang) -> str:
    if hasattr(lang, "value"):
        return lang.value
    return str(lang)


def _module_summary(
    module_name: str,
    files: list[str],
    fi_map: dict[str, FileInfo],
    routes: list[RouteInfo],
) -> tuple[str, str, list[str]]:
    """Produce (summary, purpose, public_api) for a module."""
    langs: dict[str, int] = {}
    func_count = 0
    class_count = 0
    public_api: list[str] = []
    for fp in files:
        fi = fi_map.get(fp)
        if not fi:
            continue
        lv = _lang_value(fi.language)
        langs[lv] = langs.get(lv, 0) + 1
        func_count += len(fi.functions)
        class_count += len(fi.classes)
        for fn in fi.functions:
            public_api.append(fn.name)
        for cl in fi.classes:
            public_api.append(cl.name)

    module_routes = [r for r in routes if _module_of(r.file) == module_name]
    route_bits: list[str] = []
    for r in module_routes[:6]:
        method = r.method if hasattr(r, "method") else r.get("method", "GET")
        path = r.path if hasattr(r, "path") else r.get("path", "/")
        route_bits.append(f"{method} {path}")
    route_summary = (" Routes: " + ", ".join(route_bits)) if route_bits else ""

    lang_str = ", ".join(f"{k}×{v}" for k, v in langs.items()) or "unknown"
    summary = (
        f"Module '{module_name}' — {len(files)} file(s) ({lang_str}), "
        f"{func_count} function(s), {class_count} class(es).{route_summary}"
    )
    purpose = f"Contains {func_count} function(s) and {class_count} class(es) under {module_name}."
    return summary, purpose, public_api


# ── Builder ───────────────────────────────────────────────────────────────────


def build_layers(
    file_infos: list[FileInfo],
    graph: ImportGraph | None = None,
    routes: list[RouteInfo] | None = None,
    stack: StackInfo | None = None,
) -> dict[str, Layer]:
    """Build the full layered brain from scan results.

    Returns a dict keyed by layer name.  Includes module (L1), subsystem (L2),
    and project (L4) layers.  Layer 0 (individual files) is intentionally not
    stored — it is the FileInfo cache already maintained by the scanner.
    """
    routes = routes or []
    fi_map = {fi.path: fi for fi in file_infos}

    # ── Level 1: modules (one per directory) ──────────────────────────────────
    modules: dict[str, list[str]] = {}
    for fi in file_infos:
        mod = _module_of(fi.path)
        modules.setdefault(mod, []).append(fi.path)

    layers: dict[str, Layer] = {}
    for mod_name, files in modules.items():
        summary, purpose, public_api = _module_summary(mod_name, files, fi_map, routes)
        layer = Layer(
            name=mod_name,
            level=1,
            path=mod_name,
            language=_dominant_language(files, fi_map),
            summary=summary,
            purpose=purpose,
            files=sorted(files),
            public_api=sorted(set(public_api)),
        )
        layer.validity_hash = layer.compute_hash()
        layers[mod_name] = layer

    # ── Level 2: subsystems (cluster modules by semantic role) ─────────────────
    subsystem_modules: dict[str, list[str]] = {}
    module_to_subsystem: dict[str, str] = {}
    for mod_name in modules:
        sub = _classify_subsystem(mod_name)
        subsystem_modules.setdefault(sub, []).append(mod_name)
        module_to_subsystem[mod_name] = sub

    for sub_name, mods in subsystem_modules.items():
        sub_files: list[str] = []
        sub_api: list[str] = []
        for m in mods:
            sub_files.extend(layers[m].files)
            sub_api.extend(layers[m].public_api)
        sub_summary = (
            f"Subsystem '{sub_name}' — {len(mods)} module(s), "
            f"{len(sub_files)} file(s). Modules: {', '.join(mods[:8])}."
        )
        sub_layer = Layer(
            name=sub_name,
            level=2,
            path=sub_name,
            language=_dominant_language(sub_files, fi_map),
            summary=sub_summary,
            purpose=f"Groups {len(mods)} module(s) under the '{sub_name}' concern.",
            files=sorted(set(sub_files)),
            child_layers=sorted(mods),
            public_api=sorted(set(sub_api)),
        )
        sub_layer.validity_hash = sub_layer.compute_hash()
        layers[sub_name] = sub_layer
        for m in mods:
            layers[m].parent_layer = sub_name

    # ── Inter-layer dependencies (from import graph) ───────────────────────────
    if graph is not None:
        _populate_dependencies(layers, graph, module_to_subsystem)

    # ── Level 4: project ───────────────────────────────────────────────────────
    fw_names = (
        ", ".join(f.name for f in stack.frameworks[:5]) if stack and stack.frameworks else "unknown"
    )
    runtime = stack.runtime if stack else "unknown"
    project_summary = (
        f"Project — {len(file_infos)} file(s) across {len(modules)} module(s) "
        f"and {len(subsystem_modules)} subsystem(s). "
        f"Stack: {fw_names} (runtime: {runtime})."
    )
    project_layer = Layer(
        name="__project__",
        level=4,
        path="",
        language=runtime,
        summary=project_summary,
        purpose="The whole project — top of the layer hierarchy.",
        files=sorted(fi.path for fi in file_infos),
        child_layers=sorted(subsystem_modules.keys()),
        public_api=sorted({a for lay in layers.values() for a in lay.public_api}),
    )
    project_layer.validity_hash = project_layer.compute_hash()
    layers["__project__"] = project_layer
    for sub in subsystem_modules:
        layers[sub].parent_layer = "__project__"

    return layers


def _dominant_language(files: list[str], fi_map: dict[str, FileInfo]) -> str:
    counts: dict[str, int] = {}
    for fp in files:
        fi = fi_map.get(fp)
        if fi:
            lv = _lang_value(fi.language)
            counts[lv] = counts.get(lv, 0) + 1
    if not counts:
        return ""
    return max(counts, key=counts.get)


def _populate_dependencies(
    layers: dict[str, Layer],
    graph: ImportGraph,
    module_to_subsystem: dict[str, str],
) -> None:
    """Derive module- and subsystem-level dependency edges from the graph."""
    edges: dict[str, set[str]] = {}
    raw_edges: dict[str, set[str]] = {}
    if hasattr(graph, "edges"):
        raw_edges = graph.edges
    elif isinstance(graph, dict) and "edges" in graph:
        raw_edges = graph["edges"]

    for src_file, targets in raw_edges.items():
        src_mod = _module_of(src_file)
        for tgt in targets:
            tgt_mod = _module_of(tgt) if isinstance(tgt, str) else str(tgt)
            if src_mod == tgt_mod:
                continue
            edges.setdefault(src_mod, set()).add(tgt_mod)

    # Module-level edges
    for src_mod, tgts in edges.items():
        if src_mod not in layers:
            continue
        for tgt_mod in tgts:
            if tgt_mod in layers:
                if tgt_mod not in layers[src_mod].depends_on:
                    layers[src_mod].depends_on.append(tgt_mod)
                if src_mod not in layers[tgt_mod].dependents:
                    layers[tgt_mod].dependents.append(src_mod)

    # Subsystem-level edges (cluster module edges)
    sub_edges: dict[str, set[str]] = {}
    for src_mod, tgts in edges.items():
        src_sub = module_to_subsystem.get(src_mod)
        if not src_sub:
            continue
        for tgt_mod in tgts:
            tgt_sub = module_to_subsystem.get(tgt_mod)
            if not tgt_sub or tgt_sub == src_sub:
                continue
            sub_edges.setdefault(src_sub, set()).add(tgt_sub)

    for src_sub, tgts in sub_edges.items():
        if src_sub not in layers:
            continue
        for tgt_sub in sorted(tgts):
            if tgt_sub in layers:
                if tgt_sub not in layers[src_sub].depends_on:
                    layers[src_sub].depends_on.append(tgt_sub)
                if src_sub not in layers[tgt_sub].dependents:
                    layers[tgt_sub].dependents.append(src_sub)


# ── Serialisation helpers ─────────────────────────────────────────────────────


def layers_to_dict(layers: dict[str, Layer]) -> dict:
    return {
        "version": 1,
        "layer_count": len(layers),
        "layers": {name: layer.to_dict() for name, layer in layers.items()},
    }


def layers_from_dict(data: dict) -> dict[str, Layer]:
    return {name: Layer.from_dict(d) for name, d in data.get("layers", {}).items()}


# ── Query helpers (used by the reasoning engine in later phases) ───────────────


def get_layer_context(layers: dict[str, Layer], layer_name: str, max_depth: int = 1) -> dict:
    """Return a layer plus its direct dependency summaries for fast context."""
    if layer_name not in layers:
        return {}
    out: dict[str, str] = {}
    seen: set[str] = set()

    def collect(name: str, depth: int) -> None:
        if name in seen or depth > max_depth:
            return
        seen.add(name)
        layer = layers.get(name)
        if not layer:
            return
        out[name] = layer.summary
        if depth < max_depth:
            for dep in layer.depends_on:
                collect(dep, depth + 1)

    collect(layer_name, 0)
    return out


def find_layers_for_file(layers: dict[str, Layer], file_path: str) -> list[str]:
    """Return the names of layers that contain a given file."""
    return [name for name, layer in layers.items() if file_path in layer.files]


def detect_stale_layers(old_layers: dict[str, Layer], new_layers: dict[str, Layer]) -> list[str]:
    """Compare two layer sets and return names whose hash changed."""
    stale: list[str] = []
    for name, layer in new_layers.items():
        old = old_layers.get(name)
        if old is None or old.validity_hash != layer.validity_hash:
            stale.append(name)
    return stale
