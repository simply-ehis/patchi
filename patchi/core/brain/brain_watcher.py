"""
BrainWatcher — incremental Layered Brain updates (Phase 1 of the super-agent plan).

The full :func:`build_layers` rebuild is cheap, but re-summarising every module
on every scan is wasteful for large repos.  The BrainWatcher reuses cached layer
summaries for modules whose files did **not** change, and recomputes *only* the
layers touched by a file change — propagating the invalidation up one level
(module → subsystem → project).

Change detection is content-hash based (mirrors the scanner's own per-file cache,
so unchanged files are never re-parsed either).  The watcher also records *which*
layers are stale so a downstream scan can skip or rebuild them selectively.

This module is additive: it sits on top of :mod:`layered_brain` and never alters
the scan pipeline's behaviour when no prior state exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from patchi.core.brain.framework import StackInfo
    from patchi.core.brain.import_graph import ImportGraph
    from patchi.core.brain.route_mapper import RouteInfo
    from patchi.core.brain.scanner import FileInfo

from patchi.core.brain.layered_brain import (
    Layer,
    _classify_subsystem,
    _dominant_language,
    _module_of,
    _module_summary,
    _populate_dependencies,
)
from patchi.core.brain.layered_brain import build_layers as _full_build


# ── Change tracking ────────────────────────────────────────────────────────────


import logging
_log = logging.getLogger("patchi.brain.brain_watcher")

@dataclass
class ChangeSet:
    """The set of files that changed between two snapshots."""

    changed: set[str] = field(default_factory=set)
    added: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)

    @property
    def any(self) -> bool:
        return bool(self.changed or self.added or self.removed)

    @property
    def all_paths(self) -> set[str]:
        return self.changed | self.added | self.removed

    def to_dict(self) -> dict:
        return {
            "changed": sorted(self.changed),
            "added": sorted(self.added),
            "removed": sorted(self.removed),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ChangeSet":
        return cls(
            changed=set(d.get("changed", [])),
            added=set(d.get("added", [])),
            removed=set(d.get("removed", [])),
        )


def file_snapshot(file_infos: Iterable["FileInfo"], root: Path) -> dict[str, str]:
    """Map each file path to its content hash for change detection."""
    from patchi.core.brain.scanner import _file_content_hash

    root = Path(root)
    snap: dict[str, str] = {}
    for fi in file_infos:
        try:
            snap[fi.path] = _file_content_hash(root / fi.path)
        except Exception as e:
            _log.warning("file_snapshot failed: %s", e)
            snap[fi.path] = ""
    return snap


def diff_snapshots(old: dict[str, str], new: dict[str, str]) -> ChangeSet:
    """Compare two file-hash snapshots and return what changed."""
    changed = {p for p in new if p in old and old[p] != new[p]}
    added = {p for p in new if p not in old}
    removed = {p for p in old if p not in new}
    return ChangeSet(changed=changed, added=added, removed=removed)


# ── Stale marking ──────────────────────────────────────────────────────────────


def mark_layers_stale(layers: dict[str, Layer], names: Iterable[str]) -> None:
    """Flag the given layer names (and nothing else) as stale/invalidated."""
    name_set = set(names)
    for name, layer in layers.items():
        layer.stale = name in name_set


def clear_stale(layers: dict[str, Layer]) -> None:
    """Clear the stale flag on every layer."""
    for layer in layers.values():
        layer.stale = False


def affected_layers(changes: ChangeSet, old_layers: dict[str, Layer]) -> set[str]:
    """Return every layer touched by a change, walking the parent chain up.

    A changed file invalidates its module (L1), its subsystem (L2), and the
    project layer (L4).  Anything not in this set can be left untouched.
    """
    names: set[str] = set()
    for p in changes.all_paths:
        cur = _module_of(p)
        while cur is not None:
            names.add(cur)
            layer = old_layers.get(cur)
            cur = layer.parent_layer if layer else None
    return names


# ── Incremental rebuild ────────────────────────────────────────────────────────


def update_layers(
    old_layers: dict[str, Layer],
    file_infos: list["FileInfo"],
    graph: "ImportGraph | None" = None,
    routes: list["RouteInfo"] | None = None,
    stack: "StackInfo | None" = None,
    changes: ChangeSet | None = None,
) -> tuple[dict[str, Layer], list[str]]:
    """Incrementally rebuild layers, reusing cached summaries where possible.

    Unchanged modules keep their exact previous :class:`Layer` object (no
    re-summarisation).  Only modules touched by ``changes`` (plus their
    subsystem/project ancestors) are recomputed.  Returns the new layer dict and
    the list of layer names that were actually rebuilt.
    """
    routes = routes or []
    fi_map = {fi.path: fi for fi in file_infos}

    modules: dict[str, list[str]] = {}
    for fi in file_infos:
        modules.setdefault(_module_of(fi.path), []).append(fi.path)

    changed_modules: set[str] = set()
    if changes is not None:
        for p in list(changes.changed) + list(changes.added) + list(changes.removed):
            changed_modules.add(_module_of(p))

    new_layers: dict[str, Layer] = {}
    rebuilt: list[str] = []

    # ── Level 1: modules (reuse cached summary unless changed) ──────────────────
    for mod, files in modules.items():
        if mod in old_layers and mod not in changed_modules:
            new_layers[mod] = old_layers[mod]  # no-op: reuse cached summary
        else:
            summary, purpose, api = _module_summary(mod, files, fi_map, routes)
            layer = Layer(
                name=mod,
                level=1,
                path=mod,
                language=_dominant_language(files, fi_map),
                summary=summary,
                purpose=purpose,
                files=sorted(files),
                public_api=sorted(set(api)),
            )
            layer.validity_hash = layer.compute_hash()
            new_layers[mod] = layer
            rebuilt.append(mod)

    # ── Level 2: subsystems (recompute only if a child module changed) ───────────
    subsystem_modules: dict[str, list[str]] = {}
    module_to_subsystem: dict[str, str] = {}
    for mod in modules:
        sub = _classify_subsystem(mod)
        subsystem_modules.setdefault(sub, []).append(mod)
        module_to_subsystem[mod] = sub

    changed_subsystems = {
        module_to_subsystem[m] for m in changed_modules if m in module_to_subsystem
    }

    for sub, mods in subsystem_modules.items():
        all_children_present = all(m in new_layers for m in mods)
        if (
            sub in old_layers
            and sub not in changed_subsystems
            and all_children_present
        ):
            new_layers[sub] = old_layers[sub]  # no-op: reuse cached summary
        else:
            sub_files: list[str] = []
            sub_api: list[str] = []
            for m in mods:
                sub_files.extend(new_layers[m].files)
                sub_api.extend(new_layers[m].public_api)
            sub_summary = (
                f"Subsystem '{sub}' — {len(mods)} module(s), "
                f"{len(sub_files)} file(s). Modules: {', '.join(mods[:8])}."
            )
            sub_layer = Layer(
                name=sub,
                level=2,
                path=sub,
                language=_dominant_language(sub_files, fi_map),
                summary=sub_summary,
                purpose=f"Groups {len(mods)} module(s) under the '{sub}' concern.",
                files=sorted(set(sub_files)),
                child_layers=sorted(mods),
                public_api=sorted(set(sub_api)),
            )
            sub_layer.validity_hash = sub_layer.compute_hash()
            new_layers[sub] = sub_layer
            rebuilt.append(sub)
        for m in mods:
            new_layers[m].parent_layer = sub

    # ── Inter-layer dependencies (cheap; derived from the existing graph) ────────
    if graph is not None:
        _populate_dependencies(new_layers, graph, module_to_subsystem)

    # ── Level 4: project (recompute only if the module set changed) ──────────────
    old_module_names = {n for n, l in old_layers.items() if l.level == 1}
    module_set_changed = (set(modules) != old_module_names) or bool(changed_modules)
    if "__project__" in old_layers and not module_set_changed:
        new_layers["__project__"] = old_layers["__project__"]  # no-op
    else:
        fw_names = (
            ", ".join(f.name for f in stack.frameworks[:5])
            if stack and stack.frameworks
            else "unknown"
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
            public_api=sorted({a for l in new_layers.values() for a in l.public_api}),
        )
        project_layer.validity_hash = project_layer.compute_hash()
        new_layers["__project__"] = project_layer
        rebuilt.append("__project__")
    for sub in subsystem_modules:
        new_layers[sub].parent_layer = "__project__"

    clear_stale(new_layers)
    return new_layers, rebuilt


def build_or_update(
    old_layers: dict[str, Layer],
    file_infos: list["FileInfo"],
    graph: "ImportGraph | None" = None,
    routes: list["RouteInfo"] | None = None,
    stack: "StackInfo | None" = None,
    old_snapshot: dict[str, str] | None = None,
    root: Path | None = None,
) -> tuple[dict[str, Layer], list[str], ChangeSet]:
    """High-level entry: reuse cached layers when nothing changed, else rebuild.

    Returns ``(layers, rebuilt_names, changes)``.  When there is prior state and
    no file changed, the existing layers are returned verbatim (true no-op) and
    ``rebuilt_names`` is empty.
    """
    new_snapshot = file_snapshot(file_infos, root) if root is not None else {}
    changes = (
        diff_snapshots(old_snapshot or {}, new_snapshot)
        if old_snapshot is not None
        else ChangeSet()
    )

    if old_layers and not changes.any:
        return old_layers, [], changes
    if old_layers and changes.any:
        layers, rebuilt = update_layers(
            old_layers, file_infos, graph, routes, stack, changes=changes
        )
        return layers, rebuilt, changes
    # No prior state — full build.
    layers = _full_build(file_infos, graph, routes, stack)
    return layers, list(layers.keys()), changes


# ── Watcher (stateful helper around the above) ─────────────────────────────────


class BrainWatcher:
    """Stateful helper: tracks file-snapshot history in memory and reports drift."""

    def __init__(self, root: Path):
        self.root = Path(root)

    # ── snapshot persistence ────────────────────────────────────────────────────
    def load_snapshot(self) -> dict[str, str]:
        from patchi.core import memory as mem

        data = mem.get_layers(self.root) or {}
        return data.get("file_snapshot", {})

    def save_snapshot(self, snapshot: dict[str, str]) -> None:
        from patchi.core import memory as mem

        data = mem.get_layers(self.root) or {}
        data["file_snapshot"] = snapshot
        mem.save_layers(data, self.root)

    # ── diffing ──────────────────────────────────────────────────────────────────
    def diff(self, old: dict[str, str], new: dict[str, str]) -> ChangeSet:
        return diff_snapshots(old, new)

    def affected(self, changes: ChangeSet, old_layers: dict[str, Layer]) -> set[str]:
        return affected_layers(changes, old_layers)

    def mark_stale(self, layers: dict[str, Layer], changes: ChangeSet) -> set[str]:
        """Mark the layers touched by ``changes`` as stale and return their names."""
        names = affected_layers(changes, layers)
        mark_layers_stale(layers, names)
        return names
