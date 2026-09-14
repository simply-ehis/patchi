"""
Blast radius calculation utilities.

Two levels:
  - File-level (v1, original): Uses ImportGraph. BFS on reverse edges.
  - Symbol-level (v2): Uses SymbolGraph. Weighted by test coverage + criticality.
    Both directions (downstream dependents + upstream dependencies).
    Damage-vs-repair: structural diff before/after a change.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from patchi.core.brain.import_graph import ImportGraph

# ── File-level (v1) ────────────────────────────────────────────────────────────


@dataclass
class BlastRadius:
    """Information about the blast radius of a file."""

    target: str
    direct_dependents: list[str]
    all_dependents: list[str]
    risk_level: str  # 'low', 'medium', 'high'

    @property
    def total_affected(self) -> int:
        return len(self.all_dependents)


def calculate_blast_radius(target: str, graph: ImportGraph) -> BlastRadius:
    """BFS on reverse graph to find all transitive dependents."""
    direct = sorted(graph.reverse.get(target, set()))
    all_affected: set[str] = set()
    queue = deque(direct)
    while queue:
        node = queue.popleft()
        if node == target or node in all_affected:
            continue
        all_affected.add(node)
        for parent in graph.reverse.get(node, set()):
            if parent not in all_affected:
                queue.append(parent)

    count = len(all_affected)
    risk = "low" if count == 0 else ("medium" if count <= 5 else "high")

    return BlastRadius(
        target=target,
        direct_dependents=direct,
        all_dependents=sorted(all_affected),
        risk_level=risk,
    )


def build_blast_radius_map(graph: ImportGraph) -> dict[str, BlastRadius]:
    return {node: calculate_blast_radius(node, graph) for node in graph.nodes}


# ── Symbol-level (v2) ──────────────────────────────────────────────────────────


@dataclass
class SymbolBlastResult:
    """Symbol-level blast radius with weighted scoring."""

    symbol_name: str
    file: str
    line: int
    # Downstream: what depends on this symbol
    downstream_direct: list[dict] = field(default_factory=list)
    downstream_all: list[dict] = field(default_factory=list)
    downstream_count: int = 0
    # Upstream: what this symbol depends on
    upstream_direct: list[dict] = field(default_factory=list)
    upstream_count: int = 0
    # Weighted scores
    test_coverage_score: float = 1.0  # 0-1, higher = better tested
    criticality_score: float = 0.0  # 0-1, higher = more critical
    risk_score: float = 0.0  # weighted combination
    risk_level: str = "low"
    # Damage vs repair
    structural_change_count: int = 0

    @property
    def total_affected(self) -> int:
        return self.downstream_count

    def to_dict(self) -> dict:
        return {
            "symbol": self.symbol_name,
            "file": self.file,
            "line": self.line,
            "downstream": {
                "direct": len(self.downstream_direct),
                "all": self.downstream_count,
                "samples": self.downstream_direct[:5],
            },
            "upstream": {
                "direct": len(self.upstream_direct),
                "samples": self.upstream_direct[:5],
            },
            "test_coverage_score": round(self.test_coverage_score, 3),
            "criticality_score": round(self.criticality_score, 3),
            "risk_score": round(self.risk_score, 3),
            "risk_level": self.risk_level,
            "structural_changes": self.structural_change_count,
        }


def calculate_symbol_blast_radius(
    symbol_name: str,
    file: str,
    symbol_graph: Any,
    test_coverage: dict[str, float] | None = None,
    criticality_tags: dict[str, float] | None = None,
    max_depth: int = 5,
) -> SymbolBlastResult:
    """Compute symbol-level blast radius with weighted scoring.

    Args:
        symbol_name: Name of the symbol to analyze.
        file: File path where the symbol is defined.
        symbol_graph: SymbolGraph instance.
        test_coverage: Dict of {file_path: coverage_ratio 0-1}.
        criticality_tags: Dict of {symbol_name: criticality_score 0-1}.
        max_depth: Max transitive depth.
    """
    test_coverage = test_coverage or {}
    criticality_tags = criticality_tags or {}

    target = symbol_graph.get_symbol(symbol_name, file)
    if not target:
        return SymbolBlastResult(
            symbol_name=symbol_name,
            file=file,
            line=0,
            risk_level="unknown",
            risk_score=0.0,
        )

    # Downstream: dependents
    downstream_set: dict[str, dict] = {}
    queue: list[tuple[str, str, int]] = [(s.name, s.file, 1) for s in symbol_graph.get_dependents(symbol_name, file)]
    visited: set[int] = {target.id}
    direct_downstream: list[dict] = []

    while queue:
        name, fpath, depth = queue.pop(0)
        if depth > max_depth:
            continue
        sym = symbol_graph.get_symbol(name, fpath)
        if not sym or sym.id in visited:
            continue
        visited.add(sym.id)
        entry = {"name": name, "file": fpath, "depth": depth}
        downstream_set[f"{name}:{fpath}"] = entry
        if depth == 1:
            direct_downstream.append(entry)
        # Recurse into their dependents
        for dep in symbol_graph.get_dependents(name, fpath):
            if dep.id not in visited:
                queue.append((dep.name, dep.file, depth + 1))

    # Upstream: dependencies
    upstream_list: list[dict] = []
    for dep in symbol_graph.get_dependencies(target.id):
        upstream_list.append({"name": dep.name, "file": dep.file})

    # File-level test coverage weight
    file_coverage = test_coverage.get(file, 0.5)
    downstream_file_coverage = 0.0
    if downstream_set:
        downstream_files = {v["file"] for v in downstream_set.values()}
        covered = sum(test_coverage.get(f, 0.0) for f in downstream_files)
        downstream_file_coverage = covered / len(downstream_files) if downstream_files else 0.0

    test_coverage_score = (file_coverage + downstream_file_coverage) / 2.0

    # Criticality: higher for exported/route/core symbols
    criticality = criticality_tags.get(symbol_name, 0.3)
    if target.kind == "route":
        criticality = max(criticality, 0.8)
    elif target.is_exported:
        criticality = max(criticality, 0.5)
    criticality_score = min(criticality, 1.0)

    # Risk score: more downstream = higher risk, less test coverage = higher risk
    downstream_risk = min(len(downstream_set) / 50.0, 1.0)
    coverage_risk = 1.0 - test_coverage_score
    risk_score = downstream_risk * 0.4 + coverage_risk * 0.3 + criticality_score * 0.3
    risk_score = min(risk_score, 1.0)

    risk_level = "low"
    if risk_score > 0.3:
        risk_level = "medium"
    if risk_score > 0.6:
        risk_level = "high"
    if risk_score > 0.85:
        risk_level = "critical"

    return SymbolBlastResult(
        symbol_name=symbol_name,
        file=file,
        line=target.line,
        downstream_direct=direct_downstream,
        downstream_all=list(downstream_set.values()),
        downstream_count=len(downstream_set),
        upstream_direct=upstream_list,
        upstream_count=len(upstream_list),
        test_coverage_score=test_coverage_score,
        criticality_score=criticality_score,
        risk_score=risk_score,
        risk_level=risk_level,
    )


def calculate_file_symbol_blast_radius(
    file_path: str,
    symbol_graph: Any,
    test_coverage: dict[str, float] | None = None,
    criticality_tags: dict[str, float] | None = None,
) -> list[SymbolBlastResult]:
    """Compute symbol-level blast radius for all symbols in a file."""
    symbols = symbol_graph.get_symbols_in_file(file_path)
    return [
        calculate_symbol_blast_radius(s.name, s.file, symbol_graph, test_coverage, criticality_tags) for s in symbols
    ]


@dataclass
class GraphDiffImpact:
    """Structural impact analysis from a graph diff."""

    file: str
    symbols_added: int = 0
    symbols_removed: int = 0
    symbols_modified: int = 0
    downstream_impact: int = 0
    upstream_impact: int = 0
    risk_level: str = "low"

    @property
    def total_changes(self) -> int:
        return self.symbols_added + self.symbols_removed + self.symbols_modified

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "symbols_added": self.symbols_added,
            "symbols_removed": self.symbols_removed,
            "symbols_modified": self.symbols_modified,
            "downstream_impact": self.downstream_impact,
            "upstream_impact": self.upstream_impact,
            "risk_level": self.risk_level,
        }


def analyze_graph_diff(
    diff: Any,
    symbol_graph: Any,
) -> list[GraphDiffImpact]:
    """Analyze structural impact of a graph diff (damage vs repair).

    For each file with structural changes, compute downstream/upstream impact.
    """
    if not diff or not diff.has_changes:
        return []

    affected_files: dict[str, GraphDiffImpact] = {}

    for sym in diff.added:
        if sym.file not in affected_files:
            affected_files[sym.file] = GraphDiffImpact(file=sym.file)
        affected_files[sym.file].symbols_added += 1

    for sym in diff.removed:
        if sym.file not in affected_files:
            affected_files[sym.file] = GraphDiffImpact(file=sym.file)
        affected_files[sym.file].symbols_removed += 1

    for sym in diff.modified:
        if sym.file not in affected_files:
            affected_files[sym.file] = GraphDiffImpact(file=sym.file)
        affected_files[sym.file].symbols_modified += 1

    for file, impact in affected_files.items():
        symbols = symbol_graph.get_symbols_in_file(file)
        for s in symbols:
            result = calculate_symbol_blast_radius(s.name, s.file, symbol_graph)
            impact.downstream_impact = max(impact.downstream_impact, result.downstream_count)
            impact.upstream_impact = max(impact.upstream_impact, result.upstream_count)

        total = impact.total_changes
        downstream = impact.downstream_impact
        impact.risk_level = "low"
        if (total >= 3 and downstream >= 5) or (total >= 1 and downstream >= 20):
            impact.risk_level = "critical"
        elif (total >= 2 and downstream >= 3) or downstream >= 10:
            impact.risk_level = "high"
        elif total >= 1 and downstream >= 1:
            impact.risk_level = "medium"

    return list(affected_files.values())
