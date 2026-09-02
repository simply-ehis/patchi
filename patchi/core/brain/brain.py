"""
The Brain — main scan orchestrator for Patchi.

Coordinates:
  1. File scanner (discovery + AST parse)
  2. Framework detector
  3. Route mapper
  4. Import graph builder (+ circular dep detection)
  5. Blast radius map
  6. Dead code detection
  7. App Contract inference
  8. Freshness snapshot save
  9. Brain memory save

The Brain never touches restricted paths. Every path is checked against
the config restrictions before scanning.

Output is a BrainReport: rich structured knowledge of the entire project.
"""

from __future__ import annotations

import logging

_log = logging.getLogger("patchi.brain.brain")
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.brain.blast_radius import (
    BlastRadius,
    build_blast_radius_map,
)
from patchi.core.brain.contract import ContractBuilder, ContractFlow
from patchi.core.brain.file_corpus import FileCorpus
from patchi.core.brain.framework import FrameworkDetector, StackInfo
from patchi.core.brain.freshness import save_freshness_snapshot
from patchi.core.brain.import_graph import (
    ImportGraph,
    build_graph,
    find_circular_dependencies,
    find_dead_files,
)
from patchi.core.brain.layered_brain import build_layers, layers_to_dict
from patchi.core.brain.route_mapper import RouteInfo, RouteMapper
from patchi.core.brain.scanner import FileInfo, FileScanner
from patchi.core.constants import RestrictionType

logger = logging.getLogger("patchi.brain.brain")

# ── Brain report ───────────────────────────────────────────────────────────────


@dataclass
class BrainReport:
    """Full structured knowledge of the project after a brain scan."""

    # Scan metadata
    scanned_at: str = ""
    duration_seconds: float = 0.0
    area: str | None = None  # None = full project

    # File knowledge
    file_infos: list[FileInfo] = field(default_factory=list)
    file_count: int = 0
    language_breakdown: dict[str, int] = field(default_factory=dict)

    # Stack
    stack: StackInfo | None = None

    # Routes
    routes: list[RouteInfo] = field(default_factory=list)
    route_count: int = 0

    # Graph
    import_graph: ImportGraph | None = None
    circular_dependencies: list[Any] = field(default_factory=list)
    dead_files: list[str] = field(default_factory=list)
    blast_radius_map: dict[str, BlastRadius] = field(default_factory=dict)  # Updated type

    # Graph diff (changes since last scan)
    graph_diff: dict[str, Any] = field(default_factory=dict)

    # Layered brain (Pillar 1 of the super-agent architecture)
    layers: dict = field(default_factory=dict)
    layers_rebuilt: list[str] = field(default_factory=list)  # names rebuilt this scan
    layers_changed: bool = False  # whether any file content changed since last scan

    # Guard-rail (charter) violations (Pillar 2)
    charter_violations: list[dict] = field(default_factory=list)

    # Project understanding
    project_purpose: str = ""
    project_domain: str = ""

    # Context phase (domain activation, infrastructure discovery)
    project_context: dict = field(default_factory=dict)
    active_security_domains: list[str] = field(default_factory=list)
    infrastructure_files: list[str] = field(default_factory=list)
    detected_imports: dict[str, set[str]] = field(default_factory=dict)
    # L1 enriched context (Slice 1: one AI call per scan, heuristic fallback)
    enriched_context: dict = field(default_factory=dict)

    # Contract (unconfirmed until user confirms)
    inferred_flows: list[ContractFlow] = field(default_factory=list)
    confirmed_flows: list[ContractFlow] = field(default_factory=list)

    # Doc validation
    doc_validation: dict = field(default_factory=dict)

    # Errors encountered during scan
    errors: list[dict] = field(default_factory=list)

    @property
    def is_partial(self) -> bool:
        return self.area is not None

    def summary_dict(self) -> dict:
        """Compact dict for storing in memory.brain"""
        return {
            "scanned_at": self.scanned_at,
            "duration": round(self.duration_seconds, 2),
            "area": self.area,
            "file_count": self.file_count,
            "route_count": self.route_count,
            "languages": self.language_breakdown,
            "framework": self.stack.frameworks[0].name
            if self.stack and self.stack.frameworks
            else "Unknown",
            "frameworks": [f.to_dict() for f in (self.stack.frameworks if self.stack else [])],
            "runtime": self.stack.runtime if self.stack else "",
            "has_typescript": self.stack.has_typescript if self.stack else False,
            "circular_deps": [c.short_label for c in self.circular_dependencies],
            "dead_files": self.dead_files,
            "error_count": len([fi for fi in self.file_infos if fi.error]),
            "inferred_flows": [f.to_dict() for f in self.inferred_flows],
            "confirmed_flows": [f.to_dict() for f in self.confirmed_flows],
            "project_purpose": self.project_purpose,
            "project_domain": self.project_domain,
            "project_context": self.project_context,
            "active_security_domains": self.active_security_domains,
            "enriched_context": getattr(self, "enriched_context", {}),
            "body_tags_version": 1,
            "doc_validation": self.doc_validation,
            "graph_diff": self.graph_diff,
            "stale": False,
            "last_scan": self.scanned_at,
        }


# ── Progress event ─────────────────────────────────────────────────────────────


@dataclass
class ScanProgress:
    """Emitted during scan for CLI progress bars and Web UI live feed."""

    phase: (
        str  # "discovery" | "parsing" | "framework" | "routes" | "graph" | "context" | "contract"
    )
    current: int = 0
    total: int = 0
    message: str = ""
    file_path: str = ""  # for "brain.scan.file_found" events


# ── Brain ──────────────────────────────────────────────────────────────────────


class Brain:
    """
    The brain of Patchi. Coordinates the full scan pipeline.

    Usage:
        brain = Brain(project_root)
        report = brain.scan()
        report = brain.scan("src/auth")  # targeted
    """

    def __init__(
        self,
        root: Path,
        on_progress: Callable[[ScanProgress], None] | None = None,
    ):
        self.root = root
        self.on_progress = on_progress or (lambda _: None)

    def scan(self, area: str | None = None) -> BrainReport:
        """
        Run the full brain scan pipeline.

        area: optional path/description to limit scope.
        Returns a BrainReport with everything the Brain now knows.
        """
        start_time = time.monotonic()
        report = BrainReport(
            scanned_at=datetime.now(UTC).isoformat(),
            area=area,
        )

        try:
            config = cfg.load(self.root)
        except RuntimeError:
            config = {}

        restrictions = config.get("restrictions", [])
        ignore_paths = config.get("ignore_paths", [])
        max_depth = config.get("scan_depth")

        # Build set of no-touch paths
        no_touch_paths: set[str] = set()
        for r in restrictions:
            if r.get("enabled", True) and r.get("type") == RestrictionType.NO_TOUCH.value:
                no_touch_paths.add(r["path"])
        self._emit(ScanProgress(phase="discovery", message="Discovering project files…"))

        # Load previous brain memory early (used for graph diff and confirmed flows)
        brain_mem = mem.get_brain(self.root)

        # Load incremental scan caches (M-04: hash-based file skipping)
        from patchi.core.brain.scanner import (
            _load_ast_cache,
            _load_file_info_cache,
            _save_ast_cache,
            _save_file_info_cache,
        )

        _load_ast_cache(self.root)
        _load_file_info_cache(self.root)

        # Noise exclusion at discovery time: lockfiles, generated/minified
        # bundles, and docs never enter the corpus, so no agent wastes a
        # pass on them and no findings can originate there. Supersedes the
        # old hardcoded 5-lockfile skip_files list.
        #
        # IgnoreLearner adds self-learned rules on top: .gitignore patterns,
        # directories with chronic false-positive history, and structurally
        # tool-owned data dirs (e.g. YAML rule packs nothing imports).
        learner = None
        known_fps: list = []
        try:
            import json as _json

            from patchi.core.security.ignore_learner import IgnoreLearner

            fp_path = self.root / ".patchi/memory/known_false_positives.json"
            if fp_path.is_file():
                try:
                    known_fps = _json.loads(fp_path.read_text(encoding="utf-8"))
                except Exception:  # noqa: BLE001
                    known_fps = []
            scan_cfg = {}
            try:
                from patchi.core.config import load as _cfg_load

                scan_cfg = _cfg_load(self.root)
            except Exception:  # noqa: BLE001
                scan_cfg = {}
            if not isinstance(scan_cfg, dict):
                scan_cfg = {}
            learner = IgnoreLearner(self.root, scan_cfg)
            learner.build(known_fps=known_fps or None)
        except Exception as _le:  # noqa: BLE001 — learning is best-effort
            logging.getLogger("patchi.brain").debug("ignore learner unavailable: %s", _le)
            learner = None

        corpus = FileCorpus(self.root, exclude_noise=True, ignore_learner=learner)

        # Second pass: composition analysis needs the discovered file list.
        # Tool-owned data dirs (YAML rule packs, changelog dirs, ...) found
        # now are pruned immediately and remembered for future scans.
        if learner is not None:
            try:
                learner.build(
                    known_fps=known_fps or None,
                    file_paths=list(corpus.entries.keys()),
                )
                corpus.prune_with(learner)
                learner.promote_to_global()
            except Exception as _pe:  # noqa: BLE001
                logging.getLogger("patchi.brain").debug("learner second pass failed: %s", _pe)

        scanner = FileScanner(
            root=self.root,
            ignore_paths=list(no_touch_paths) + ignore_paths,
            max_depth=max_depth,
            corpus=corpus,
        )

        all_paths = scanner.discover(area)
        total = len(all_paths)
        self._emit(
            ScanProgress(phase="parsing", current=0, total=total, message=f"Parsing {total} files…")
        )

        file_infos: list[FileInfo] = []
        for i, path in enumerate(all_paths):
            rel = path.relative_to(self.root).as_posix()
            self._emit(
                ScanProgress(
                    phase="parsing",
                    current=i + 1,
                    total=total,
                    file_path=rel,
                    message=f"Parsing {rel}",
                )
            )
            fi = scanner.scan_file(path)
            file_infos.append(fi)
            if fi.error:
                report.errors.append({"file": fi.path, "error": fi.error})

        report.file_infos = file_infos
        report.file_count = len(file_infos)
        report.language_breakdown = _count_languages(file_infos)
        self._emit(ScanProgress(phase="framework", message="Detecting framework and stack…"))
        detector = FrameworkDetector(self.root, corpus=corpus)
        stack = detector.detect()
        report.stack = stack

        if stack.frameworks:
            fw_names = ", ".join(f.name for f in stack.frameworks[:3])
            self._emit(ScanProgress(phase="framework", message=f"Detected: {fw_names}"))
        self._emit(ScanProgress(phase="routes", message="Mapping routes and endpoints…"))
        mapper = RouteMapper(self.root, stack)
        routes = mapper.extract(file_infos)
        report.routes = routes
        report.route_count = len(routes)
        self._emit(ScanProgress(phase="routes", message=f"Found {len(routes)} routes"))
        self._emit(ScanProgress(phase="graph", message="Building import graph…"))
        graph = build_graph(file_infos, self.root)
        circular_deps = find_circular_dependencies(graph)
        dead_files = find_dead_files(file_infos, graph)
        blast_map = build_blast_radius_map(graph)  # Updated call

        # ── Import graph diff against previous scan ──────────────────────────
        old_edges: set[tuple[str, str]] = set()
        old_nodes: set[str] = set()
        prev_graph_data = brain_mem.get("import_graph", {})
        if prev_graph_data:
            for src, targets in prev_graph_data.get("edges", {}).items():
                for tgt in targets:
                    old_edges.add((src, tgt))
            old_nodes = set(prev_graph_data.get("nodes", []))

        new_edges: set[tuple[str, str]] = set()
        for src, targets in graph.edges.items():
            for tgt in targets:
                new_edges.add((src, tgt))
        new_nodes = set(graph.nodes)

        report.graph_diff = {
            "added_edges": sorted([list(e) for e in new_edges - old_edges]),
            "removed_edges": sorted([list(e) for e in old_edges - new_edges]),
            "new_files": sorted(new_nodes - old_nodes),
            "removed_files": sorted(old_nodes - new_nodes),
        }

        report.import_graph = graph
        report.circular_dependencies = circular_deps
        report.dead_files = dead_files
        report.blast_radius_map = blast_map  # Updated assignment

        # ── Layered brain (Pillar 1) — incremental when prior state exists ────
        self._emit(ScanProgress(phase="graph", message="Building layered brain…"))
        try:
            from patchi.core.brain.brain_watcher import (
                build_or_update,
                file_snapshot,
            )
            from patchi.core.brain.layered_brain import layers_from_dict

            _old_data = mem.read(mem.MemoryCategory.LAYERS, self.root) or {}
            _old_layers = layers_from_dict(_old_data) if _old_data.get("layers") else {}
            _old_snap = _old_data.get("file_snapshot")
            report.layers, _rebuilt, _changes = build_or_update(
                _old_layers,
                file_infos,
                graph,
                routes,
                stack,
                old_snapshot=_old_snap,
                root=self.root,
            )
            report.layers_rebuilt = sorted(_rebuilt)
            report.layers_changed = _changes.any
            _new_snap = file_snapshot(file_infos, self.root)
            # Record which layers are stale so consumers (scan/incremental) can
            # skip or rebuild only what changed. BrainWatcher "detects, never acts".
            if _changes.any:
                try:
                    mem.mark_brain_stale(
                        sorted(_changes.all_paths),
                        self.root,
                        stale_layers=sorted(_rebuilt),
                    )
                except Exception as e:
                    logger.warning("Brain.scan failed: %s", e)
        except Exception as e:
            # Fall back to a full (non-incremental) build — never break the scan.
            logger.warning("Brain.scan failed: %s", e)
            report.layers = build_layers(file_infos, graph, routes, stack)
            report.layers_rebuilt = sorted(report.layers.keys())
            report.layers_changed = True
            _new_snap = {}

        # ── Guard rails: charter drift detection (Pillar 2) ──────────────────
        self._emit(ScanProgress(phase="graph", message="Checking project charter…"))
        try:
            from patchi.core.brain.charter import check_charter, load_charter

            charter = load_charter(self.root)
            if charter is not None:
                detected_fw = (
                    [f.name for f in stack.frameworks] if stack and stack.frameworks else []
                )
                violations = check_charter(
                    charter,
                    {name: lyr.to_dict() for name, lyr in report.layers.items()},
                    detected_frameworks=detected_fw,
                    routes=routes,
                    file_infos=file_infos,
                )
                report.charter_violations = [v.to_finding() for v in violations]
        except Exception as e:
            logger.warning("Brain.scan failed: %s", e)

        self._emit(
            ScanProgress(
                phase="graph",
                message=(
                    f"{len(graph.nodes)} nodes · "
                    f"{len(circular_deps)} circular deps · "
                    f"{len(dead_files)} dead files"
                ),
            )
        )
        # ── Context phase: discover docs, infrastructure, dependencies ────────
        self._emit(
            ScanProgress(phase="context", message="Discovering documentation and infrastructure…")
        )
        context_data = self._discover_project_context(self.root, file_infos, report, stack)
        report.project_context = context_data["context"]
        report.active_security_domains = context_data["active_domains"]
        report.infrastructure_files = context_data["infrastructure_files"]

        self._emit(
            ScanProgress(
                phase="context",
                message=(
                    f"{len(context_data['active_domains'])} security domain(s) activated · "
                    f"dep: {context_data['context'].get('deployment_model', 'local')}"
                ),
            )
        )
        # ── L2 Body tags + Understander (core-aware, not insertion order) ─
        body_tags: dict[str, dict] = {}
        try:
            from patchi.core.brain.body_tags import build_body_tags, save_body_tags
            from patchi.core.brain.understander import Understander

            # Need layers already built (previous phase sets report.layers at line ~410)
            layers_dict = getattr(report, "layers", {}) or {}
            body_tags = build_body_tags(
                report.file_infos, report.import_graph, layers_dict, report.routes, report.blast_radius_map
            )
            save_body_tags(body_tags, self.root)
            self._emit(ScanProgress(phase="context", message=f"Body tags: {len(body_tags)} files tagged"))
            # stash for understander reuse
            report.body_tags = body_tags  # type: ignore[attr-defined]
            # Understander instance for enriched + contract phases
            _understander = Understander(self.root, report.file_infos, body_tags, report.blast_radius_map, report.routes)
            report._understander = _understander  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            logger.warning("body_tags/understander failed: %s", exc)
            body_tags = {}
            # keep report._understander unset -> fallbacks use slicing

        # ── L1 Enriched context (one AI call, offline-safe) ──────────────────
        try:
            from patchi.core.brain.enriched_context import enrich_project_context

            cfg_for_ai: dict = {}
            try:
                cfg_for_ai = cfg.load(self.root)
                if not isinstance(cfg_for_ai, dict):
                    cfg_for_ai = {}
            except Exception:
                cfg_for_ai = {}
            # L1 spec: ProjectInsight + StackInfo + layer summaries (1 call, 1s timeout honoured)
            _core_hint: dict = {}
            if getattr(report, "_understander", None) is not None:
                try:
                    _u_block = report._understander.as_prompt_block(limit=8)  # type: ignore[attr-defined]
                    _core_hint["core_files_block"] = _u_block
                except Exception as _exc:
                    _log.debug('suppressed: %s', _exc)
            # ProjectInsight
            try:
                from patchi.core.brain.project_reader import read_project_insight

                _pi = read_project_insight(self.root)
                _core_hint["project_insight"] = _pi.to_dict()
            except Exception as _exc:
                _log.debug('suppressed: %s', _exc)
            # Layer summaries (up to 10)
            try:
                _layer_summ = []
                for lname, lyr in getattr(report, "layers", {}).items():
                    _layer_summ.append({"name": lname, "level": getattr(lyr, "level", 0), "summary": getattr(lyr, "summary", "")[:220]})
                    if len(_layer_summ) >= 10:
                        break
                _core_hint["layer_summaries"] = _layer_summ
            except Exception as _exc:
                _log.debug('suppressed: %s', _exc)
            report.enriched_context = enrich_project_context(
                self.root,
                cfg_for_ai,
                report.stack,
                report.routes,
                report.file_infos,
                report.project_context,
                report.active_security_domains,
                extra_context=_core_hint,
            )
            self._emit(
                ScanProgress(
                    phase="context",
                    message=f"Enriched: {report.enriched_context.get('domain','?')} "
                    f"({report.enriched_context.get('source','?')})",
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("enriched_context failed, heuristic fallback: %s", exc)
            report.enriched_context = {
                "purpose_1sent": report.project_context.get("purpose", "") if isinstance(report.project_context, dict) else "",
                "source": "heuristic_wire_fallback",
            }
        # ── Project purpose (AI-powered or fallback) ──────────────────────────
        self._emit(ScanProgress(phase="contract", message="Understanding project purpose…"))
        report.project_purpose, report.project_domain = self._infer_project_purpose(
            file_infos, stack, report
        )

        self._emit(ScanProgress(phase="contract", message="Understanding project…"))
        builder = ContractBuilder(routes, file_infos, dead_files, circular_deps, root=self.root)

        # Smart inference: reads project files first, then falls back
        # to AI-powered, then pattern-based
        config = {}
        try:
            config = cfg.load(self.root)
        except RuntimeError:
            config = {}

        # Try project-aware inference first (reads README, package.json, etc.)
        project_flows = builder.project_infer()
        if project_flows:
            inferred = project_flows
        else:
            # Fall back to AI-powered contract
            ai_flows = builder.ai_infer(config)
            inferred = ai_flows if ai_flows is not None else builder.infer()
        report.inferred_flows = inferred

        # Auto-lock contract if flows were inferred (non-interactive)
        # This allows p fix to work without requiring --contract first
        if inferred and not brain_mem.get("contract_locked"):
            # Auto-confirm all non-suggested flows with medium+ confidence
            auto_confirmed = [f for f in inferred if not f.suggested and f.confidence in ("high", "medium")]
            if auto_confirmed:
                for f in auto_confirmed:
                    f.confirmed = True
                brain_mem["confirmed_flows"] = [f.to_dict() for f in auto_confirmed]
                brain_mem["contract_locked"] = True
                brain_mem["contract_auto_formed"] = True
                logger.info("Auto-locked contract with %d flows", len(auto_confirmed))

        # Load any previously confirmed flows from memory
        if brain_mem.get("confirmed_flows"):
            from patchi.core.brain.contract import flows_from_dict

            report.confirmed_flows = flows_from_dict(brain_mem["confirmed_flows"])
        save_freshness_snapshot(self.root, [fi.path for fi in file_infos])

        # ── Documentation validation ──────────────────────────────────────────
        self._emit(
            ScanProgress(phase="doc-validation", message="Validating documentation against code…")
        )
        doc_result = self._run_doc_validation(self.root, file_infos, routes, config, brain_mem)
        report.doc_validation = doc_result
        brain_mem["doc_validation"] = doc_result

        # ── Save to memory ────────────────────────────────────────────────────
        report.duration_seconds = time.monotonic() - start_time
        brain_data = report.summary_dict()
        brain_data["import_graph"] = graph.to_dict()

        # Preserve confirmed flows from previous scan if this is targeted
        if area and brain_mem.get("confirmed_flows"):
            brain_data["confirmed_flows"] = brain_mem["confirmed_flows"]

        # Persist doc validation results
        if brain_mem.get("doc_validation"):
            brain_data["doc_validation"] = brain_mem["doc_validation"]

        mem.save_brain(brain_data, self.root)

        # ── Build assurance graph (auto-populated each scan) ──────────────────
        try:
            from patchi.core.assurance.builder import build_assurance_graph

            assurance_graph = build_assurance_graph(
                self.root,
                brain_data=brain_data,
                route_map=[r.to_dict() for r in report.routes] if report.routes else None,
                import_graph_data=graph.to_dict() if graph else None,
            )
            assurance_graph.save(self.root)
            report.assurance_graph = (
                assurance_graph.to_dict()
                if hasattr(report, "assurance_graph")
                else assurance_graph.to_dict()
            )
        except Exception as e:
            logger.debug("Assurance graph build skipped: %s", e)

        # ── Contract diff 3.1.3-7 — frontend ↔ backend mismatch (missing/orphan/method/param) ─
        try:
            from patchi.core.brain.contract_diff import build_and_save as _cd_build

            _cd = _cd_build(self.root, report.file_infos, report.routes)
            report.contract_diff = _cd.to_dict()  # type: ignore[attr-defined]
            # surface as findings for p findings / gate (only missing + orphan at medium)
            from patchi.core.agents.base import Finding, Severity

            _cd_findings = []
            for m in _cd.missing_routes:
                _cd_findings.append(
                    Finding(
                        agent="ContractDiff",
                        type="contract_missing_route",
                        severity=Severity.MEDIUM,
                        file=m.get("file", ""),
                        line=m.get("line", 0),
                        message=f"Frontend calls {m.get('method')} {m.get('raw')} with no backend route (404)",
                        cwe="CWE-444",
                    ).to_dict()
                )
            for o in _cd.orphan_endpoints:
                _cd_findings.append(
                    Finding(
                        agent="ContractDiff",
                        type="contract_orphan_endpoint",
                        severity=Severity.LOW,
                        file=o.get("file", ""),
                        line=o.get("line", 0),
                        message=f"Backend {o.get('method')} {o.get('path')} never called by frontend (dead API)",
                    ).to_dict()
                )
            if _cd_findings:
                mem.save_scan_result("ContractDiff", {"findings": _cd_findings}, self.root)
        except Exception as exc:  # noqa: BLE001
            _log.debug("contract_diff failed: %s", exc)

        # Persist the layered brain (Pillar 1) as a separate memory file, plus the
        # file-content snapshot that powers incremental (no-op) rebuilds.
        # L3: build RAG index at scan time (cached layer[].summary embeddings)
        try:
            if report.layers:
                _layers_data = layers_to_dict(report.layers)
                if _new_snap:
                    _layers_data["file_snapshot"] = _new_snap
                # L3 RAG index: term frequencies per layer, stored for cosine query
                try:
                    import re as _re

                    _rag_index: dict[str, dict] = {}
                    for _lname, _lyr in report.layers.items():
                        txt = f"{_lname} {getattr(_lyr,'summary','')} {getattr(_lyr,'purpose','')}".lower()
                        toks = [t for t in _re.findall(r"[a-z0-9_]+", txt) if len(t) > 2]
                        tf: dict[str, int] = {}
                        for t in toks:
                            tf[t] = tf.get(t, 0) + 1
                        _rag_index[_lname] = {"tf": tf, "summary": getattr(_lyr, "summary", "")[:500]}
                    _layers_data["rag_index"] = _rag_index
                    _layers_data["rag_index_version"] = 1
                except Exception as _exc:
                    _log.debug('suppressed: %s', _exc)
                mem.save_layers(_layers_data, self.root)
        except Exception as e:
            logger.warning("Brain.scan failed: %s", e)
        # Persist charter violations as a scan result (Pillar 2) so they surface
        # in the unified findings list for both humans and agents. Always saved
        # (even if empty) to clear stale findings from a previous scan.
        try:
            mem.save_scan_result(
                "CharterGuard",
                {"findings": report.charter_violations},
                self.root,
            )
        except Exception as e:
            logger.warning("Brain.scan failed: %s", e)
        mem.save_scan_result(
            "Brain",
            {
                "file_count": report.file_count,
                "route_count": report.route_count,
                "duration": round(report.duration_seconds, 2),
                "area": area,
            },
            self.root,
        )

        # Record health score to scan_history SQLite (M-09)
        try:
            from patchi.core.health import compute as compute_health
            from patchi.core.security.history import patchi_record_scan

            hs = compute_health(self.root)
            # Flatten findings from scan results for history
            scan_results = mem.get_scan_results(self.root)
            all_findings = []
            for _agent_name, data in scan_results.items():
                for f in data.get("findings", []):
                    if isinstance(f, dict):
                        all_findings.append(f)
            patchi_record_scan(
                self.root,
                "Brain",
                all_findings,
                duration_ms=int(report.duration_seconds * 1000),
                health_score=hs.total,
            )
        except Exception as e:
            logger.warning("Brain.scan failed: %s", e)

        # Persist incremental scan caches (M-04)
        try:
            _save_ast_cache(self.root)
            _save_file_info_cache(self.root)
        except Exception as e:
            logger.warning("Brain.scan failed: %s", e)

        return report

    def _run_doc_validation(
        self,
        root: Path,
        file_infos: list[FileInfo],
        routes: list[RouteInfo],
        config: dict,
        brain_mem: dict,
    ) -> dict:
        """Validate documentation against actual code.

        Uses DocClaimAgent (LLM-based) when AI is available, falls back
        to heuristic doc_validator for offline mode.
        """
        ai_config = config.get("ai", {})
        has_ai = bool(ai_config.get("keys") or ai_config.get("local_model_name"))

        if has_ai:
            try:
                from patchi.core.agents.base import AgentInput, AgentResult
                from patchi.core.agents.doc_claim_agent import (
                    DocClaimAgent,
                    verify_claims_against_code,
                )

                agent = DocClaimAgent()
                inp = AgentInput(
                    root=root,
                    scope=[],
                    brain=brain_mem,
                    config=config,
                    extra={},
                )
                result = AgentResult(agent_name="DocClaimAgent", agent_group="SCANNER")
                agent._run(inp, result)

                claims = result.data.get("claims", [])
                if claims:
                    claims = verify_claims_against_code(
                        claims=claims,
                        file_infos=file_infos,
                        routes=routes,
                        config=config,
                    )
                    verified = [c for c in claims if c.get("verified")]
                    stale = [c for c in claims if not c.get("verified")]
                    doc_files = result.data.get("doc_files_found", [])
                    return {
                        "validated_claims": verified,
                        "stale_claims": stale,
                        "summary": (
                            f"DocClaimAgent: {len(verified)} verified, {len(stale)} stale "
                            f"across {len(doc_files)} doc file(s)."
                        ),
                        "doc_files_found": doc_files,
                        "total_claims": len(claims),
                        "method": "llm",
                    }

                # LLM returned no claims but was available — use heuristic fallback
                logger.info("DocClaimAgent returned no claims, falling back to heuristic")
            except Exception as e:
                logger.warning(f"DocClaimAgent failed: {e}")

        # Fallback: heuristic doc_validator
        try:
            from patchi.core.brain.doc_validator import validate_project_docs

            result = validate_project_docs(root, file_infos, routes, ai_config)
            result["method"] = "heuristic"
            return result
        except Exception as e:
            logger.warning(f"Doc validator fallback also failed: {e}")
            return {
                "validated_claims": [],
                "stale_claims": [],
                "summary": "Doc validation unavailable",
                "doc_files_found": [],
                "total_claims": 0,
                "method": "none",
            }

    def _infer_project_purpose(
        self,
        file_infos: list[FileInfo],
        stack: StackInfo,
        report: BrainReport,
    ) -> tuple[str, str]:
        """
        Infer what the project does using AI (preferred) or fallback heuristics.
        Returns (project_purpose, project_domain).
        """
        # Try AI first
        try:
            config = cfg.load(self.root)
            ai_config = config.get("ai", {})
        except RuntimeError:
            config = {}
            ai_config = {}
        has_ai = bool(ai_config.get("keys")) or bool(ai_config.get("local_model_name"))
        active_domains = report.active_security_domains
        if has_ai:
            purpose = self._ai_project_purpose(file_infos, stack, config, report.routes)
            if purpose:
                domain = self._domain_from_purpose(purpose, active_domains)
                return purpose, domain

        # Fallback: build purpose from frameworks, routes, and file purposes
        frameworks = [f.name for f in (stack.frameworks if stack else [])]
        fw = ", ".join(frameworks) if frameworks else "Unknown"

        # Determine category from file purposes
        purposes = [fi.purpose for fi in file_infos if fi.purpose]
        has_routes = bool(report.routes)
        has_cli = any("cli" in p.lower() for p in purposes)
        has_web = any(
            "web" in p.lower() or "route" in p.lower() or "api" in p.lower() or "http" in p.lower()
            for p in purposes
        )
        has_test = any("test" in p.lower() for p in purposes)
        has_security = any(
            "security" in p.lower() or "scanner" in p.lower() or "audit" in p.lower()
            for p in purposes
        )
        has_models = any(
            "model" in p.lower() or "schema" in p.lower() or "database" in p.lower()
            for p in purposes
        )

        # Build category description
        parts = []
        if has_web and has_routes:
            parts.append("web application")
        elif has_web:
            parts.append("web-enabled project")
        if has_cli:
            parts.append("CLI tool")
        if has_models:
            parts.append("data-driven")
        if has_security:
            parts.append("security analysis tool")
        if has_test:
            parts.append("test framework")
        if not parts:
            parts.append("software project")

        category = " + ".join(parts)
        route_count = len(report.routes)
        route_note = f" with {route_count} routes" if route_count > 0 else ""

        purpose = f"A {fw} {category}{route_note}."
        domain = self._domain_from_purpose(purpose, report.active_security_domains)
        return purpose, domain

    def _ai_project_purpose(
        self,
        file_infos: list[FileInfo],
        stack: StackInfo,
        config: dict,
        routes: list[RouteInfo] | None = None,
    ) -> str | None:
        """Use AI to generate a one-sentence project purpose."""
        from patchi.core.ai.prompts import Skill, get_system_prompt
        from patchi.core.fix.base import _call_ai

        # Summarise the top 30 files for context
        lines = []
        for fi in file_infos[:30]:
            funcs = ", ".join(f.name for f in fi.functions[:3])
            classes = ", ".join(c.name for c in fi.classes[:3])
            parts = [fi.path]
            if fi.purpose:
                parts.append(f"({fi.purpose})")
            if funcs:
                parts.append(f"fns: [{funcs}]")
            if classes:
                parts.append(f"cls: [{classes}]")
            lines.append(" ".join(parts))

        frameworks = [f.name for f in (stack.frameworks if stack else [])]
        fw = ", ".join(frameworks) if frameworks else "Unknown"
        route_lines = [r.method + " " + r.path for r in (routes or [])[:20]]

        prompt = (
            "Analyse this codebase and answer in ONE SHORT SENTENCE what the project does. "
            "Then on the next line, tell me the domain "
            "(e.g. web-app, CLI-tool, library, game, dev-tool, mobile-app, data-pipeline).\n\n"
            f"Framework: {fw}\n"
            f"Total files: {len(file_infos)}\n"
            f"Routes ({len(route_lines)} shown):\n" + "\n".join(route_lines) + "\n\n"
            "Key files:\n" + "\n".join(lines) + "\n\n"
            "Format:\n"
            "PURPOSE: <one sentence>\n"
            "DOMAIN: <domain>"
        )
        sys_prompt = get_system_prompt(Skill.SCAN_SUMMARY)
        result = _call_ai(prompt, config, max_tokens=200, system_prompt=sys_prompt)
        if not result:
            return None

        lines = result.strip().split("\n")
        purpose = ""
        domain = ""
        for line in lines:
            if line.upper().startswith("PURPOSE:"):
                purpose = line.split(":", 1)[1].strip()
            elif line.upper().startswith("DOMAIN:"):
                domain = line.split(":", 1)[1].strip()

        if purpose:
            self.project_domain = domain
            return purpose
        return None

    @staticmethod
    def _domain_from_purpose(purpose: str, active_domains: list[str] | None = None) -> str:
        """Infer a short domain label from a purpose sentence heuristically."""
        p = purpose.lower()
        if active_domains:
            if "mobile" in active_domains:
                return "mobile-app"
            if "desktop-app" in active_domains:
                return "desktop-app"
            if "agent-orchestration" in active_domains:
                return "agent-orchestrator"
            if "github-app-bot" in active_domains:
                return "github-app"
            if "mcp-tool-surface" in active_domains:
                return "mcp-tool"
        if any(w in p for w in ("web", "http", "api", "rest", "server", "frontend")):
            return "web-app"
        if any(w in p for w in ("cli", "command line", "terminal")):
            return "CLI-tool"
        if any(w in p for w in ("library", "package", "sdk")):
            return "library"
        if any(w in p for w in ("game", "gaming")):
            return "game"
        if any(w in p for w in ("mobile", "android", "ios")):
            return "mobile-app"
        if any(w in p for w in ("data", "pipeline", "etl", "analytics")):
            return "data-pipeline"
        if any(w in p for w in ("dev", "developer", "tool")):
            return "dev-tool"
        return "unknown"

    def _discover_project_context(
        self,
        root: Path,
        file_infos: list[FileInfo],
        report: BrainReport,
        stack: StackInfo,
    ) -> dict:
        """
        Discover documentation, config files, infrastructure, and dependencies
        to build a rich project context dict and activate security domains.

        This is the Brain's "context" phase — it gathers everything needed
        to determine what kind of project this is and which domains apply.
        """
        from patchi.core.brain.domain_activator import build_project_context

        doc_files: list[str] = []
        config_files: list[str] = []
        infra_files: list[str] = []
        dependency_names: set[str] = set()
        detected_imports: set[str] = set()
        file_extensions: set[str] = set()

        doc_patterns = {".md", ".rst", ".txt", ".adoc"}
        config_patterns = {".toml", ".json", ".cfg", ".conf", ".ini", ".env"}
        infra_keywords = [
            "dockerfile",
            "docker-compose",
            "kubernetes",
            "k8s",
            "deployment",
            "service.yaml",
            "terraform",
            "cloudformation",
            "pulumi",
            "github/",
            "gitlab-ci",
            "jenkinsfile",
            "circleci",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "requirements.txt",
            "Pipfile",
            "poetry.lock",
            "go.sum",
            "Cargo.lock",
            "Gemfile.lock",
            "serverless.yml",
            "template.yaml",
            "wrangler.toml",
            "manifest.json",
        ]

        for fi in file_infos:
            rel = fi.path.replace("\\", "/")
            lower_path = rel.lower()
            ext = Path(rel).suffix

            if ext in doc_patterns:
                doc_files.append(rel)
            elif ext in config_patterns:
                config_files.append(rel)
            if any(kw in lower_path for kw in infra_keywords):
                infra_files.append(rel)

            file_extensions.add(ext if ext.startswith(".") else f".{ext}" if ext else "")

            for imp in fi.imports:
                detected_imports.add(imp.name if hasattr(imp, "name") else str(imp))

        file_extensions.discard("")

        # Extract dependency names from package manifests
        for mf in ["package.json", "requirements.txt", "pyproject.toml", "Cargo.toml", "go.mod"]:
            mf_path = root / mf
            if mf_path.exists():
                try:
                    text = mf_path.read_text(encoding="utf-8", errors="replace")
                    if mf == "package.json":
                        import json

                        pkg = json.loads(text)
                        for section in ("dependencies", "devDependencies", "peerDependencies"):
                            for name in pkg.get(section, {}):
                                dependency_names.add(name.lower())
                    else:
                        for line in text.splitlines():
                            line = line.strip()
                            if line and not line.startswith(("#", "//", "--", "[")):
                                if "=" in line:
                                    dependency_names.add(line.split("=")[0].strip().lower())
                                elif ":" in line:
                                    pass  # skip JSON-like lines
                                elif line.startswith("require ") or line.startswith("module "):
                                    pass  # skip Go module directives
                                else:
                                    name = line.split(">=")[0].split("~=")[0].split("==")[0].strip()
                                    if name and not name.startswith(("-", "_", ".")):
                                        dependency_names.add(name.lower())
                except Exception as e:
                    logger.warning("Brain._discover_project_context failed: %s", e)

        # Determine framework flags
        has_web = bool(stack.frameworks) and any(
            f.name.lower() in ("fastapi", "flask", "django", "express", "spring", "gin", "echo")
            for f in stack.frameworks
        )
        has_cli = bool(stack.frameworks) and any(
            f.name.lower() in ("click", "typer", "argparse", "commander", "cobra", "urfave/cli")
            for f in stack.frameworks
        )
        has_mobile = any(
            ext in (".kt", ".kts", ".swift", ".dart", ".java", ".gradle") for ext in file_extensions
        )

        route_paths = [r.path for r in report.routes if hasattr(r, "path")]
        config_keys: set[str] = set()
        for cf in config_files:
            full_path = root / cf
            try:
                text = full_path.read_text(encoding="utf-8", errors="replace")[:5000]
                for line in text.splitlines():
                    if "=" in line or ":" in line:
                        config_keys.add(line.split("=")[0].split(":")[0].strip().lower())
            except Exception as e:
                logger.warning("Brain._discover_project_context failed: %s", e)

        context = build_project_context(
            file_infos=file_infos,
            detected_imports=detected_imports,
            dependency_names=dependency_names,
            route_paths=route_paths,
            config_keys=config_keys,
            infrastructure_files=infra_files,
            has_web_framework=has_web,
            has_cli_framework=has_cli,
            has_mobile_code=has_mobile,
            file_extensions=file_extensions,
        )

        return {
            "context": context,
            "active_domains": context.get("relevant_domains", []),
            "infrastructure_files": infra_files,
            "doc_files": doc_files,
            "config_files": config_files,
        }

    def _emit(self, progress: ScanProgress) -> None:
        try:
            self.on_progress(progress)
        except Exception as e:
            logger.warning("Brain._emit failed: %s", e)


# ── Helpers ────────────────────────────────────────────────────────────────────


def _count_languages(file_infos: list[FileInfo]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for fi in file_infos:
        lang = fi.language.value
        counts[lang] = counts.get(lang, 0) + 1
    # Sort by count descending
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))
