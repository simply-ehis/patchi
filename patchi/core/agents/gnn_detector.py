"""
GNN-based bug detection agent for Patchi.

Uses a true Graph Neural Network (GIN + GAT) over Code Property Graphs to
flag vulnerability patterns. High-recall by design: findings are MEDIUM
"review these functions" signals with CWE references — never proof.

Honesty contract (PLAN_runtime_bug_detection.md Slice 3.2):
  - model missing / checksum bad / weights untrained -> clear skip line,
    zero findings. NEVER a silent no-op, never fabricated output.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Severity,
    make_finding,
    register,
)

logger = logging.getLogger("patchi.core.agents.gnn_detector")

_SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git", "build", "dist"}
_ANALYZE_EXTENSIONS = {".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp"}


@register
class GNNBugDetector(BaseAgent):
    """Graph-pattern vulnerability detector (GIN+GAT over CPGs)."""

    name = "GNNBugDetector"
    group = AgentGroup.SECURITY
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        cfg = inp.config or {}
        gnn_cfg = cfg.get("gnn", {}) or {}
        allow_untrained = bool(gnn_cfg.get("allow_untrained", False))
        threshold = float(gnn_cfg.get("threshold", 0.5))
        max_files = int(gnn_cfg.get("max_files", 100))

        from patchi.core.agents.gnn_models import GNNVulnerabilityClassifier

        model = GNNVulnerabilityClassifier(
            allow_untrained=allow_untrained, threshold=threshold
        )
        if not model.available:
            # Honest skip: visible in result data AND agent logs.
            reason = model.skip_reason()
            logger.info("GNNBugDetector skipped: %s", reason)
            result.data["skipped_reason"] = reason
            result.files_scanned = 0
            result.status = self._status_skipped()
            return

        cpg_available = self._cpg_available()
        if not cpg_available:
            result.data["skipped_reason"] = "CPG extractor unavailable"
            result.files_scanned = 0
            result.status = self._status_skipped()
            return

        from patchi.core.agents.cpg_extractor import CPGExtractor

        extractor = CPGExtractor()
        root = Path(inp.root)
        files = self._files_to_analyze(inp, max_files)

        findings_added = 0
        processed = 0
        for rel_path, abs_path in files:
            try:
                graph = extractor.extract_graph(str(abs_path), root)
                if not graph or not graph.get("nodes"):
                    continue
            except Exception as e:  # noqa: BLE001
                logger.debug("CPG extraction failed for %s: %s", rel_path, e)
                continue

            for vuln in model.detect_vulnerabilities(graph):
                severity = Severity(vuln.get("severity", "info"))
                finding = make_finding(
                    agent=self.name,
                    finding_type="model_detected_vulnerability",
                    severity=severity,
                    file=rel_path,
                    line=int(vuln.get("line", 0)),
                    message=vuln.get("title", "GNN pattern match"),
                    detail=vuln.get("description", ""),
                    suggestion=vuln.get("suggestion", ""),
                    cwe=vuln.get("cwe", ""),
                    confidence=vuln.get("confidence", 0.5),
                    function=vuln.get("function", ""),
                    trusted_model=model.trusted,
                )
                result.add_finding(finding)
                findings_added += 1
            processed += 1

        result.files_scanned = processed
        result.data["gnn_findings"] = findings_added
        result.data["model_trusted"] = model.trusted
        result.status = self._status_done()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _status_skipped(self):
        from patchi.core.agents.base import AgentStatus

        return AgentStatus.SKIPPED

    def _status_done(self):
        from patchi.core.agents.base import AgentStatus

        return AgentStatus.DONE

    def _cpg_available(self) -> bool:
        try:
            from patchi.core.agents.cpg_extractor import CPGExtractor  # noqa: F401

            return True
        except ImportError:
            return False

    def _files_to_analyze(self, inp: AgentInput, max_files: int):
        root = Path(inp.root)
        if inp.scope:
            for rel in inp.scope[:max_files]:
                p = (root / rel).resolve()
                if p.is_file() and p.suffix.lower() in _ANALYZE_EXTENSIONS:
                    yield rel.replace("\\", "/"), p
            return
        count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                if count >= max_files:
                    return
                if Path(name).suffix.lower() not in _ANALYZE_EXTENSIONS:
                    continue
                p = Path(dirpath) / name
                rel = p.relative_to(root).as_posix()
                yield rel, p
                count += 1
