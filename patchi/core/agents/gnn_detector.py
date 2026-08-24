"""
GNN-based bug detection agent for Patchi.

This agent uses Graph Neural Networks to detect structural vulnerabilities in code
by analyzing Code Property Graphs (CPGs). It complements the existing static analysis
and AI-powered fix generation pipeline.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    register,
)

logger = logging.getLogger(__name__)


def make_finding(
    agent: str,
    finding_type: str,
    severity: str,
    file: str,
    line: int = 0,
    message: str = "",
    detail: str = "",
    code_snippet: str = "",
    suggestion: str = "",
    fix_agent: Optional[str] = None,
    cwe: str = "",
    **kwargs,
) -> Finding:
    """Create a finding for the GNN detector."""
    return Finding(
        agent=agent,
        type=finding_type,
        severity=severity,
        file=file,
        line=line,
        message=message,
        detail=detail,
        code_snippet=code_snippet,
        suggestion=suggestion,
        fix_agent=fix_agent,
        cwe=cwe,
        extra=kwargs,
    )


@register
class GNNBugDetector(BaseAgent):
    """
    GNN-based bug detection agent.

    Uses Graph Neural Networks to detect structural vulnerabilities by analyzing
    Code Property Graphs (CPGs). This agent complements the existing static analysis
    pipeline by providing deeper semantic analysis of code structure.

    The agent processes files through a three-stage pipeline:
    1. Graph extraction (CPG creation)
    2. GNN inference for vulnerability detection
    3. Finding generation and integration
    """

    name = "GNNBugDetector"
    group = AgentGroup.SECURITY
    timeout = 60

    def __init__(self):
        super().__init__()
        self.model = None
        self.graph_extractor = None
        self._initialize_model()

    def _initialize_model(self) -> None:
        """Initialize the GNN model and graph extractor."""
        try:
            # Import here to avoid hard dependencies
            from patchi.core.agents.gnn_models import GNNVulnerabilityClassifier
            from patchi.core.agents.cpg_extractor import CPGExtractor

            self.model = GNNVulnerabilityClassifier()
            self.graph_extractor = CPGExtractor()
            logger.info("GNN model and graph extractor initialized successfully")
        except ImportError as e:
            logger.warning(f"Could not import GNN components: {e}")
            logger.info("GNN detector will operate in limited mode")
            self.model = None
            self.graph_extractor = None

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run GNN-based bug detection."""
        logger.info("Starting GNN-based bug detection")

        # Check if GNN components are available
        if self.model is None or self.graph_extractor is None:
            logger.warning("GNN components not available, skipping detection")
            result.files_scanned = 0
            return

        findings = []
        files_processed = 0

        # Get files to analyze based on input scope
        files_to_analyze = self._get_files_to_analyze(inp)

        for file_path in files_to_analyze:
            try:
                # Extract Code Property Graph
                cpg = self.graph_extractor.extract_graph(file_path, inp.root)

                # Run GNN inference
                vulnerabilities = self.model.detect_vulnerabilities(cpg)

                # Convert vulnerabilities to findings
                for vuln in vulnerabilities:
                    finding = self._vulnerability_to_finding(
                        vuln, file_path, inp.root
                    )
                    if finding:
                        findings.append(finding)

                files_processed += 1

            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
                continue

        # Add findings to result
        for finding in findings:
            result.add_finding(finding)

        result.files_scanned = files_processed
        result.data["gnn_findings"] = len(findings)

        logger.info(
            f"GNN detection completed: {len(findings)} vulnerabilities found "
            f"in {files_processed} files"
        )

    def _get_files_to_analyze(self, inp: AgentInput) -> List[Path]:
        """Get list of files to analyze based on input scope."""
        files = []

        # Check if extra contains file scope
        if hasattr(inp, "extra") and inp.extra:
            if "files" in inp.extra:
                files.extend(Path(f) for f in inp.extra["files"])

        # If no specific files, analyze all Python files by default
        if not files:
            for root, dirs, filenames in os.walk(inp.root):
                for filename in filenames:
                    if filename.endswith((".py", ".cpp", ".c", ".java", ".js", ".ts", ".go", ".rs")):
                        files.append(Path(root) / filename)

        return files

    def _vulnerability_to_finding(
        self, vuln: Dict[str, Any], file_path: Path, root: Path
    ) -> Optional[Finding]:
        """Convert a GNN vulnerability detection to a Finding."""
        try:
            # Map GNN severity to Patchi severity
            severity = self._map_severity(vuln.get("severity", "medium"))

            # Determine fix agent based on vulnerability type
            fix_agent = self._determine_fix_agent(vuln.get("type", ""))

            # Create relative file path
            try:
                rel_path = file_path.relative_to(root)
            except ValueError:
                rel_path = file_path

            return make_finding(
                agent=self.name,
                finding_type=vuln.get("type", "gnn_detected_vulnerability"),
                severity=severity,
                file=str(rel_path),
                line=vuln.get("line", 0),
                message=vuln.get("title", ""),
                detail=vuln.get("description", ""),
                code_snippet=vuln.get("code_snippet", ""),
                suggestion=vuln.get("suggestion", ""),
                fix_agent=fix_agent,
                cwe=vuln.get("cwe", ""),
                confidence=vuln.get("confidence", 0.5),
                vulnerability_category=vuln.get("category", ""),
                affected_function=vuln.get("function", ""),
            )
        except Exception as e:
            logger.error(f"Error converting vulnerability to finding: {e}")
            return None

    def _map_severity(self, gnn_severity: str) -> str:
        """Map GNN severity to Patchi severity."""
        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
        }
        return severity_map.get(gnn_severity.lower(), "MEDIUM")

    def _determine_fix_agent(self, vuln_type: str) -> Optional[str]:
        """Determine which fix agent should handle this vulnerability."""
        # Map vulnerability types to fix agents
        type_to_agent = {
            "buffer_overflow": "SecurityFixer",
            "null_pointer_dereference": "CodeFixer",
            "memory_leak": "MemoryFixer",
            "race_condition": "SecurityFixer",
            "type_mismatch": "CodeFixer",
            "logic_bug": "RefactorAgent",
            "sql_injection": "SecurityFixer",
            "xss": "SecurityFixer",
            "path_traversal": "SecurityFixer",
        }
        return type_to_agent.get(vuln_type, None)

    def is_available(self) -> bool:
        """Check if GNN detector is available."""
        return self.model is not None and self.graph_extractor is not None

    def get_supported_languages(self) -> List[str]:
        """Get list of supported programming languages."""
        if self.graph_extractor:
            return self.graph_extractor.supported_languages
        return []