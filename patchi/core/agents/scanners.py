"""
All 20 scanner agents for Patchi.

This file has been split into separate modules for better maintainability:
- core_scanner.py
- side_file_scanner.py
- ui_scanner.py
- dependency_scanner.py
- test_scanner.py
- dead_code_scanner.py
- env_scanner.py
- route_graph_scanner.py
- type_scanner.py
- comment_scanner.py
- (duplicate_scanner.py DELETED — clone detection was noise, not signal)

Each agent inherits BaseAgent, implements _run(), and is registered
via the @register decorator so the coordinator can find it by name.
"""

from __future__ import annotations

from .base import register
from .build_tool_validator import BuildToolValidatorAgent
from .cicd_generator import CICDGeneratorAgent
from .comment_scanner import CommentScanner
from .core_scanner import CoreScanner
from .coverage_prioritizer import CoveragePrioritizerAgent
from .dead_code_hygiene import DeadCodeHygieneAgent
from .dead_code_scanner import DeadCodeScanner
from .dependency_scanner import DependencyScanner
from .env_scanner import EnvScanner
from .license_compliance import LicenseComplianceAgent
from .refactoring_agent import RefactoringAgent
from .route_graph_scanner import RouteGraphScanner
from .sbom_generator import SBOMGeneratorAgent
from .side_file_scanner import SideFileScanner
from .snapshot_drift_detector import SnapshotDriftDetectorAgent
from .spa_route_inventory import SPARouteInventoryAgent
from .test_scanner import TestScanner
from .type_scanner import TypeScanner
from .ui_scanner import UIScanner

__all__ = [
    "CoreScanner",
    "SideFileScanner",
    "UIScanner",
    "DependencyScanner",
    "TestScanner",
    "DeadCodeScanner",
    "DeadCodeHygieneAgent",
    "RefactoringAgent",
    "SBOMGeneratorAgent",
    "CICDGeneratorAgent",
    "SPARouteInventoryAgent",
    "CoveragePrioritizerAgent",
    "BuildToolValidatorAgent",
    "LicenseComplianceAgent",
    "SnapshotDriftDetectorAgent",
    "EnvScanner",
    "RouteGraphScanner",
    "TypeScanner",
    "CommentScanner",
    "register",
]
