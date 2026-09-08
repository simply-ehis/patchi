"""
Test agent aggregation module for Patchi.

Exports all test agent classes and shared test helper types.
"""

from __future__ import annotations

from ..agents.base import register
from .app_discovery_agent import AppDiscoveryAgent  # noqa: F401
from .api_contract_agent import APIContractAgent
from .browser_test_agent import BrowserTestAgent
from .e2e_flow_agent import E2EFlowAgent
from .flake_detector_agent import FlakeDetectorAgent  # noqa: F401
from .regression_agent import RegressionAgent
from .security_test_agent import SecurityTestAgent
from .stress_test_agent import StressTestAgent
from .ui_accessibility_agent import UIAccessibilityAgent
from .ui_button_agent import UIButtonAgent
from .ui_layout_agent import UILayoutAgent
from .unit_test_agent import TestCase, TestSuite, UnitTestAgent, _run
from .visual_regression_agent import VisualRegressionAgent

# Live v2 runner registers its agent on import (additive — never breaks v1)
try:
    from .live_v2.runner import LiveTestRunnerV2Agent  # noqa: F401
except Exception as _e:  # pragma: no cover — playwright-less envs still work
    import logging as _logging

    _logging.getLogger("patchi.testing").warning("LiveTestRunnerV2Agent unavailable: %s", _e)

__all__ = [
    "AppDiscoveryAgent",
    "APIContractAgent",
    "BrowserTestAgent",
    "E2EFlowAgent",
    "FlakeDetectorAgent",
    "RegressionAgent",
    "SecurityTestAgent",
    "StressTestAgent",
    "TestCase",
    "TestSuite",
    "UIAccessibilityAgent",
    "UIButtonAgent",
    "UILayoutAgent",
    "UnitTestAgent",
    "VisualRegressionAgent",
    "_run",
    "register",
]
