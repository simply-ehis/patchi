"""
Test agent aggregation module for Patchi.

Exports all test agent classes and shared test helper types.
"""

from __future__ import annotations

from ..agents.base import register
from .accessibility_agent import AccessibilityAgent
from .api_contract_agent import APIContractAgent
from .browser_test_agent import BrowserTestAgent
from .e2e_flow_agent import E2EFlowAgent
from .regression_agent import RegressionAgent
from .security_test_agent import SecurityTestAgent
from .stress_test_agent import StressTestAgent
from .ui_accessibility_agent import UIAccessibilityAgent
from .ui_button_agent import UIButtonAgent
from .ui_layout_agent import UILayoutAgent
from .unit_test_agent import TestCase, TestSuite, UnitTestAgent, _run
from .visual_regression_agent import VisualRegressionAgent

__all__ = [
    "AccessibilityAgent",
    "APIContractAgent",
    "BrowserTestAgent",
    "E2EFlowAgent",
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
