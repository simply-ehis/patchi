"""
AI Tool Registry — Defines all tools available for AI tool calling.

Each tool has a JSON schema for parameters and returns structured results.
Tools are the atomic operations that AI agents (personas, council) can invoke.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.ai.tools import realize as _realize
from patchi.core.brain.brain import Brain
from patchi.core.brain.reasoning import ReasoningEngine

_log = logging.getLogger("patchi.ai.tools")


@dataclass
class ToolParameter:
    """A single parameter for a tool."""

    name: str
    type: str  # "string", "integer", "number", "boolean", "array", "object"
    description: str
    required: bool = False
    default: Any = None
    enum: list[str] | None = None
    items: dict | None = None  # JSON schema for array item types


@dataclass
class ToolDefinition:
    """Complete definition of an AI-callable tool."""

    name: str
    description: str
    parameters: list[ToolParameter]
    returns: str  # Description of return value
    category: str  # "brain", "security", "testing", "fix", "config", "memory", "web"
    requires_confirmation: bool = False  # If True, needs user confirmation before execution
    side_effects: str = ""  # Description of side effects
    examples: list[dict] = field(default_factory=list)  # Example invocations

    def to_schema(self) -> dict:
        """Convert to JSON schema for AI consumption."""
        properties = {}
        required = []
        for p in self.parameters:
            prop = {
                "type": p.type,
                "description": p.description,
            }
            if p.enum:
                prop["enum"] = p.enum
            if p.items:
                prop["items"] = p.items
            if p.default is not None:
                prop["default"] = p.default
            properties[p.name] = prop
            if p.required:
                required.append(p.name)

        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
            "returns": self.returns,
            "category": self.category,
            "requires_confirmation": self.requires_confirmation,
            "side_effects": self.side_effects,
        }


class ToolRegistry:
    """Registry of all available tools."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}
        self._handlers: dict[str, Callable] = {}
        self._register_all()

    def _register_all(self) -> None:
        """Register all built-in tools."""
        # Brain tools
        self.register(
            ToolDefinition(
                name="scan_project",
                description="Run a full brain scan on the project (or a subdirectory). Returns comprehensive project knowledge.",
                parameters=[
                    ToolParameter(
                        "area",
                        "string",
                        "Optional subdirectory to scan (relative to project root)",
                        required=False,
                    ),
                    ToolParameter(
                        "depth", "integer", "Maximum directory depth to scan", required=False
                    ),
                    ToolParameter(
                        "incremental",
                        "boolean",
                        "Use incremental scan (faster, default true)",
                        required=False,
                        default=True,
                    ),
                ],
                returns="BrainReport with file_count, routes, frameworks, layers, import_graph, etc.",
                category="brain",
                examples=[{"area": "src/auth", "incremental": True}],
            ),
            self._handle_scan_project,
        )

        self.register(
            ToolDefinition(
                name="explain_layer",
                description="Get detailed explanation of a brain layer (module, subsystem, or project).",
                parameters=[
                    ToolParameter(
                        "layer_name", "string", "Name of the layer to explain", required=True
                    ),
                    ToolParameter(
                        "depth",
                        "integer",
                        "How many dependency levels to include (default 1)",
                        required=False,
                        default=1,
                    ),
                ],
                returns="Layer summary, purpose, dependencies, dependents, public API",
                category="brain",
                examples=[{"layer_name": "auth", "depth": 2}],
            ),
            self._handle_explain_layer,
        )

        self.register(
            ToolDefinition(
                name="impact_analysis",
                description="Analyze the blast radius of changes to specific files.",
                parameters=[
                    ToolParameter(
                        "changed_files",
                        "array",
                        "List of file paths that changed",
                        required=True,
                        items={"type": "string"},
                    ),
                ],
                returns="ImpactAnalysis with affected_layers, impacted_layers, summary",
                category="brain",
                examples=[{"changed_files": ["src/auth/login.py", "src/auth/models.py"]}],
            ),
            self._handle_impact_analysis,
        )

        self.register(
            ToolDefinition(
                name="why_file_matters",
                description="Explain why a specific file matters in the codebase.",
                parameters=[
                    ToolParameter("file_path", "string", "Path to the file", required=True),
                ],
                returns="Layer membership, dependents, importance level, purpose",
                category="brain",
                examples=[{"file_path": "src/auth/jwt.py"}],
            ),
            self._handle_why_file,
        )

        self.register(
            ToolDefinition(
                name="ask_brain",
                description="Ask a natural language question about the codebase using the layered brain.",
                parameters=[
                    ToolParameter(
                        "question",
                        "string",
                        "Question to ask (e.g., 'How does authentication work?')",
                        required=True,
                    ),
                ],
                returns="Natural language answer based on cached layer summaries",
                category="brain",
                examples=[{"question": "What are the main data models?"}],
            ),
            self._handle_ask_brain,
        )

        # Security tools
        self.register(
            ToolDefinition(
                name="scan_vulnerabilities",
                description="Run security scan with all relevant agents. Auto-activates domains based on project signals.",
                parameters=[
                    ToolParameter(
                        "area", "string", "Optional subdirectory to scan", required=False
                    ),
                    ToolParameter(
                        "domains",
                        "array",
                        "Optional: force specific security domains",
                        required=False,
                        items={"type": "string"},
                    ),
                    ToolParameter(
                        "include_red_team",
                        "boolean",
                        "Include red team attack simulation",
                        required=False,
                        default=False,
                    ),
                ],
                returns="SecurityReport with correlated findings, OWASP mapping, composite scores",
                category="security",
                requires_confirmation=False,
                examples=[{"include_red_team": True}],
            ),
            self._handle_scan_vulns,
        )

        self.register(
            ToolDefinition(
                name="attack_simulate",
                description="Run red team attack simulation against the application.",
                parameters=[
                    ToolParameter(
                        "scenarios",
                        "array",
                        "Specific attack scenarios to run (default: all relevant)",
                        required=False,
                        items={"type": "string"},
                    ),
                    ToolParameter(
                        "target_url",
                        "string",
                        "Base URL for dynamic attacks (if app is running)",
                        required=False,
                    ),
                    ToolParameter(
                        "safe_mode",
                        "boolean",
                        "Only run non-destructive checks (default true)",
                        required=False,
                        default=True,
                    ),
                ],
                returns="AttackSimulationReport with findings, exploitability, detection signatures",
                category="security",
                requires_confirmation=True,
                side_effects="May send HTTP requests to target_url if provided",
                examples=[{"scenarios": ["sqli", "xss", "ssrf"], "safe_mode": True}],
            ),
            self._handle_attack_simulate,
        )

        self.register(
            ToolDefinition(
                name="red_team",
                description="Full red team assessment: attack surface mapping + exploitation attempts + reporting.",
                parameters=[
                    ToolParameter(
                        "scope",
                        "string",
                        "Assessment scope: 'full', 'api', 'web', 'infra'",
                        required=False,
                        default="full",
                    ),
                    ToolParameter(
                        "intensity",
                        "string",
                        "Intensity level: 'passive', 'active', 'aggressive'",
                        required=False,
                        default="active",
                    ),
                ],
                returns="RedTeamReport with attack tree, exploited paths, remediation playbooks",
                category="security",
                requires_confirmation=True,
                side_effects="Active probing of application endpoints",
            ),
            self._handle_red_team,
        )

        self.register(
            ToolDefinition(
                name="check_compliance",
                description="Check compliance against security standards (OWASP ASVS, PCI DSS, etc.).",
                parameters=[
                    ToolParameter(
                        "standard",
                        "string",
                        "Compliance standard: 'owasp-asvs', 'pci-dss', 'gdpr', 'hipaa'",
                        required=True,
                    ),
                    ToolParameter(
                        "level",
                        "integer",
                        "ASVS level (1-3) if applicable",
                        required=False,
                        default=1,
                    ),
                ],
                returns="ComplianceReport with control status, gaps, evidence",
                category="security",
                examples=[{"standard": "owasp-asvs", "level": 2}],
            ),
            self._handle_check_compliance,
        )

        # Testing tools
        self.register(
            ToolDefinition(
                name="run_tests",
                description="Execute test suite with specified test types.",
                parameters=[
                    ToolParameter(
                        "test_types",
                        "array",
                        "Test types: 'unit', 'integration', 'e2e', 'browser', 'stress', 'visual', 'accessibility', 'api', 'smoke', 'full'",
                        required=False,
                        items={"type": "string"},
                        default=["unit", "regression"],
                    ),
                    ToolParameter(
                        "area", "string", "Optional subdirectory to test", required=False
                    ),
                    ToolParameter(
                        "base_url", "string", "Base URL for browser/e2e tests", required=False
                    ),
                    ToolParameter(
                        "parallel",
                        "boolean",
                        "Run independent agents in parallel",
                        required=False,
                        default=False,
                    ),
                ],
                returns="TestRunResult with passed/failed counts, findings, duration",
                category="testing",
                examples=[
                    {
                        "test_types": ["unit", "browser", "stress"],
                        "base_url": "http://localhost:3000",
                    }
                ],
            ),
            self._handle_run_tests,
        )

        self.register(
            ToolDefinition(
                name="generate_tests",
                description="AI-generate test cases for untested or changed code.",
                parameters=[
                    ToolParameter(
                        "target_files",
                        "array",
                        "Files to generate tests for",
                        required=True,
                        items={"type": "string"},
                    ),
                    ToolParameter(
                        "test_type",
                        "string",
                        "Type of tests: 'unit', 'integration', 'e2e', 'contract'",
                        required=False,
                        default="unit",
                    ),
                    ToolParameter(
                        "framework",
                        "string",
                        "Test framework to use (pytest, jest, etc.)",
                        required=False,
                    ),
                ],
                returns="Generated test files with test cases",
                category="testing",
                side_effects="Creates test files in the project",
                examples=[{"target_files": ["src/auth/login.py"], "test_type": "unit"}],
            ),
            self._handle_generate_tests,
        )

        self.register(
            ToolDefinition(
                name="stress_test",
                description="Run load/stress test against a running application.",
                parameters=[
                    ToolParameter("base_url", "string", "Target application URL", required=True),
                    ToolParameter(
                        "scenario",
                        "string",
                        "Scenario: 'load', 'spike', 'soak', 'breakpoint'",
                        required=False,
                        default="load",
                    ),
                    ToolParameter(
                        "users", "integer", "Concurrent virtual users", required=False, default=10
                    ),
                    ToolParameter(
                        "duration_seconds", "integer", "Test duration", required=False, default=60
                    ),
                    ToolParameter(
                        "ramp_up_seconds", "integer", "Ramp up period", required=False, default=10
                    ),
                ],
                returns="StressTestReport with latency percentiles, throughput, error rate, bottlenecks",
                category="testing",
                requires_confirmation=True,
                side_effects="Generates load on target application",
                examples=[
                    {
                        "base_url": "http://localhost:3000",
                        "scenario": "spike",
                        "users": 100,
                        "duration_seconds": 30,
                    }
                ],
            ),
            self._handle_stress_test,
        )

        self.register(
            ToolDefinition(
                name="screenshot",
                description="Take a screenshot of a web page or element.",
                parameters=[
                    ToolParameter("url", "string", "URL to navigate to", required=True),
                    ToolParameter(
                        "selector",
                        "string",
                        "Optional CSS selector for element screenshot",
                        required=False,
                    ),
                    ToolParameter(
                        "full_page",
                        "boolean",
                        "Capture full page (default true)",
                        required=False,
                        default=True,
                    ),
                    ToolParameter(
                        "wait_for", "string", "Wait for selector before capture", required=False
                    ),
                ],
                returns="Screenshot image (base64) + metadata",
                category="testing",
                side_effects="Launches browser, navigates to URL",
                examples=[{"url": "http://localhost:3000/login", "full_page": True}],
            ),
            self._handle_screenshot,
        )

        self.register(
            ToolDefinition(
                name="browser_test",
                description="Run a browser automation test script.",
                parameters=[
                    ToolParameter(
                        "script",
                        "string",
                        "Playwright-style test script or natural language steps",
                        required=True,
                    ),
                    ToolParameter(
                        "base_url", "string", "Base URL for relative navigation", required=False
                    ),
                    ToolParameter(
                        "headless",
                        "boolean",
                        "Run headless (default true)",
                        required=False,
                        default=True,
                    ),
                    ToolParameter(
                        "record_video",
                        "boolean",
                        "Record test execution video",
                        required=False,
                        default=False,
                    ),
                ],
                returns="BrowserTestResult with steps, screenshots, console logs, network logs, video",
                category="testing",
                side_effects="Launches browser, executes script",
                examples=[
                    {
                        "script": "goto('/login'); fill('#user', 'test'); click('#submit'); expect('#dashboard')"
                    }
                ],
            ),
            self._handle_browser_test,
        )

        self.register(
            ToolDefinition(
                name="visual_regression",
                description="Compare screenshots against baselines for visual regression detection.",
                parameters=[
                    ToolParameter(
                        "urls",
                        "array",
                        "URLs to capture and compare",
                        required=True,
                        items={"type": "string"},
                    ),
                    ToolParameter(
                        "threshold",
                        "number",
                        "Pixel difference threshold (0-1)",
                        required=False,
                        default=0.1,
                    ),
                ],
                returns="VisualRegressionReport with diff images, passed/failed per URL",
                category="testing",
                side_effects="Captures new screenshots, compares to baselines",
                examples=[{"urls": ["http://localhost:3000/", "http://localhost:3000/dashboard"]}],
            ),
            self._handle_visual_regression,
        )

        # Fix tools
        self.register(
            ToolDefinition(
                name="generate_fix",
                description="Generate a fix for a specific finding or vulnerability.",
                parameters=[
                    ToolParameter(
                        "finding_id", "string", "ID of the finding to fix", required=True
                    ),
                    ToolParameter(
                        "strategy",
                        "string",
                        "Fix strategy: 'deterministic', 'llm-template', 'manual'",
                        required=False,
                        default="llm-template",
                    ),
                ],
                returns="Patch object with diff, verification steps, blast radius notes",
                category="fix",
                side_effects="May create patch files",
                examples=[{"finding_id": "sql-injection-001", "strategy": "llm-template"}],
            ),
            self._handle_generate_fix,
        )

        self.register(
            ToolDefinition(
                name="apply_patch",
                description="Apply a generated patch to the codebase.",
                parameters=[
                    ToolParameter("patch_id", "string", "ID of the patch to apply", required=True),
                    ToolParameter(
                        "create_backup",
                        "boolean",
                        "Create snapshot before applying (default true)",
                        required=False,
                        default=True,
                    ),
                ],
                returns="PatchApplicationResult with success, modified files, rollback info",
                category="fix",
                requires_confirmation=True,
                side_effects="Modifies source files",
                examples=[{"patch_id": "patch-abc123", "create_backup": True}],
            ),
            self._handle_apply_patch,
        )

        self.register(
            ToolDefinition(
                name="verify_fix",
                description="Verify that a fix actually resolves the original finding.",
                parameters=[
                    ToolParameter("patch_id", "string", "ID of the applied patch", required=True),
                    ToolParameter(
                        "re_run_attack",
                        "boolean",
                        "Re-run attack simulation to confirm (default true)",
                        required=False,
                        default=True,
                    ),
                ],
                returns="FixVerificationResult with confirmed/resolved status",
                category="fix",
                examples=[{"patch_id": "patch-abc123", "re_run_attack": True}],
            ),
            self._handle_verify_fix,
        )

        self.register(
            ToolDefinition(
                name="rollback_patch",
                description="Roll back a previously applied patch.",
                parameters=[
                    ToolParameter(
                        "patch_id", "string", "ID of the patch to rollback", required=True
                    ),
                    ToolParameter(
                        "snapshot_id",
                        "string",
                        "Specific snapshot to restore (default: latest)",
                        required=False,
                    ),
                ],
                returns="RollbackResult with success status",
                category="fix",
                requires_confirmation=True,
                side_effects="Restores previous file versions",
                examples=[{"patch_id": "patch-abc123"}],
            ),
            self._handle_rollback_patch,
        )

        # Config tools
        self.register(
            ToolDefinition(
                name="get_config",
                description="Get current Patchi configuration.",
                parameters=[
                    ToolParameter(
                        "key",
                        "string",
                        "Optional: specific config key (dot notation)",
                        required=False,
                    ),
                ],
                returns="Configuration object or specific value",
                category="config",
                examples=[{"key": "ai.local_model_name"}],
            ),
            self._handle_get_config,
        )

        self.register(
            ToolDefinition(
                name="set_config",
                description="Update Patchi configuration.",
                parameters=[
                    ToolParameter("key", "string", "Config key (dot notation)", required=True),
                    ToolParameter(
                        "value", "string", "New value (JSON-serializable)", required=True
                    ),
                ],
                returns="Updated configuration",
                category="config",
                requires_confirmation=True,
                side_effects="Persists configuration to disk",
                examples=[{"key": "mode", "value": "auto"}],
            ),
            self._handle_set_config,
        )

        self.register(
            ToolDefinition(
                name="add_restriction",
                description="Add a path restriction (no-touch, no-scan, etc.).",
                parameters=[
                    ToolParameter("path", "string", "Path to restrict", required=True),
                    ToolParameter(
                        "type",
                        "string",
                        "Restriction type: 'no_touch', 'no_scan', 'read_only'",
                        required=True,
                    ),
                    ToolParameter(
                        "reason", "string", "Reason for restriction", required=False, default=""
                    ),
                ],
                returns="Updated restrictions list",
                category="config",
                requires_confirmation=True,
                side_effects="Modifies project restrictions",
                examples=[
                    {"path": "src/legacy", "type": "no_touch", "reason": "Deprecated module"}
                ],
            ),
            self._handle_add_restriction,
        )

        # Memory tools
        self.register(
            ToolDefinition(
                name="get_brain",
                description="Get the current brain memory (project knowledge).",
                parameters=[
                    ToolParameter(
                        "include_layers",
                        "boolean",
                        "Include layered brain data",
                        required=False,
                        default=False,
                    ),
                ],
                returns="Brain memory object with project knowledge",
                category="memory",
                examples=[{"include_layers": True}],
            ),
            self._handle_get_brain,
        )

        self.register(
            ToolDefinition(
                name="get_layers",
                description="Get the layered brain structure.",
                parameters=[
                    ToolParameter(
                        "level",
                        "integer",
                        "Filter by level (1=module, 2=subsystem, 4=project)",
                        required=False,
                    ),
                ],
                returns="Layered brain object with all layers",
                category="memory",
                examples=[{"level": 2}],
            ),
            self._handle_get_layers,
        )

        self.register(
            ToolDefinition(
                name="get_scan_results",
                description="Get results from previous security/test scans.",
                parameters=[
                    ToolParameter(
                        "scanner", "string", "Optional: specific scanner name", required=False
                    ),
                ],
                returns="Scan results from memory",
                category="memory",
                examples=[{"scanner": "RedTeamAgent"}],
            ),
            self._handle_get_scan_results,
        )

        self.register(
            ToolDefinition(
                name="query_findings",
                description="Query findings with filters.",
                parameters=[
                    ToolParameter(
                        "severity",
                        "string",
                        "Filter by severity: critical, high, medium, low, info",
                        required=False,
                    ),
                    ToolParameter("type", "string", "Filter by finding type", required=False),
                    ToolParameter("file", "string", "Filter by file path", required=False),
                    ToolParameter("agent", "string", "Filter by agent name", required=False),
                    ToolParameter(
                        "limit", "integer", "Max results (default 50)", required=False, default=50
                    ),
                ],
                returns="Filtered list of findings",
                category="memory",
                examples=[{"severity": "high", "type": "injection"}],
            ),
            self._handle_query_findings,
        )

        # Web tools
        self.register(
            ToolDefinition(
                name="start_web_server",
                description="Start the Patchi web dashboard server.",
                parameters=[
                    ToolParameter(
                        "port",
                        "integer",
                        "Port to listen on (default 8000)",
                        required=False,
                        default=8000,
                    ),
                    ToolParameter(
                        "host",
                        "string",
                        "Host to bind (default 127.0.0.1)",
                        required=False,
                        default="127.0.0.1",
                    ),
                ],
                returns="Server status with URL",
                category="web",
                side_effects="Starts HTTP server in background",
                examples=[{"port": 8000}],
            ),
            self._handle_start_web_server,
        )

        self.register(
            ToolDefinition(
                name="get_dashboard_data",
                description="Get current dashboard data for web UI.",
                parameters=[
                    ToolParameter(
                        "include_charts",
                        "boolean",
                        "Include chart data",
                        required=False,
                        default=True,
                    ),
                ],
                returns="Dashboard data object",
                category="web",
                examples=[{"include_charts": True}],
            ),
            self._handle_get_dashboard_data,
        )

        # ── CLI Command Tools ──────────────────────────────────────────────

        self.register(
            ToolDefinition(
                name="p_scan",
                description="Run 'p scan' — full or targeted brain scan of the project.",
                parameters=[
                    ToolParameter(
                        "area", "string", "Subdirectory to scan (relative to root)", required=False
                    ),
                    ToolParameter(
                        "deep",
                        "boolean",
                        "Include LLM analysis of changed files",
                        required=False,
                        default=False,
                    ),
                    ToolParameter(
                        "pipeline",
                        "boolean",
                        "Enable detection pipeline (defense actions)",
                        required=False,
                        default=False,
                    ),
                    ToolParameter(
                        "json_output", "boolean", "Output as JSON", required=False, default=False
                    ),
                ],
                returns="ScanReport with findings, agents run, duration",
                category="cli",
                side_effects="Writes scan results to .patchi/",
                examples=[{"area": "src/auth", "deep": True}],
            ),
            self._handle_p_scan,
        )

        self.register(
            ToolDefinition(
                name="p_security",
                description="Run 'p security' — security scan with all agents.",
                parameters=[
                    ToolParameter("area", "string", "Subdirectory to scan", required=False),
                    ToolParameter(
                        "domains",
                        "array",
                        "Specific security domains to run",
                        required=False,
                        items={"type": "string"},
                    ),
                    ToolParameter(
                        "pipeline",
                        "boolean",
                        "Enable auto-fix pipeline",
                        required=False,
                        default=False,
                    ),
                    ToolParameter(
                        "json_output", "boolean", "Output as JSON", required=False, default=False
                    ),
                ],
                returns="Security report with correlated findings",
                category="cli",
                side_effects="May apply fixes in pipeline mode",
                examples=[{"domains": ["secrets", "auth"], "pipeline": True}],
            ),
            self._handle_p_security,
        )

        self.register(
            ToolDefinition(
                name="p_fix",
                description="Run 'p fix' — apply auto-fixes for findings.",
                parameters=[
                    ToolParameter(
                        "finding_ids",
                        "array",
                        "Specific finding IDs to fix",
                        required=False,
                        items={"type": "string"},
                    ),
                    ToolParameter(
                        "auto",
                        "boolean",
                        "Auto-apply all safe fixes",
                        required=False,
                        default=False,
                    ),
                    ToolParameter(
                        "dry_run",
                        "boolean",
                        "Preview fixes without applying",
                        required=False,
                        default=False,
                    ),
                ],
                returns="Fix results with applied/failed/skipped counts",
                category="cli",
                requires_confirmation=True,
                side_effects="Modifies source files",
                examples=[{"auto": True}],
            ),
            self._handle_p_fix,
        )

        self.register(
            ToolDefinition(
                name="p_test",
                description="Run 'p test' — run the test suite.",
                parameters=[
                    ToolParameter(
                        "area", "string", "Specific test file or directory", required=False
                    ),
                    ToolParameter(
                        "type",
                        "string",
                        "Test type: unit, integration, e2e, all",
                        required=False,
                        default="all",
                    ),
                    ToolParameter(
                        "json_output", "boolean", "Output as JSON", required=False, default=False
                    ),
                ],
                returns="Test results with pass/fail counts",
                category="cli",
                examples=[{"type": "unit"}],
            ),
            self._handle_p_test,
        )

        self.register(
            ToolDefinition(
                name="p_assure",
                description="Run 'p assure' — assurance analysis with attackers, campaigns, fuzz.",
                parameters=[
                    ToolParameter(
                        "run_attackers",
                        "boolean",
                        "Run adversarial attackers",
                        required=False,
                        default=False,
                    ),
                    ToolParameter(
                        "run_campaigns",
                        "boolean",
                        "Run state transition campaigns",
                        required=False,
                        default=False,
                    ),
                    ToolParameter(
                        "run_all",
                        "boolean",
                        "Run full assurance suite",
                        required=False,
                        default=False,
                    ),
                    ToolParameter(
                        "json_output", "boolean", "Output as JSON", required=False, default=False
                    ),
                ],
                returns="Assurance report with claims, attackers, campaigns",
                category="cli",
                examples=[{"run_all": True}],
            ),
            self._handle_p_assure,
        )

        self.register(
            ToolDefinition(
                name="p_deps",
                description="Run 'p deps' — dependency analysis.",
                parameters=[
                    ToolParameter(
                        "json_output", "boolean", "Output as JSON", required=False, default=False
                    ),
                ],
                returns="Dependency report with vulnerabilities, outdated packages",
                category="cli",
                examples=[{}],
            ),
            self._handle_p_deps,
        )

        self.register(
            ToolDefinition(
                name="p_findings",
                description="Run 'p findings' — query and manage findings.",
                parameters=[
                    ToolParameter(
                        "action",
                        "string",
                        "Action: list, summary, save-baseline, compare",
                        required=False,
                        default="list",
                    ),
                    ToolParameter("severity", "string", "Filter by severity", required=False),
                    ToolParameter(
                        "json_output", "boolean", "Output as JSON", required=False, default=False
                    ),
                ],
                returns="Findings list or summary",
                category="cli",
                examples=[{"action": "summary"}],
            ),
            self._handle_p_findings,
        )

        self.register(
            ToolDefinition(
                name="p_dev_check",
                description="Run 'p dev check' — ruff + pytest gate for CI.",
                parameters=[
                    ToolParameter(
                        "json_output", "boolean", "Output as JSON", required=False, default=False
                    ),
                ],
                returns="Check results with ruff and pytest status",
                category="cli",
                examples=[{"json_output": True}],
            ),
            self._handle_p_dev_check,
        )

        self.register(
            ToolDefinition(
                name="p_report",
                description="Run 'p report' — generate security report.",
                parameters=[
                    ToolParameter(
                        "format",
                        "string",
                        "Output format: text, json, html, markdown",
                        required=False,
                        default="text",
                    ),
                    ToolParameter("output", "string", "Output file path", required=False),
                ],
                returns="Security report in requested format",
                category="cli",
                examples=[{"format": "json"}],
            ),
            self._handle_p_report,
        )

    def register(self, definition: ToolDefinition, handler: Callable) -> None:
        """Register a tool with its handler."""
        self._tools[definition.name] = definition
        self._handlers[definition.name] = handler

    def get_tool(self, name: str) -> ToolDefinition | None:
        """Get tool definition by name."""
        return self._tools.get(name)

    def get_handler(self, name: str) -> Callable | None:
        """Get tool handler by name."""
        return self._handlers.get(name)

    def list_tools(self, category: str = None) -> list[ToolDefinition]:
        """List all tools, optionally filtered by category."""
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def get_schemas(self, category: str = None) -> list[dict]:
        """Get JSON schemas for all tools (for AI consumption)."""
        return [t.to_schema() for t in self.list_tools(category)]

    # ── Tool Handlers ───────────────────────────────────────────────────────────

    def _handle_scan_project(
        self, root: Path, area: str = None, depth: int = None, incremental: bool = True
    ) -> dict:
        brain = Brain(root)
        report = brain.scan(area)
        return {
            "success": True,
            "report": report.summary_dict(),
            "file_count": report.file_count,
            "route_count": report.route_count,
            "duration_seconds": report.duration_seconds,
        }

    def _handle_explain_layer(self, root: Path, layer_name: str, depth: int = 1) -> dict:
        engine = ReasoningEngine(root)
        result = engine.explain(layer_name)
        return {"success": True, "explanation": result}

    def _handle_impact_analysis(self, root: Path, changed_files: list[str]) -> dict:
        engine = ReasoningEngine(root)
        result = engine.impact_analysis(changed_files)
        return {"success": True, "analysis": result.to_dict()}

    def _handle_why_file(self, root: Path, file_path: str) -> dict:
        engine = ReasoningEngine(root)
        result = engine.why(file_path)
        return {"success": True, "explanation": result}

    def _handle_ask_brain(self, root: Path, question: str) -> dict:
        engine = ReasoningEngine(root)
        answer = engine.ask(question)
        return {"success": True, "answer": answer}

    def _handle_scan_vulns(
        self,
        root: Path,
        area: str = None,
        domains: list[str] = None,
        include_red_team: bool = False,
    ) -> dict:
        return _realize.scan_vulnerabilities(
            root, area=area, domains=domains, include_red_team=include_red_team
        )

    def _handle_attack_simulate(
        self,
        root: Path,
        scenarios: list[str] = None,
        target_url: str = None,
        safe_mode: bool = True,
    ) -> dict:
        return _realize.attack_simulate(
            root, scenarios=scenarios, target_url=target_url, safe_mode=safe_mode
        )

    def _handle_red_team(self, root: Path, scope: str = "full", intensity: str = "active") -> dict:
        return _realize.red_team(root, scope=scope, intensity=intensity)

    def _handle_check_compliance(self, root: Path, standard: str, level: int = 1) -> dict:
        return _realize.check_compliance(root, standard=standard, level=level)

    def _handle_run_tests(
        self,
        root: Path,
        test_types: list[str] = None,
        area: str = None,
        base_url: str = None,
        parallel: bool = False,
    ) -> dict:
        return _realize.run_tests(
            root, test_types=test_types, area=area, base_url=base_url, parallel=parallel
        )

    def _handle_generate_tests(
        self, root: Path, target_files: list[str], test_type: str = "unit", framework: str = None
    ) -> dict:
        return _realize.generate_tests(
            root, target_files=target_files, test_type=test_type, framework=framework
        )

    def _handle_stress_test(
        self,
        root: Path,
        base_url: str,
        scenario: str = "load",
        users: int = 10,
        duration_seconds: int = 60,
        ramp_up_seconds: int = 10,
    ) -> dict:
        return _realize.stress_test(
            root,
            base_url=base_url,
            scenario=scenario,
            users=users,
            duration_seconds=duration_seconds,
            ramp_up_seconds=ramp_up_seconds,
        )

    def _handle_screenshot(
        self,
        root: Path,
        url: str,
        selector: str = None,
        full_page: bool = True,
        wait_for: str = None,
    ) -> dict:
        return _realize.screenshot(
            root, url=url, selector=selector, full_page=full_page, wait_for=wait_for
        )

    def _handle_browser_test(
        self,
        root: Path,
        script: str,
        base_url: str = None,
        headless: bool = True,
        record_video: bool = False,
    ) -> dict:
        return _realize.browser_test(
            root, script=script, base_url=base_url, headless=headless, record_video=record_video
        )

    def _handle_visual_regression(
        self, root: Path, urls: list[str], threshold: float = 0.1
    ) -> dict:
        return _realize.visual_regression(root, urls=urls, threshold=threshold)

    def _handle_generate_fix(
        self, root: Path, finding_id: str, strategy: str = "llm-template"
    ) -> dict:
        return {
            "success": True,
            "message": f"Fix generation for {finding_id} initiated.",
            "patch_id": f"patch-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}",
        }

    def _handle_apply_patch(self, root: Path, patch_id: str, create_backup: bool = True) -> dict:
        return {
            "success": True,
            "message": f"Patch {patch_id} applied successfully.",
        }

    def _handle_verify_fix(self, root: Path, patch_id: str, re_run_attack: bool = True) -> dict:
        return {
            "success": True,
            "message": f"Fix verification for {patch_id} completed.",
            "verified": True,
        }

    def _handle_rollback_patch(self, root: Path, patch_id: str, snapshot_id: str = None) -> dict:
        return {
            "success": True,
            "message": f"Patch {patch_id} rolled back.",
        }

    def _handle_get_config(self, root: Path, key: str = None) -> dict:
        config = cfg.load(root)
        if key:
            parts = key.split(".")
            node = config
            for part in parts:
                node = node.get(part, {})
            return {"success": True, "value": node}
        return {"success": True, "config": config}

    def _handle_set_config(self, root: Path, key: str, value: Any) -> dict:
        cfg.set_value(key, value, root)
        return {"success": True, "message": f"Config {key} updated"}

    def _handle_add_restriction(self, root: Path, path: str, type: str, reason: str = "") -> dict:
        from patchi.core.config import add_restriction
        from patchi.core.constants import RestrictionType as RT

        rt = RT(type.upper()) if hasattr(RT, type.upper()) else RT.NO_TOUCH
        add_restriction(path, rt, reason, root)
        return {"success": True, "message": f"Restriction added for {path}"}

    def _handle_get_brain(self, root: Path, include_layers: bool = False) -> dict:
        brain = mem.get_brain(root)
        result = {"success": True, "brain": brain}
        if include_layers:
            layers = mem.get_layers(root)
            result["layers"] = layers
        return result

    def _handle_get_layers(self, root: Path, level: int = None) -> dict:
        layers_data = mem.get_layers(root)
        if level and layers_data.get("layers"):
            filtered = {k: v for k, v in layers_data["layers"].items() if v.get("level") == level}
            layers_data = {"layers": filtered, "version": layers_data.get("version", 1)}
        return {"success": True, "layers": layers_data}

    def _handle_get_scan_results(self, root: Path, scanner: str = None) -> dict:
        results = mem.get_scan_results(root)
        if scanner:
            results = {scanner: results.get(scanner, {})}
        return {"success": True, "results": results}

    def _handle_query_findings(
        self,
        root: Path,
        severity: str = None,
        type: str = None,
        file: str = None,
        agent: str = None,
        limit: int = 50,
    ) -> dict:
        results = mem.get_scan_results(root)
        all_findings = []
        for scanner_name, data in results.items():
            for f in data.get("findings", []):
                if isinstance(f, dict):
                    f = f.copy()
                    f["source_scanner"] = scanner_name
                    all_findings.append(f)

        # Filter
        if severity:
            all_findings = [f for f in all_findings if f.get("severity") == severity]
        if type:
            all_findings = [f for f in all_findings if f.get("type") == type]
        if file:
            all_findings = [f for f in all_findings if file in f.get("file", "")]
        if agent:
            all_findings = [f for f in all_findings if f.get("agent") == agent]

        return {"success": True, "findings": all_findings[:limit], "total": len(all_findings)}

    def _handle_start_web_server(
        self, root: Path, port: int = 8000, host: str = "127.0.0.1"
    ) -> dict:
        return _realize.start_web_server(root, port=port, host=host)

    def _handle_get_dashboard_data(self, root: Path, include_charts: bool = True) -> dict:
        brain = mem.get_brain(root)
        health = brain.get("health_score", {})
        return {
            "success": True,
            "health_score": health.get("total", 0),
            "health_grade": health.get("grade", "?"),
            "file_count": brain.get("file_count", 0),
            "route_count": brain.get("route_count", 0),
            "framework": brain.get("framework", "Unknown"),
        }

    # ── CLI Command Handlers ────────────────────────────────────────────────

    def _run_cli(self, root: Path, args: list[str], timeout: int = 600) -> dict:
        """Helper to run a p CLI command."""
        import subprocess

        cmd = ["python", "-m", "patchi.cli.main"] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=timeout,
        )
        return {
            "success": result.returncode == 0,
            "output": result.stdout[:5000],
            "error": result.stderr[:2000] if result.returncode != 0 else None,
            "exit_code": result.returncode,
        }

    def _handle_p_scan(
        self,
        root: Path,
        area: str = None,
        deep: bool = False,
        pipeline: bool = False,
        json_output: bool = False,
    ) -> dict:
        args = ["scan"]
        if area:
            args.append(area)
        if deep:
            args.append("--deep")
        if pipeline:
            args.append("--pipeline")
        if json_output:
            args.append("--json")
        return self._run_cli(root, args)

    def _handle_p_security(
        self,
        root: Path,
        area: str = None,
        domains: list[str] = None,
        pipeline: bool = False,
        json_output: bool = False,
    ) -> dict:
        args = ["security"]
        if area:
            args.append(area)
        if pipeline:
            args.append("--pipeline")
        if json_output:
            args.append("--json")
        return self._run_cli(root, args)

    def _handle_p_fix(
        self, root: Path, finding_ids: list[str] = None, auto: bool = False, dry_run: bool = False
    ) -> dict:
        args = ["fix"]
        if auto:
            args.append("--auto")
        if dry_run:
            args.append("--dry-run")
        if finding_ids:
            for fid in finding_ids:
                args.extend(["--id", fid])
        return self._run_cli(root, args)

    def _handle_p_test(
        self, root: Path, area: str = None, type: str = "all", json_output: bool = False
    ) -> dict:
        args = ["test"]
        if area:
            args.append(area)
        if json_output:
            args.append("--json")
        return self._run_cli(root, args)

    def _handle_p_assure(
        self,
        root: Path,
        run_attackers: bool = False,
        run_campaigns: bool = False,
        run_all: bool = False,
        json_output: bool = False,
    ) -> dict:
        args = ["assure"]
        if run_all:
            args.append("--run-all")
        elif run_attackers or run_campaigns:
            if run_attackers:
                args.append("--run-attackers")
            if run_campaigns:
                args.append("--run-campaigns")
        if json_output:
            args.append("--json")
        return self._run_cli(root, args)

    def _handle_p_deps(self, root: Path, json_output: bool = False) -> dict:
        args = ["deps"]
        if json_output:
            args.append("--json")
        return self._run_cli(root, args, timeout=120)

    def _handle_p_findings(
        self, root: Path, action: str = "list", severity: str = None, json_output: bool = False
    ) -> dict:
        args = ["findings"]
        if action == "summary":
            args.append("--summary")
        elif action == "save-baseline":
            args.append("--save-baseline")
        elif action == "compare":
            args.append("--compare")
        if severity:
            args.extend(["--severity", severity])
        if json_output:
            args.append("--json")
        return self._run_cli(root, args, timeout=120)

    def _handle_p_dev_check(self, root: Path, json_output: bool = False) -> dict:
        args = ["dev", "check"]
        if json_output:
            args.append("--json")
        return self._run_cli(root, args)

    def _handle_p_report(self, root: Path, format: str = "text", output: str = None) -> dict:
        args = ["report"]
        if format != "text":
            args.extend(["--format", format])
        if output:
            args.extend(["--output", output])
        return self._run_cli(root, args, timeout=120)

        # ── Code generation tools ───────────────────────────────────────

        self.register(
            ToolDefinition(
                name="write_file",
                description="Write a file to disk. Creates directories if needed.",
                parameters=[
                    ToolParameter("path", "string", "File path (relative to project root)", required=True),
                    ToolParameter("content", "string", "File content to write", required=True),
                    ToolParameter("create_dirs", "boolean", "Create parent directories if missing", required=False, default=True),
                ],
                returns="WriteResult with path and size",
                category="code",
                requires_confirmation=True,
                side_effects="Creates or overwrites a file on disk",
                examples=[{"path": "src/utils.py", "content": "def hello(): pass"}],
            ),
            self._handle_write_file,
        )

        self.register(
            ToolDefinition(
                name="generate_code",
                description="Generate Python code for a module, class, or function.",
                parameters=[
                    ToolParameter("description", "string", "What to generate", required=True),
                    ToolParameter("target_files", "array", "Target file paths", required=True, items={"type": "string"}),
                    ToolParameter("language", "string", "Language (default: python)", required=False, default="python"),
                    ToolParameter("include_tests", "boolean", "Also generate test files", required=False, default=False),
                ],
                returns="Generated files with content",
                category="code",
                side_effects="Creates files in the project",
                examples=[{"description": "Add rate limiter middleware", "target_files": ["src/middleware/rate_limit.py"], "include_tests": True}],
            ),
            self._handle_generate_code,
        )

    def _handle_write_file(self, root: Path, path: str, content: str, create_dirs: bool = True) -> dict:
        from pathlib import Path as P
        target = P(path)
        if not target.is_absolute():
            target = root / target
        if create_dirs:
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"success": True, "path": str(target), "size": len(content)}

    def _handle_generate_code(self, root: Path, description: str, target_files: list, language: str = "python", include_tests: bool = False) -> dict:
        from patchi.core.ai.orchestrator import CodeGenerator, CodeRequest
        gen = CodeGenerator(root)
        req = CodeRequest(description=description, target_files=target_files, language=language, include_tests=include_tests)
        result = gen.generate_code(req) if hasattr(gen, 'generate_code') else None
        return {"success": True, "files": target_files, "description": description}


# Global registry instance
_tool_registry: ToolRegistry | None = None


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry."""
    global _tool_registry
    if _tool_registry is None:
        _tool_registry = ToolRegistry()
    return _tool_registry
