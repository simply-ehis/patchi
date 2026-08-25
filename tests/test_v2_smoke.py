"""
Smoke tests for Patchi v2.0 upgrades.

Verifies:
1. Council + personas import and register correctly
2. Tool registry loads with all tools
3. Domain activator v2 scores domains from signals
4. Red team engine loads YAML scenarios
5. Live v2 modules import
6. Dashboard v2 router imports

Run: python -m pytest tests/test_v2_smoke.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture()
def patchi_project(tmp_path: Path) -> Path:
    """Create a minimal initialized Patchi project."""
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / ".patchi" / "memory").mkdir(parents=True)
    (root / "src" / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/users/{user_id}')\n"
        "def get_user(user_id: str):\n"
        "    import sqlite3\n"
        "    conn = sqlite3.connect('db.sqlite')\n"
        "    return conn.execute('SELECT * FROM users WHERE id=' + user_id).fetchall()\n",
        encoding="utf-8",
    )
    # Minimal memory files so mem.get_* don't explode
    for name in ("brain", "layers", "scans"):
        (root / ".patchi" / "memory" / f"{name}.json").write_text("{}", encoding="utf-8")
    (root / ".patchi" / "memory" / "patches.json").write_text("[]", encoding="utf-8")
    (root / ".patchi" / "memory" / "failed.json").write_text("[]", encoding="utf-8")
    (root / ".patchi" / "memory" / "issues.json").write_text("[]", encoding="utf-8")
    (root / ".patchi" / "config.json").write_text(json.dumps({"mode": "confirm"}), encoding="utf-8")
    return root


def test_personas_register():
    """All 8 personas register in the registry."""
    import patchi.core.brain.personas  # noqa: F401  (triggers registration)
    from patchi.core.brain.personas.base import list_personas

    names = list_personas()
    assert len(names) == 8, f"Expected 8 personas, got {len(names)}: {names}"
    expected = {
        "ArchitectPersona",
        "SecurityOfficerPersona",
        "TestEngineerPersona",
        "PerformanceAnalystPersona",
        "DevOpsEngineerPersona",
        "CodeReviewerPersona",
        "ProductOwnerPersona",
        "IncidentResponderPersona",
    }
    assert set(names) == expected


def test_persona_creation(patchi_project):
    """Personas can be instantiated against a project."""
    import patchi.core.brain.personas  # noqa: F401
    from patchi.core.brain.personas.base import create_persona, PERSONA_REGISTRY

    persona = create_persona(
        name="ArchitectPersona",
        root=patchi_project,
        brain_layers={},
        project_context={"project_purpose": "test"},
        config={},
    )
    assert persona is not None
    assert persona.get_expertise_areas()
    assert persona.get_style().value in ("cautious", "aggressive", "balanced", "innovative", "pragmatic")


def test_persona_heuristic_fallback(patchi_project):
    """When no AI is available, persona.analyze returns a heuristic decision."""
    import patchi.core.brain.personas  # noqa: F401
    from patchi.core.brain.personas.base import create_persona

    persona = create_persona(
        name="SecurityOfficerPersona",
        root=patchi_project,
        brain_layers={},
        project_context={},
        config={},  # No AI keys → heuristic path
    )
    decision = persona.analyze("SQL injection risk in user endpoint")
    assert decision.persona_name == "SecurityOfficerPersona"
    assert 0.0 <= decision.confidence <= 1.0
    assert decision.recommendation


def test_tool_registry_complete():
    """Tool registry has tools across all categories."""
    from patchi.core.ai.tools.registry import get_tool_registry

    registry = get_tool_registry()
    tools = registry.list_tools()
    names = {t.name for t in tools}

    categories = {t.category for t in tools}
    assert {"brain", "security", "testing", "fix", "memory"} <= categories

    # Key tools present
    for required in (
        "scan_project", "explain_layer", "impact_analysis",
        "scan_vulnerabilities", "attack_simulate", "red_team",
        "run_tests", "stress_test", "screenshot",
        "generate_fix", "apply_patch",
    ):
        assert required in names, f"Missing tool: {required}"

    # Schemas are valid JSON-schema-ish dicts
    schemas = registry.get_schemas()
    assert all("name" in s and "parameters" in s for s in schemas)


def test_tool_executor_memory_tool(patchi_project):
    """Executor runs a read-only memory tool end-to-end."""
    import asyncio

    from patchi.core.ai.tool_executor import ToolExecutor

    executor = ToolExecutor(patchi_project, confirmation_provider=None)
    result = asyncio.get_event_loop().run_until_complete(
        executor.execute("get_brain", {}, invoked_by="test", skip_confirmation=True)
    )
    # CLIConfirmationProvider(None default=False) — but skip_confirmation bypasses.
    assert result.success is True or result.error == "User declined confirmation"


def test_domain_activator_signals(patchi_project):
    """Domain activator detects SQL injection signal from vulnerable code."""
    from patchi.core.security.domain_activator_v2 import SignalExtractor

    extractor = SignalExtractor(patchi_project)
    signals = extractor._extract_code_signals([])  # file_infos empty; reads via content cache? No—

    # The code-signal extraction works off FileInfo objects; craft a fake one
    class FakeImport:
        def __init__(self, name):
            self.name = name

    class FakeFI:
        path = "src/app.py"
        error = None
        imports = [FakeImport("sqlite3")]

    signals = extractor._extract_code_signals([FakeFI()])
    domains = {s.domain for s in signals}
    assert any("injection" in d for d in domains), f"No injection domain in {domains}"


def test_red_team_scenario_loading(patchi_project):
    """Red team engine loads the YAML attack scenarios."""
    from patchi.core.security.red_team_engine import RedTeamEngine

    engine = RedTeamEngine.__new__(RedTeamEngine)  # Skip __init__ (needs package paths)
    engine.scenarios_dir = Path(__file__).parent.parent / "patchi" / "core" / "security" / "attack_scenarios"
    engine._scenarios_cache = {}

    scenarios = engine._load_scenarios()
    assert len(scenarios) >= 10, f"Expected >=10 scenarios, got {len(scenarios)}"

    ids = set(scenarios.keys())
    assert "sqli-basic-union" in ids
    assert "xss-reflected-basic" in ids
    assert "auth-jwt-alg-none" in ids

    # Scenario structure sanity
    for sid, sc in scenarios.items():
        assert sc.get("id") == sid
        assert sc.get("name"), sid
        assert sc.get("severity") in ("critical", "high", "medium", "low"), sid
        assert sc.get("attack_steps"), sid


def test_scenario_selection_scoring(patchi_project):
    """Scenario selection prefers relevant scenarios by context."""
    from patchi.core.security.red_team_engine import RedTeamEngine

    engine = RedTeamEngine.__new__(RedTeamEngine)
    engine.scenarios_dir = Path(__file__).parent.parent / "patchi" / "core" / "security" / "attack_scenarios"
    engine._scenarios_cache = {}

    context = {
        "active_security_domains": ["injection-sql"],
        "frameworks": [{"name": "FastAPI"}],
        "component_type": "backend-api",
    }
    selected = engine.select_scenarios(context, scope="full", intensity="active")
    assert selected
    # A SQL injection scenario should rank highly given the context
    top_ids = [s["id"] for s in selected[:5]]
    assert any("sqli" in i for i in top_ids), f"SQLi not in top 5: {top_ids}"


def test_live_v2_imports():
    """All live testing v2 modules import cleanly."""
    from patchi.core.testing.live_v2.browser_pool import BrowserPool, BrowserConfig  # noqa: F401
    from patchi.core.testing.live_v2.stress_orchestrator import (  # noqa: F401
        StressConfig,
        StressOrchestrator,
    )
    from patchi.core.testing.live_v2.screenshot_manager import (  # noqa: F401
        ScreenshotManager,
        ScreenshotConfig,
    )


def test_stress_config_defaults():
    from patchi.core.testing.live_v2.stress_orchestrator import StressConfig

    cfg = StressConfig(base_url="http://localhost:3000")
    assert cfg.scenario == "load"
    assert cfg.users == 10


def test_dashboard_v2_router_imports():
    """Dashboard v2 router imports without breaking core app."""
    try:
        from patchi.web.routes.dashboard_v2 import router  # noqa: F401

        assert router is not None
    except Exception as e:
        pytest.fail(f"dashboard_v2 failed to import: {e}")


def test_council_import_and_selection(patchi_project):
    """Council imports and selects relevant personas for an issue."""
    from patchi.core.brain.council import Council

    council = Council(patchi_project)

    security_issue = "Critical SQL injection vulnerability found in login endpoint"
    selected = council._select_personas(security_issue)
    assert "security_officer" in selected, f"Security officer not selected: {selected}"
    assert len(selected) >= 3

    perf_issue = "Application latency is very slow under load"
    selected_perf = council._select_personas(perf_issue)
    assert "performance_analyst" in selected_perf
