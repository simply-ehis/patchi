"""Unit tests for patchi.core.agents.base"""

import unittest
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    get_agent,
    list_agents,
    make_finding,
    register,
)

# ── Minimal concrete agent for testing ────────────────────────────────────────


class OkAgent(BaseAgent):
    name = "OkAgent"
    group = AgentGroup.SCANNER
    timeout = 5

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        result.files_scanned = 3
        result.add_finding(
            make_finding(
                agent="OkAgent",
                finding_type="test_finding",
                severity=Severity.LOW,
                file="src/foo.py",
                line=10,
                message="Test message.",
            )
        )


class ErrorAgent(BaseAgent):
    name = "ErrorAgent"
    group = AgentGroup.SCANNER
    timeout = 5

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        raise ValueError("Intentional test error")


class SkipAgent(BaseAgent):
    name = "SkipAgent"
    group = AgentGroup.SCANNER
    timeout = 5

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        self.skip(result, "No TypeScript files found.")


def _make_input() -> AgentInput:
    return AgentInput(
        root=Path("/tmp"),
        scope=[],
        brain={},
        config={},
    )


class TestBaseAgent(unittest.TestCase):
    def test_run_returns_result(self):
        agent = OkAgent()
        result = agent.run(_make_input())
        self.assertIsInstance(result, AgentResult)

    def test_successful_run_sets_done(self):
        result = OkAgent().run(_make_input())
        self.assertEqual(result.status, AgentStatus.DONE)

    def test_findings_populated(self):
        result = OkAgent().run(_make_input())
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].type, "test_finding")

    def test_files_scanned_populated(self):
        result = OkAgent().run(_make_input())
        self.assertEqual(result.files_scanned, 3)

    def test_duration_populated(self):
        result = OkAgent().run(_make_input())
        # duration_ms is int(seconds * 1000) — can be 0 for very fast agents
        self.assertGreaterEqual(result.duration_ms, 0)
        # But timestamps must be set
        self.assertNotEqual(result.started_at, "")
        self.assertNotEqual(result.completed_at, "")

    def test_timestamps_populated(self):
        result = OkAgent().run(_make_input())
        self.assertNotEqual(result.started_at, "")
        self.assertNotEqual(result.completed_at, "")

    def test_exception_sets_failed(self):
        result = ErrorAgent().run(_make_input())
        self.assertEqual(result.status, AgentStatus.FAILED)

    def test_exception_captured_in_errors(self):
        result = ErrorAgent().run(_make_input())
        self.assertTrue(any("ValueError" in e for e in result.errors))

    def test_skip_sets_skipped(self):
        result = SkipAgent().run(_make_input())
        self.assertEqual(result.status, AgentStatus.SKIPPED)

    def test_skip_records_reason(self):
        result = SkipAgent().run(_make_input())
        self.assertIn("skip_reason", result.data)

    def test_agent_name_in_result(self):
        result = OkAgent().run(_make_input())
        self.assertEqual(result.agent_name, "OkAgent")

    def test_agent_group_in_result(self):
        result = OkAgent().run(_make_input())
        self.assertEqual(result.agent_group, AgentGroup.SCANNER)


class TestAgentResult(unittest.TestCase):
    def _make_result(self) -> AgentResult:
        r = AgentResult(
            agent_name="Test",
            agent_group=AgentGroup.SCANNER,
            status=AgentStatus.DONE,
        )
        return r

    def test_finding_count_zero_initially(self):
        r = self._make_result()
        self.assertEqual(r.finding_count, 0)

    def test_add_finding_increments_count(self):
        r = self._make_result()
        r.add_finding(make_finding("Test", "bug", Severity.HIGH, "a.py", "msg"))
        self.assertEqual(r.finding_count, 1)

    def test_has_critical_false_when_no_critical(self):
        r = self._make_result()
        r.add_finding(make_finding("Test", "bug", Severity.LOW, "a.py", "msg"))
        self.assertFalse(r.has_critical)

    def test_has_critical_true_when_critical_present(self):
        r = self._make_result()
        r.add_finding(make_finding("Test", "bug", Severity.CRITICAL, "a.py", "msg"))
        self.assertTrue(r.has_critical)

    def test_by_severity_groups_correctly(self):
        r = self._make_result()
        r.add_finding(make_finding("T", "x", Severity.HIGH, "a.py", "m"))
        r.add_finding(make_finding("T", "x", Severity.HIGH, "b.py", "m"))
        r.add_finding(make_finding("T", "x", Severity.MEDIUM, "c.py", "m"))
        self.assertEqual(len(r.by_severity["high"]), 2)
        self.assertEqual(len(r.by_severity["medium"]), 1)
        self.assertEqual(len(r.by_severity["low"]), 0)

    def test_add_error_sets_failed(self):
        r = self._make_result()
        r.add_error("something broke")
        self.assertEqual(r.status, AgentStatus.FAILED)
        self.assertIn("something broke", r.errors)

    def test_to_dict_keys(self):
        r = self._make_result()
        d = r.to_dict()
        for key in ("agent", "group", "status", "findings", "data", "errors"):
            self.assertIn(key, d)

    def test_summary_line_includes_name(self):
        r = self._make_result()
        line = r.summary_line()
        self.assertIn("Test", line)


class TestFinding(unittest.TestCase):
    def test_to_dict(self):
        f = make_finding(
            agent="CoreScanner",
            finding_type="parse_error",
            severity=Severity.LOW,
            file="src/app.py",
            line=42,
            message="Could not parse.",
            cwe="CWE-710",
        )
        d = f.to_dict()
        self.assertEqual(d["agent"], "CoreScanner")
        self.assertEqual(d["type"], "parse_error")
        self.assertEqual(d["severity"], "low")
        self.assertEqual(d["file"], "src/app.py")
        self.assertEqual(d["line"], 42)
        self.assertEqual(d["cwe"], "CWE-710")

    def test_extra_kwargs_in_dict(self):
        f = make_finding("A", "t", Severity.LOW, "f.py", "m", similarity_score=0.91)
        d = f.to_dict()
        self.assertEqual(d["similarity_score"], 0.91)


class TestSeverity(unittest.TestCase):
    def test_sort_key_order(self):
        self.assertLess(Severity.CRITICAL.sort_key(), Severity.HIGH.sort_key())
        self.assertLess(Severity.HIGH.sort_key(), Severity.MEDIUM.sort_key())
        self.assertLess(Severity.MEDIUM.sort_key(), Severity.LOW.sort_key())
        self.assertLess(Severity.LOW.sort_key(), Severity.INFO.sort_key())

    def test_color_returns_string(self):
        for sev in Severity:
            self.assertIsInstance(sev.color(), str)
            self.assertTrue(sev.color().startswith("#"))


class ShadowAgent(BaseAgent):
    name = "ShadowAgent"
    group = AgentGroup.TEST

    def _run(self, inp, result):
        pages = {"a": {"violations": []}}
        total = sum(len(item.get("violations", [])) for item in pages.values())
        for _url, result in pages.items():  # shadow! rebinds the AgentResult
            total += len(result.get("violations", []))
        result.status = AgentStatus.DONE
        return


class TestRegistry(unittest.TestCase):
    def tearDown(self):
        from patchi.core.agents.base import deregister
        deregister(self._test_agent) if hasattr(self, '_test_agent') else None

    def test_register_makes_agent_findable(self):
        @register
        class MyTestAgent(BaseAgent):
            name = "MyTestAgent"
            group = AgentGroup.SCANNER

            def _run(self, inp, result):
                pass

        self._test_agent = MyTestAgent
        self.assertIsNotNone(get_agent("MyTestAgent"))

    def test_get_agent_returns_none_for_unknown(self):
        self.assertIsNone(get_agent("GhostAgent_XYZ_999"))

    def test_list_agents_returns_all(self):
        # After importing scanners, all 11 should be registered
        import patchi.core.agents.scanners  # noqa

        agents = list_agents(AgentGroup.SCANNER)
        self.assertGreaterEqual(len(agents), 11)

    def test_list_agents_filter_by_group(self):
        import patchi.core.agents.scanners  # noqa

        scanner_agents = list_agents(AgentGroup.SCANNER)
        for a in scanner_agents:
            self.assertEqual(a.group, AgentGroup.SCANNER)

    # ── Auto-discovery + contract check ───────────────────────────────────

    def test_register_rejects_plain_class(self):
        """@register on a non-BaseAgent class must raise — the PysaAgent/
        CodeqlAgent bug (registered plain classes with no run()) fails at
        registration time, not silently in the pipeline."""
        with self.assertRaises(TypeError):

            @register
            class NotAnAgent:
                name = "NotAnAgent"

    def test_register_rejects_missing_name(self):
        with self.assertRaises(TypeError):

            @register
            class NoNameAgent(BaseAgent):
                group = AgentGroup.SCANNER

                def _run(self, inp, result):
                    pass

    def test_register_rejects_bad_group(self):
        with self.assertRaises(TypeError):

            @register
            class BadGroupAgent(BaseAgent):
                name = "BadGroupAgent"
                group = "scanner"  # not an AgentGroup member

                def _run(self, inp, result):
                    pass

    def test_validate_agent_registry_clean_after_discovery(self):
        """Discovering every agent module must import cleanly and leave a
        registry with zero contract violations."""
        from patchi.core.agents.base import (
            discover_agent_modules,
            validate_agent_registry,
        )

        self.assertEqual(discover_agent_modules(), [])
        self.assertEqual(validate_agent_registry(), [])

    def test_discovery_imports_more_than_aggregators(self):
        """Auto-discovery walks the whole package tree, so a module that is NOT
        imported by scanners.py / security_agents.py / test_agents.py / fix/
        still fires its @register — e.g. flake_detector_agent is not re-exported
        by test_agents, and attack_agent/doc_claim_agent are not
        pulled in by any aggregator."""
        from patchi.core.agents.base import AGENT_PACKAGES, discover_agent_modules

        self.assertEqual(discover_agent_modules(), [])
        for name in (
            "FlakeDetectorAgent",
            "AttackAgent",
            "DocClaimAgent",
        ):
            self.assertIsNotNone(get_agent(name), f"{name} must register via discovery")
        # The walk covers all five packages.
        self.assertGreaterEqual(len(AGENT_PACKAGES), 5)

    def test_validate_agent_registry_flags_broken_registration(self):
        """A registered non-BaseAgent (injected to bypass the register guard)
        must be flagged by the startup contract check."""
        from patchi.core.agents import base as base_mod

        base_mod._REGISTRY["SneakyPlain"] = object  # bypass register()
        try:
            violations = base_mod.validate_agent_registry()
        finally:
            base_mod._REGISTRY.pop("SneakyPlain", None)
        self.assertTrue(
            any("SneakyPlain" in v and "not a BaseAgent" in v for v in violations),
            f"expected a contract violation, got {violations}",
        )

    def test_register_rejects_old_style_run_signature(self):
        """register() must reject an agent whose _run is old-style
        (self, inp) instead of (self, inp, result) — the inspect.signature
        shim that tolerated that shape is gone."""
        from patchi.core.agents import base as base_mod

        class OldStyleAgent(base_mod.BaseAgent):
            name = "OldStyleAgent"
            group = base_mod.AgentGroup.SCANNER

            def _run(self, inp):  # old shape
                return base_mod.AgentResult(status=base_mod.AgentStatus.DONE)

        with self.assertRaises(TypeError) as ctx:
            base_mod.register(OldStyleAgent)
        self.assertIn("_run(self, inp, result)", str(ctx.exception))

    def test_validate_agent_registry_flags_wrong_run_signature(self):
        """Direct _REGISTRY injections with a wrong _run shape must be
        flagged by the startup contract check (defense-in-depth for entries
        that bypass register())."""
        from patchi.core.agents import base as base_mod

        class BadShapeAgent(base_mod.BaseAgent):
            name = "BadShapeAgent"
            group = base_mod.AgentGroup.SCANNER

            def _run(self, inp):  # old shape
                return base_mod.AgentResult(status=base_mod.AgentStatus.DONE)

        base_mod._REGISTRY["BadShapeAgent"] = BadShapeAgent
        try:
            violations = base_mod.validate_agent_registry()
        finally:
            base_mod._REGISTRY.pop("BadShapeAgent", None)
        self.assertTrue(
            any("BadShapeAgent" in v and "inp, result" in v for v in violations),
            f"expected a _run-signature violation, got {violations}",
        )

    def test_registry_flags_result_shadowing_in_run(self):
        """_run(inp, result) mutates the passed-in result, so any rebinding of
        the `result` name followed by a later use is a latent crash (the
        accessibility/api-contract shadow bugs) — validate_agent_registry must
        flag it statically."""
        from patchi.core.agents import base as base_mod

        # Module-level so inspect.getsource(cls) can resolve its source.
        base_mod._REGISTRY["ShadowAgent"] = ShadowAgent
        try:
            violations = base_mod.validate_agent_registry()
        finally:
            base_mod._REGISTRY.pop("ShadowAgent", None)
        self.assertTrue(
            any("ShadowAgent" in v and "rebinds `result`" in v for v in violations),
            f"expected a shadowing violation, got {violations}",
        )

    def test_registry_clean_agents_have_no_shadowing(self):
        """The live fleet must be free of `result` rebinding in _run — the
        shadow check runs over every registered agent."""
        from patchi.core.agents.base import (
            discover_agent_modules,
            list_agents,
            validate_agent_registry,
        )

        self.assertEqual(discover_agent_modules(), [])
        violations = validate_agent_registry()
        shadow_violations = [v for v in violations if "rebinds `result`" in v]
        self.assertEqual(
            shadow_violations, [], f"agents shadow `result` in _run: {shadow_violations}"
        )
        self.assertGreater(len(list_agents()), 90)


if __name__ == "__main__":
    unittest.main()
