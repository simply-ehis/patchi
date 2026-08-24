"""
Plan Auditor Agent — audits a Patchi checkout against build plan specs.

Only runs when the scanned root actually contains the Patchi package (a
`patchi/core/security` tree); against any third-party project the checks are
meaningless — every Patchi-internal path it references is absent by
construction, so emitting them would fabricate CRITICAL/HIGH findings.

Checks that:
- All agents registered in BUILD_PLAN.md are actually registered
- All CLI commands exist and are wired up
- All security scan types work
- All test files exist for new modules
- Health score components are wired correctly
"""

from __future__ import annotations

import re
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    list_agents,
    register,
)


@register
class PlanAuditorAgent(BaseAgent):
    """Audits codebase against BUILD_PLAN.md specifications."""

    name = "PlanAuditorAgent"
    group = AgentGroup.GUARD
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root

        # This agent audits PATCHI ITSELF against its build plan (registered
        # agents, CLI wiring, Patchi-internal modules). Every check below is
        # meaningless when the scanned project is not a Patchi checkout — the
        # paths it references simply cannot exist in a third-party codebase,
        # so emitting them would fabricate CRITICAL/HIGH findings about a
        # project it isn't auditing. Skip unless a Patchi package is present.
        if not (root / "patchi" / "core" / "security").is_dir():
            return

        # Check 1: All security agents registered
        self._check_security_agents(root, result)

        # Check 2: All CLI commands wired
        self._check_cli_commands(root, result)

        # Check 3: New modules exist
        self._check_new_modules(root, result)

        # Check 4: Test coverage for new modules
        self._check_test_coverage(root, result)

        # Check 5: Health score wiring
        self._check_health_wiring(root, result)

    def _check_security_agents(self, root: Path, result: AgentResult) -> None:
        """Verify all registered security agents are imported in security_agents.py."""
        expected_agents = [
            a.name
            for a in list_agents()
            if a.group == AgentGroup.SECURITY or a.name == "PlanAuditorAgent"
        ]

        sec_file = root / "patchi" / "core" / "security" / "security_agents.py"
        if not sec_file.exists():
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="plan_audit",
                    severity=Severity.CRITICAL,
                    file="patchi/core/security/security_agents.py",
                    message="security_agents.py not found",
                )
            )
            return

        try:
            content = sec_file.read_text(encoding="utf-8")
        except OSError:
            return
        for agent_name in expected_agents:
            if agent_name not in content:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="plan_audit",
                        severity=Severity.HIGH,
                        file="patchi/core/security/security_agents.py",
                        message=f"Agent '{agent_name}' not imported in security_agents.py",
                    )
                )

        # Check __all__ includes all agents
        all_match = re.search(r"__all__\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if all_match:
            all_text = all_match.group(1)
            for agent_name in expected_agents:
                if f"'{agent_name}'" not in all_text and f'"{agent_name}"' not in all_text:
                    result.add_finding(
                        Finding(
                            agent=self.name,
                            type="plan_audit",
                            severity=Severity.MEDIUM,
                            file="patchi/core/security/security_agents.py",
                            message=f"Agent '{agent_name}' not in __all__",
                        )
                    )

    def _check_cli_commands(self, root: Path, result: AgentResult) -> None:
        """Verify all CLI commands exist."""
        expected_commands = [
            "init",
            "scan",
            "status",
            "fix",
            "review",
            "patch",
            "undo",
            "queue",
            "memory",
            "key",
            "agents",
            "watch",
            "mode",
            "restrict",
            "notify",
            "web",
            "doctor",
            "model",
            "report",
            "hosted",
            "test",
            "security",
            "explain",
            "blast",
            "trend",
            "audit",
            "learn",
            "chat",
            "settings",
            "access",
            "ai",
            "help",
        ]

        cmd_dir = root / "patchi" / "cli" / "commands"
        if not cmd_dir.exists():
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="plan_audit",
                    severity=Severity.CRITICAL,
                    file="patchi/cli/commands/",
                    message="Commands directory not found",
                )
            )
            return

        existing = {f.stem for f in cmd_dir.glob("*.py")}
        for cmd in expected_commands:
            expected_file = f"{cmd}_cmd" if cmd != "init" else "init"
            if expected_file not in existing:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="plan_audit",
                        severity=Severity.HIGH,
                        file=f"patchi/cli/commands/{expected_file}.py",
                        message=f"CLI command '{cmd}' not found",
                    )
                )

    def _check_new_modules(self, root: Path, result: AgentResult) -> None:
        """Verify new security modules exist."""
        expected_modules = [
            "orchestrator.py",
            "secrets_guard.py",
            "supply_chain.py",
            "iac_scanner.py",
            "policy_engine.py",
            "cve_monitor.py",
            "red_team_agent.py",
        ]

        sec_dir = root / "patchi" / "core" / "security"
        for mod in expected_modules:
            if not (sec_dir / mod).exists():
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="plan_audit",
                        severity=Severity.HIGH,
                        file=f"patchi/core/security/{mod}",
                        message=f"New module '{mod}' not found",
                    )
                )

        # Check security_test_agent
        test_dir = root / "patchi" / "core" / "testing"
        if not (test_dir / "security_test_agent.py").exists():
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="plan_audit",
                    severity=Severity.HIGH,
                    file="patchi/core/testing/security_test_agent.py",
                    message="SecurityTestAgent module not found",
                )
            )

    def _check_test_coverage(self, root: Path, result: AgentResult) -> None:
        """Verify tests exist for new modules."""
        test_file = root / "tests" / "test_new_security_agents.py"
        if not test_file.exists():
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="plan_audit",
                    severity=Severity.HIGH,
                    file="tests/test_new_security_agents.py",
                    message="New security agent tests not found",
                )
            )
        else:
            try:
                content = test_file.read_text(encoding="utf-8")
            except OSError:
                return
            test_count = content.count("def test_")
            if test_count < 20:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="plan_audit",
                        severity=Severity.MEDIUM,
                        file="tests/test_new_security_agents.py",
                        message=f"Only {test_count} tests in new security agent test file (expected 20+)",
                    )
                )

    def _check_health_wiring(self, root: Path, result: AgentResult) -> None:
        """Verify health score references new agents."""
        health_file = root / "patchi" / "core" / "health.py"
        if not health_file.exists():
            return

        try:
            content = health_file.read_text(encoding="utf-8")
        except OSError:
            return
        # Check that security agents list includes new agents
        new_agents = ["InjectionAgent", "AuthZAgent", "CryptoAgent", "NetworkAgent", "PrivacyAgent"]
        for agent in new_agents:
            if agent not in content:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="plan_audit",
                        severity=Severity.MEDIUM,
                        file="patchi/core/health.py",
                        message=f"Health score doesn't reference '{agent}'",
                    )
                )
