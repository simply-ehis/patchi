"""
Red Team Agent — adversarial testing and attack simulation.

Generates adversarial test cases and simulates attacker workflows.
Reports findings with exploit scenarios and severity.
"""

from __future__ import annotations

import re

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)


@register
class RedTeamAgent(BaseAgent):
    """Adversarial testing: attack trees, exploit scenarios, fuzzing targets."""

    name = "RedTeamAgent"
    group = AgentGroup.SECURITY
    timeout = 120

    # Static-analysis hits mapped to the attack-scenario library
    # (patchi/core/security/attack_scenarios/) and fix playbooks, so findings
    # from this agent feed the Red Team Engine / AutoFixer pipeline instead of
    # being dead-end pattern reports.
    _PATTERN_LINKS: dict[str, tuple[str, str]] = {
        # finding-message substring -> (scenario_family, remediation_playbook)
        "eval(": ("injection-command", "fix-command-injection-no-eval"),
        "exec(": ("injection-command", "fix-command-injection-no-exec"),
        "os.system": ("injection-command", "fix-command-injection-shell-false"),
        "subprocess.call": ("injection-command", "fix-command-injection-shell-false"),
        "pickle deserialization": ("deserialization", "fix-deserialization-safe-load"),
        "marshal deserialization": ("deserialization", "fix-deserialization-safe-load"),
        "yaml.load": ("deserialization", "fix-deserialization-safe-load"),
        "template rendering": ("xss-template", "fix-xss-template-autoescape"),
        "debug mode enabled": ("security-headers", "fix-misconfig-debug-off"),
        "allowed_hosts": ("security-headers", "fix-misconfig-host-allowlist"),
    }

    def _link_for(self, message: str) -> tuple[str, str]:
        for needle, link in self._PATTERN_LINKS.items():
            if needle.lower() in message.lower():
                return link
        return ("", "")

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        routes = inp.brain.get("routes", [])
        files_scanned = 0

        # Analyze routes for attack surface
        for route_info in routes:
            route = (
                route_info.get("path", "")
                if isinstance(route_info, dict)
                else getattr(route_info, "path", "")
            )
            method = (
                route_info.get("method", "get")
                if isinstance(route_info, dict)
                else getattr(route_info, "method", "get")
            ).lower()

            # Check for parameterized routes (injection surface)
            if re.search(r"\{[^}]+\}|:<\w+>|\d+", route):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="attack_surface",
                        severity=Severity.MEDIUM,
                        file="",
                        line=0,
                        message=f"Parameterized route: {method.upper()} {route}",
                        detail="Route accepts dynamic parameters — verify input validation",
                        suggestion="Validate/parameterize inputs; see sqli-basic-union scenario",
                        cwe="CWE-20",
                        extra={
                            "attack_surface": "static",
                            "scenario_family": "injection",
                            "remediation_playbook": "fix-sqli-parameterized-queries",
                            "route": f"{method.upper()} {route}",
                        },
                    )
                )

            # State-changing without apparent auth
            if method in ("post", "put", "patch", "delete"):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="attack_surface",
                        severity=Severity.HIGH,
                        file="",
                        line=0,
                        message=f"State-changing endpoint: {method.upper()} {route}",
                        detail="Verify authentication and authorization are enforced",
                        suggestion="Enforce auth decorators + object-level authz checks",
                        cwe="CWE-306",
                        extra={
                            "attack_surface": "static",
                            "scenario_family": "authorization",
                            "remediation_playbook": "fix-authz-role-checks",
                            "route": f"{method.upper()} {route}",
                        },
                    )
                )

        # Scan source for attack patterns
        source_patterns = ["*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.go", "*.java"]
        attack_patterns = [
            (r"eval\s*\(", Severity.CRITICAL, "eval() usage — potential code injection"),
            (r"exec\s*\(", Severity.CRITICAL, "exec() usage — potential code injection"),
            (r"os\.system\s*\(", Severity.CRITICAL, "os.system() — command injection risk"),
            (
                r"subprocess\.call\s*\(",
                Severity.HIGH,
                "subprocess.call — verify input sanitization",
            ),
            (r"pickle\.loads?\s*\(", Severity.CRITICAL, "pickle deserialization — RCE risk"),
            (r"marshal\.loads?\s*\(", Severity.CRITICAL, "marshal deserialization — RCE risk"),
            (
                r"yaml\.load\s*\([^)]*\)",
                Severity.HIGH,
                "yaml.load without SafeLoader — code execution risk",
            ),
            (
                r"template\.render\s*\(",
                Severity.MEDIUM,
                "Template rendering — verify XSS protection",
            ),
            (r"DEBUG\s*=\s*True", Severity.HIGH, "Debug mode enabled — information disclosure"),
            (r'ALLOWED_HOSTS\s*=\s*\["?\*"?\]', Severity.HIGH, "ALLOWED_HOSTS set to wildcard"),
        ]

        for pattern in source_patterns:
            for fpath in safe_rglob(inp.root, pattern):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                files_scanned += 1

                lines = content.splitlines()
                for i, line in enumerate(lines, 1):
                    for rx, sev, msg in attack_patterns:
                        if re.search(rx, line):
                            family, playbook = self._link_for(msg)
                            result.add_finding(
                                Finding(
                                    agent=self.name,
                                    type="vulnerable_pattern",
                                    severity=sev,
                                    file=rel,
                                    line=i,
                                    message=msg,
                                    code_snippet=line.strip()[:120],
                                    suggestion=(
                                        f"Remediate via playbook: {playbook}"
                                        if playbook
                                        else "Review for safe usage or remove"
                                    ),
                                    extra={
                                        "attack_surface": "static",
                                        "scenario_family": family,
                                        "remediation_playbook": playbook,
                                    },
                                )
                            )

        result.files_scanned = files_scanned
