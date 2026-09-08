"""
Command Families — organized command discovery for Patchi CLI.

Groups commands into families. `p <family>` runs the default action.
`p <family> commands` shows all subcommands in that family.

Usage:
    from patchi.cli.command_families import FAMILIES, get_family, list_families
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CommandFamily:
    """A family of related commands."""

    name: str
    description: str
    default_command: str | None = None  # What `p <family>` runs
    commands: list[str] = field(default_factory=list)  # Subcommands in this family
    agent_domain: str | None = None  # Linked AgentDomain for agent discovery


FAMILIES: dict[str, CommandFamily] = {
    "test": CommandFamily(
        name="test",
        description="Testing — unit, e2e, visual, stress, regression",
        default_command="test",
        commands=["unit", "e2e", "visual", "stress", "generate", "report", "config", "regression"],
        agent_domain="testing",
    ),
    "scan": CommandFamily(
        name="scan",
        description="Scanning — full analysis, security, structure",
        default_command="scan",
        commands=["deep", "security", "structure", "since", "contract", "changed"],
        agent_domain="code_quality",
    ),
    "fix": CommandFamily(
        name="fix",
        description="Fixing — propose and apply fixes",
        default_command="fix",
        commands=["auto", "review", "patch", "undo", "redo", "rollback"],
        agent_domain="integration",
    ),
    "ready": CommandFamily(
        name="ready",
        description="Ship readiness — is my code ready to ship?",
        default_command="ready",
        commands=["quick", "ci", "json", "baseline"],
        agent_domain="testing",
    ),
    "security": CommandFamily(
        name="security",
        description="Security — vulnerability scanning and hardening",
        default_command="security",
        commands=["chains", "findings", "rules", "deps", "assure", "charter", "restrict"],
        agent_domain="security",
    ),
    "web": CommandFamily(
        name="web",
        description="Web dashboard — launch and manage the web UI",
        default_command="web",
        commands=["host", "port", "open", "project"],
        agent_domain="infrastructure",
    ),
    "status": CommandFamily(
        name="status",
        description="Status — project health and monitoring",
        default_command="status",
        commands=["doctor", "cockpit", "trend", "heatmap"],
        agent_domain="infrastructure",
    ),
    "audit": CommandFamily(
        name="audit",
        description="Auditing — full project audit",
        default_command="audit",
        commands=["quick", "plan", "intent", "html", "json"],
        agent_domain="code_quality",
    ),
    "config": CommandFamily(
        name="config",
        description="Configuration — settings and preferences",
        default_command="config",
        commands=["key", "model", "settings", "brain", "access", "link", "notify", "rules", "plugins"],
        agent_domain="infrastructure",
    ),
    "agent": CommandFamily(
        name="agent",
        description="Agents — list, run, and manage agents",
        default_command="agents",
        commands=["list", "run", "stats", "reset"],
        agent_domain="infrastructure",
    ),
    "git": CommandFamily(
        name="git",
        description="Git — blame and log integration",
        default_command="git",
        commands=["blame", "log"],
        agent_domain="infrastructure",
    ),
    "maintain": CommandFamily(
        name="maintain",
        description="Maintenance — updates and cleanup",
        default_command="update",
        commands=["cleanup", "doctor"],
        agent_domain="infrastructure",
    ),
    "hosted": CommandFamily(
        name="hosted",
        description="Hosted — production monitoring",
        default_command="hosted",
        commands=["init", "worker", "daemon", "guard", "status", "logs", "token", "block"],
        agent_domain="infrastructure",
    ),
    "ai": CommandFamily(
        name="ai",
        description="AI — chat and model configuration",
        default_command="ai",
        commands=["status", "test", "add", "remove", "profiles"],
        agent_domain="infrastructure",
    ),
    "report": CommandFamily(
        name="report",
        description="Reporting — generate and export reports",
        default_command="report",
        commands=["export", "weekly"],
        agent_domain="testing",
    ),
    "init": CommandFamily(
        name="init",
        description="Initialize — project setup",
        default_command="init",
        commands=["auto", "no-logo"],
        agent_domain="infrastructure",
    ),
    "queue": CommandFamily(
        name="queue",
        description="Queue — manage the scan queue",
        default_command="queue",
        commands=["pause", "resume", "skip", "mode"],
        agent_domain="infrastructure",
    ),
    "plan": CommandFamily(
        name="plan",
        description="Planning — plan changes",
        default_command="plan",
        commands=["format", "missing-import"],
        agent_domain="infrastructure",
    ),
    "verify": CommandFamily(
        name="verify",
        description="Verify — independent re-run of tests",
        default_command="verify",
        commands=[],
        agent_domain="testing",
    ),
    "help": CommandFamily(
        name="help",
        description="Help — show help and documentation",
        default_command="help",
        commands=["all", "group", "json", "write-md"],
        agent_domain="infrastructure",
    ),
    "watch": CommandFamily(
        name="watch",
        description="Watch — auto-scan on file saves",
        default_command="watch",
        commands=[],
        agent_domain="infrastructure",
    ),
    "doctor": CommandFamily(
        name="doctor",
        description="Doctor — system health check",
        default_command="doctor",
        commands=[],
        agent_domain="infrastructure",
    ),
    "trend": CommandFamily(
        name="trend",
        description="Trend — historical analysis",
        default_command="trend",
        commands=[],
        agent_domain="testing",
    ),
    "memory": CommandFamily(
        name="memory",
        description="Memory — persistent context and learning",
        default_command="memory",
        commands=[],
        agent_domain="infrastructure",
    ),
}


def get_family(name: str) -> CommandFamily | None:
    """Get a family by name."""
    return FAMILIES.get(name)


def list_families() -> list[CommandFamily]:
    """List all families in order."""
    return list(FAMILIES.values())


def find_family_for_command(command: str) -> CommandFamily | None:
    """Find which family a command belongs to."""
    for family in FAMILIES.values():
        if command in family.commands or command == family.default_command:
            return family
    return None


def format_family_help(family: CommandFamily) -> str:
    """Format help text for a family."""
    lines = [f"p {family.name} — {family.description}"]
    if family.commands:
        lines.append("")
        lines.append("Subcommands:")
        for cmd in family.commands:
            lines.append(f"  p {family.name} {cmd}")
    return "\n".join(lines)


def format_all_families() -> str:
    """Format help text for all families."""
    lines = ["Patchi Command Families", "=" * 40, ""]
    for family in FAMILIES.values():
        lines.append(f"p {family.name:12} — {family.description}")
    lines.append("")
    lines.append("Use 'p <family> commands' to see all subcommands in a family.")
    return "\n".join(lines)