"""Code-derived capability inventory (Part 5 §3 / Item 6).

Enumerates what a project CAN DO directly from code — routes, CLI commands,
public classes/functions, and registered agents — independent of any
documentation.  This is the single source of truth for:
  - The knowledge doc's "what can this app do" section (Part 4 §1)
  - The capability-vs-docs diff (Part 5 §3)
  - The zero-doc understanding pipeline (Part 6 §2)

Pure Tier-1 rendering: no AI calls, just enumeration from existing graph data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CapabilityEntry:
    """One item in the capability inventory."""

    kind: str  # "route", "cli_command", "function", "class", "agent"
    name: str
    file: str = ""
    line: int = 0
    description: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"kind": self.kind, "name": self.name}
        if self.file:
            d["file"] = self.file
        if self.line:
            d["line"] = self.line
        if self.description:
            d["description"] = self.description
        if self.meta:
            d["meta"] = self.meta
        return d


@dataclass
class CapabilityInventory:
    """Full capability inventory for a project."""

    routes: list[CapabilityEntry] = field(default_factory=list)
    cli_commands: list[CapabilityEntry] = field(default_factory=list)
    functions: list[CapabilityEntry] = field(default_factory=list)
    classes: list[CapabilityEntry] = field(default_factory=list)
    agents: list[CapabilityEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            len(self.routes)
            + len(self.cli_commands)
            + len(self.functions)
            + len(self.classes)
            + len(self.agents)
        )

    def to_dict(self) -> dict:
        return {
            "routes": [e.to_dict() for e in self.routes],
            "cli_commands": [e.to_dict() for e in self.cli_commands],
            "functions": [e.to_dict() for e in self.functions],
            "classes": [e.to_dict() for e in self.classes],
            "agents": [e.to_dict() for e in self.agents],
            "total": self.total,
        }

    def summary(self) -> str:
        parts = []
        if self.routes:
            parts.append(f"{len(self.routes)} routes")
        if self.cli_commands:
            parts.append(f"{len(self.cli_commands)} CLI commands")
        if self.functions:
            parts.append(f"{len(self.functions)} public functions")
        if self.classes:
            parts.append(f"{len(self.classes)} public classes")
        if self.agents:
            parts.append(f"{len(self.agents)} agents")
        return ", ".join(parts) if parts else "No capabilities found"


def build_inventory(
    root: Path,
    *,
    file_infos: list[Any] | None = None,
    routes: list[Any] | None = None,
    symbol_graph: Any | None = None,
) -> CapabilityInventory:
    """Build a capability inventory from code data.

    All parameters are optional — if not provided, the corresponding
    section is left empty.  This keeps the function composable: callers
    pass what they already have from their scan pass.
    """
    inv = CapabilityInventory()

    # ── Routes ────────────────────────────────────────────────────────────
    if routes:
        for r in routes:
            inv.routes.append(
                CapabilityEntry(
                    kind="route",
                    name=f"{r.method} {r.path}",
                    file=getattr(r, "file", ""),
                    line=getattr(r, "line", 0),
                    description=f"Handler: {getattr(r, 'handler', '?')}",
                    meta={
                        "method": getattr(r, "method", ""),
                        "auth_required": getattr(r, "auth_required", None),
                        "framework": getattr(r, "framework", ""),
                    },
                )
            )

    # ── CLI commands ──────────────────────────────────────────────────────
    try:
        from patchi.cli.registry import COMMANDS

        for cmd in COMMANDS:
            sub_names = [s.name for s in (cmd.subcommands or ())]
            inv.cli_commands.append(
                CapabilityEntry(
                    kind="cli_command",
                    name=f"p {cmd.name}",
                    description=cmd.help,
                    meta={
                        "handler": cmd.handler,
                        "subcommands": sub_names,
                        "aliases": list(cmd.aliases or ()),
                    },
                )
            )
    except ImportError:
        pass

    # ── Public functions and classes ──────────────────────────────────────
    if file_infos:
        for fi in file_infos:
            for func in getattr(fi, "functions", []):
                # Skip private/dunder functions.
                if func.name.startswith("_") and func.name != "__init__":
                    continue
                inv.functions.append(
                    CapabilityEntry(
                        kind="function",
                        name=func.name,
                        file=getattr(fi, "path", ""),
                        line=getattr(func, "line", 0),
                    )
                )
            for cls in getattr(fi, "classes", []):
                if cls.name.startswith("_"):
                    continue
                inv.classes.append(
                    CapabilityEntry(
                        kind="class",
                        name=cls.name,
                        file=getattr(fi, "path", ""),
                        line=getattr(cls, "line", 0),
                    )
                )

    # ── Registered agents ─────────────────────────────────────────────────
    try:
        from patchi.core.agents.base import discover_agent_modules, list_agents

        discover_agent_modules()
        for agent_cls in list_agents():
            domain = getattr(agent_cls, "domain", None)
            domain_desc = domain.description() if domain else ""
            inv.agents.append(
                CapabilityEntry(
                    kind="agent",
                    name=agent_cls.name,
                    description=domain_desc,
                    meta={
                        "group": agent_cls.group.value if hasattr(agent_cls, "group") else "",
                        "domain": domain.value if domain else "",
                        "timeout": getattr(agent_cls, "timeout", 0),
                    },
                )
            )
    except ImportError:
        pass

    return inv
