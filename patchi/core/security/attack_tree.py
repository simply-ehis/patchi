"""
Attack Tree generation — renders exploit chains as goal-oriented trees.

Where ChainAnalyzer answers "how do findings connect?", the attack tree
answers "what could an attacker achieve, and via which paths?".

A tree is built per GOAL (e.g. "Steal Secrets", "Execute Code", "Impersonate
Users"). Each chain whose terminal impact maps to that goal becomes a path in
the tree; intermediate nodes become branches. The result renders as an ASCII
tree for the CLI and a nested dict for the web panel.

Deterministic: same findings + graph -> same tree. Zero AI calls.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from patchi.core.security.chain_analyzer import Chain, ChainAnalyzer

_log = logging.getLogger("patchi.security.attack_tree")

# Impact finding types -> attacker goals
_GOAL_MAP: dict[str, str] = {
    "secret": "Steal Credentials / Secrets",
    "hardcoded": "Steal Credentials / Secrets",
    "password": "Steal Credentials / Secrets",
    "sensitive_data": "Exfiltrate Sensitive Data",
    "session": "Impersonate Users",
    "rce": "Execute Arbitrary Code",
    "deserialization": "Execute Arbitrary Code",
    "command_injection": "Execute Arbitrary Code",
}

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class TreeNode:
    """One node in an attack tree."""

    label: str
    detail: str = ""
    children: list["TreeNode"] = field(default_factory=list)
    severity: str = "medium"
    score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "detail": self.detail,
            "severity": self.severity,
            "score": round(self.score, 1),
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class AttackTree:
    """Goal-oriented view over a set of exploit chains."""

    goal: str
    root: TreeNode
    chain_count: int = 0
    worst_severity: str = "info"

    def render(self) -> str:
        """ASCII rendering for CLI output."""
        lines = [f"[ATTACK TREE] Goal: {self.goal}"]
        lines.append(f"  Paths: {self.chain_count}  Worst: {self.worst_severity}")

        def _walk(node: TreeNode, prefix: str, is_last: bool) -> None:
            connector = "`-- " if is_last else "|-- "
            sev_tag = f" ({node.severity})" if node.severity != "medium" else ""
            lines.append(f"{prefix}{connector}{node.label}{sev_tag}")
            kids = node.children
            for i, child in enumerate(kids):
                ext = "    " if is_last else "|   "
                _walk(child, prefix + ext, i == len(kids) - 1)

        for i, child in enumerate(self.root.children):
            _walk(child, "", i == len(self.root.children) - 1)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "goal": self.goal,
            "chain_count": self.chain_count,
            "worst_severity": self.worst_severity,
            "root": self.root.to_dict(),
        }


def _goal_for(chain: Chain) -> Optional[str]:
    """Map a chain's terminal node to an attacker goal."""
    terminal = chain.nodes[-1].finding.type.lower()
    for pattern, goal in _GOAL_MAP.items():
        if pattern in terminal:
            return goal
    return None


def build_attack_trees(
    chains: list[Chain],
    max_depth: int = 6,
) -> list[AttackTree]:
    """
    Group chains into goal-oriented attack trees.

    Args:
        chains: output of ChainAnalyzer.find_chains()
        max_depth: cap on tree rendering depth

    Returns:
        Trees sorted by worst severity, highest first.
    """
    by_goal: dict[str, list[Chain]] = {}
    for chain in chains:
        goal = _goal_for(chain)
        if goal is None:
            continue
        by_goal.setdefault(goal, []).append(chain)

    trees: list[AttackTree] = []
    for goal, goal_chains in by_goal.items():
        worst = max(
            (_SEVERITY_ORDER.get(c.severity, 0) for c in goal_chains), default=0
        )
        root = TreeNode(label=f"Goal: {goal}")
        # Each chain becomes one path under the root; branch labels come from
        # the entry/exploit steps, leaf is the impact.
        for chain in sorted(goal_chains, key=lambda c: c.score, reverse=True)[:max_depth]:
            branch_label = f"{chain.nodes[0].finding.type} @ {chain.nodes[0].finding.file}"
            branch = TreeNode(
                label=branch_label,
                detail=chain.narrative,
                severity=chain.severity,
                score=chain.score,
            )
            if len(chain.nodes) > 2:
                mid = TreeNode(label=f"via {chain.nodes[1].finding.type}")
                leaf_label = f"{chain.nodes[-1].finding.type} @ {chain.nodes[-1].finding.file}"
                leaf = TreeNode(
                    label=leaf_label,
                    severity=chain.severity,
                    score=chain.score,
                )
                mid.children.append(leaf)
                branch.children.append(mid)
            else:
                leaf_label = f"{chain.nodes[-1].finding.type} @ {chain.nodes[-1].finding.file}"
                branch.children.append(TreeNode(label=leaf_label, severity=chain.severity))
            root.children.append(branch)

        trees.append(
            AttackTree(
                goal=goal,
                root=root,
                chain_count=len(goal_chains),
                worst_severity=[s for s, v in _SEVERITY_ORDER.items() if v == worst][0]
                or "info",
            )
        )

    trees.sort(key=lambda t: _SEVERITY_ORDER.get(t.worst_severity, 0), reverse=True)
    return trees


def trees_from_findings(
    findings: Iterable[Any],
    import_edges: Optional[dict[str, set[str]]] = None,
) -> tuple[list[AttackTree], list[Chain]]:
    """Convenience: findings -> chains -> trees in one call."""
    analyzer = ChainAnalyzer(findings, import_edges=import_edges)
    chains = analyzer.find_chains()
    return build_attack_trees(chains), chains
