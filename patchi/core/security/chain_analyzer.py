"""
Exploit Chain Engine — turns isolated findings into attack narratives.

A SQL injection in a rarely-hit endpoint is Medium. The same SQL injection
reachable without authentication, chained past a missing rate limit into an
unencrypted admin cookie, is Critical. Static scanners see the pieces; this
module assembles the pieces into the story an attacker would tell.

How it works (deterministic, zero AI, bounded):

1. Each Finding becomes a node classified as an ENTRY (exposes attack
   surface: missing auth, open CORS, debug mode...), an EXPLOIT (injection,
   XSS, SSRF...), or an IMPACT amplifier (secrets, weak crypto, sensitive
   data exposure).
2. An edge A -> B ("A enables B") is added when the pair matches a chain
   rule AND the findings are co-located (same file) or import-connected
   (B's module imports A's module).
3. A chain is any path entry -> ... -> impact of length >= 2.
4. Chains are scored by exploitability and sorted worst-first.

Severity escalation: a chain's severity is at least HIGH when it links two
or more confirmed findings — the compound condition is what makes it
dangerous, even if each piece alone looked Medium.

No AI calls. No network. Pure graph analysis over the findings you already have.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

_log = logging.getLogger("patchi.security.chain_analyzer")


class NodeRole(str, Enum):
    """What role a finding plays in an attack chain."""

    ENTRY = "entry"          # opens the door
    EXPLOIT = "exploit"      # the actual attack step
    IMPACT = "impact"        # what the attacker walks away with
    STANDALONE = "standalone"  # not part of any known chain pattern


# ── Chain rules ────────────────────────────────────────────────────────────────
# Each rule: (source_type_pattern, target_type_pattern, edge_label).
# Type patterns are matched with substring semantics against finding.type so
# "sqli", "sql_injection", "injection_sql" all match "sql".

_CHAIN_RULES: tuple[tuple[str, str, str], ...] = (
    # Entry -> exploit edges
    ("auth", "inject", "unauthenticated input reaches injector"),
    ("auth", "xss", "unauthenticated input reaches XSS sink"),
    ("auth", "ssrf", "unauthenticated request forges SSRF"),
    ("auth", "idor", "no auth boundary protects object access"),
    ("open_redirect", "xss", "redirect target smuggles script"),
    ("cors", "xss", "permissive CORS lets attacker read XSS payload"),
    ("debug", "inject", "debug mode leaks internals that shape payloads"),
    ("rate_limit", "brute", "no throttle permits unlimited attempts"),
    ("rate_limit", "inject", "no throttle permits payload fuzzing"),
    # Exploit -> impact edges
    ("inject", "secret", "injection exfiltrates stored secrets"),
    ("inject", "sensitive_data", "injection dumps sensitive tables"),
    ("ssrf", "secret", "SSRF reaches internal metadata/credential service"),
    ("idor", "sensitive_data", "object access crosses ownership boundary"),
    ("xss", "session", "script lifts session cookies/tokens"),
    ("xss", "secret", "script scrapes secrets rendered into DOM"),
    ("deserialization", "rce", "deserialization gadget yields code execution"),
    ("command_injection", "secret", "command execution reads env/key material"),
    ("path_traversal", "secret", "traversal reads key/config files"),
    ("weak_crypto", "session", "forgeable tokens defeat session integrity"),
    ("hardcoded_secret", "secret", "committed key grants direct access"),
    # Amplifier edges
    ("jwt", "auth", "token flaw defeats the auth layer itself"),
    ("csrf", "state_change", "forged request drives privileged mutation"),
)


def _matches(pattern: str, finding_type: str) -> bool:
    return pattern in finding_type.lower()


def classify(finding_type: str) -> NodeRole:
    """Classify a finding type into its chain role."""
    t = finding_type.lower()
    if any(k in t for k in ("auth", "cors", "debug", "rate_limit", "redirect", "open")):
        return NodeRole.ENTRY
    if any(
        k in t
        for k in (
            "inject", "xss", "ssrf", "idor", "deserial", "traversal",
            "rce", "sqli", "xxe",
        )
    ):
        return NodeRole.EXPLOIT
    if any(
        k in t
        for k in (
            "secret", "crypto", "sensitive", "session", "jwt",
            "hardcoded", "password", "key",
        )
    ):
        return NodeRole.IMPACT
    return NodeRole.STANDALONE


@dataclass
class ChainNode:
    """One finding participating in a chain."""

    finding: Any  # patchi.core.agents.base.Finding
    role: NodeRole

    @property
    def key(self) -> tuple:
        f = self.finding
        return (f.file, f.line, f.type)

    @property
    def severity(self) -> str:
        return self.finding.severity.value


@dataclass
class Chain:
    """An ordered attack path: entry -> exploits -> impact."""

    nodes: list[ChainNode]
    edges: list[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.nodes)

    @property
    def severity(self) -> str:
        """Escalated severity: multi-step chains are at least HIGH."""
        order = ["info", "low", "medium", "high", "critical"]
        worst = max(
            (order.index(n.severity) for n in self.nodes if n.severity in order),
            default=0,
        )
        if self.length >= 2:
            worst = max(worst, order.index("high"))
        if self.length >= 3:
            worst = max(worst, order.index("critical"))
        return order[worst]

    @property
    def score(self) -> float:
        """Exploitability score 0-100: depth × severity × confirmation spread."""
        sev_weight = {"info": 5, "low": 15, "medium": 35, "high": 70, "critical": 90}
        base = max(
            (sev_weight.get(n.severity, 20) for n in self.nodes), default=20
        )
        depth_bonus = min((self.length - 1) * 8, 24)
        agents = {n.finding.agent for n in self.nodes}
        confirm_bonus = min(len(agents) * 4, 12)
        return min(base + depth_bonus + confirm_bonus, 100)

    @property
    def narrative(self) -> str:
        """Human-readable attack story assembled from the edge labels."""
        parts = [f"[{n.finding.type}] {n.finding.file}:{n.finding.line}" for n in self.nodes]
        story = " -> ".join(parts)
        if self.edges:
            story += "  |  " + "; ".join(self.edges)
        return story

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "score": round(self.score, 1),
            "length": self.length,
            "narrative": self.narrative,
            "steps": [
                {
                    "role": n.role.value,
                    "type": n.finding.type,
                    "file": n.finding.file,
                    "line": n.finding.line,
                    "severity": n.severity,
                    "agent": n.finding.agent,
                }
                for n in self.nodes
            ],
        }


class ChainAnalyzer:
    """Builds exploit chains from a set of findings."""

    def __init__(
        self,
        findings: Iterable[Any],
        import_edges: Optional[dict[str, set[str]]] = None,
    ):
        """
        Args:
            findings: patchi.core.agents.base.Finding objects (or duck-typed:
                need .type/.file/.line/.severity/.agent).
            import_edges: optional {importer_file: {imported_files...}} map.
                Co-location alone is enough to link findings; import edges let
                chains cross module boundaries (route -> service -> repo).
        """
        self.import_edges = import_edges or {}
        self.nodes: list[ChainNode] = []
        for f in findings:
            role = classify(getattr(f, "type", ""))
            if role is not NodeRole.STANDALONE:
                self.nodes.append(ChainNode(finding=f, role=role))
        self._index()

    def _index(self) -> None:
        self.by_file: dict[str, list[ChainNode]] = defaultdict(list)
        for n in self.nodes:
            self.by_file[n.finding.file].append(n)

    def _connected(self, a: ChainNode, b: ChainNode) -> bool:
        """True when b is reachable from a's location (same file or import path)."""
        fa, fb = a.finding.file, b.finding.file
        if fa == fb:
            return True
        return fb in self.import_edges.get(fa, set())

    def _edge_label(self, src: ChainNode, dst: ChainNode) -> Optional[str]:
        st, dt = src.finding.type.lower(), dst.finding.type.lower()
        for sp, dp, label in _CHAIN_RULES:
            if _matches(sp, st) and _matches(dp, dt):
                return label
        return None

    def _adjacency(self) -> dict[int, list[tuple[int, str]]]:
        adj: dict[int, list[tuple[int, str]]] = defaultdict(list)
        for i, src in enumerate(self.nodes):
            for j, dst in enumerate(self.nodes):
                if i == j:
                    continue
                # Enforce direction: entries start chains, impacts end them.
                order = {NodeRole.ENTRY: 0, NodeRole.EXPLOIT: 1, NodeRole.IMPACT: 2}
                if order[src.role] > order[dst.role]:
                    continue
                if not self._connected(src, dst):
                    continue
                label = self._edge_label(src, dst)
                if label:
                    adj[i].append((j, label))
        return adj

    def find_chains(self, max_chains: int = 50, max_depth: int = 5) -> list[Chain]:
        """Return all entry->...->impact chains, worst-first, capped."""
        adj = self._adjacency()
        chains: list[Chain] = []

        def dfs(idx: int, path: list[int], labels: list[str], seen: set[int]) -> None:
            if len(chains) >= max_chains * 4 or len(path) > max_depth:
                return
            node = self.nodes[idx]
            # Entry->exploit pairs are already actionable ("unauthenticated
            # SQL injection"); record them AND keep walking toward impact.
            if len(path) >= 2 and node.role in (NodeRole.EXPLOIT, NodeRole.IMPACT):
                chains.append(
                    Chain(nodes=[self.nodes[i] for i in path], edges=list(labels))
                )
                if node.role == NodeRole.IMPACT:
                    return  # impact terminates a chain
            for j, label in adj.get(idx, []):
                if j in seen:
                    continue
                dfs(j, path + [j], labels + [label], seen | {j})

        for i, n in enumerate(self.nodes):
            if n.role == NodeRole.ENTRY:
                dfs(i, [i], [], {i})
            elif n.role == NodeRole.EXPLOIT:
                # Exploit-to-impact pairs also count (2-node chains).
                for j, label in adj.get(i, []):
                    if self.nodes[j].role == NodeRole.IMPACT:
                        chains.append(
                            Chain(
                                nodes=[self.nodes[i], self.nodes[j]],
                                edges=[label],
                            )
                        )

        chains.sort(key=lambda c: c.score, reverse=True)
        # Dedup identical narratives (same steps via different DFS orders)
        seen_narratives: set[str] = set()
        unique: list[Chain] = []
        for c in chains:
            sig = tuple(n.key for n in c.nodes)
            if sig not in seen_narratives:
                seen_narratives.add(sig)
                unique.append(c)
        return unique[:max_chains]

    def summary(self) -> dict[str, Any]:
        """Aggregate stats for reporting / web panels."""
        chains = self.find_chains()
        sev_counts: dict[str, int] = defaultdict(int)
        for c in chains:
            sev_counts[c.severity] += 1
        return {
            "findings_analyzed": len(self.nodes),
            "chains_found": len(chains),
            "by_severity": dict(sev_counts),
            "worst": chains[0].to_dict() if chains else None,
        }
