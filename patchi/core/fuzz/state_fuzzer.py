"""StateFuzzer — explore application state machine transitions.

Given an AssuranceGraph with states and transitions, generates test
sequences that attempt illegal state transitions, replay attacks,
and concurrent state mutations.
"""

from __future__ import annotations

from dataclasses import dataclass

from patchi.core.assurance.graph import AssuranceGraph


@dataclass
class StateTransition:
    """A single state transition."""

    from_state: str
    to_state: str
    action: str  # trigger/action name

    def to_dict(self) -> dict:
        return {
            "from": self.from_state,
            "to": self.to_state,
            "action": self.action,
        }


@dataclass
class FuzzPath:
    """A path through the state machine for testing."""

    label: str
    transitions: list[StateTransition]
    strategy: str  # "illegal", "replay", "boundary", "concurrent"
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "transitions": [t.to_dict() for t in self.transitions],
            "strategy": self.strategy,
            "description": self.description,
        }


class StateFuzzer:
    """Generate state-machine fuzz paths from an AssuranceGraph."""

    def __init__(self, graph: AssuranceGraph | None = None):
        self._graph = graph
        self._transitions: list[StateTransition] = []
        self._states: set[str] = set()
        self._legal_map: dict[str, list[str]] = {}

    def load_graph(self, graph: AssuranceGraph) -> None:
        """Load transitions from an assurance graph's data."""
        self._graph = graph
        self._extract_transitions()

    def _extract_transitions(self) -> None:
        """Extract state transitions from the graph."""
        if self._graph is None:
            return

        self._transitions = []
        self._states = set()
        self._legal_map = {}

        for claim in self._graph.claims.values():
            # Extract states and transitions from claim evidence
            for ev in claim.evidence:
                artifact = ev.artifact
                if "from_state" in artifact and "to_state" in artifact:
                    t = StateTransition(
                        from_state=artifact["from_state"],
                        to_state=artifact["to_state"],
                        action=artifact.get("action", "unknown"),
                    )
                    self._transitions.append(t)
                    self._states.add(t.from_state)
                    self._states.add(t.to_state)
                    self._legal_map.setdefault(t.from_state, []).append(t.to_state)

    def load_from_dict(self, data: dict) -> None:
        """Load transitions from a dict (e.g. from brain data)."""
        self._transitions = []
        self._states = set()
        self._legal_map = {}

        for t_data in data.get("transitions", []):
            t = StateTransition(
                from_state=t_data["from_state"],
                to_state=t_data["to_state"],
                action=t_data.get("action", "unknown"),
            )
            self._transitions.append(t)
            self._states.add(t.from_state)
            self._states.add(t.to_state)
            self._legal_map.setdefault(t.from_state, []).append(t.to_state)

    def generate(self, max_paths: int = 30) -> list[FuzzPath]:
        """Generate fuzz paths through the state machine."""
        results: list[FuzzPath] = []

        if not self._states:
            return results

        # 1. Illegal transitions (try going to every state from every state)
        results.extend(self._illegal_transitions())

        # 2. Replay attack (repeat same transition)
        results.extend(self._replay_attacks())

        # 3. Boundary paths (start→end shortest paths, then extend)
        results.extend(self._boundary_paths())

        # 4. Missing guards (states with many outgoing transitions)
        results.extend(self._unguarded_transitions())

        return results[:max_paths]

    def _illegal_transitions(self) -> list[FuzzPath]:
        """Try transitions that should not be legal."""
        results: list[FuzzPath] = []
        for from_s in self._states:
            legal_targets = set(self._legal_map.get(from_s, []))
            for to_s in self._states:
                if to_s != from_s and to_s not in legal_targets:
                    results.append(
                        FuzzPath(
                            label=f"illegal_{from_s}_to_{to_s}",
                            transitions=[StateTransition(from_s, to_s, "test_illegal")],
                            strategy="illegal",
                            description=f"Attempt illegal transition: {from_s} → {to_s}",
                        )
                    )
        return results

    def _replay_attacks(self) -> list[FuzzPath]:
        """Replay the same transition multiple times."""
        results: list[FuzzPath] = []
        for t in self._transitions:
            results.append(
                FuzzPath(
                    label=f"replay_{t.from_state}_{t.to_state}_x3",
                    transitions=[t, t, t],
                    strategy="replay",
                    description=f"Replay {t.action} ({t.from_state}→{t.to_state}) 3 times",
                )
            )
        return results

    def _boundary_paths(self) -> list[FuzzPath]:
        """Find longest paths through the state machine."""
        results: list[FuzzPath] = []
        if not self._transitions:
            return results

        # Find start states (no incoming transitions)
        all_targets = {t.to_state for t in self._transitions}
        start_states = self._states - all_targets
        if not start_states:
            start_states = {self._transitions[0].from_state}

        # DFS to find paths
        for start in start_states:
            paths = self._dfs_paths(start, max_depth=6, max_results=5)
            for path in paths:
                results.append(
                    FuzzPath(
                        label=f"boundary_path_{'_'.join(t.from_state for t in path)}",
                        transitions=path,
                        strategy="boundary",
                        description=f"Path: {' → '.join(t.from_state for t in path)} → {path[-1].to_state}",
                    )
                )
        return results

    def _dfs_paths(
        self, start: str, max_depth: int = 6, max_results: int = 5
    ) -> list[list[StateTransition]]:
        """DFS to find paths through the state machine."""
        results: list[list[StateTransition]] = []
        stack: list[tuple[str, list[StateTransition], set[str]]] = [(start, [], {start})]

        while stack and len(results) < max_results:
            state, path, visited = stack.pop()
            targets = self._legal_map.get(state, [])
            for target in targets:
                if target in visited:
                    continue
                transition = next(
                    (
                        t
                        for t in self._transitions
                        if t.from_state == state and t.to_state == target
                    ),
                    StateTransition(state, target, "unknown"),
                )
                new_path = path + [transition]
                if len(new_path) >= max_depth:
                    results.append(new_path)
                else:
                    stack.append((target, new_path, visited | {target}))

        return results

    def _unguarded_transitions(self) -> list[FuzzPath]:
        """Find states with many outgoing transitions (potential missing guards)."""
        results: list[FuzzPath] = []
        for state, targets in self._legal_map.items():
            if len(targets) >= 3:
                # Try all outgoing transitions in sequence
                transitions = [
                    next(
                        (
                            t
                            for t in self._transitions
                            if t.from_state == state and t.to_state == tgt
                        ),
                        StateTransition(state, tgt, "unknown"),
                    )
                    for tgt in targets
                ]
                results.append(
                    FuzzPath(
                        label=f"unguarded_{state}",
                        transitions=transitions,
                        strategy="boundary",
                        description=f"State '{state}' has {len(targets)} outgoing transitions — test all",
                    )
                )
        return results
