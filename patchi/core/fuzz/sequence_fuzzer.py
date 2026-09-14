"""SequenceFuzzer — reorder and combine API operations to find race conditions.

Given a set of API operations, generates permutations that test TOCTOU,
replay, and ordering vulnerabilities.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any


@dataclass
class FuzzSequence:
    """A sequence of operations to execute against the target."""

    label: str
    operations: list[dict[str, Any]]
    strategy: str  # "permutation", "replay", "concurrent", "interleaved"
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "operations": self.operations[:10],  # cap for display
            "strategy": self.strategy,
            "description": self.description,
        }


class SequenceFuzzer:
    """Generate operation sequences that test ordering vulnerabilities."""

    def __init__(self, max_permutations: int = 20):
        self._max_perm = max_permutations

    def generate(
        self,
        operations: list[dict[str, Any]],
        max_depth: int = 4,
    ) -> list[FuzzSequence]:
        """Generate fuzz sequences from a list of API operations."""
        results: list[FuzzSequence] = []

        if len(operations) < 1:
            return results

        # 1. Pairwise permutations (all 2-element orderings)
        results.extend(self._pairwise_permutations(operations))

        # 2. Replay sequences (same op repeated)
        results.extend(self._replay_sequences(operations))

        # 3. Concurrent pairs (two ops that should be atomic)
        results.extend(self._concurrent_pairs(operations))

        # 4. Full permutations (if small enough)
        if len(operations) <= 6:
            results.extend(self._full_permutations(operations))

        return results[: self._max_perm]

    def _pairwise_permutations(self, operations: list[dict[str, Any]]) -> list[FuzzSequence]:
        """Test every pair of operations in both orderings."""
        results: list[FuzzSequence] = []
        for i, op_a in enumerate(operations):
            for j, op_b in enumerate(operations):
                if i >= j:
                    continue
                # Normal order
                results.append(
                    FuzzSequence(
                        label=f"pair_{i}_{j}_normal",
                        operations=[op_a, op_b],
                        strategy="permutation",
                        description=f"Execute {op_a.get('method', '?')} then {op_b.get('method', '?')}",
                    )
                )
                # Reversed order
                results.append(
                    FuzzSequence(
                        label=f"pair_{j}_{i}_reversed",
                        operations=[op_b, op_a],
                        strategy="permutation",
                        description=f"Execute {op_b.get('method', '?')} then {op_a.get('method', '?')} (reversed)",
                    )
                )
        return results

    def _replay_sequences(self, operations: list[dict[str, Any]]) -> list[FuzzSequence]:
        """Test replaying the same operation multiple times."""
        results: list[FuzzSequence] = []
        for i, op in enumerate(operations):
            # Double replay
            results.append(
                FuzzSequence(
                    label=f"replay_{i}_double",
                    operations=[op, op],
                    strategy="replay",
                    description=f"Replay {op.get('method', '?')} twice (idempotency test)",
                )
            )
            # Triple replay
            results.append(
                FuzzSequence(
                    label=f"replay_{i}_triple",
                    operations=[op, op, op],
                    strategy="replay",
                    description=f"Replay {op.get('method', '?')} three times (idempotency test)",
                )
            )
        return results

    def _concurrent_pairs(self, operations: list[dict[str, Any]]) -> list[FuzzSequence]:
        """Mark operation pairs as concurrent (for testing race conditions)."""
        results: list[FuzzSequence] = []
        for i, op_a in enumerate(operations):
            for j, op_b in enumerate(operations):
                if i >= j:
                    continue
                if self._are_concurrent(op_a, op_b):
                    results.append(
                        FuzzSequence(
                            label=f"concurrent_{i}_{j}",
                            operations=[op_a, op_b],
                            strategy="concurrent",
                            description=f"Execute {op_a.get('method', '?')} and {op_b.get('method', '?')} concurrently"
                            f" (race condition test)",
                        )
                    )
        return results

    def _full_permutations(self, operations: list[dict[str, Any]]) -> list[FuzzSequence]:
        """Generate all permutations of small operation sets."""
        results: list[FuzzSequence] = []
        for perm in itertools.permutations(range(len(operations))):
            ops = [operations[i] for i in perm]
            results.append(
                FuzzSequence(
                    label=f"perm_{'_'.join(map(str, perm))}",
                    operations=ops,
                    strategy="permutation",
                    description=f"Permutation: {' → '.join(o.get('method', '?') for o in ops)}",
                )
            )
        return results

    def _are_concurrent(self, op_a: dict, op_b: dict) -> bool:
        """Determine if two operations could race (same resource, different actions)."""
        path_a = op_a.get("path", "")
        path_b = op_b.get("path", "")
        method_a = op_a.get("method", "")
        method_b = op_b.get("method", "")

        # Same path but different HTTP methods
        if path_a == path_b and method_a != method_b:
            return True
        # Both mutating the same resource
        mutating = {"POST", "PUT", "PATCH", "DELETE"}
        if path_a == path_b and method_a in mutating and method_b in mutating:
            return True
        return False
