"""InputFuzzer — mutate inputs for security boundary testing.

Generates mutated variants of input values to test injection, overflow,
encoding bypass, and format-string vulnerabilities.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any


@dataclass
class FuzzInput:
    """A single fuzz input variant."""

    label: str
    value: Any
    strategy: str  # "boundary", "injection", "encoding", "overflow", "format"
    expected_impact: str = ""  # "crash", "injection", "bypass", "error"

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "value": str(self.value)[:200],
            "strategy": self.strategy,
            "expected_impact": self.expected_impact,
        }


# ── Boundary values per type ────────────────────────────────────────────────

_BOUNDARY_STRINGS = [
    "",  # empty
    " ",  # whitespace
    "a" * 10_000,  # long
    "\x00",  # null byte
    "🔥" * 100,  # emoji
    "\n\r\t",  # control chars
    "true",
    "false",
    "null",  # type confusion
    "-1",
    "0",
    "2147483647",  # numeric boundaries
    "99999999999999999999",  # overflow
]

_INJECTION_STRINGS = [
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "${7*7}",
    "{{constructor.constructor('return this')()}}",
    "../../etc/passwd",
    "'; exec('ls'); --",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "1; rm -rf /",
]

_ENCODING_STRINGS = [
    "%27%20OR%201%3D1",  # URL-encoded
    "&lt;script&gt;",  # HTML entities
    "JCBhbGVydCgxKQ==",  # base64
    "%00",  # null byte URL
    "\\u0027",  # unicode escape
    "%EF%BC%87",  # fullwidth apostrophe
    ".LogInformation",  # log injection
    "\r\nSet-Cookie: admin=1",  # CRLF injection
]

_FORMAT_STRINGS = [
    "%s%s%s%s%s%s%s%s",
    "%x%x%x%x%x%x%x%x",
    "%n%n%n%n%n%n%n%n",
    "{0.__class__.__bases__}",
    "${{7*7}}",
]


class InputFuzzer:
    """Generate mutated input variants for endpoint/parameter testing."""

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    def fuzz_string(self, original: str, count: int = 20) -> list[FuzzInput]:
        """Generate mutated string variants."""
        results: list[FuzzInput] = []

        # Boundary values
        for val in _BOUNDARY_STRINGS:
            results.append(
                FuzzInput(label=f"boundary_{val[:10]!r}", value=val, strategy="boundary")
            )

        # Injection payloads
        for val in _INJECTION_STRINGS:
            results.append(
                FuzzInput(
                    label=f"injection_{val[:10]!r}",
                    value=val,
                    strategy="injection",
                    expected_impact="injection",
                )
            )

        # Encoding bypasses
        for val in _ENCODING_STRINGS:
            results.append(
                FuzzInput(
                    label=f"encoding_{val[:10]!r}",
                    value=val,
                    strategy="encoding",
                    expected_impact="bypass",
                )
            )

        # Format strings
        for val in _FORMAT_STRINGS:
            results.append(
                FuzzInput(
                    label=f"format_{val[:10]!r}",
                    value=val,
                    strategy="format",
                    expected_impact="error",
                )
            )

        # Random mutations of the original
        for i in range(max(0, count - len(results))):
            mutated = self._mutate_string(original)
            results.append(
                FuzzInput(
                    label=f"random_{i}",
                    value=mutated,
                    strategy="random",
                )
            )

        return results[:count]

    def fuzz_numeric(self, original: int, count: int = 10) -> list[FuzzInput]:
        """Generate mutated numeric variants."""
        boundaries = [0, -1, 1, 2**31 - 1, 2**31, 2**63 - 1, -(2**31), -(2**63)]
        results = [
            FuzzInput(label=f"boundary_{v}", value=v, strategy="boundary") for v in boundaries
        ]
        for i in range(max(0, count - len(results))):
            results.append(
                FuzzInput(
                    label=f"random_{i}",
                    value=self._rng.randint(-10_000, 10_000),
                    strategy="random",
                )
            )
        return results[:count]

    def fuzz_dict(self, original: dict, count: int = 15) -> list[FuzzInput]:
        """Generate mutated dict variants (extra keys, type confusion, nested depth)."""
        results: list[FuzzInput] = []

        # Extra keys
        results.append(
            FuzzInput(
                label="extra_admin_key",
                value={**original, "admin": True, "is_admin": True, "role": "admin"},
                strategy="boundary",
                expected_impact="privilege_escalation",
            )
        )

        # Null values
        results.append(
            FuzzInput(
                label="null_values",
                value=dict.fromkeys(original),
                strategy="boundary",
            )
        )

        # Nested depth bomb
        nested: Any = "leaf"
        for _ in range(100):
            nested = {"a": nested}
        results.append(
            FuzzInput(
                label="nested_depth_100",
                value={"__proto__": nested},
                strategy="overflow",
                expected_impact="crash",
            )
        )

        # Prototype pollution
        results.append(
            FuzzInput(
                label="proto_pollution",
                value={**original, "__proto__": {"admin": True}},
                strategy="injection",
                expected_impact="privilege_escalation",
            )
        )

        # Type confusion
        for key in list(original.keys())[:3]:
            confused = {**original}
            confused[key] = [original[key]]
            confused[f"{key}_array"] = original[key]
            results.append(
                FuzzInput(
                    label=f"type_confusion_{key}",
                    value=confused,
                    strategy="injection",
                )
            )

        return results[:count]

    def _mutate_string(self, s: str) -> str:
        """Apply a random mutation to a string."""
        ops = [
            self._flip_case,
            self._insert_special,
            self._truncate,
            self._repeat,
            self._shuffle,
            self._append_null,
        ]
        return self._rng.choice(ops)(s)

    def _flip_case(self, s: str) -> str:
        return "".join(c.swapcase() if c.isalpha() else c for c in s)

    def _insert_special(self, s: str) -> str:
        specials = ["\x00", "\n", "\r", "'", '"', "\\", "%00"]
        pos = self._rng.randint(0, max(len(s), 1))
        return s[:pos] + self._rng.choice(specials) + s[pos:]

    def _truncate(self, s: str) -> str:
        return s[: self._rng.randint(0, max(len(s) - 1, 0))]

    def _repeat(self, s: str) -> str:
        return s * self._rng.randint(2, 5)

    def _shuffle(self, s: str) -> str:
        lst = list(s)
        self._rng.shuffle(lst)
        return "".join(lst)

    def _append_null(self, s: str) -> str:
        return s + "\x00" * self._rng.randint(1, 10)
