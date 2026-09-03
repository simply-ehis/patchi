"""
RustUnwrapAgent §8.2.4 — clippy style unwrap/expect audit.

Finds .unwrap() / .expect() without descriptive message, suggests ?, expect("msg") or pattern match.
Optionally runs `cargo clippy -- -W clippy::unwrap_used` if cargo available.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

_log = logging.getLogger("patchi.agents.rust_unwrap")

_UNWRAP_RE = re.compile(r"\.unwrap\(\)")
_EXPECT_RE = re.compile(r"\.expect\(\s*\"\"|\.expect\(\s*''|\\.expect\(\s*\)")


@register
class RustUnwrapAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "RustUnwrapAgent"
    description = "Rust unwrap()/expect() audit §8.2.4 — clippy unwrap_used"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Try clippy
        if shutil.which("cargo"):
            try:
                proc = subprocess.run(
                    ["cargo", "clippy", "--", "-W", "clippy::unwrap_used", "-W", "clippy::expect_used"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=str(inp.root),
                )
                for line in (proc.stderr + proc.stdout).splitlines():
                    if "unwrap_used" in line or "expect_used" in line:
                        # clippy: file:line:col: warning: used `unwrap()`...
                        m = re.match(r"([^:]+):(\d+):\d+:\s*warning:\s*(.*)", line)
                        if m:
                            result.add_finding(
                                make_finding(
                                    severity=Severity.LOW,
                                    file=m.group(1),
                                    line_start=int(m.group(2)),
                                    title="clippy::unwrap_used",
                                    description=m.group(3).strip()[:200],
                                    finding_type="rust_unwrap",
                                )
                            )
            except Exception as exc:  # noqa: BLE001
                _log.debug("clippy failed: %s", exc)

        for fp in safe_rglob(inp.root, "*.rs"):
            rel = fp.relative_to(inp.root).as_posix()
            try:
                txt = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(txt.splitlines(), 1):
                if _UNWRAP_RE.search(line):
                    result.add_finding(
                        make_finding(
                            severity=Severity.LOW,
                            file=rel,
                            line_start=i,
                            title="Unsafe .unwrap() — panics on Err/None",
                            description="Prefer `?`, `unwrap_or`, or `.expect(\"context\")` with message. Clippy: unwrap_used.",
                            evidence=line.strip()[:120],
                            finding_type="rust_unwrap",
                        )
                    )
                elif _EXPECT_RE.search(line):
                    result.add_finding(
                        make_finding(
                            severity=Severity.LOW,
                            file=rel,
                            line_start=i,
                            title="Empty .expect(\"\") — no context",
                            description="`.expect(\"\")` gives no diagnostic; use descriptive message.",
                            evidence=line.strip()[:120],
                            finding_type="rust_expect_empty",
                        )
                    )
        result.status = AgentStatus.SUCCEEDED
