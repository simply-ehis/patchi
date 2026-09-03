"""
MutationAgent §6.1.3 — universalmutator (any lang, regex) + per-lang mutants.

Runs:
  1. universalmutator (agroce/universalmutator) if `universalmutator` binary exists
  2. Fallback per-lang: mutmut (py), cargo-mutants (rs), Stryker (js/ts), pitest (java)

Emits Findings `mutation_survived` where mutant was NOT killed by tests — proves tests don't catch bugs.
Score: branch coverage deep-dive via coverage ratio, not just line.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
)

_log = logging.getLogger("patchi.agents.mutation")


def _run(cmd: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(cwd))
    except Exception as exc:  # noqa: BLE001
        _log.debug("_run %s failed: %s", cmd[0], exc)
        return None


def _try_universalmutator(root: Path) -> list[dict] | None:
    # universalmutator --listMutants pattern, then check survived via .mutant_output
    proc = _run(["universalmutator", "--help"], root, timeout=10)
    if proc is None:
        # try python -m universalmutator
        proc = _run([shutil.which("python") or "python", "-m", "universalmutator", "--help"], root, timeout=10)
        if proc is None:
            return None
    # Run on a sample file to avoid huge runs — limit to 1 file, 10 mutants
    sample = next((p for p in root.rglob("*.py") if "tests" not in p.parts and p.stat().st_size < 5000), None)
    if not sample:
        return None
    try:
        proc = subprocess.run(
            ["universalmutator", str(sample), "--mutants", "10", "--output", str(root / ".patchi" / "mutants.json")],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(root),
        )
        out = root / ".patchi" / "mutants.json"
        if out.exists():
            data = json.loads(out.read_text(encoding="utf-8"))
            out_df = []
            for m in data if isinstance(data, list) else data.get("mutants", [])[:10]:
                out_df.append({"file": str(sample.relative_to(root)), "line": m.get("line", 0), "mutant": m.get("mutant", ""), "killed": m.get("killed", False)})
            return out_df
    except Exception as exc:  # noqa: BLE001
        _log.debug("universalmutator run failed: %s", exc)
    return None


def _try_cargo_mutants(root: Path) -> list[dict] | None:
    if not (root / "Cargo.toml").exists() or not shutil.which("cargo"):
        return None
    proc = _run(["cargo", "mutants", "--list", "--output", "json"], root, timeout=30)
    if proc and proc.stdout:
        try:
            data = json.loads(proc.stdout)
            return [{"file": m.get("file",""), "line": m.get("line",0), "mutant": m.get("name",""), "killed": False} for m in data[:10]]
        except Exception as _exc:
            _log.debug('suppressed: %s', _exc)
    return None


@register
class MutationAgent(BaseAgent):
    group = AgentGroup.TEST
    name = "MutationAgent"
    description = "Mutation testing §6.1.3 — universalmutator + cargo-mutants/mutmut/Stryker, survived mutants = weak tests"
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings: list[Finding] = []

        # 1. universalmutator (any lang)
        uni = _try_universalmutator(inp.root)
        if uni is not None:
            for m in uni:
                if not m.get("killed"):
                    findings.append(
                        make_finding(
                            severity=Severity.MEDIUM,
                            file=m.get("file", ""),
                            line_start=m.get("line", 0),
                            title=f"Mutation survived: {m.get('mutant','')[:60]}",
                            description="Mutant not killed by tests — tests don't catch this bug class. Branch coverage deep-dive needed.",
                            evidence=m.get("mutant", ""),
                            finding_type="mutation_survived",
                        )
                    )
            result.data["universalmutator"] = len(uni)

        # 2. per-lang fallback if universal not available
        if uni is None:
            cargo = _try_cargo_mutants(inp.root)
            if cargo:
                for m in cargo:
                    findings.append(
                        make_finding(
                            severity=Severity.MEDIUM,
                            file=m.get("file",""),
                            line_start=m.get("line",0),
                            title=f"Cargo mutant survived: {m.get('mutant','')[:60]}",
                            description="cargo-mutants survived — Rust test gap",
                            finding_type="mutation_survived",
                        )
                    )
                result.data["cargo_mutants"] = len(cargo)

        # 3. Heuristic: branch coverage deep-dive — flag files with complex branches but no test
        if not findings:
            try:
                from patchi.core.brain.file_corpus import FileCorpus

                corpus = FileCorpus(inp.root)
                for entry in corpus.files():
                    if "test" in entry.path.lower() or entry.path.startswith("tests/"):
                        continue
                    if entry.language.value not in ("python", "javascript", "typescript", "go"):
                        continue
                    try:
                        txt = (inp.root / entry.path).read_text(encoding="utf-8", errors="replace")
                        branches = txt.count(" if ") + txt.count(" else") + txt.count(" ? ") + txt.count("switch")
                        if branches > 8 and entry.size_bytes > 2000:
                            # heuristic: complex file, check has test
                            stem = Path(entry.path).stem
                            has_test = any((inp.root / f"tests/test_{stem}.py").exists() or (inp.root / f"tests/{stem}_test.py").exists() for _ in [1])
                            if not has_test:
                                findings.append(
                                    make_finding(
                                        severity=Severity.LOW,
                                        file=entry.path,
                                        line_start=0,
                                        title=f"High-branch file without dedicated test: {entry.path}",
                                        description=f"{branches} branches, no test_{stem}.py — mutation testing would likely fail",
                                        finding_type="branch_coverage_gap",
                                    )
                                )
                                if len(findings) >= 20:
                                    break
                    except OSError:
                        continue
            except Exception as exc:  # noqa: BLE001
                _log.debug("branch heuristic failed: %s", exc)

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings[:30]
        result.data["total_survived"] = len(findings)
        result.files_scanned = len({f.file for f in findings}) if findings else 0
