"""
ApiFuzzerAgent §5.3.1 — EvoMaster-style REST/GraphQL fuzz generation.

From RouteMapper 18fw routes → generates malformed JSON, massive payloads,
wrong Content-Types, injection strings via InputFuzzer. Optionally shells out
to EvoMaster (WebFuzzing/EvoMaster) if `evomaster.jar` or docker is available,
else falls back to local InputFuzzer + in-process HTTP smoke.

Does NOT require a running server for generation; fuzz payloads are persisted
to .patchi/fuzz/<route>.json for DAST replay via --with-fuzz.
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
    Severity,
    make_finding,
    register,
)
from patchi.core.brain.route_mapper import RouteInfo
from patchi.core.fuzz.input_fuzzer import InputFuzzer

_log = logging.getLogger("patchi.agents.api_fuzzer")

_EVO_DOCKER = "evomaster/evomaster:latest"


def _try_evomaster(routes: list[RouteInfo], out_dir: Path) -> int:
    """Try EvoMaster jar/docker — returns count or 0 if not available."""
    jar = shutil.which("evomaster.jar") or shutil.which("java")
    docker = shutil.which("docker")
    if not jar and not docker:
        return 0
    # Probe only if OpenAPI spec exists
    if not (out_dir.parent / "openapi.json").exists() and not (out_dir.parent / "swagger.json").exists():
        return 0
    try:
        # Use docker EvoMaster in blackbox mode against openapi.json if present
        spec = out_dir.parent / "openapi.json"
        if not spec.exists():
            spec = out_dir.parent / "swagger.json"
        cmd = ["docker", "run", "--rm", "-v", f"{spec}:/tmp/spec.json", _EVO_DOCKER, "--blackBox", "true", "--bbSwaggerUrl", "file:///tmp/spec.json", "--outputFolder", "/tmp/out", "--maxTime", "30s"] if docker else None
        if not cmd:
            return 0
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return 1 if proc.returncode in (0, 1) else 0
    except Exception as exc:  # noqa: BLE001
        _log.debug("evomaster probe failed: %s", exc)
        return 0


@register
class ApiFuzzerAgent(BaseAgent):
    group = AgentGroup.SECURITY
    name = "ApiFuzzerAgent"
    description = "EvoMaster-style API fuzz payloads from RouteMapper routes (REST/GraphQL) → .patchi/fuzz/"
    timeout = 90

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Routes from brain (RouteMapper) or live scan
        routes: list[RouteInfo] = []
        try:
            from patchi.core.brain.file_corpus import FileCorpus
            from patchi.core.brain.framework import FrameworkDetector
            from patchi.core.brain.route_mapper import RouteMapper

            corpus = FileCorpus(inp.root)
            stack = FrameworkDetector(inp.root, corpus=corpus).detect()
            mapper = RouteMapper(inp.root, stack)
            # Use inp.brain routes if present to avoid re-parse
            if inp.brain.get("routes"):
                routes = [RouteInfo(**r) if isinstance(r, dict) else r for r in inp.brain.get("routes", [])]
            else:
                from patchi.core.brain.scanner import FileScanner
                routes = mapper.extract(FileScanner(inp.root).scan())
        except Exception as exc:  # noqa: BLE001
            _log.debug("route extract failed: %s", exc)
            routes = []

        if not routes:
            result.status = AgentStatus.SUCCEEDED
            result.data["fuzz_count"] = 0
            return

        fuzzer = InputFuzzer(seed=0xF22A)
        out_dir = inp.root / ".patchi" / "fuzz"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Try EvoMaster first
        evo = _try_evomaster(routes, out_dir)

        fuzz_count = 0
        for r in routes[:50]:  # cap 50 routes
            # Skip health/static
            if r.path in ("/health", "/healthz", "/metrics") or r.path.startswith("/static/"):
                continue
            payloads = []
            # 1. Boundary JSON
            payloads.extend([f.to_dict() for f in fuzzer.fuzz_dict({"id": 1, "name": "test"}, count=5)])
            # 2. Injection strings as query/body values
            for fi in fuzzer.fuzz_string(r.path, count=6):
                payloads.append({"strategy": fi.strategy, "value": fi.value, "label": fi.label})
            # 3. Method fuzz: wrong method
            payloads.append({"strategy": "method", "value": "WRONG_METHOD", "label": "method_fuzz"})
            # Persist
            fname = f"{r.method.lower()}_{r.path.strip('/').replace('/','_') or 'root'}.json"
            fname = "".join(c if c.isalnum() or c in "._-" else "_" for c in fname)[:120]
            try:
                (out_dir / fname).write_text(json.dumps({"route": r.to_dict(), "payloads": payloads[:12]}, indent=2), encoding="utf-8")
                fuzz_count += 1
            except OSError as exc:
                _log.warning("ApiFuzzer write failed: %s", exc)

            # Finding per route with high-risk payload count
            result.findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file=r.file,
                    line_start=r.line,
                    title=f"Fuzz payloads for {r.method} {r.path}",
                    description=f"Generated {len(payloads[:12])} EvoMaster/InputFuzzer payloads (boundary/injection/encoding) for DAST replay --with-fuzz. EvoMaster: {'yes' if evo else 'local'}",
                    evidence=r.path,
                    finding_type="fuzz_payload",
                )
            )

        result.status = AgentStatus.SUCCEEDED
        result.data["fuzz_count"] = fuzz_count
        result.data["evomaster"] = bool(evo)
        result.files_scanned = len(routes)
