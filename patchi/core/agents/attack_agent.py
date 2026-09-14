"""
AttackAgent — Metasploit auxiliary/scanner probe integration.

Uses pymetasploit3 bridge to msfrpcd to run auxiliary/scanner modules
against the local project. Never targets external hosts — localhost only.

Flow:
  1. Read project brain data (framework, ports, routes)
  2. Pick relevant auxiliary/scanner modules based on framework
  3. Connect to msfrpcd on localhost:55553
  4. Run each module against 127.0.0.1
  5. Return findings as structured JSON

Optional dependency: pymetasploit3 (pip install patchi[msf])
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
)

# ── Framework → auxiliary/scanner module mapping ──────────────────────────────

# Shared module groups to avoid duplication
_HTTP_COMMON = [
    "scanner/http/http_header_xss",
    "scanner/http/http_version",
    "scanner/http/options",
]

_FRAMEWORK_MODULES: dict[str, list[str]] = {
    "flask": [*_HTTP_COMMON, "scanner/http/http_methods"],
    "django": [*_HTTP_COMMON, "scanner/http/http_methods"],
    "fastapi": _HTTP_COMMON,
    "express": _HTTP_COMMON,
    "react": [
        "scanner/http/http_header_xss",
        "scanner/http/http_version",
    ],
    "spring": [*_HTTP_COMMON, "scanner/http/http_methods"],
}

_FALLBACK_MODULES = _HTTP_COMMON

_DEFAULT_PORT = 8000


@register
class AttackAgent(BaseAgent):
    """Metasploit auxiliary/scanner probe integration (localhost only)."""

    group = AgentGroup.TEST
    name = "AttackAgent"
    timeout = 120  # Metasploit modules can take a while

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # ── 1. Check if pymetasploit3 is available ────────────────────────────
        try:
            import pymetasploit3  # noqa: F401
        except ImportError:
            # Optional dependency — skip cleanly, never FAIL the agent run.
            self.skip(result, "pymetasploit3 not installed. Run: pip install patchi[msf]")
            return

        # ── 2. Read brain data for framework / port hints ─────────────────────
        brain = inp.brain
        frameworks = _get_frameworks(brain)
        routes = brain.get("routes", [])

        # Determine target port from config, routes, or default
        target_port = _pick_port(brain, routes)
        target_ip = "127.0.0.1"
        result.data["target"] = f"{target_ip}:{target_port}"
        result.data["frameworks"] = frameworks

        # Part 7 (Item 7): scope gate — active testing against non-local
        # hosts requires explicit user confirmation.  AttackAgent always
        # targets localhost, but guard against future target changes.
        from patchi.core.testing.gate import require_scope

        allowed, scope_reason = require_scope(f"http://{target_ip}:{target_port}")
        if not allowed:
            self.skip(result, f"Scope gate: {scope_reason}")
            result.data["scope_blocked"] = True
            return

        # ── 3. Pick modules ──────────────────────────────────────────────────
        modules = _pick_modules(frameworks)

        result.data["modules_selected"] = modules

        # ── 4. Connect to msfrpcd and run modules ────────────────────────────
        from pymetasploit3.msfrpc import MsfRpcClient

        password = inp.extra.get("msf_password", "")
        msf_port = inp.extra.get("msf_port", 55553)
        msf_ssl = inp.extra.get("msf_ssl", True)
        msf_module_timeout = inp.extra.get("msf_module_timeout", 30)

        try:
            client = MsfRpcClient(password, port=msf_port, ssl=msf_ssl)
        except Exception as exc:
            result.add_error(
                f"Cannot connect to msfrpcd at 127.0.0.1:{msf_port} — {exc}. "
                f"Make sure msfrpcd is running (msfrpcd -P your_password -S -a 127.0.0.1 -p {msf_port})"
            )
            return

        with ThreadPoolExecutor(max_workers=1) as pool:
            for module_name in modules:
                future = pool.submit(self._run_module, client, module_name, target_ip, target_port, modules, result)
                try:
                    finding = future.result(timeout=msf_module_timeout)
                    if finding:
                        result.findings.append(finding)
                except FutureTimeout:
                    result.errors.append(f"{module_name}: timed out after {msf_module_timeout}s")
                except Exception as exc:
                    result.errors.append(f"{module_name}: {exc}")

    def _run_module(
        self,
        client,
        module_name: str,
        target_ip: str,
        target_port: int,
        modules: list[str],
        result: AgentResult,
    ) -> Finding | None:
        """Run a single auxiliary/scanner module and return a Finding."""
        try:
            aux = client.modules.use("auxiliary", module_name)
            aux["RHOSTS"] = target_ip
            aux["RPORT"] = target_port
            raw = aux.execute()
        except Exception as exc:
            result.errors.append(f"{module_name}: {exc}")
            return None

        if not raw:
            return None

        # Normalise result to dict
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                parsed = {"raw_output": raw[:500]}
        else:
            parsed = raw if isinstance(raw, dict) else {"data": str(raw)}

        # Determine severity based on module output
        severity = _classify_severity(module_name, parsed)

        # Store full result in data
        result.data.setdefault("module_results", {})[module_name] = parsed

        # Build a Finding for display
        message = f"{module_name} — {severity.value}"
        detail_lines = []
        if isinstance(parsed, dict):
            for k, v in list(parsed.items())[:5]:
                detail_lines.append(f"{k}: {v}")
        detail = "\n".join(detail_lines)

        return Finding(
            agent=self.name,
            type="metasploit_aux",
            severity=severity,
            file="metasploit",
            line=0,
            message=message[:120],
            detail=detail[:1000] or "No detail returned",
            extra={
                "module": module_name,
                "target": f"{target_ip}:{target_port}",
                "raw": parsed if isinstance(parsed, dict) else {"output": str(parsed)[:500]},
            },
        )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_frameworks(brain: dict) -> list[str]:
    """Extract framework names from brain data."""
    frameworks = []
    fw_raw = brain.get("framework", "")
    if fw_raw and fw_raw != "Unknown":
        frameworks.append(fw_raw.lower())

    fws_raw = brain.get("frameworks", [])
    for fw in fws_raw:
        name = ""
        if isinstance(fw, dict):
            name = fw.get("name", "")
        elif isinstance(fw, str):
            name = fw
        if name and name.lower() not in frameworks:
            frameworks.append(name.lower())
    return frameworks


def _pick_port(brain: dict, routes: list) -> int:
    """Pick the most likely target port from brain/routes data."""
    config_fallback = brain.get("config", {}).get("port", None)
    if config_fallback:
        return int(config_fallback)
    return _DEFAULT_PORT


def _pick_modules(frameworks: list[str]) -> list[str]:
    """Select relevant auxiliary/scanner modules based on detected frameworks."""
    selected: list[str] = []
    seen: set[str] = set()
    for fw in frameworks:
        for mod in _FRAMEWORK_MODULES.get(fw, []):
            if mod not in seen:
                selected.append(mod)
                seen.add(mod)
    if not selected:
        selected = list(_FALLBACK_MODULES)
    return selected


def _classify_severity(module_name: str, result: dict) -> Severity:
    """Heuristic to map module results to a severity level."""
    job_id = result.get("job_id")
    if job_id is not None:
        return Severity.INFO

    raw_out = str(result).lower()
    vuln_keywords = ["vulnerable", "found", "detected", "xss", "cve", "open", "leaked"]
    if any(kw in raw_out for kw in vuln_keywords):
        return Severity.MEDIUM

    if result.get("error"):
        return Severity.LOW

    return Severity.INFO
