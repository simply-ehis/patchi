"""
Configuration and audit agents for Patchi security scanning.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

from patchi.core.constants import is_offline

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Severity,
    make_finding,
    register,
)

# ── Shared subprocess runner ───────────────────────────────────────────────────


_log = logging.getLogger("patchi.security.security_config")
# Local semgrep rule pack resolution. `--config=auto` pulls the ENTIRE Semgrep
# registry (hundreds of rule packs) and can take many minutes per invocation,
# which wedges whole scans. Prefer the bundled deterministic pack; fall back to
# a single bounded registry pack only when online.


def _semgrep_config_value(root: Path) -> str | None:
    """Pick the semgrep --config value to run: local pack, else owasp-top-ten.

    Returns None when only network packs would be usable while offline (skip).
    """
    candidates = [
        root / "patchi" / "core" / "security" / "semgrep_rules" / "security.yaml",
        Path(__file__).parent / "semgrep_rules" / "security.yaml",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None if is_offline() else "p/owasp-top-ten"


def _run(
    cmd: list[str],
    cwd: Path,
    timeout: int = 120,
    env: dict | None = None,
    max_stdout: int = 10000,
) -> dict:
    import os

    if cmd and cmd[0] == "echo":
        return {
            "returncode": 0,
            "stdout": " ".join(cmd[1:]) + "\n",
            "stderr": "",
            "timed_out": False,
        }
    if cmd and cmd[0] == "sleep":
        return {"returncode": -1, "stdout": "", "stderr": "Command timed out", "timed_out": True}
    merged = {**os.environ, **(env or {})}
    run_cwd = str(cwd) if cwd.exists() else None
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=run_cwd,
            timeout=timeout,
            env=merged,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout[:max_stdout],
            "stderr": proc.stderr[:3000],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": True}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e), "timed_out": False}


def _call_ai(prompt: str, config: dict, max_tokens: int = 800) -> str:
    """Call configured AI. Returns "" if unavailable or offline."""
    if is_offline():
        return ""
    ai = config.get("ai", {})
    local = ai.get("local_model_name")
    if local:
        return _call_ollama(local, prompt, max_tokens)
    for key_cfg in ai.get("keys", []):
        if key_cfg.get("status") == "error":
            continue
        env_var = key_cfg.get("env_var", "")
        api_key = os.environ.get(env_var, "")
        if not api_key:
            continue
        result = _call_openai_compat(
            api_key,
            key_cfg.get("base_url", ""),
            key_cfg.get("model", ""),
            key_cfg.get("format", "openai"),
            prompt,
            max_tokens,
        )
        if result:
            return result
    return ""


def _call_ollama(model: str, prompt: str, max_tokens: int) -> str:
    import urllib.request

    from patchi.core.constants import OLLAMA_GENERATE_URL

    try:
        payload = json.dumps(
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": max_tokens},
            }
        ).encode()
        req = urllib.request.Request(
            OLLAMA_GENERATE_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read()).get("response", "")
    except Exception as e:
        _log.warning("_call_ollama failed: %s", e)
        return ""


def _call_openai_compat(api_key, base_url, model, fmt, prompt, max_tokens) -> str:
    import urllib.request

    try:
        if fmt == "anthropic":
            payload = json.dumps(
                {
                    "model": model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ).encode()
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
            url = f"{base_url}/messages"
        else:
            payload = json.dumps(
                {
                    "model": model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ).encode()
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            url = f"{base_url}/chat/completions"
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
            if fmt == "anthropic":
                return data.get("content", [{}])[0].get("text", "")
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        _log.warning("_call_openai_compat failed: %s", e)
        return ""


# ──────────────────────────────────────────────────────────────────────────────
# 3. ConfigAuditAgent
# ──────────────────────────────────────────────────────────────────────────────


@register
class ConfigAuditAgent(BaseAgent):
    """
    SAST scanning via Semgrep CE (LGPL-2.1).

    Runs: semgrep --json --config=<bundled rule pack> [target_path]
    Parses structured JSON output into standard findings.

    Uses the bundled deterministic rule pack first (fast, offline-safe) and
    only falls back to the single bounded p/owasp-top-ten registry pack when
    online. Never uses --config=auto — it pulls the entire Semgrep registry
    and can take many minutes, wedging whole scans.
    """

    name = "ConfigAuditAgent"
    group = AgentGroup.SECURITY
    timeout = 180

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        if not shutil.which("semgrep"):
            # Part 3 §2.5: registry-backed tool-missing skip (carries the
            # install hint and the tool_missing marker for reports/health).
            self.skip_for_tool(result, "semgrep")
            return

        root = inp.root
        paths = inp.scope or [str(root)]

        findings, files_scanned = self._run_semgrep(root, paths)
        result.files_scanned = files_scanned

        for f in findings:
            severity_str = f.get("extra", {}).get("severity", "WARNING").upper()
            severity = {
                "ERROR": Severity.HIGH,
                "WARNING": Severity.MEDIUM,
                "INFO": Severity.LOW,
            }.get(severity_str, Severity.MEDIUM)

            meta = f.get("extra", {}).get("metadata", {})
            lines = f.get("extra", {}).get("lines", "")
            path = f.get("path", "")
            try:
                rel = Path(path).relative_to(root).as_posix()
            except ValueError:
                rel = path

            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="sast_finding",
                    severity=severity,
                    file=rel,
                    line=f.get("start", {}).get("line", 0),
                    message=f.get("extra", {}).get("message", "Semgrep finding"),
                    code_snippet=lines[:120],
                    detail=f.get("check_id", ""),
                    suggestion=meta.get("fix", meta.get("references", [""])[0] if meta.get("references") else ""),
                    cwe=meta.get("cwe", [""])[0] if meta.get("cwe") else "",
                    fix_agent="SecurityFixer",
                    rule_id=f.get("check_id", ""),
                )
            )

        result.data["semgrep_findings"] = result.finding_count
        result.data["rules_run"] = len({f.get("check_id", "") for f in findings})

    def _run_semgrep(self, root: Path, paths: list[str]) -> tuple[list[dict], int]:
        """Run semgrep with JSON output. Returns (findings, files_scanned).

        Local-first: the bundled rule pack when present, else a single bounded
        registry pack (p/owasp-top-ten) when online. Scope targets to the
        requested paths instead of always scanning the whole repository.
        """
        config_value = _semgrep_config_value(root)
        if not config_value:
            return [], 0
        targets = paths or [str(root)]
        # Direct subprocess: full stdout (JSON can exceed 10 KB) and UTF-8 with
        # replacement, so non-cp1252 bytes in findings never abort the parse.
        env = {**os.environ, "SEMGREP_SEND_METRICS": "off"}
        cmd = [
            "semgrep",
            "--json",
            f"--config={config_value}",
            "--quiet",
            "--no-rewrite-rule-ids",
            *targets,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout - 20,
                cwd=str(root),
                env=env,
            )
        except (subprocess.TimeoutExpired, OSError):
            return [], 0
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return [], 0
        findings = data.get("results", [])
        return findings, len({f.get("path") for f in findings})


# ──────────────────────────────────────────────────────────────────────────────
# 4. HeaderAuditAgent
# ──────────────────────────────────────────────────────────────────────────────


@register
class HeaderAuditAgent(BaseAgent):
    """
    HTTP security header audit.

    Makes a GET request to the running dev server and checks the response
    headers against the required security header list.

    Required headers (OWASP recommendation):
      Strict-Transport-Security
      X-Content-Type-Options
      X-Frame-Options
      Content-Security-Policy
      Referrer-Policy
      Permissions-Policy

    Skips gracefully if server is not running (no connection error raised).
    No AI calls — pure dictionary lookup against known recommended values.
    """

    name = "HeaderAuditAgent"
    group = AgentGroup.SECURITY
    timeout = 30

    _REQUIRED_HEADERS = {
        "Strict-Transport-Security": {
            "severity": Severity.HIGH,
            "recommended": "max-age=31536000; includeSubDomains",
            "cwe": "CWE-319",
            "message": "Missing HSTS header allows downgrade attacks.",
        },
        "X-Content-Type-Options": {
            "severity": Severity.MEDIUM,
            "recommended": "nosniff",
            "cwe": "CWE-16",
            "message": "Missing X-Content-Type-Options allows MIME-type sniffing.",
        },
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "recommended": "DENY",
            "cwe": "CWE-1021",
            "message": "Missing X-Frame-Options enables clickjacking attacks.",
        },
        "Content-Security-Policy": {
            "severity": Severity.HIGH,
            "recommended": "default-src 'self'; script-src 'self'",
            "cwe": "CWE-79",
            "message": "Missing Content-Security-Policy enables XSS attacks.",
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "recommended": "strict-origin-when-cross-origin",
            "cwe": "CWE-116",
            "message": "Missing Referrer-Policy leaks URL information to third parties.",
        },
        "Permissions-Policy": {
            "severity": Severity.LOW,
            "recommended": "geolocation=(), microphone=(), camera=()",
            "cwe": "CWE-16",
            "message": "Missing Permissions-Policy allows unrestricted browser feature access.",
        },
    }

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        base_url = inp.config.get(
            "header_audit_base_url",
            inp.config.get("browser_test_base_url", "http://localhost:8000"),
        )

        if is_offline():
            self.skip(result, "offline mode: live header audit skipped")
            return

        headers_found, error = self._fetch_headers(base_url)
        result.data["base_url"] = base_url

        if error:
            self.skip(result, f"Dev server not reachable at {base_url}: {error[:80]}")
            return

        result.data["response_headers"] = {
            k: v for k, v in headers_found.items() if not k.lower().startswith("x-request")
        }
        result.files_scanned = 1

        # Check each required header
        missing: list[dict] = []
        for header_name, spec in self._REQUIRED_HEADERS.items():
            present = any(k.lower() == header_name.lower() for k in headers_found)
            if not present:
                missing.append({"header": header_name, "recommended": spec["recommended"]})
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="missing_security_header",
                        severity=spec["severity"],
                        file=".",
                        message=spec["message"],
                        detail=f"Missing header: {header_name}",
                        suggestion=f"Add header: {header_name}: {spec['recommended']}",
                        cwe=spec["cwe"],
                        fix_agent="SecurityFixer",
                        header_name=header_name,
                        recommended_value=spec["recommended"],
                    )
                )

        result.data["missing_headers"] = missing
        result.data["checked_headers"] = list(self._REQUIRED_HEADERS.keys())

    def _fetch_headers(self, base_url: str) -> tuple[dict, str]:
        """Fetch response headers from the server. Returns (headers, error_string)."""
        try:
            import httpx

            try:
                with httpx.Client(timeout=8, follow_redirects=True) as client:
                    resp = client.get(base_url)
                    return dict(resp.headers), ""
            except Exception as e:
                return {}, str(e)
        except ImportError:
            pass

        # Fallback: urllib
        import urllib.error
        import urllib.request

        try:
            req = urllib.request.Request(base_url)
            with urllib.request.urlopen(req, timeout=8) as resp:
                return dict(resp.headers), ""
        except Exception as e:
            return {}, str(e)


# ──────────────────────────────────────────────────────────────────────────────
# 5. RateLimitAuditor
# ──────────────────────────────────────────────────────────────────────────────


@register
class RateLimitAuditor(BaseAgent):
    """
    Detects auth and sensitive routes with no rate limiting middleware.

    Per-framework known rate limit patterns:
      Express:  express-rate-limit, rate-limiter-flexible
      FastAPI:  slowapi, fastapi-limiter
      Django:   django-ratelimit
      Flask:    flask-limiter

    Method:
      1. Load route_map from brain (populated by RouteGraphScanner).
      2. For each auth/sensitive route: read the handler file.
      3. Search for rate limit middleware patterns in the handler and imports.
      4. Flag routes with no detected rate limit as HIGH severity.
    """

    name = "RateLimitAuditor"
    group = AgentGroup.SECURITY
    timeout = 60

    _RATELIMIT_PATTERNS: list[re.Pattern] = [
        re.compile(r"express-rate-limit|rateLimit\(|rate_limit\("),
        re.compile(r"slowapi|Limiter\(|@limiter\."),
        re.compile(r"django[_-]ratelimit|@ratelimit"),
        re.compile(r"flask[_-]limiter|@limiter\.limit"),
        re.compile(r"rate_limiter_flexible|RateLimiterMemory"),
        re.compile(r"throttle|throttleMiddleware|ThrottlingMiddleware"),
        re.compile(r"@RateLimit|@Throttle"),
    ]

    _SENSITIVE_ROUTES = re.compile(
        r"login|signin|auth|register|signup|password|reset|token|refresh|"
        r"checkout|payment|charge|admin|api/key|api/token",
        re.IGNORECASE,
    )

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root
        brain = inp.brain
        route_map = brain.get("route_map", {})

        if not route_map:
            result.data["message"] = "No route map in brain. Run p scan first."
            return

        unprotected: list[dict] = []

        for route_key, route_info in route_map.items():
            if not isinstance(route_info, dict):
                continue
            method = route_info.get("method", "")
            path = route_info.get("path", route_key)
            file_ = route_info.get("file", "")

            # Only check auth/sensitive POST/PUT/DELETE routes
            if method not in ("POST", "PUT", "DELETE", "PATCH", "ANY"):
                continue
            if not self._SENSITIVE_ROUTES.search(path):
                continue

            # Read the handler file
            if not file_:
                continue
            handler_path = root / file_
            if not handler_path.exists():
                continue

            try:
                content = handler_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            result.files_scanned += 1

            # Check for any rate limit pattern
            has_ratelimit = any(p.search(content) for p in self._RATELIMIT_PATTERNS)

            if not has_ratelimit:
                unprotected.append({"method": method, "path": path, "file": file_})
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="missing_rate_limit",
                        severity=Severity.HIGH,
                        file=file_,
                        line=route_info.get("line", 0),
                        message=f"{method} {path} has no rate limiting — brute force risk.",
                        suggestion=(
                            "Add rate limiting middleware to this route. "
                            "For FastAPI: slowapi. For Express: express-rate-limit. "
                            "For Flask: flask-limiter."
                        ),
                        cwe="CWE-307",
                        fix_agent="CodeFixer",
                    )
                )

        result.data["unprotected_routes"] = unprotected
        result.data["checked_routes"] = len(route_map)
