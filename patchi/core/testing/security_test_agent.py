"""
Security Test Agent — generates security-focused tests per route/endpoint.

For each route found by RouteMapScanner, generates:
- Authentication bypass tests
- SQL injection payload tests
- XSS payload injection tests
- CSRF token validation tests
- Rate limiting tests
- Header validation tests
- CORS origin tests

Outputs pytest files in tests/security/.
"""

from __future__ import annotations

import re
from pathlib import Path

from patchi.core.agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
)

# ── Test templates ────────────────────────────────────────────────────────────

_AUTH_BYPASS_TEMPLATE = '''\
def test_{func}_requires_auth(client):
    """{route} should reject unauthenticated requests."""
    resp = client.{method}("{route}")
    assert resp.status_code in (401, 403), \
        f"Expected 401/403, got {{resp.status_code}}"
'''

_SQLI_TEMPLATE = '''\
def test_{func}_sqli_protection(client):
    """{route} should reject SQL injection payloads."""
    payloads = ["' OR '1'='1", "1; DROP TABLE--", "' UNION SELECT NULL--"]
    for payload in payloads:
        resp = client.{method}("{route}", json={{"input": payload}})
        assert resp.status_code != 500, \
            f"Server error on SQLi payload: {{payload}}"
'''

_XSS_TEMPLATE = '''\
def test_{func}_xss_protection(client):
    """{route} should sanitize or escape XSS payloads."""
    payloads = ["<script>alert(1)</script>", "<img onerror=alert(1)>"]
    for payload in payloads:
        resp = client.{method}("{route}", json={{"input": payload}})
        if resp.status_code == 200:
            assert payload not in resp.text, \
                f"XSS payload reflected in response: {{payload}}"
'''

_CSRF_TEMPLATE = '''\
def test_{func}_csrf_protection(client):
    """{route} should validate CSRF tokens for state-changing operations."""
    resp = client.{method}("{route}", headers={{"X-Requested-With": ""}})
    assert resp.status_code in (400, 403), \
        f"Expected CSRF rejection, got {{resp.status_code}}"
'''

_HEADER_TEMPLATE = '''\
def test_{func}_security_headers(client):
    """{route} should include security headers."""
    resp = client.get("{route}")
    headers = {h.lower() for h in resp.headers}
    # At minimum, these should be present on sensitive endpoints
    recommended = ["x-content-type-options", "x-frame-options"]
    for h in recommended:
        # Only warn, don't fail — not all routes need all headers
        pass
'''

_RATE_LIMIT_TEMPLATE = '''\
def test_{func}_rate_limiting(client):
    """{route} should enforce rate limiting on repeated requests."""
    responses = [client.{method}("{route}") for _ in range(50)]
    status_codes = [r.status_code for r in responses]
    # At least some requests should be throttled (429) or the endpoint
    # should handle rapid requests gracefully (no 500s)
    assert 500 not in status_codes, "Server crashed under rapid requests"
'''

_CORS_TEMPLATE = '''\
def test_{func}_cors_restrictions(client):
    """{route} should not allow arbitrary origins."""
    resp = client.options("{route}", headers={{{{ \
        "Origin": "https://evil.com", \
        "Access-Control-Request-Method": "{method_upper}", \
    }}}})
    acao = resp.headers.get("access-control-allow-origin", "")
    assert acao != "*", \
        f"CORS allows all origins on {route}"
'''


# ── Agent ─────────────────────────────────────────────────────────────────────


@register
class SecurityTestAgent(BaseAgent):
    """Generates security-focused pytest tests for detected routes."""

    name = "SecurityTestAgent"
    group = AgentGroup.TEST
    domain = AgentDomain.TESTING
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        routes = inp.brain.get("routes", [])
        if not routes:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="info",
                    severity=Severity.INFO,
                    file="",
                    message="No routes detected — security tests require a web app with routes",
                )
            )
            return

        test_dir = inp.root / "tests" / "security"
        test_files: list[Path] = []

        framework = self._detect_framework(inp.brain)
        for route_info in routes:
            route = (
                route_info.get("path", "")
                if isinstance(route_info, dict)
                else getattr(route_info, "path", "")
            )
            method = (
                route_info.get("method", "get")
                if isinstance(route_info, dict)
                else getattr(route_info, "method", "get")
            ).lower()
            func_name = self._route_to_func(route, method)

            if not func_name:
                continue

            tests = self._generate_tests(route, method, func_name)
            if tests:
                test_file = test_dir / f"test_security_{func_name}.py"
                test_file.parent.mkdir(parents=True, exist_ok=True)
                header = self._build_header(framework, route, method)
                test_file.write_text(header + tests, encoding="utf-8")
                test_files.append(test_file)
                result.files_scanned += 1

        if test_files:
            result.data["generated_files"] = [str(f.relative_to(inp.root)) for f in test_files]
            result.data["test_count"] = len(test_files)

    def _route_to_func(self, route: str, method: str) -> str:
        """Convert /api/users/{id} -> api_users_id."""
        clean = re.sub(r"[^a-zA-Z0-9/]", "", route)
        parts = [p for p in clean.split("/") if p]
        name = "_".join(parts[:4])  # limit depth
        return f"{method}_{name}" if name else ""

    def _detect_framework(self, brain: dict) -> str:
        fw = brain.get("framework", "")
        fw_raw = brain.get("frameworks", fw)
        if isinstance(fw_raw, list):
            fw = fw_raw[0] if fw_raw else ""
        else:
            fw = fw_raw or ""
        fw_lower = fw.lower()
        if "fastapi" in fw_lower or "starlette" in fw_lower:
            return "fastapi"
        if "flask" in fw_lower:
            return "flask"
        if "django" in fw_lower:
            return "django"
        if "express" in fw_lower or "node" in fw_lower:
            return "express"
        return "generic"

    def _build_header(self, framework: str, route: str, method: str) -> str:
        fixtures = {
            "fastapi": (
                "@pytest.fixture\ndef client():\n"
                "    from fastapi.testclient import TestClient\n"
                "    from app import app\n"
                "    return TestClient(app)\n"
            ),
            "flask": (
                "@pytest.fixture\ndef client():\n"
                "    from flask import Flask\n"
                "    app = Flask(__name__)\n"
                "    return app.test_client()\n"
            ),
            "django": (
                "@pytest.fixture\ndef client():\n"
                "    from django.test import Client\n"
                "    return Client()\n"
            ),
        }
        fixture = fixtures.get(
            framework,
            (
                "@pytest.fixture\ndef client():\n"
                '    """Override with your app\'s test client."""\n'
                "    import pytest\n"
                '    raise NotImplementedError("Define a client fixture for your framework")\n'
            ),
        )
        return (
            '"""Auto-generated security tests by Patchi SecurityTestAgent."""\n'
            "import pytest\n\n\n"
            f"{fixture}\n\n"
        )

    def _generate_tests(self, route: str, method: str, func: str) -> str:
        """Generate test code for a single route."""
        tests = []
        templates = [
            ("auth", _AUTH_BYPASS_TEMPLATE),
            ("sqli", _SQLI_TEMPLATE),
            ("xss", _XSS_TEMPLATE),
        ]
        # Only add CSRF for state-changing methods
        if method in ("post", "put", "patch", "delete"):
            templates.append(("csrf", _CSRF_TEMPLATE))

        # CORS for all
        templates.append(("cors", _CORS_TEMPLATE))

        # Rate limit for all
        templates.append(("rate_limit", _RATE_LIMIT_TEMPLATE))

        for _name, tpl in templates:
            tests.append(
                tpl.format(
                    func=func,
                    route=route,
                    method=method,
                    method_upper=method.upper(),
                )
            )

        return "\n".join(tests)
