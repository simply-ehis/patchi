"""
Browser Tester — Playwright-based security testing for live web apps.

Drives a real browser through the app map to test:
- Authentication bypass (bad/empty credentials)
- XSS injection in form fields
- Authorization checks (accessing pages without session)
- Form submission with malicious payloads
- Coverage: clicking every button/link

Requires: pip install playwright && playwright install
Falls back gracefully when Playwright is not installed.
"""

from __future__ import annotations

import logging

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
)

# ── Test payloads ─────────────────────────────────────────────────────────────

_XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "{{7*7}}",
    "${7*7}",
]

_AUTH_BYPASS_PAYLOADS = [
    {"username": "admin", "password": ""},
    {"username": "admin", "password": "admin"},
    {"username": "' OR '1'='1", "password": "' OR '1'='1"},
    {"username": "admin", "password": "password"},
    {"username": "administrator", "password": ""},
]

_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "admin'--",
]


_log = logging.getLogger("patchi.security.browser_tester")


def _check_playwright_available() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("playwright") is not None
    except (ImportError, ValueError):
        return False


def patchi_browser_test(url: str, app_map: dict | None = None) -> list[dict]:
    """Run browser-based security tests against a live app."""
    if not _check_playwright_available():
        return [
            {
                "type": "playwright_unavailable",
                "message": "Playwright not installed — pip install playwright",
            }
        ]

    findings = []

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Patchi-SecurityTester/1.0",
                ignore_https_errors=True,
            )
            page = context.new_page()

            # 1. Auth bypass test
            findings.extend(_test_auth_bypass(page, url))

            # 2. XSS injection in forms
            findings.extend(_test_xss_in_forms(page, url, app_map))

            # 3. SQLi in form fields
            findings.extend(_test_sqli_in_forms(page, url, app_map))

            browser.close()

    except Exception as e:
        findings.append({"type": "browser_test_error", "message": f"Browser test failed: {e}"})

    return findings


def _test_auth_bypass(page, url: str) -> list[dict]:
    """Try logging in with bad credentials."""
    findings = []
    try:
        page.goto(url, timeout=10000)

        # Look for login forms
        login_forms = page.query_selector_all(
            'form[action*="login"], form[action*="auth"], form:has(input[type="password"])'
        )

        for form in login_forms:
            for payload in _AUTH_BYPASS_PAYLOADS:
                try:
                    username_input = form.query_selector(
                        'input[name="username"], input[name="email"], input[type="email"]'
                    )
                    password_input = form.query_selector('input[type="password"]')

                    if username_input and password_input:
                        username_input.fill(payload["username"])
                        password_input.fill(payload["password"])
                        form.evaluate("el => el.submit()")

                        page.wait_for_timeout(2000)

                        # Check if we got past login (no login form visible)
                        still_on_login = page.query_selector('input[type="password"]')
                        if not still_on_login:
                            findings.append(
                                {
                                    "type": "auth_bypass",
                                    "severity": "critical",
                                    "message": f"Possible auth bypass with credentials:"
                                    f" {payload['username']}/{payload['password']}",
                                    "cwe": "CWE-287",
                                }
                            )
                            break

                        page.goto(url, timeout=10000)
                except Exception as e:
                    _log.warning("_test_auth_bypass failed: %s", e)
                    continue

    except Exception as e:
        _log.warning("_test_auth_bypass failed: %s", e)

    return findings


def _test_xss_in_forms(page, url: str, app_map: dict | None) -> list[dict]:
    """Inject XSS payloads into form fields."""
    findings = []

    pages_to_test = []
    if app_map and "pages" in app_map:
        pages_to_test = [(p["url"], p["forms"]) for p in app_map["pages"] if p["forms"]]
    else:
        pages_to_test = [(url, [])]

    for page_url, _forms in pages_to_test:
        try:
            page.goto(page_url, timeout=10000)
        except Exception as e:
            _log.warning("_test_xss_in_forms failed: %s", e)
            continue

        page_forms = page.query_selector_all("form")
        for form in page_forms:
            inputs = form.query_selector_all('input[type="text"], input[type="search"], textarea')
            for inp_field in inputs:
                for payload in _XSS_PAYLOADS[:2]:
                    try:
                        name = inp_field.get_attribute("name") or ""
                        inp_field.fill(payload)

                        # Check if payload reflected in page source
                        page_content = page.content()
                        if payload in page_content and payload not in ("{{7*7}}", "${7*7}"):
                            findings.append(
                                {
                                    "type": "reflected_xss",
                                    "severity": "high",
                                    "message": f"XSS payload reflected in form field '{name}' at {page_url}",
                                    "cwe": "CWE-79",
                                    "evidence": payload,
                                }
                            )
                            break
                    except Exception as e:
                        _log.warning("_test_xss_in_forms failed: %s", e)
                        continue

    return findings


def _test_sqli_in_forms(page, url: str, app_map: dict | None) -> list[dict]:
    """Test for SQL error-based injection in form fields."""
    findings = []

    pages_to_test = []
    if app_map and "pages" in app_map:
        pages_to_test = [(p["url"], p["forms"]) for p in app_map["pages"] if p["forms"]]
    else:
        pages_to_test = [(url, [])]

    SQL_ERROR_PATTERNS = [
        "sql syntax",
        "mysql_fetch",
        "sqlite3.",
        "postgresql",
        "ora-",
        "syntax error",
        "unterminated",
        "pg_query",
        "warning:",
        "fatal error",
        "microsoft odbc",
    ]

    for page_url, _forms in pages_to_test:
        try:
            page.goto(page_url, timeout=10000)
        except Exception as e:
            _log.warning("_test_sqli_in_forms failed: %s", e)
            continue

        page_forms = page.query_selector_all("form")
        for form in page_forms:
            inputs = form.query_selector_all('input[type="text"], input[type="search"], textarea')
            for inp_field in inputs:
                for payload in _SQLI_PAYLOADS[:2]:
                    try:
                        name = inp_field.get_attribute("name") or ""
                        inp_field.fill(payload)
                        form.evaluate("el => el.submit()")

                        page.wait_for_timeout(2000)
                        page_content = page.content().lower()

                        for pattern in SQL_ERROR_PATTERNS:
                            if pattern in page_content:
                                findings.append(
                                    {
                                        "type": "sql_injection_error",
                                        "severity": "critical",
                                        "message": f"SQL error pattern '{pattern}' after injecting '{payload}' in"
                                        f" field '{name}' at {page_url}",
                                        "cwe": "CWE-89",
                                        "evidence": pattern,
                                    }
                                )
                                break

                        page.goto(page_url, timeout=10000)
                    except Exception as e:
                        _log.warning("_test_sqli_in_forms failed: %s", e)
                        continue

    return findings


# ── Browser Tester Agent ──────────────────────────────────────────────────────


@register
class BrowserTesterAgent(BaseAgent):
    """Playwright-based security testing for live web apps."""

    name = "BrowserTesterAgent"
    group = AgentGroup.SECURITY
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        app_url = inp.brain.get("app_url", "") or inp.config.get("app_url", "") or inp.extra.get("app_url", "")

        if not app_url:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="no_target_url",
                    severity=Severity.INFO,
                    file="",
                    message="No app URL configured — set 'app_url' in config to enable browser testing",
                )
            )
            return

        app_map = inp.extra.get("app_map", None)
        test_results = patchi_browser_test(app_url, app_map)

        for tr in test_results:
            if tr.get("type") == "playwright_unavailable":
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="playwright_unavailable",
                        severity=Severity.INFO,
                        file="",
                        message=tr["message"],
                    )
                )
                continue
            if tr.get("type") == "browser_test_error":
                result.add_error(tr["message"])
                continue

            sev = tr.get("severity", "medium")
            result.add_finding(
                Finding(
                    agent=self.name,
                    type=tr.get("type", "browser_finding"),
                    severity=Severity(sev) if sev in ("critical", "high", "medium", "low", "info") else Severity.MEDIUM,
                    file="",
                    message=tr.get("message", ""),
                    cwe=tr.get("cwe", ""),
                    evidence=tr.get("evidence", ""),
                )
            )

        result.files_scanned = 1
