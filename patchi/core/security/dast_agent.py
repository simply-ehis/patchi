"""
DAST Agent — Dynamic Application Security Testing with Playwright.

Performs live security testing against running applications:
- XSS (Cross-Site Scripting) injection
- SQL Injection testing
- CSRF vulnerability detection
- Clickjacking checks
- Security header validation
- Information disclosure detection
- Screenshot capture for evidence

Uses BrowserPool for parallel testing and ScreenshotManager for evidence.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

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

_log = logging.getLogger("patchi.security.dast")

# Additional XSS payloads from DASTScanner
ADDITIONAL_XSS_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'-alert(1)-'",
]

# Additional security headers from DASTScanner
ADDITIONAL_HEADER_CHECKS = [
    (
        "x-content-type-options",
        "nosniff",
        "Missing X-Content-Type-Options header",
        "medium",
    ),
    ("x-xss-protection", None, "Missing X-XSS-Protection header", "low"),
]

# Auth bypass keywords from DASTScanner
AUTH_BYPASS_KEYWORDS = [
    "dashboard",
    "admin",
    "settings",
    "profile",
    "logout",
]

# Info disclosure indicators from DASTScanner
INFO_DISCLOSURE_INDICATORS = [
    "traceback",
    "stack trace",
    "exception in",
]

# Open redirect payloads from DASTScanner
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
]

# Common endpoint paths from DASTScanner for discovery
COMMON_ENDPOINT_PATHS = [
    "/",
    "/login",
    "/admin",
    "/api",
    "/dashboard",
    "/settings",
    "/profile",
    "/users",
    "/health",
    "/api/health",
    "/api/status",
    "/static/",
]


@dataclass
class DASTTest:
    """A single DAST test case."""

    name: str
    description: str
    category: str  # xss, sqli, csrf, header, info_disclosure, clickjacking
    severity: Severity
    test_fn: str  # Method name to call
    tags: list[str] | None = None


# ── Test Registry ────────────────────────────────────────────────────────────

DAST_TESTS: list[DASTTest] = [
    # XSS Tests
    DASTTest(
        name="xss_reflected_basic",
        description="Test for reflected XSS via basic script injection",
        category="xss",
        severity=Severity.HIGH,
        test_fn="test_xss_reflected",
        tags=["xss", "injection", "reflected"],
    ),
    DASTTest(
        name="xss_stored_svg",
        description="Test for stored XSS via SVG injection",
        category="xss",
        severity=Severity.HIGH,
        test_fn="test_xss_svg",
        tags=["xss", "injection", "stored"],
    ),
    # SQL Injection Tests
    DASTTest(
        name="sqli_error_based",
        description="Test for SQL injection via error-based extraction",
        category="sqli",
        severity=Severity.CRITICAL,
        test_fn="test_sqli_error",
        tags=["sqli", "injection", "database"],
    ),
    DASTTest(
        name="sqli_union_select",
        description="Test for SQL injection via UNION SELECT",
        category="sqli",
        severity=Severity.CRITICAL,
        test_fn="test_sqli_union",
        tags=["sqli", "injection", "database"],
    ),
    # Security Headers
    DASTTest(
        name="missing_content_security_policy",
        description="Check for missing Content-Security-Policy header",
        category="header",
        severity=Severity.MEDIUM,
        test_fn="test_csp_header",
        tags=["headers", "csp"],
    ),
    DASTTest(
        name="missing_x_frame_options",
        description="Check for missing X-Frame-Options header (clickjacking)",
        category="clickjacking",
        severity=Severity.MEDIUM,
        test_fn="test_x_frame_options",
        tags=["headers", "clickjacking"],
    ),
    DASTTest(
        name="missing_hsts",
        description="Check for missing Strict-Transport-Security header",
        category="header",
        severity=Severity.LOW,
        test_fn="test_hsts_header",
        tags=["headers", "hsts"],
    ),
    # Information Disclosure
    DASTTest(
        name="server_version_disclosure",
        description="Check for server version disclosure in headers",
        category="info_disclosure",
        severity=Severity.LOW,
        test_fn="test_server_version",
        tags=["info", "server"],
    ),
    DASTTest(
        name="error_page_disclosure",
        description="Check if error pages reveal stack traces",
        category="info_disclosure",
        severity=Severity.MEDIUM,
        test_fn="test_error_disclosure",
        tags=["info", "errors"],
    ),
    # Directory Traversal
    DASTTest(
        name="directory_traversal",
        description="Test for directory traversal via path manipulation",
        category="path_traversal",
        severity=Severity.HIGH,
        test_fn="test_directory_traversal",
        tags=["traversal", "directory"],
    ),
    # CSRF
    DASTTest(
        name="csrf_token_missing",
        description="Check for missing CSRF tokens in forms",
        category="csrf",
        severity=Severity.MEDIUM,
        test_fn="test_csrf_token",
        tags=["csrf", "forms"],
    ),
    # Auth Bypass (from DASTScanner)
    DASTTest(
        name="auth_bypass",
        description="Test for authentication bypass on protected pages",
        category="auth_bypass",
        severity=Severity.CRITICAL,
        test_fn="test_auth_bypass",
        tags=["auth", "bypass"],
    ),
    # Open Redirect (from DASTScanner)
    DASTTest(
        name="open_redirect",
        description="Test for open redirect vulnerabilities",
        category="open_redirect",
        severity=Severity.HIGH,
        test_fn="test_open_redirect",
        tags=["redirect", "open_redirect"],
    ),
    # Additional Security Headers (from DASTScanner)
    DASTTest(
        name="missing_x_content_type_options",
        description="Check for missing X-Content-Type-Options header",
        category="header",
        severity=Severity.MEDIUM,
        test_fn="test_additional_headers",
        tags=["headers", "x-content-type-options"],
    ),
    DASTTest(
        name="missing_x_xss_protection",
        description="Check for missing X-XSS-Protection header",
        category="header",
        severity=Severity.LOW,
        test_fn="test_additional_headers",
        tags=["headers", "x-xss-protection"],
    ),
    # Stack Trace Disclosure (from DASTScanner)
    DASTTest(
        name="stack_trace_disclosure",
        description="Check if error pages reveal stack traces",
        category="info_disclosure",
        severity=Severity.HIGH,
        test_fn="test_stack_trace_disclosure",
        tags=["info", "stack_trace"],
    ),
]


class DASTAgent(BaseAgent):
    """
    Dynamic Application Security Testing agent.

    Runs live security tests against a running web application using Playwright.
    Captures screenshots as evidence and reports findings.
    """

    name = "DASTAgent"
    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    timeout = 300  # 5 minutes for browser tests

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run DAST tests against the target application."""
        target_url = self._detect_target(inp.root)
        if not target_url:
            result.add_finding(Finding(
                agent=self.name,
                type="dast_config",
                severity=Severity.INFO,
                message="No running web application detected. Start the web server first.",
            ))
            return

        _log.info("DAST: Testing %s", target_url)

        # Run tests synchronously (browser tests)
        test_results = asyncio.run(self._run_tests(target_url, inp))

        # Add findings to result
        for finding in test_results:
            result.add_finding(finding)

        result.files_scanned = 1
        result.data["target_url"] = target_url
        result.data["tests_run"] = len(DAST_TESTS)
        result.data["findings_count"] = len(test_results)

    async def _run_tests(self, target_url: str, inp: AgentInput) -> list[Finding]:
        """Run all DAST tests asynchronously with video recording."""
        findings: list[Finding] = []

        try:
            from patchi.core.testing.live_v2.screenshot_manager import ScreenshotManager
            from patchi.core.testing.live_v2.video_recorder import (
                RecordingConfig,
                VideoRecorder,
            )

            screenshot_mgr = ScreenshotManager(
                baseline_dir=inp.root / ".patchi" / "evidence" / "dast"
            )

            # Initialize video recorder — outputs to evidence/video
            video_dir = inp.root / ".patchi" / "evidence" / "video"
            video_dir.mkdir(parents=True, exist_ok=True)
            recorder = VideoRecorder(RecordingConfig(output_dir=video_dir))

            # Run each test with video recording
            for test in DAST_TESTS:
                recording_id = None
                try:
                    finding, recording_id = await self._run_test_recorded(
                        recorder, screenshot_mgr, test, target_url
                    )
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    _log.warning("DAST test %s failed: %s", test.name, e)
                finally:
                    # Ensure recording is stopped even on error
                    if recording_id and recording_id in recorder._active_recordings:
                        try:
                            await recorder.stop_recording(recording_id)
                        except Exception as _exc:
                            _log.warning('_run_tests failed: %s', _exc)

        except ImportError:
            _log.warning("Playwright not installed. Install with: pip install playwright")
        except Exception as e:
            _log.error("DAST agent failed: %s", e)

        return findings

    async def _run_test_recorded(
        self,
        recorder,
        screenshot_mgr,
        test: DASTTest,
        target_url: str,
    ) -> tuple[Finding | None, str | None]:
        """Run a single DAST test with video recording.

        Returns (finding, recording_id) so the caller can stop the recording.
        """
        # Start a recorded browser context for this test
        test_name = f"dast_{test.name}_{int(time.time())}"
        context, browser = await recorder.start_recording(test_name)
        recording_id = f"{test_name}-{int(time.time())}"

        page = await context.new_page()

        try:
            # Get the test function
            test_fn = getattr(self, test.test_fn, None)
            if not test_fn:
                _log.warning("DAST test function not found: %s", test.test_fn)
                return None, recording_id

            # Run the test
            vuln_found, evidence = await test_fn(page, target_url, screenshot_mgr)

            if vuln_found:
                # Capture screenshot as evidence
                try:
                    await screenshot_mgr.capture(
                        page, target_url, name=f"dast_{test.name}"
                    )
                except Exception as e:
                    _log.debug("Screenshot capture failed: %s", e)

                return Finding(
                    agent=self.name,
                    type=f"dast_{test.category}",
                    severity=test.severity,
                    message=test.description,
                    file=target_url,
                    suggestion=f"Fix {test.category} vulnerability: {evidence}",
                    code_snippet=evidence[:500] if evidence else "",
                ), recording_id

            return None, recording_id

        finally:
            # Close page and stop recording
            try:
                await page.close()
            except Exception as _exc:
                _log.warning('_run_test_recorded failed: %s', _exc)
            # Stop recording and save video
            try:
                if recording_id in recorder._active_recordings:
                    recording = await recorder.stop_recording(recording_id)
                    _log.info(
                        "DAST video recorded: %s (%.1fs)",
                        test.name,
                        recording.total_duration_seconds,
                    )
            except Exception as e:
                _log.debug("Video recording stop failed: %s", e)
            try:
                await browser.close()
            except Exception as _exc:
                _log.warning('_run_test_recorded failed: %s', _exc)

    # ── XSS Tests ──────────────────────────────────────────────────────────

    async def test_xss_reflected(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Test for reflected XSS via basic script injection."""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]

        for payload in payloads:
            try:
                # Try common injection points
                test_urls = [
                    f"{base_url}?q={payload}",
                    f"{base_url}/search?q={payload}",
                    f"{base_url}/?error={payload}",
                ]

                for url in test_urls:
                    await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                    content = await page.content()

                    # Check if payload is reflected unescaped
                    if payload in content and "<script>" in payload:
                        return True, f"Reflected XSS at {url} with payload: {payload}"

            except Exception:
                continue

        return False, ""

    async def test_xss_svg(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Test for stored XSS via SVG injection."""

        try:
            # Try common upload/comment endpoints
            endpoints = ["/upload", "/comment", "/profile", "/bio"]

            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)

                # Look for file upload inputs
                file_inputs = await page.query_selector_all('input[type="file"]')
                if file_inputs:
                    # Note: actual file upload testing would require creating a temp file
                    return True, f"Potential XSS via SVG upload at {url}"

        except Exception as _exc:
            _log.warning('test_xss_svg failed: %s', _exc)

        return False, ""

    # ── SQL Injection Tests ────────────────────────────────────────────────

    async def test_sqli_error(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Test for SQL injection via error-based extraction."""
        payloads = [
            "'",
            "1' OR '1'='1",
            "1' UNION SELECT NULL--",
        ]

        sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-01756",
            "PostgreSQL",
            "SQLite3::",
            "Microsoft OLE DB",
            "ODBC SQL Server",
        ]

        for payload in payloads:
            try:
                test_urls = [
                    f"{base_url}?id={payload}",
                    f"{base_url}/user?id={payload}",
                    f"{base_url}/api/data?id={payload}",
                ]

                for url in test_urls:
                    await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                    content = await page.content()

                    for error in sql_errors:
                        if error.lower() in content.lower():
                            return True, f"SQL injection error at {url}: {error}"

            except Exception:
                continue

        return False, ""

    async def test_sqli_union(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Test for SQL injection via UNION SELECT."""
        # Simplified check - look for SQL error patterns
        return await self.test_sqli_error(page, base_url, screenshot_mgr)

    # ── Header Tests ───────────────────────────────────────────────────────

    async def test_csp_header(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Check for missing Content-Security-Policy header."""
        try:
            response = await page.goto(base_url, wait_until="domcontentloaded")
            csp = response.headers.get("content-security-policy", "")

            if not csp:
                return True, "Missing Content-Security-Policy header"

        except Exception as _exc:
            _log.warning('test_csp_header failed: %s', _exc)

        return False, ""

    async def test_x_frame_options(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Check for missing X-Frame-Options header."""
        try:
            response = await page.goto(base_url, wait_until="domcontentloaded")
            xfo = response.headers.get("x-frame-options", "")
            csp = response.headers.get("content-security-policy", "")

            if not xfo and "frame-ancestors" not in csp:
                return True, "Missing X-Frame-Options header (clickjacking risk)"

        except Exception as _exc:
            _log.warning('test_x_frame_options failed: %s', _exc)

        return False, ""

    async def test_hsts_header(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Check for missing Strict-Transport-Security header."""
        if not base_url.startswith("https"):
            return False, ""

        try:
            response = await page.goto(base_url, wait_until="domcontentloaded")
            hsts = response.headers.get("strict-transport-security", "")

            if not hsts:
                return True, "Missing Strict-Transport-Security header"

        except Exception as _exc:
            _log.warning('test_hsts_header failed: %s', _exc)

        return False, ""

    # ── Information Disclosure ─────────────────────────────────────────────

    async def test_server_version(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Check for server version disclosure in headers."""
        try:
            response = await page.goto(base_url, wait_until="domcontentloaded")
            server = response.headers.get("server", "")
            x_powered = response.headers.get("x-powered-by", "")

            if server and any(v in server.lower() for v in ["apache", "nginx", "iis"]):
                return True, f"Server version disclosed: {server}"

            if x_powered:
                return True, f"X-Powered-By disclosed: {x_powered}"

        except Exception as _exc:
            _log.warning('test_server_version failed: %s', _exc)

        return False, ""

    async def test_error_disclosure(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Check if error pages reveal stack traces."""
        error_indicators = [
            "Traceback (most recent call last)",
            "Stack Trace:",
            "at line",
            "Exception in thread",
            "Fatal error",
        ]

        try:
            # Try to trigger error pages
            error_urls = [
                f"{base_url}/nonexistent-page-12345",
                f"{base_url}/api/nonexistent-endpoint",
                f"{base_url}/?error=trigger",
            ]

            for url in error_urls:
                await page.goto(url, wait_until="domcontentloaded")
                content = await page.content()

                for indicator in error_indicators:
                    if indicator.lower() in content.lower():
                        return True, f"Error disclosure at {url}: {indicator}"

        except Exception as _exc:
            _log.warning('test_error_disclosure failed: %s', _exc)

        return False, ""

    # ── Directory Traversal ────────────────────────────────────────────────

    async def test_directory_traversal(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Test for directory traversal via path manipulation."""
        payloads = [
            "../../../etc/passwd",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc/passwd",
        ]

        traversal_indicators = [
            "root:x:0:0",
            "/bin/bash",
            "/bin/sh",
            "[boot loader]",
        ]

        for payload in payloads:
            try:
                test_urls = [
                    f"{base_url}/file?path={payload}",
                    f"{base_url}/download?file={payload}",
                    f"{base_url}/view?path={payload}",
                ]

                for url in test_urls:
                    await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                    content = await page.content()

                    for indicator in traversal_indicators:
                        if indicator in content:
                            return True, f"Directory traversal at {url}: {indicator}"

            except Exception:
                continue

        return False, ""

    # ── CSRF Tests ─────────────────────────────────────────────────────────

    async def test_csrf_token(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Check for missing CSRF tokens in forms."""
        try:
            await page.goto(base_url, wait_until="domcontentloaded")

            # Find all forms
            forms = await page.query_selector_all("form")

            for _i, form in enumerate(forms):
                # Check for CSRF token fields
                csrf_inputs = await form.query_selector_all(
                    'input[name*="csrf"], input[name*="token"], input[name="_token"]'
                )

                method = await form.get_attribute("method") or "GET"
                if method.upper() == "POST" and not csrf_inputs:
                    action = await form.get_attribute("action") or "unknown"
                    return True, f"Form at {action} missing CSRF token"

        except Exception as _exc:
            _log.warning('test_csrf_token failed: %s', _exc)

        return False, ""

    # ── Endpoint Discovery (from DASTScanner) ──────────────────────────────

    async def _discover_endpoints(self, base_url: str) -> list[str]:
        """Discover endpoints by crawling the app (from DASTScanner)."""
        import socket
        endpoints = set()
        endpoints.add(base_url)

        for path in COMMON_ENDPOINT_PATHS:
            url = f"{base_url}{path}"
            try:
                # Quick TCP check first
                try:
                    with socket.create_connection(("127.0.0.1", 80), timeout=1):
                        pass
                except Exception:
                    pass  # Can't check easily without page context

                # Use page context for actual check
                async with self._temp_page() as page:
                    resp = await page.goto(url, wait_until="domcontentloaded", timeout=5000)
                    if resp and resp.status < 400:
                        endpoints.add(url)
                        # Extract links from page
                        links = await page.eval_on_selector_all(
                            "a[href]",
                            "els => els.map(e => e.href)",
                        )
                        for link in links:
                            if link.startswith(base_url):
                                endpoints.add(link)
            except Exception as _exc:
                _log.debug('_discover_endpoints failed: %s', _exc)

        return list(endpoints)[:50]  # cap at 50 endpoints

    async def _temp_page(self):
        """Create a temporary page for endpoint discovery."""
        from patchi.core.testing.live_v2.browser_pool import BrowserPool
        pool = BrowserPool()
        await pool.initialize()
        page = await pool.get_page()
        return page

    # ── Auth Bypass Tests (from DASTScanner) ──────────────────────────────

    async def test_auth_bypass(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Test for authentication bypass on protected pages."""
        try:
            resp = await page.goto(base_url, wait_until="domcontentloaded", timeout=5000)
            if not resp:
                return False, ""

            content = await page.content()
            has_login = bool(await page.query_selector("input[type=password]"))
            has_protected = any(
                kw in content.lower()
                for kw in AUTH_BYPASS_KEYWORDS
            )

            if has_protected and not has_login:
                # Page has protected content but no login form — possible bypass
                return True, f"Auth bypass: Protected content accessible without authentication at {base_url}"

        except Exception as e:
            _log.debug("Auth bypass test failed: %s", e)

        return False, ""

    # ── Open Redirect Tests (from DASTScanner) ──────────────────────────────

    async def test_open_redirect(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Test for open redirect vulnerabilities."""
        for payload in OPEN_REDIRECT_PAYLOADS:
            try:
                test_url = f"{base_url}?redirect={payload}"
                resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=5000)
                if resp and page.url.startswith("http"):
                    current = page.url
                    if "evil.com" in current:
                        return True, f"Open redirect at {test_url}: Redirected to {current}"

            except Exception:
                continue

        return False, ""

    # ── Additional Security Headers (from DASTScanner) ──────────────────────

    async def test_additional_headers(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Check for additional missing security headers."""
        try:
            resp = await page.goto(base_url, wait_until="domcontentloaded")
            if not resp:
                return False, ""

            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, expected_value, message, severity in ADDITIONAL_HEADER_CHECKS:
                if header not in headers:
                    return True, message
                elif expected_value and headers[header] != expected_value:
                    return True, f"{header} = {headers[header]} (expected {expected_value})"

        except Exception as e:
            _log.debug("Additional headers test failed: %s", e)

        return False, ""

    # ── Info Disclosure Stack Trace (from DASTScanner) ──────────────────────

    async def test_stack_trace_disclosure(
        self, page: Any, base_url: str, screenshot_mgr: Any
    ) -> tuple[bool, str]:
        """Check if error pages reveal stack traces."""
        try:
            error_urls = [
                f"{base_url}/nonexistent-page-12345",
                f"{base_url}/api/nonexistent-endpoint",
                f"{base_url}/?error=trigger",
            ]

            for url in error_urls:
                await page.goto(url, wait_until="domcontentloaded")
                content = await page.content()

                for indicator in INFO_DISCLOSURE_INDICATORS:
                    if indicator.lower() in content.lower():
                        return True, f"Stack trace disclosure at {url}: {indicator}"

        except Exception as _exc:
            _log.warning('test_stack_trace_disclosure failed: %s', _exc)

        return False, ""

    # ── Helper Methods ─────────────────────────────────────────────────────

    def _detect_target(self, root) -> str | None:
        """Detect the target URL for testing."""
        import socket

        # Try common ports
        ports = [1612, 8000, 3000, 8080, 80]

        for port in ports:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return f"http://127.0.0.1:{port}"
            except (ConnectionRefusedError, OSError):
                continue

        # Check if there's a web server in the config
        try:
            from patchi.core import config as cfg

            config = cfg.load(root)
            web_config = config.get("web", {})
            host = web_config.get("host", "127.0.0.1")
            port = web_config.get("port", 1612)
            return f"http://{host}:{port}"
        except Exception as _exc:
            _log.warning('_detect_target failed: %s', _exc)

        return None


# Register the agent
register(DASTAgent)
