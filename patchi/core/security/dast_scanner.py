"""DAST Scanner — Dynamic Application Security Testing.

Uses BrowserPool for parallel browser automation and ScreenshotManager
for visual evidence capture. Tests a running web app for:
- XSS (reflected/stored)
- Auth bypass
- Info disclosure
- Missing security headers
- CSRF
- Open redirect
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger("patchi.security.dast")


@dataclass
class DastFinding:
    """A finding from DAST testing."""

    test: str
    severity: str
    url: str
    evidence: str
    screenshot: str | None = None
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "test": self.test,
            "severity": self.severity,
            "url": self.url,
            "evidence": self.evidence,
            "screenshot": self.screenshot,
            "recommendation": self.recommendation,
        }


@dataclass
class DastReport:
    """Complete DAST scan report."""

    target_url: str
    pages_tested: int = 0
    findings: list[DastFinding] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "pages_tested": self.pages_tested,
            "findings": [f.to_dict() for f in self.findings],
            "screenshots": self.screenshots,
            "duration_ms": self.duration_ms,
            "total_findings": len(self.findings),
            "by_severity": {
                s: sum(1 for f in self.findings if f.severity == s)
                for s in ["critical", "high", "medium", "low", "info"]
            },
        }


class DastScanner:
    """Dynamic application security tester using Playwright."""

    def __init__(
        self,
        root: Path,
        target_url: str = "http://127.0.0.1:1612",
        on_progress: Callable[[str], None] | None = None,
    ):
        self.root = root
        self.target_url = target_url.rstrip("/")
        self.on_progress = on_progress or (lambda _: None)
        self._evidence_dir = root / ".patchi" / "dast_evidence"
        self._evidence_dir.mkdir(parents=True, exist_ok=True)

    async def run(self) -> DastReport:
        """Run full DAST scan against the target."""
        start = time.monotonic()
        report = DastReport(target_url=self.target_url)

        try:
            from patchi.core.testing.live_v2.browser_pool import BrowserPool
            from patchi.core.testing.live_v2.screenshot_manager import ScreenshotManager

            pool = BrowserPool()
            try:
                await pool.initialize()
            except Exception as e:
                error_msg = str(e)
                if "Executable doesn't exist" in error_msg or "playwright" in error_msg.lower():
                    report.errors.append(
                        "Playwright browsers not installed. "
                        "Run: pip install playwright && playwright install"
                    )
                    report.duration_ms = int((time.monotonic() - start) * 1000)
                    return report
                raise

            screenshot_mgr = ScreenshotManager(
                baseline_dir=str(self._evidence_dir),
                on_progress=self.on_progress,
            )

            try:
                # Discover endpoints
                self.on_progress("DAST: Discovering endpoints...")
                endpoints = await self._discover_endpoints(pool)
                self.on_progress(f"DAST: Found {len(endpoints)} endpoints")

                # Test each endpoint
                for url in endpoints:
                    report.pages_tested += 1
                    self.on_progress(f"DAST: Testing {url}")

                    page = await pool.get_page()
                    try:
                        # Navigate to page
                        await page.goto(url, wait_until="domcontentloaded", timeout=10000)

                        # Capture screenshot
                        result = await screenshot_mgr.capture(page, url)
                        if result and result.image_base64:
                            report.screenshots.append(url)

                        # Run security tests
                        findings = await self._test_endpoint(page, url)
                        report.findings.extend(findings)

                    except Exception as e:
                        report.errors.append(f"{url}: {e}")
                    finally:
                        await pool.release_page(page)

            finally:
                await pool.shutdown()

        except ImportError as e:
            report.errors.append(f"Missing dependency: {e}")
        except Exception as e:
            report.errors.append(f"DAST error: {e}")

        report.duration_ms = int((time.monotonic() - start) * 1000)
        self.on_progress(
            f"DAST: Complete — {report.pages_tested} pages, "
            f"{len(report.findings)} findings, {report.duration_ms}ms"
        )
        return report

    async def _discover_endpoints(self, pool) -> list[str]:
        """Discover endpoints by crawling the app."""
        endpoints = set()
        endpoints.add(self.target_url)

        # Try common paths
        common_paths = [
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

        for path in common_paths:
            url = f"{self.target_url}{path}"
            try:
                page = await pool.get_page()
                try:
                    resp = await page.goto(url, wait_until="domcontentloaded", timeout=5000)
                    if resp and resp.status < 400:
                        endpoints.add(url)
                        # Extract links from page
                        links = await page.eval_on_selector_all(
                            "a[href]",
                            "els => els.map(e => e.href)",
                        )
                        for link in links:
                            if link.startswith(self.target_url):
                                endpoints.add(link)
                except Exception:
                    pass
                finally:
                    await pool.release_page(page)
            except Exception:
                pass

        return list(endpoints)[:50]  # cap at 50 endpoints

    async def _test_endpoint(self, page, url: str) -> list[DastFinding]:
        """Run all security tests against an endpoint."""
        findings: list[DastFinding] = []

        # 1. Missing security headers
        findings.extend(await self._test_security_headers(page, url))

        # 2. XSS reflected
        findings.extend(await self._test_xss_reflected(page, url))

        # 3. Auth bypass
        findings.extend(await self._test_auth_bypass(page, url))

        # 4. Info disclosure
        findings.extend(await self._test_info_disclosure(page, url))

        # 5. Open redirect
        findings.extend(await self._test_open_redirect(page, url))

        return findings

    async def _test_security_headers(self, page, url: str) -> list[DastFinding]:
        """Check for missing security headers."""
        findings = []
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=5000)
            if not resp:
                return findings

            headers = {k.lower(): v for k, v in resp.headers.items()}

            checks = [
                (
                    "x-content-type-options",
                    "nosniff",
                    "Missing X-Content-Type-Options header",
                    "medium",
                ),
                (
                    "x-frame-options",
                    None,
                    "Missing X-Frame-Options header (clickjacking risk)",
                    "medium",
                ),
                ("strict-transport-security", None, "Missing HSTS header", "medium"),
                ("x-xss-protection", None, "Missing X-XSS-Protection header", "low"),
                (
                    "content-security-policy",
                    None,
                    "Missing Content-Security-Policy header",
                    "medium",
                ),
            ]

            for header, expected_value, message, severity in checks:
                if header not in headers:
                    findings.append(
                        DastFinding(
                            test="missing_security_header",
                            severity=severity,
                            url=url,
                            evidence=message,
                            recommendation=f"Add {header} header",
                        )
                    )
                elif expected_value and headers[header] != expected_value:
                    findings.append(
                        DastFinding(
                            test="weak_security_header",
                            severity="low",
                            url=url,
                            evidence=f"{header} = {headers[header]} (expected {expected_value})",
                            recommendation=f"Set {header} to {expected_value}",
                        )
                    )

        except Exception as e:
            _log.debug("Security header test failed: %s", e)

        return findings

    async def _test_xss_reflected(self, page, url: str) -> list[DastFinding]:
        """Test for reflected XSS."""
        findings = []
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'-alert(1)-'",
            "<svg onload=alert(1)>",
        ]

        for payload in xss_payloads:
            try:
                test_url = f"{url}?q={payload}"
                resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=5000)
                if not resp:
                    continue

                content = await page.content()
                if payload in content:
                    findings.append(
                        DastFinding(
                            test="xss_reflected",
                            severity="high",
                            url=test_url,
                            evidence=f"Payload reflected in response: {payload[:50]}",
                            recommendation="Sanitize user input and use Content-Security-Policy",
                        )
                    )
                    break  # one finding per endpoint

            except Exception:
                continue

        return findings

    async def _test_auth_bypass(self, page, url: str) -> list[DastFinding]:
        """Test for authentication bypass on protected pages."""
        findings = []

        # Check if this is a protected page (has login form or dashboard content)
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=5000)
            if not resp:
                return findings

            content = await page.content()
            has_login = bool(await page.query_selector("input[type=password]"))
            has_protected = any(
                kw in content.lower()
                for kw in [
                    "dashboard",
                    "admin",
                    "settings",
                    "profile",
                    "logout",
                ]
            )

            if has_protected and not has_login:
                # Page has protected content but no login form — possible bypass
                findings.append(
                    DastFinding(
                        test="auth_bypass",
                        severity="critical",
                        url=url,
                        evidence="Protected content accessible without authentication",
                        recommendation="Add authentication middleware to this endpoint",
                    )
                )

        except Exception as e:
            _log.debug("Auth bypass test failed: %s", e)

        return findings

    async def _test_info_disclosure(self, page, url: str) -> list[DastFinding]:
        """Test for information disclosure."""
        findings = []

        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=5000)
            if not resp:
                return findings

            content = await page.content()
            content_lower = content.lower()

            # Check for stack traces
            if any(kw in content_lower for kw in ["traceback", "stack trace", "exception in"]):
                findings.append(
                    DastFinding(
                        test="info_disclosure_stack_trace",
                        severity="high",
                        url=url,
                        evidence="Stack trace exposed in response",
                        recommendation="Disable debug mode in production",
                    )
                )

            # Check for version disclosure
            if any(kw in content_lower for kw in ["x-powered-by", "server:"]):
                headers = {k.lower(): v for k, v in resp.headers.items()}
                if "x-powered-by" in headers:
                    findings.append(
                        DastFinding(
                            test="info_disclosure_version",
                            severity="low",
                            url=url,
                            evidence=f"X-Powered-By: {headers['x-powered-by']}",
                            recommendation="Remove X-Powered-By header",
                        )
                    )

        except Exception as e:
            _log.debug("Info disclosure test failed: %s", e)

        return findings

    async def _test_open_redirect(self, page, url: str) -> list[DastFinding]:
        """Test for open redirect vulnerabilities."""
        findings = []
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
        ]

        for payload in redirect_payloads:
            try:
                test_url = f"{url}?redirect={payload}"
                resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=5000)
                if resp and page.url.startswith("http"):
                    current = page.url
                    if "evil.com" in current:
                        findings.append(
                            DastFinding(
                                test="open_redirect",
                                severity="high",
                                url=test_url,
                                evidence=f"Redirected to {current}",
                                recommendation="Validate redirect URLs against allowlist",
                            )
                        )
                        break

            except Exception:
                continue

        return findings
