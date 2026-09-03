"""ConsoleLoggingAgent §p test — background console/pageerror capture.

Runs automatically when `p test` is active (Group.TEST), never under `p scan`.
Attaches Playwright console + pageerror listeners on every discovered route
(via shared open_page helper) and tails the app launcher log, so JS runtime
noise is captured even on pages other testers skip. Findings are console-error
clusters; raw traces go to result.data for brain/verify.py merging.
"""

from __future__ import annotations

import logging
from collections import Counter

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

_log = logging.getLogger("patchi.agents.console_logging")


@register
class ConsoleLoggingAgent(BaseAgent):
    group = AgentGroup.TEST
    name = "ConsoleLoggingAgent"
    description = "Background console/pageerror capture across routes + app log tail"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError:
            self.skip(result, "playwright not installed — pip install playwright")
            return

        from patchi.core.testing._browser import discover_routes, find_server, open_page

        base_url = find_server(inp.root, inp.config, inp.extra)
        if not base_url:
            self.skip(result, "no running server found — start `p web` (default :1612)")
            return

        routes = discover_routes(inp.config, inp.extra)
        if not routes:
            self.skip(result, "no routes discovered")
            return

        from patchi.core.brain.trace_log import trace_agent

        console_errors: list[str] = []
        page_errors: list[str] = []
        pages_tested = 0
        error_pages = 0

        with trace_agent(self.name, root=inp.root) as trace:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                try:
                    for page_path in routes[:15]:
                        ps = open_page(browser, f"{base_url}{page_path}")
                        try:
                            if ps.status and ps.status >= 400:
                                error_pages += 1
                                continue
                            for ce in ps.console_errors:
                                console_errors.append(f"{page_path} :: {ce[:200]}")
                            for pe in ps.page_errors:
                                page_errors.append(f"{page_path} :: {pe[:200]}")
                            pages_tested += 1
                        finally:
                            ps.page.close()
                finally:
                    browser.close()

            # Tail the app launcher log for server-side noise
            app_log_lines: list[str] = []
            log_path = inp.root / ".patchi" / "launcher" / "app.log"
            try:
                if log_path.exists():
                    text = log_path.read_text(encoding="utf-8", errors="replace")
                    app_log_lines = [ln for ln in text.splitlines() if ln.strip()][-50:]
            except OSError as exc:
                _log.debug("app log tail failed: %s", exc)

            trace.files_scanned = pages_tested

            # Cluster console errors so one noisy library = one finding
            clusters = Counter()
            for entry in console_errors:
                route, _, msg = entry.partition(" :: ")
                key = (route, msg[:80])
                clusters[key] += 1
            for (route, msg), count in sorted(clusters.items(), key=lambda kv: -kv[1])[:10]:
                text = msg[:160] or "empty error text"
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="console_error",
                        severity=Severity.LOW if count == 1 else Severity.MEDIUM,
                        file=route,
                        message=f"Console error ×{count} on {route}: {text}",
                    )
                )
            for entry in page_errors[:10]:
                route, _, msg = entry.partition(" :: ")
                text = msg[:160] or "empty error text"
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="page_error",
                        severity=Severity.MEDIUM,
                        file=route,
                        message=f"Uncaught page error on {route}: {text}",
                    )
                )
            if error_pages:
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="console_error_pages",
                        severity=Severity.HIGH,
                        file="(all pages)",
                        message=f"{error_pages} page(s) HTTP ≥400 — console capture skipped",
                    )
                )
            if not console_errors and not page_errors and pages_tested > 0:
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="console_summary",
                        severity=Severity.INFO,
                        file="(all pages)",
                        message=f"Console clean: {pages_tested} pages, 0 console/page errors",
                    )
                )

            result.data["suite"] = {
                "runner": "console_logging",
                "pages_tested": pages_tested,
                "console_errors": console_errors[:10],
                "page_errors": page_errors[:10],
                "error_pages": error_pages,
                "app_log_tail": app_log_lines[-10:],
            }
            result.files_scanned = pages_tested
            trace.findings = len(result.findings)

        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE
