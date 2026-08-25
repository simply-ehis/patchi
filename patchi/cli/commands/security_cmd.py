"""
`p security` — Run security scans against the project.

Usage:
  p security                 — run all defensive security agents (27+ agents)
  p security taint           — taint analysis only
  p security secrets         — secret/credential scan only
  p security config          — Semgrep SAST scan only
  p security headers         — HTTP security header audit
  p security ratelimit       — rate limit coverage audit
  p security cors            — CORS configuration audit
  p security deps            — dependency CVE check
  p security probe           — offensive probing (requires dev_mode=true)
  p security jwt             — JWT implementation analysis
  p security sensitive       — PII and credential exposure scan
  p security auth            — authentication and session audit
  p security ssrf            — SSRF vulnerability analysis
  p security injection       — SQLi, XSS, command injection, path traversal
  p security authz           — authorization bypass, IDOR, privilege escalation
  p security crypto          — weak crypto, hardcoded keys, PRNG issues
  p security network         — SSL/TLS config, cipher suites, HTTPS enforcement
  p security privacy         — PII handling, GDPR/CCPA, consent mechanisms
  p security depvuln         — multi-ecosystem dependency CVE check
  p security compliance      — PCI DSS, HIPAA, GDPR, SOX compliance
  p security secrets_guard   — pre-apply secrets gate, .env/docker/K8s scanning
  p security supply          — supply chain: typosquatting, pinning, 7 ecosystems
  p security iac             — IaC: Dockerfile, docker-compose, K8s, Terraform
  p security container       — container image CVE scanning (Trivy)
  p security policy          — YAML/JSON policy enforcement (SOC2, HIPAA, PCI-DSS)
  p security cve             — OSV API CVE queries for npm/PyPI
  p security redteam         — attack surface analysis, vulnerable patterns
  p security precheck        — Layer 0: instant banned-API + lint checks
  p security runtime         — runtime header, TLS, method tampering (requires app_url)
  p security appmap          — crawl live app, map pages/forms/entry points
  p security browsertest     — Playwright XSS/SQLi/auth bypass testing
  p security evidence        — screenshot/video evidence capture
  p security blast           — blast radius analysis for proposed fixes
  p security governance      — action logging + policy gate
  p security history         — scan history + analytics
  p security report          — comprehensive security report (with orchestrator)
  p security cdn             — CDN/edge cache security analysis
  p security dns             — DNS security analysis
  p security emailauth       — email authentication (SPF/DKIM/DMARC) analysis
  p security push            — push notification security (FCM/APNs) analysis
  p security saml            — SAML/SSO security analysis
  p security secrets_runtime — secrets runtime management analysis
  p security mesh            — service mesh security (Istio/Linkerd) analysis
  p security k8s             — Kubernetes cluster hardening analysis
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.cli.display.live_progress import LiveProgress
from patchi.core import memory as mem
from patchi.core.config import require_project_root

_MAPS_DIR = Path(__file__).resolve().parent

import logging

_log = logging.getLogger("patchi.cli.security_cmd")

def _load_maps() -> tuple[dict[str, str], list[str]]:
    """Load security agent mapping data from external JSON config."""
    maps_file = _MAPS_DIR / "agent_maps.json"
    try:
        data = json.loads(maps_file.read_text(encoding="utf-8"))
        sec = data["security"]
        return sec["scan_types"], sec["defensive_agents"]
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        con.print(f"[yellow]Warning: could not load agent_maps.json: {e}[/yellow]")
        return {}, []

_AGENT_MAP, _DEFENSIVE_AGENTS = _load_maps()

def run(
    scan_type: str | None = None,
    area: str | None = None,
    root: Path | None = None,
    policy_file: str | None = None,
) -> None:
    """Entry point for `p security [type] [area]`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # Import agents to trigger registration
    import patchi.core.security.security_agents  # noqa: F401
    from patchi.core import config as cfg
    from patchi.core.agents.base import AgentGroup, AgentInput, list_agents

    try:
        config = cfg.load(r)
    except Exception as e:
        _log.warning("run failed: %s", e)
        config = {}

    brain = mem.get_brain(r)
    project_purpose = brain.get("project_purpose", "")
    project_domain = brain.get("project_domain", "")
    project_context = brain.get("project_context", {})
    active_domains = brain.get("active_security_domains", [])
    all_agents = {a.name: a for a in list_agents(AgentGroup.SECURITY)}

    # Determine which agents to run
    if scan_type is None:
        # All defensive agents
        to_run = [all_agents[n] for n in _DEFENSIVE_AGENTS if n in all_agents]
    else:
        agent_name = _AGENT_MAP.get(scan_type.lower())
        if not agent_name or agent_name not in all_agents:
            con.print(f"[red]Unknown scan type: {scan_type!r}[/red]")
            con.print(f"[dim]Valid: {', '.join(_AGENT_MAP.keys())}[/dim]")
            return
        to_run = [all_agents[agent_name]]

    if not to_run:
        con.print("[red]No security agents available.[/red]")
        return

    con.print()
    label = f" [dim]→ {area}[/dim]" if area else ""
    type_label = scan_type or "full"
    con.print(
        f"[bold #C8621A]Security scan ({type_label}){label}[/bold #C8621A]  "
        f"[dim]{len(to_run)} agent(s)[/dim]"
    )
    con.print()

    scope = _scope_from_area(r, area)

    if policy_file and scan_type == "policy":
        config["policy_file"] = policy_file

    results = []
    lp = LiveProgress(con, title=f"Security scan ({type_label})")
    lp.start()
    for agent_cls in to_run:
        short_name = agent_cls.name.replace("Agent", "").replace("Auditor", "")
        lp.set_progress(len(results) + 1, len(to_run), short_name)
        lp.log(f"  {short_name}…")
        lp.update()

        inp = AgentInput(
            root=r,
            scope=scope,
            brain=brain,
            config=config,
            purpose=project_purpose,
            domain=project_domain,
            context=project_context,
            active_domains=active_domains,
            on_message=lambda n, msg, s: (lp.log(f"    {msg}", s), lp.update()),
        )
        result = agent_cls().run(inp)
        from patchi.core.security.pattern_context import suppress_findings

        suppress_findings(result)
        results.append(result)

        total_findings = sum(r.finding_count for r in results)
        lp.set_findings(total_findings)

        # Show top findings inline
        if result.findings:
            for f in result.findings[:2]:
                sev_color = {"critical": "bold red", "high": "red", "medium": "yellow"}.get(
                    f.severity.value, "dim"
                )
                lp.log(f"    ! [{f.severity.value}] {f.message[:70]}", sev_color)
            if len(result.findings) > 2:
                lp.log(f"    \u2026 and {len(result.findings) - 2} more", "dim")

        lp.update()

        # Persist findings to scan_results memory
        try:
            mem.save_scan_result(
                agent_cls.name,
                {
                    "status": result.status.value,
                    "duration_ms": result.duration_ms,
                    "finding_count": result.finding_count,
                    "files_scanned": result.files_scanned,
                    "findings": [f.to_dict() for f in result.findings],
                    **{
                        k: v
                        for k, v in result.data.items()
                        if isinstance(v, (str, int, float, bool, list))
                    },
                },
                r,
            )
        except Exception as e:
            _log.warning("run failed: %s", e)

    total = sum(r.finding_count for r in results)
    lp.stop(summary=f"{len(results)} agents - {total} findings")
    _show_results(results)

def run_security(args) -> None:
    """Namespace-shaped entry for the CLI registry (self-routing).

    The framework passes the whole parsed Namespace; this replicates the exact
    routing the legacy main.py ladder did before the migration, so `p security`
    keeps the same behavior for every `type` value (including `report`).
    """
    scan_type = getattr(args, "type", None)
    if scan_type == "report":
        run_report()
    else:
        run(
            scan_type=scan_type,
            area=getattr(args, "area", None),
            policy_file=getattr(args, "policy", None),
        )

def run_report(root: Path | None = None) -> None:
    """Entry point for `p security report`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    import patchi.core.security.security_agents  # noqa: F401
    from patchi.core import config as cfg
    from patchi.core.agents.base import AgentGroup, AgentInput, list_agents

    try:
        config = cfg.load(r)
    except Exception as e:
        _log.warning("run_report failed: %s", e)
        config = {}

    brain = mem.get_brain(r)
    project_purpose = brain.get("project_purpose", "")
    project_domain = brain.get("project_domain", "")
    project_context = brain.get("project_context", {})
    active_domains = brain.get("active_security_domains", [])
    all_agents = {a.name: a for a in list_agents(AgentGroup.SECURITY)}

    con.print()
    con.print("[bold #C8621A]Generating comprehensive security report…[/bold #C8621A]")
    con.print()

    # Run all defensive agents
    defensive = [all_agents[n] for n in _DEFENSIVE_AGENTS if n in all_agents]
    results = []

    lp = LiveProgress(con, title="Security report")
    lp.start()
    for agent_cls in defensive:
        short_name = agent_cls.name.replace("Agent", "").replace("Auditor", "")
        lp.set_progress(len(results) + 1, len(defensive), short_name)
        lp.log(f"  {short_name}…")
        lp.update()
        inp = AgentInput(root=r, scope=[], brain=brain, config=config, purpose=project_purpose, domain=project_domain, context=project_context, active_domains=active_domains, on_message=lambda n, msg, s: (lp.log(f"    {msg}", s), lp.update()))
        result = agent_cls().run(inp)
        from patchi.core.security.pattern_context import suppress_findings

        suppress_findings(result)
        results.append(result)
        total_findings = sum(r.finding_count for r in results)
        lp.set_findings(total_findings)
        if result.findings:
            for f in result.findings[:2]:
                sev_color = {"critical": "bold red", "high": "red", "medium": "yellow"}.get(f.severity.value, "dim")
                lp.log(f"    ! [{f.severity.value}] {f.message[:70]}", sev_color)
        lp.update()

    total = sum(r.finding_count for r in results)
    lp.stop(summary=f"{len(results)} agents - {total} findings")

    # Run SecurityOrchestrator for deduplication and correlation
    from patchi.core.security.orchestrator import SecurityOrchestrator

    orch = SecurityOrchestrator()
    report = orch.correlate(results)

    # Aggregate results
    total_findings = report.total_findings
    by_severity = report.by_severity

    all_clean = total_findings == 0

    # Summary panel
    if all_clean:
        con.print(
            Panel(
                "[bold #4ADE80]No security issues found across all agents.[/bold #4ADE80]",
                border_style="#4ADE80",
                padding=(0, 1),
            )
        )
    else:
        summary_parts = []
        if by_severity["critical"]:
            summary_parts.append(f"[#FF4D6D]{by_severity['critical']} critical[/#FF4D6D]")
        if by_severity["high"]:
            summary_parts.append(f"[#FF8C42]{by_severity['high']} high[/#FF8C42]")
        if by_severity["medium"]:
            summary_parts.append(f"[#FACC15]{by_severity['medium']} medium[/#FACC15]")
        if by_severity["low"]:
            summary_parts.append(f"[#4ADE80]{by_severity['low']} low[/#4ADE80]")

        con.print(
            Panel(
                f"[bold #FF4D6D]{total_findings} security findings[/bold #FF4D6D]\n"
                f"  {', '.join(summary_parts)}",
                border_style="#FF4D6D" if by_severity["critical"] else "#FACC15",
                padding=(0, 1),
            )
        )

    # Per-agent breakdown
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Agent", style="bold #F2EDD6", width=25)
    table.add_column("Status", width=10)
    table.add_column("Critical", justify="right", width=9)
    table.add_column("High", justify="right", width=7)
    table.add_column("Medium", justify="right", width=8)
    table.add_column("Low", justify="right", width=6)
    table.add_column("Info", justify="right", width=6)

    for r in results:
        by_sev = r.by_severity
        crit = len(by_sev.get("critical", []))
        high = len(by_sev.get("high", []))
        med = len(by_sev.get("medium", []))
        low = len(by_sev.get("low", []))
        info = len(by_sev.get("info", []))

        status_color = (
            "#FF4D6D"
            if crit > 0
            else ("#FF8C42" if high > 0 else ("#FACC15" if med > 0 else "#4ADE80"))
        )
        status_label = "issues" if r.finding_count > 0 else "clean"

        table.add_row(
            r.agent_name.replace("Agent", "").replace("Auditor", ""),
            Text(status_label, style=status_color),
            Text(str(crit), style="#FF4D6D bold") if crit else "—",
            Text(str(high), style="#FF8C42") if high else "—",
            str(med) if med else "—",
            str(low) if low else "—",
            str(info) if info else "—",
        )

    con.print(table)

    # Orchestrator correlation summary
    if report.correlation_count > 0:
        con.print()
        con.print(
            f"[bold #C8621A]Orchestrator:[/bold #C8621A] "
            f"[dim]{report.correlation_count} finding(s) confirmed by multiple agents[/dim]"
        )

    # Top correlated findings
    correlated = [c for c in report.findings if len(c.confirmed_by) > 1]
    if correlated:
        con.print()
        con.print("[bold #FF8C42]Multi-agent confirmed findings:[/bold #FF8C42]")
        for cf in correlated[:5]:
            sev_color = cf.finding.severity.color()
            loc = f"{cf.finding.file}:{cf.finding.line}" if cf.finding.line else cf.finding.file
            con.print(
                f"  [{sev_color}]●[/{sev_color}] [dim]{loc}[/dim] "
                f"[dim]({', '.join(cf.confirmed_by[:3])})[/dim]"
            )
            con.print(f"    {cf.finding.message[:80]}")

    # OWASP distribution
    if report.by_owasp:
        con.print()
        con.print("[bold #C8621A]OWASP Top 10 Distribution:[/bold #C8621A]")
        for owasp_cat, count in sorted(report.by_owasp.items(), key=lambda x: -x[1]):
            con.print(f"  [dim]{count}[/dim] {owasp_cat}")

    # Critical and high findings detail
    for r in results:
        critical_high = [f for f in r.findings if f.severity.value in ("critical", "high")]
        if not critical_high:
            continue

        con.print()
        agent_label = r.agent_name.replace("Agent", "").replace("Auditor", "")
        con.print(f"[bold #FF4D6D]{agent_label} — critical/high findings:[/bold #FF4D6D]")

        for finding in critical_high[:10]:
            sev_color = "#FF4D6D" if finding.severity.value == "critical" else "#FF8C42"
            loc = f"{finding.file}:{finding.line}" if finding.line else finding.file
            con.print(f"  [{sev_color}]●[/{sev_color}] [dim]{loc}[/dim]")
            con.print(f"    {finding.message[:80]}")
            if finding.suggestion:
                con.print(f"    [dim italic]{finding.suggestion[:80]}[/dim italic]")

    con.print()
    con.print("[dim]Run [bold]p fix[/bold] to apply security fixes.[/dim]")
    con.print()

    # Save report to memory
    try:
        mem.save_scan_result(
            "SecurityReport",
            {
                "status": "done",
                "total_findings": total_findings,
                "by_severity": by_severity,
                "agents_run": len(results),
                "correlation_count": report.correlation_count,
                "timestamp": time.time(),
            },
            r,
        )
    except Exception as e:
        _log.warning("run_report failed: %s", e)

def _show_results(results: list) -> None:
    from patchi.core.agents.base import AgentStatus

    all_clean = all(r.finding_count == 0 for r in results if r.status not in (AgentStatus.SKIPPED,))

    con.print()

    if all_clean:
        con.print(
            Panel(
                "[bold #4ADE80]No security issues found.[/bold #4ADE80]",
                border_style="#4ADE80",
                padding=(0, 1),
            )
        )
        for r in results:
            if r.status == AgentStatus.SKIPPED:
                reason = r.data.get("skip_reason", "skipped")
                con.print(
                    f"  [dim]○ {r.agent_name.replace('Agent', '').replace('Auditor', '')}:"
                    f" {reason[:60]}[/dim]"
                )
            else:
                con.print(
                    f"  [dim]✓ {r.agent_name.replace('Agent', '').replace('Auditor', '')}: "
                    f"clean ({r.files_scanned} files, {r.duration_ms}ms)[/dim]"
                )
        con.print()
        return

    # Summary table
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Agent", style="bold #F2EDD6", width=22)
    table.add_column("Status", width=10)
    table.add_column("Critical", justify="right", width=9)
    table.add_column("High", justify="right", width=7)
    table.add_column("Medium", justify="right", width=8)
    table.add_column("Low", justify="right", width=6)
    table.add_column("ms", justify="right", width=7)

    for r in results:
        if r.status == AgentStatus.SKIPPED:
            table.add_row(
                r.agent_name.replace("Agent", "").replace("Auditor", ""),
                Text("skipped", style="dim"),
                "—",
                "—",
                "—",
                "—",
                str(r.duration_ms),
            )
            continue

        by_sev = r.by_severity
        crit = len(by_sev.get("critical", []))
        high = len(by_sev.get("high", []))
        med = len(by_sev.get("medium", []))
        low = len(by_sev.get("low", []))

        status_color = "#FF4D6D" if (crit + high) > 0 else ("#FACC15" if med > 0 else "#4ADE80")
        status_label = "issues" if r.finding_count > 0 else "clean"

        table.add_row(
            r.agent_name.replace("Agent", "").replace("Auditor", ""),
            Text(status_label, style=status_color),
            Text(str(crit), style="#FF4D6D bold") if crit else "—",
            Text(str(high), style="#FF8C42") if high else "—",
            str(med) if med else "—",
            str(low) if low else "—",
            str(r.duration_ms),
        )

    con.print(table)

    # Critical and high findings detail
    for r in results:
        critical_high = [f for f in r.findings if f.severity.value in ("critical", "high")]
        if not critical_high:
            continue

        con.print()
        agent_label = r.agent_name.replace("Agent", "").replace("Auditor", "")
        con.print(f"[bold #FF4D6D]{agent_label} — critical/high findings:[/bold #FF4D6D]")

        for finding in critical_high[:6]:
            sev_color = "#FF4D6D" if finding.severity.value == "critical" else "#FF8C42"
            loc = f"{finding.file}:{finding.line}" if finding.line else finding.file
            con.print(f"  [{sev_color}]●[/{sev_color}] [dim]{loc}[/dim]")
            con.print(f"    {finding.message[:80]}")
            if finding.suggestion:
                con.print(f"    [dim italic]{finding.suggestion[:80]}[/dim italic]")

    con.print()
    con.print("[dim]Run [bold]p fix[/bold] to apply security fixes.[/dim]")
    con.print()

def _scope_from_area(root: Path, area: str | None) -> list[str]:
    if not area:
        return []
    area_path = root / area
    if area_path.is_file():
        return [area]
    if area_path.is_dir():
        return [
            str(p.relative_to(root))
            for p in area_path.rglob("*")
            if p.is_file() and p.suffix in (".py", ".js", ".ts", ".php")
        ]
    return []
