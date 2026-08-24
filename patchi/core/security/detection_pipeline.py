"""
Detection Pipeline — orchestrates the full pipeline:
  SecurityReport -> ConfidenceGate -> Layer2Orchestrator -> GatedReport

Stages:
   1. Gate every finding through ConfidenceGate
   2. Run Sigma rule matching against findings (context-aware correlation)
   3. Partition by routing tier (defend / ai_analyze / human_review / discard)
   4. Send medium-confidence findings to Layer 2 AI for confirmation
   5. Promote AI-confirmed findings to 'defend', dismiss dismissed ones
   6. Return final GatedReport
"""

from __future__ import annotations

from pathlib import Path

from patchi.core.security.confidence_gate import ConfidenceGate
from patchi.core.security.gated_finding import GatedReport
from patchi.core.security.layer2_orchestrator import Layer2Orchestrator
from patchi.core.security.orchestrator import SecurityReport


class DetectionPipeline:
    """Wires ConfidenceGate + Layer2Orchestrator + Sigma into a single pipeline."""

    def __init__(self, root: Path, config: dict | None = None, component_types=None):
        self.root = root
        self.config = config or {}
        self.gate = ConfidenceGate(root, config)
        self.layer2 = Layer2Orchestrator(root, config)
        self._sigma_set = None
        self._domain_loader = None
        self._component_types = component_types

    def _get_sigma_set(self):
        if self._sigma_set is None:
            from patchi.core.detector.sigma_engine import SigmaRuleSet
            sigma_dir = self.root / (self.config.get("pipeline", {}).get("sigma_rules_dir", ".patchi/sigma"))
            self._sigma_set = SigmaRuleSet.load_directory(sigma_dir)
            if self._sigma_set.count > 0:
                import logging
                logging.getLogger("patchi.detection").info("Loaded %d Sigma rules from %s", self._sigma_set.count, sigma_dir)
        return self._sigma_set

    def _findings_to_events(self, findings):
        from patchi.core.detector.event import Event, EventSeverity, EventSource
        events = []
        for cf in findings:
            sev_map = {"critical": EventSeverity.CRITICAL, "high": EventSeverity.HIGH, "medium": EventSeverity.MEDIUM, "low": EventSeverity.LOW}
            event = Event(
                title=cf.finding.message[:200] if cf.finding.message else cf.finding.type,
                severity=sev_map.get(cf.finding.severity, EventSeverity.INFO),
                source=EventSource.SECURITY_SCAN,
                source_details={
                    "file": cf.finding.file or "",
                    "line": cf.finding.line or 0,
                    "agent": cf.finding.agent or "",
                    "cwe": cf.finding.cwe or "",
                    "category": "security_scan",
                },
            )
            events.append(event)
        return events

    def process(self, report: SecurityReport) -> GatedReport:
        if not report.findings:
            return GatedReport(
                stats={"total": 0, "defend": 0, "ai_analyze": 0, "human_review": 0, "discarded": 0}
            )

        # Stage 1: Gate all findings
        gated_list = [self.gate.gate(cf) for cf in report.findings]

        # Stage 1a: Domain taxonomy matching — enrich findings with ASVS/domain context
        try:
            from patchi.core.security.domain_loader import DomainLoader
            if self._domain_loader is None:
                self._domain_loader = DomainLoader(
                    self.root, component_types=self._component_types
                )
            loader = self._domain_loader
            for gf in gated_list:
                ctrl_matches = loader.match_finding_to_controls(
                    gf.finding.type, gf.finding.file or "", gf.finding.message
                )
                if ctrl_matches:
                    gf.domain_controls = [
                        {"control_id": c.control_id, "name": c.name, "severity": c.severity}
                        for c in ctrl_matches
                    ]
                    playbook = loader.get_playbook(ctrl_matches[0].control_id)
                    if playbook:
                        gf.playbook_ref = playbook.control_id
                        gf.fix_strategy = playbook.fix_strategy
        except Exception as e:
            import logging
            logging.getLogger("patchi.detection").warning("Domain taxonomy enrichment failed: %s", e)

        # Stage 1b: Sigma rule matching — boosts confidence for known attack patterns
        sigma_set = self._get_sigma_set()
        if sigma_set and sigma_set.count > 0:
            events = self._findings_to_events(report.findings)
            for event in events:
                matches = sigma_set.match(event)
                for match in matches:
                    for gf in gated_list:
                        if match.technique_id and str(match.technique_id) != "unknown":
                            tid = match.technique_id.value if hasattr(match.technique_id, 'value') else str(match.technique_id)
                            if tid in gf.finding.message or \
                               (gf.finding.cwe and tid in gf.finding.cwe):
                                gf.confidence_tier = "high"
                                gf.routing = "defend"
                                gf.routing_reason = f"Sigma rule match: {match.rule_name} ({tid})"
                                gf.sigma_matches = getattr(gf, 'sigma_matches', []) + [match]

        # Stage 2: Partition
        high = [g for g in gated_list if g.routing == "defend"]
        medium = [g for g in gated_list if g.routing == "ai_analyze"]
        low = [g for g in gated_list if g.routing == "human_review"]
        discarded = [g for g in gated_list if g.routing == "discard"]

        # Stage 3: AI analysis for medium-confidence findings
        if medium:
            ai_results = self.layer2.analyze(medium)
            for gf, ai_res in zip(medium, ai_results):
                if ai_res.confirmed:
                    gf.confidence_tier = "high"
                    gf.routing = "defend"
                    gf.routing_reason = f"AI confirmed: {ai_res.summary}"
                    high.append(gf)
                else:
                    gf.routing = "discard"
                    gf.routing_reason = f"AI dismissed: {ai_res.summary}"
                    discarded.append(gf)

        return GatedReport(
            findings=high + [g for g in medium if g.routing == "ai_analyze"] + low + discarded,
            stats={
                "total": len(gated_list),
                "defend": len(high),
                "ai_analyze": len([g for g in medium if g.routing == "ai_analyze"]),
                "human_review": len(low),
                "discarded": len(discarded),
            },
        )
