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
from patchi.core.security.orchestrator import CorrelatedFinding, SecurityReport


def _as_correlated(finding) -> CorrelatedFinding:
    """Wrap a raw Finding as a single-agent CorrelatedFinding."""
    if isinstance(finding, CorrelatedFinding):
        return finding
    return CorrelatedFinding(
        finding=finding,
        confirmed_by=[getattr(finding, "agent", "") or "unknown"],
        composite_score=0.0,
    )


class DetectionPipeline:
    """Wires ConfidenceGate + Layer2Orchestrator + Sigma into a single pipeline."""

    def __init__(
        self, root: Path, config: dict | None = None,
        component_types=None, brain_context=None,
    ):
        self.root = root
        self.config = config or {}
        self.gate = ConfidenceGate(root, config)
        self.layer2 = Layer2Orchestrator(root, config)
        self._sigma_set = None
        self._domain_loader = None
        self._noise_filter = None
        self._component_types = component_types
        self._brain = brain_context  # BrainContext for context-aware classification
        # Pre-load DomainLoader in background to avoid blocking on first use
        self._domain_loader_future = None
        try:
            import concurrent.futures as _cf

            from patchi.core.security.domain_loader import DomainLoader
            pool = _cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="dl-pipeline")

            def _preload() -> DomainLoader:
                # Construct + force the (lazy) load in this background thread.
                _ldr = DomainLoader(root, component_types=component_types)
                _ldr.list_domains()  # parses + caches taxonomy off the hot path
                return _ldr

            self._domain_loader_future = pool.submit(_preload)
            pool.shutdown(wait=False)
        except Exception as _exc:
            logging.getLogger("patchi").debug('suppressed: %s', _exc)

    def _get_sigma_set(self):
        if self._sigma_set is None:
            from patchi.core.detector.sigma_engine import SigmaRuleSet

            sigma_dir = self.root / (
                self.config.get("pipeline", {}).get("sigma_rules_dir", ".patchi/sigma")
            )
            self._sigma_set = SigmaRuleSet.load_directory(sigma_dir)
            if self._sigma_set.count > 0:
                import logging

                logging.getLogger("patchi.detection").info(
                    "Loaded %d Sigma rules from %s", self._sigma_set.count, sigma_dir
                )
        return self._sigma_set

    def _findings_to_events(self, findings):
        from patchi.core.detector.event import Event, EventSeverity, EventSource

        events = []
        for cf in findings:
            sev_map = {
                "critical": EventSeverity.CRITICAL,
                "high": EventSeverity.HIGH,
                "medium": EventSeverity.MEDIUM,
                "low": EventSeverity.LOW,
            }
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

        # Stage 0: Noise filter — findings from tests/lockfiles/generated/docs
        # are severity-capped (or discarded) before scoring. This kills the
        # bulk of false-positive volume at the cheapest possible point.
        noise_stats = None
        try:
            from patchi.core.security.noise_filter import NoiseFilter

            if self._noise_filter is None:
                self._noise_filter = NoiseFilter(self.root, self.config)
            if self._noise_filter.enabled:
                kept, nf_report = self._noise_filter.apply(report.findings)
                noise_stats = nf_report.to_dict()
                gated_list = [self.gate.gate(_as_correlated(f)) for f in kept]
            else:
                gated_list = [self.gate.gate(cf) for cf in report.findings]
        except Exception as e:
            import logging

            logging.getLogger("patchi.detection").warning(
                "Noise filter failed (non-fatal, scanning all): %s", e
            )
            gated_list = [self.gate.gate(cf) for cf in report.findings]

        # Stage 1a: Domain taxonomy matching — enrich findings with ASVS/domain context
        try:
            # Use pre-loaded DomainLoader if available, else create new
            if self._domain_loader is None:
                if self._domain_loader_future is not None:
                    try:
                        self._domain_loader = self._domain_loader_future.result(timeout=0)
                    except Exception as _exc:
                        logging.getLogger("patchi").debug('suppressed: %s', _exc)
                if self._domain_loader is None:
                    from patchi.core.security.domain_loader import DomainLoader
                    self._domain_loader = DomainLoader(
                        self.root, component_types=self._component_types,
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

            logging.getLogger("patchi.detection").warning(
                "Domain taxonomy enrichment failed: %s", e
            )

        # Stage 1a½: Brain context — context-aware false-positive reduction
        if self._brain and self._brain.is_loaded():
            for gf in gated_list:
                fctx = self._brain.get_finding_context(
                    gf.finding.file or "", gf.finding.type, gf.finding.message
                )
                # Demote test fixture findings (they contain intentional vulns)
                if fctx["is_test_fixture"] and gf.routing == "defend":
                    gf.routing = "ai_analyze"
                    gf.routing_reason = (
                        f"Test fixture — demoted for AI review ({gf.routing_reason})"
                    )
                    gf.confidence_score = min(gf.confidence_score, 0.5)
                # Boost findings in critical directories
                if fctx["project_relevance"] == "high":
                    gf.confidence_score = min(1.0, gf.confidence_score + 0.1)
                # Add domain context to finding message for downstream use
                if fctx["domain_matches"]:
                    domains_str = ', '.join(fctx['domain_matches'][:3])
                    gf.routing_reason = (
                        f"[domains: {domains_str}] {gf.routing_reason}"
                    )

        # Stage 1b: Sigma rule matching — boosts confidence for known attack patterns
        sigma_set = self._get_sigma_set()
        if sigma_set and sigma_set.count > 0:
            events = self._findings_to_events(report.findings)
            for event in events:
                matches = sigma_set.match(event)
                for match in matches:
                    for gf in gated_list:
                        # Noise-capped findings are never Sigma-promoted:
                        # test fixtures etc. legitimately contain attack
                        # patterns and must not be re-escalated to defend.
                        if getattr(gf.finding, "noise_category", None):
                            continue
                        if match.technique_id and str(match.technique_id) != "unknown":
                            tid = (
                                match.technique_id.value
                                if hasattr(match.technique_id, "value")
                                else str(match.technique_id)
                            )
                            if tid in gf.finding.message or (
                                gf.finding.cwe and tid in gf.finding.cwe
                            ):
                                gf.confidence_tier = "high"
                                gf.routing = "defend"
                                gf.routing_reason = f"Sigma rule match: {match.rule_name} ({tid})"
                                gf.sigma_matches = getattr(gf, "sigma_matches", []) + [match]

        # Stage 2: Partition
        high = [g for g in gated_list if g.routing == "defend"]
        medium = [g for g in gated_list if g.routing == "ai_analyze"]
        low = [g for g in gated_list if g.routing == "human_review"]
        discarded = [g for g in gated_list if g.routing == "discard"]

        # Stage 3: AI analysis for medium-confidence findings
        if medium:
            ai_results = self.layer2.analyze(medium)
            for gf, ai_res in zip(medium, ai_results, strict=False):
                if ai_res.confirmed:
                    # Graded calibration: blend the model's confidence
                    # adjustment into the heuristic score, not just a binary
                    # yes/no. adjustment is roughly [-1, 1] -> map to [0, 1].
                    if ai_res.confidence_adjustment:
                        ai_conf = max(0.0, min(1.0, 0.5 + float(ai_res.confidence_adjustment) / 2))
                        recalc = self.gate.gate(_as_correlated(gf.finding), ai_confidence=ai_conf)
                        gf.confidence_score = recalc.confidence_score
                        if recalc.confidence_score >= 0.7:
                            gf.confidence_tier = "high"
                    gf.routing = "defend"
                    gf.routing_reason = (
                        f"AI confirmed ({gf.confidence_score:.2f}): {ai_res.summary}"
                    )
                    high.append(gf)
                else:
                    gf.routing = "discard"
                    gf.routing_reason = f"AI dismissed: {ai_res.summary}"
                    discarded.append(gf)

        # Stage 4: Noise learning loop — persist every rejected finding as a
        # known false positive so future scans pre-penalize (or, with
        # fp_auto_discard, drop it outright). This is what stops the same
        # noise from resurfacing thousands of times.
        try:
            learned = self.gate.learn_from_dismissed(GatedReport(findings=discarded, stats={}))
            if learned:
                import logging

                logging.getLogger("patchi.detection").info(
                    "Learned %d new false positive(s) from rejected findings", learned
                )
        except Exception as e:
            import logging

            logging.getLogger("patchi.detection").warning(
                "FP learning loop failed (non-fatal): %s", e
            )

        stats = {
            "total": len(gated_list),
            "defend": len(high),
            "ai_analyze": len([g for g in medium if g.routing == "ai_analyze"]),
            "human_review": len(low),
            "discarded": len(discarded),
        }
        if noise_stats is not None:
            stats["noise"] = noise_stats

        return GatedReport(
            findings=high + [g for g in medium if g.routing == "ai_analyze"] + low + discarded,
            stats=stats,
        )
