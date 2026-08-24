"""
DefectDojoReporter — optional push of Patchi defense results to DefectDojo.

DefectDojo is an open-source vulnerability management platform.
https://github.com/DefectDojo/django-DefectDojo

Configuration (opt-in, disabled by default):
  {
    "defectdojo": {
      "enabled": false,
      "url": "https://demo.defectdojo.org",
      "api_key": "",
      "auto_create_product": true,
      "product_name": "auto",        // "auto" = use project directory name
      "engagement_prefix": "scan-"
    }
  }

Usage:
    reporter = DefectDojoReporter(config)
    reporter.push_gated_report(gated_report, project_root)
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from loguru import logger


class DefectDojoReporter:
    """
    Push Patchi defense pipeline results to DefectDojo.

    All operations are optional and fail gracefully — never block scans.
    """

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        dd_cfg = self.config.get("defectdojo", {})
        self.enabled = dd_cfg.get("enabled", False)
        self.base_url = dd_cfg.get("url", "").rstrip("/")
        self.api_key = dd_cfg.get("api_key", "")
        self.auto_create_product = dd_cfg.get("auto_create_product", True)
        self.product_name = dd_cfg.get("product_name", "auto")
        self.engagement_prefix = dd_cfg.get("engagement_prefix", "scan-")

        if self.enabled and not self.base_url:
            logger.warning("DefectDojo enabled but no URL configured — disabling")
            self.enabled = False
        if self.enabled and not self.api_key:
            logger.warning("DefectDojo enabled but no API key configured — disabling")
            self.enabled = False

    def push_gated_report(self, gated_report: Any, root: Path) -> dict:
        """
        Push a GatedReport to DefectDojo.

        Args:
            gated_report: GatedReport from DetectionPipeline.process()
            root: Project root Path (used for product name)

        Returns:
            dict with status and details
        """
        if not self.enabled:
            return {"status": "skipped", "reason": "DefectDojo not enabled"}

        try:
            import httpx  # noqa: F401 — used to check availability
        except ImportError:
            logger.warning("httpx not installed — cannot push to DefectDojo")
            return {"status": "skipped", "reason": "httpx not installed"}

        product_name = Path(root).name if self.product_name == "auto" else self.product_name

        # Build findings payload
        findings = []
        for gf in getattr(gated_report, "findings", []):
            f = getattr(gf, "finding", gf)
            findings.append(self._finding_to_dd(f, gf))

        if not findings:
            return {"status": "skipped", "reason": "No findings to push"}

        # Ensure product and engagement exist
        product_id = self._get_or_create_product(product_name)
        if not product_id:
            return {"status": "error", "reason": "Failed to get/create product"}

        engagement_id = self._create_engagement(product_id, product_name)
        if not engagement_id:
            return {"status": "error", "reason": "Failed to create engagement"}

        # Push import scan
        return self._import_scan(engagement_id, findings, product_name)

    # ── Finding conversion ────────────────────────────────────────────────

    def _finding_to_dd(self, finding: Any, gated_finding: Any = None) -> dict:
        """Convert a Patchi Finding to DefectDojo finding format."""
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
        }

        cwe = 0
        if hasattr(finding, "cwe") and finding.cwe:
            try:
                cwe = int(str(finding.cwe).replace("CWE-", ""))
            except ValueError:
                cwe = 0

        can_defend = False
        if gated_finding is not None:
            can_defend = getattr(gated_finding, "can_defend", False)

        severity = severity_map.get(
            getattr(finding, "severity", "info").value
            if hasattr(getattr(finding, "severity", ""), "value")
            else str(getattr(finding, "severity", "info")).lower(),
            "Info",
        )

        return {
            "title": getattr(finding, "message", "Untitled finding")[:500],
            "severity": severity,
            "file_path": getattr(finding, "file", ""),
            "line": getattr(finding, "line", 0),
            "cwe": cwe,
            "description": getattr(finding, "detail", "")[:2000],
            "remediation": getattr(finding, "suggestion", "")[:1000],
            "active": True,
            "verified": can_defend,
            "false_positive": False,
            "duplicate": False,
        }

    # ── DefectDojo API calls ──────────────────────────────────────────────

    def _api_call(self, method: str, endpoint: str, **kwargs) -> dict | None:
        """Make an HTTP call to DefectDojo API."""
        try:
            import httpx
        except ImportError:
            return None

        url = f"{self.base_url}/api/v2/{endpoint}"
        headers = {
            "Authorization": f"Token {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            if method == "GET":
                r = httpx.get(url, headers=headers, params=kwargs.get("params"), timeout=30)
            elif method == "POST":
                r = httpx.post(url, headers=headers, json=kwargs.get("json", {}), timeout=30)
            else:
                return None

            if r.status_code in (200, 201):
                return r.json()
            logger.debug(f"DefectDojo API error: {r.status_code} {r.text[:200]}")
            return None
        except Exception as e:
            logger.debug(f"DefectDojo request failed: {e}")
            return None

    def _get_or_create_product(self, product_name: str) -> int | None:
        """Get existing product or create new one. Returns product_id."""
        # Try to find existing product
        result = self._api_call("GET", "products", params={"limit": 100})
        if result:
            for p in result.get("results", []):
                if p.get("name") == product_name:
                    return p["id"]

        # Create if auto-create enabled
        if not self.auto_create_product:
            logger.warning(f"Product '{product_name}' not found and auto_create is false")
            return None

        result = self._api_call(
            "POST",
            "products",
            json={
                "name": product_name,
                "description": f"Patchi scan findings for {product_name}",
                "prod_type": 1,  # default product type
            },
        )
        if result:
            return result["id"]
        return None

    def _create_engagement(self, product_id: int, product_name: str) -> int | None:
        """Create a new engagement for a scan. Returns engagement_id."""
        engagement_name = f"{self.engagement_prefix}{int(time.time())}"
        result = self._api_call(
            "POST",
            "engagements",
            json={
                "name": engagement_name,
                "product": product_id,
                "target_start": time.strftime("%Y-%m-%d"),
                "target_end": time.strftime("%Y-%m-%d"),
                "engagement_type": "CI/CD",
                "status": "In Progress",
                "description": f"Patchi scan of {product_name}",
            },
        )
        if result:
            return result["id"]
        return None

    def _import_scan(self, engagement_id: int, findings: list[dict], product_name: str) -> dict:
        """Push findings as an import-scan."""
        result = self._api_call(
            "POST",
            "import-scan/",
            json={
                "engagement": engagement_id,
                "scan_type": "Patchi Scan",
                "product_name": product_name,
                "findings": findings,
            },
        )
        if result:
            count = len(findings)
            logger.info(f"Pushed {count} findings to DefectDojo (engagement {engagement_id})")
            return {"status": "success", "finding_count": count, "engagement_id": engagement_id}
        return {"status": "error", "reason": "Import scan API call failed"}
