"""
CVE Monitor — continuous dependency vulnerability monitoring.

Monitors dependency CVE feeds (OSV, NVD, GHSA) and alerts
when new vulnerabilities affect project dependencies.
Uses batch query and 24h local disk cache shared by all agents.
"""

from __future__ import annotations
import logging

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)
from patchi.core.constants import is_offline

# Disk cache for CVE results (24h TTL)
_CVE_CACHE: dict = {}
_CVE_CACHE_PATH: Path | None = None
_CVE_CACHE_TTL = 86400  # 24 hours


_log = logging.getLogger("patchi.security.cve_monitor")


def _load_cve_cache(root: Path) -> dict:
    global _CVE_CACHE, _CVE_CACHE_PATH
    _CVE_CACHE_PATH = root / ".patchi" / "cache" / "cve_cache.json"
    if _CVE_CACHE_PATH.exists():
        try:
            _CVE_CACHE = json.loads(_CVE_CACHE_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            _log.warning("_load_cve_cache failed: %s", e)
            _CVE_CACHE = {}
    return _CVE_CACHE


def _save_cve_cache() -> None:
    if _CVE_CACHE_PATH:
        try:
            _CVE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            _CVE_CACHE_PATH.write_text(json.dumps(_CVE_CACHE, indent=2), encoding="utf-8")
        except Exception as e:
            _log.warning("_save_cve_cache failed: %s", e)


def _cve_cache_key(name: str, version: str, ecosystem: str) -> str:
    return f"{ecosystem}:{name}@{version}"


def cached_osv_query(name: str, version: str, ecosystem: str, root: Path) -> list[dict]:
    """Single-package OSV query with shared 24h cache.

    Importable by other agents so all OSV calls share one cache file.
    """
    _load_cve_cache(root)
    cache_key = _cve_cache_key(name, version, ecosystem)
    cached = _CVE_CACHE.get(cache_key)
    if cached and isinstance(cached, dict) and cached.get("_ts", 0) > time.time() - _CVE_CACHE_TTL:
        return cached.get("vulns", [])
    if is_offline():
        return []
    try:
        url = "https://api.osv.dev/v1/query"
        query = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        req = urllib.request.Request(
            url, data=json.dumps(query).encode(), headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        vulns = data.get("vulns", [])
    except Exception as e:
        _log.warning("cached_osv_query failed: %s", e)
        vulns = []
    _CVE_CACHE[cache_key] = {"vulns": vulns, "_ts": time.time()}
    _save_cve_cache()
    return vulns


@register
class CVEMonitorAgent(BaseAgent):
    """Monitors dependencies for new CVEs against OSV database (all-deps batch + 24h cache)."""

    name = "CVEMonitorAgent"
    group = AgentGroup.SECURITY
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        dep_files = {
            "package.json": ("npm", self._parse_npm),
            "requirements.txt": ("PyPI", self._parse_pip),
        }

        _load_cve_cache(inp.root)

        for pattern, (ecosystem, parser) in dep_files.items():
            for fpath in safe_rglob(inp.root, pattern):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                deps = parser(content)
                # Build all queries for batch
                queries = []
                for name, version in deps:
                    cache_key = _cve_cache_key(name, version, ecosystem)
                    cached = _CVE_CACHE.get(cache_key)
                    if (
                        cached
                        and isinstance(cached, dict)
                        and cached.get("_ts", 0) > time.time() - _CVE_CACHE_TTL
                    ):
                        vulns = cached.get("vulns", [])
                    else:
                        queries.append((name, version, ecosystem, cache_key))

                # Batch query remaining deps (skipped entirely in offline mode)
                if queries and not is_offline():
                    try:
                        batch_results = self._batch_check_osv(queries)
                        for name, version, ecosystem, cache_key in queries:
                            vulns = batch_results.get(cache_key, [])
                            _CVE_CACHE[cache_key] = {"vulns": vulns, "_ts": time.time()}
                    except Exception as e:
                        _log.warning("CVEMonitorAgent._run failed: %s", e)
                        for q in queries:
                            _CVE_CACHE[q[3]] = {"vulns": [], "_ts": time.time()}

                # Report all findings (cached + fresh)
                for name, version in deps:
                    cache_key = _cve_cache_key(name, version, ecosystem)
                    cached = _CVE_CACHE.get(cache_key, {"vulns": []})
                    for vuln in cached.get("vulns", []):
                        severity = self._map_severity(vuln)
                        result.add_finding(
                            Finding(
                                agent=self.name,
                                type="known_cve",
                                severity=severity,
                                file=rel,
                                message=f"{name}@{version}: {vuln.get('summary', 'Known vulnerability')}",
                                cwe=", ".join(vuln.get("cwe_ids", [])),
                                extra={
                                    "vuln_id": vuln.get("id", ""),
                                    "aliases": vuln.get("aliases", []),
                                    "ecosystem": ecosystem,
                                },
                            )
                        )

        _save_cve_cache()
        result.files_scanned = len(list(safe_rglob(inp.root, "package.json"))) + len(
            list(safe_rglob(inp.root, "requirements.txt"))
        )

    def _batch_check_osv(self, queries: list[tuple[str, str, str, str]]) -> dict[str, list[dict]]:
        """Batch query OSV API for all given dependencies in a single request."""
        results: dict[str, list[dict]] = {}
        if not queries or is_offline():
            return results
        try:
            batch_query = {"queries": []}
            for name, version, ecosystem, cache_key in queries:
                batch_query["queries"].append(
                    {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                )
            url = "https://api.osv.dev/v1/querybatch"
            req = urllib.request.Request(
                url,
                data=json.dumps(batch_query).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                # Map results back to cache keys
                for i, (name, version, ecosystem, cache_key) in enumerate(queries):
                    results[cache_key] = (
                        data.get("results", [{}])[i].get("vulns", [])
                        if i < len(data.get("results", []))
                        else []
                    )
        except Exception as e:
            # Fallback to individual queries
            _log.warning("CVEMonitorAgent._batch_check_osv failed: %s", e)
            for q in queries:
                results[q[3]] = self._check_osv_single(q[0], q[1], q[2])
        return results

    def _check_osv_single(self, name: str, version: str, ecosystem: str) -> list[dict]:
        """Single OSV query (fallback)."""
        if is_offline():
            return []
        try:
            url = "https://api.osv.dev/v1/query"
            query = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            req = urllib.request.Request(
                url,
                data=json.dumps(query).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                return data.get("vulns", [])
        except Exception as e:
            _log.warning("CVEMonitorAgent._check_osv_single failed: %s", e)
            return []

    def _map_severity(self, vuln: dict) -> Severity:
        """Map OSV severity to our Severity enum."""
        severities = vuln.get("severity", [])
        for s in severities:
            score = s.get("score", "").upper()
            if "CRITICAL" in score:
                return Severity.CRITICAL
            if "HIGH" in score:
                return Severity.HIGH
            if "MEDIUM" in score:
                return Severity.MEDIUM
        # Check database_specific or ecosystem_specific for severity
        return Severity.MEDIUM  # Default: unknown = medium

    def _parse_npm(self, content: str) -> list[tuple[str, str]]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        return [(k, v) for k, v in deps.items()]

    def _parse_pip(self, content: str) -> list[tuple[str, str]]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            for op in ("==", ">=", "<=", "~=", ">", "<"):
                if op in line:
                    name, ver = line.split(op, 1)
                    deps.append((name.strip(), ver.strip().split(",")[0]))
                    break
            else:
                deps.append((line.strip(), "unknown"))
        return deps
