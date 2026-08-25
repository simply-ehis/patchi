"""
Runtime Request Interceptor — real-time request/response defense for hosted mode.

Intercepts HTTP requests, feeds them through the DetectionPipeline, and blocks
or modifies responses based on confidence-gated findings.

Three integration modes:
  1. ASGI middleware (FastAPI/Starlette)     — recommended for Patchi's web UI
  2. WSGI middleware (Flask/Django)           — fallback
  3. Reverse proxy sidecar (standalone)       — separate process intercepting traffic

All modes are optional, opt-in via config:
  {
    "pipeline": {
      "interceptor": {
        "enabled": false,
        "mode": "asgi",          // asgi | wsgi | sidecar
        "block_threshold": 0.7,  // confidence score threshold for blocking
        "rate_limit": 100,       // max inspected requests per minute
        "exclude_paths": ["/health", "/metrics", "/static"]
      }
    }
  }
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from loguru import logger

_log = logging.getLogger("patchi.security.request_interceptor")


class RequestInterceptor:
    """
    Runtime request interceptor for hosted mode.

    Usage (ASGI):
        from patchi.core.security.request_interceptor import RequestInterceptor
        interceptor = RequestInterceptor(root, config)
        app.add_middleware(interceptor.asgi_middleware)

    Usage (standalone inspection):
        result = interceptor.inspect_request(method, path, headers, body)
        if result.should_block:
            return 403
    """

    def __init__(self, root: Path, config: dict | None = None):
        self.root = root
        self.config = config or {}
        interceptor_cfg = self.config.get("pipeline", {}).get("interceptor", {})
        self.enabled = interceptor_cfg.get("enabled", False)
        self.block_threshold = interceptor_cfg.get("block_threshold", 0.7)
        self.rate_limit = interceptor_cfg.get("rate_limit", 100)  # per minute
        self.exclude_paths = set(
            interceptor_cfg.get("exclude_paths", ["/health", "/metrics", "/static"])
        )

        # Rate limit tracking
        self._window_start = time.monotonic()
        self._window_count = 0

        # Threat intelligence cache (IP → threat score)
        self._threat_ips: dict[str, dict] = {}
        self._injection_cache: dict[str, float] = {}  # normalized payload → confidence
        # Bound the caches: keys are client-controlled, so unbounded growth is
        # a memory DoS on a long-running hosted process.
        self._max_threat_ips = 10_000
        self._max_injection_cache = 10_000

    def should_inspect(self, path: str) -> bool:
        """Check if path should be inspected (not excluded, not static)."""
        if not self.enabled:
            return False
        for excluded in self.exclude_paths:
            if path.startswith(excluded):
                return False
        return True

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limit. Returns True if allowed."""
        now = time.monotonic()
        if now - self._window_start > 60:
            self._window_start = now
            self._window_count = 0
        if self._window_count >= self.rate_limit:
            return False
        self._window_count += 1
        return True

    # ── Request inspection ────────────────────────────────────────────────

    def inspect_request(self, method: str, path: str, headers: dict, body: str = "") -> dict:
        """
        Inspect a single HTTP request for threats.

        Returns:
            {
                "should_block": bool,
                "confidence": float,
                "threat_type": str | None,
                "reason": str | None,
                "findings": list[dict],
            }
        """
        if not self._check_rate_limit():
            return {
                "should_block": False,
                "confidence": 0.0,
                "threat_type": None,
                "reason": "Rate limited (inspector)",
                "findings": [],
            }

        findings = []
        ip = (
            headers.get("x-forwarded-for", headers.get("remote-addr", "unknown"))
            .split(",")[0]
            .strip()
        )

        # 1. Known malicious IP check
        if ip in self._threat_ips:
            ti = self._threat_ips[ip]
            if ti["score"] >= self.block_threshold:
                return {
                    "should_block": True,
                    "confidence": ti["score"],
                    "threat_type": "known_malicious_ip",
                    "reason": f"Known malicious IP (score: {ti['score']})",
                    "findings": [],
                }

        # 2. Injection detection in path/body
        body_lower = body.lower()
        query = path.lower()

        injection_patterns = [
            ("sqli", ["'", '"', "union select", "or 1=1", "drop table", ";--", "admin'--"]),
            ("xss", ["<script", "onerror=", "onload=", "javascript:", "alert("]),
            ("path_traversal", ["../", "..\\", "%2e%2e%2f", "....//"]),
            ("command_injection", ["; ", "| ", "`", "$(", "&& ", "|| "]),
            ("ssti", ["{{", "{%", "${", "#{"]),
        ]

        for threat_type, patterns in injection_patterns:
            for pat in patterns:
                if pat in body_lower or pat in query:
                    confidence = 0.8 if pat in body_lower else 0.6
                    if len(self._injection_cache) < self._max_injection_cache:
                        cache_key = f"{threat_type}:{hash(body)}"
                        self._injection_cache[cache_key] = confidence
                    findings.append(
                        {
                            "type": threat_type,
                            "confidence": confidence,
                            "pattern": pat,
                            "location": "body" if pat in body_lower else "path",
                        }
                    )

        # 3. Rate spike detection (same IP, multiple requests)
        if ip not in self._threat_ips:
            if len(self._threat_ips) >= self._max_threat_ips:
                self.clear_stale_threats()
            if len(self._threat_ips) >= self._max_threat_ips:
                # Still at the cap — drop the oldest entry instead of growing
                # without bound.
                self._threat_ips.pop(next(iter(self._threat_ips)))
            self._threat_ips[ip] = {"score": 0.0, "count": 0, "first_seen": time.time()}
        self._threat_ips[ip]["count"] += 1

        ip_data = self._threat_ips[ip]
        elapsed = time.time() - ip_data["first_seen"]
        # Only judge sustained request rates over a real window. Measuring
        # bursts against a sub-second elapsed time makes any two quick
        # requests look like thousands per second (false positive).
        if elapsed >= 1.0:
            rps = ip_data["count"] / elapsed
            if rps > 50:  # more than 50 req/s from same IP
                ip_data["score"] = min(1.0, ip_data["score"] + 0.2)
                findings.append(
                    {
                        "type": "rate_spike",
                        "confidence": min(0.9, rps / 100),
                        "pattern": f"{ip_data['count']} requests in {elapsed:.0f}s",
                        "location": "ip",
                    }
                )

        if not findings:
            return {
                "should_block": False,
                "confidence": 0.0,
                "threat_type": None,
                "reason": "No threats detected",
                "findings": [],
            }

        # Compute max confidence
        max_conf = max(f["confidence"] for f in findings)
        top_threat = max(findings, key=lambda f: f["confidence"])

        return {
            "should_block": max_conf >= self.block_threshold,
            "confidence": max_conf,
            "threat_type": top_threat["type"],
            "reason": f"Detected {top_threat['type']} (confidence: {max_conf:.2f})",
            "findings": findings,
        }

    # ── ASGI middleware ───────────────────────────────────────────────────

    async def asgi_middleware(self, scope: dict, receive: callable, send: callable) -> None:
        """ASGI middleware for FastAPI/Starlette."""
        if scope["type"] != "http":
            # Non-HTTP scopes (lifespan, websockets) must pass through
            # untouched — `send` takes a message, not the scope tuple.
            return

        path = scope.get("path", "/")
        if not self.should_inspect(path):
            return

        method = scope.get("method", "GET")
        headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}

        # Read request body
        body = ""
        if method in ("POST", "PUT", "PATCH"):
            try:
                more = True
                while more:
                    message = await receive()
                    if message["type"] == "http.request":
                        body += message.get("body", b"").decode("utf-8", errors="ignore")
                        more = message.get("more_body", False)
                    else:
                        break
            except Exception as e:
                _log.warning("RequestInterceptor.asgi_middleware failed: %s", e)

        result = self.inspect_request(method, path, headers, body)
        if result["should_block"]:
            logger.warning(f"Blocked request: {method} {path} — {result['reason']}")
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": json.dumps(
                        {"error": "Request blocked", "reason": result["reason"]}
                    ).encode(),
                }
            )
            return

    # ── Threat intelligence maintenance ───────────────────────────────────

    def add_threat_ip(self, ip: str, score: float = 1.0, reason: str = "") -> None:
        """Manually add an IP to the threat list (from DefenseLayer block_ip)."""
        self._threat_ips[ip] = {
            "score": score,
            "count": 0,
            "first_seen": time.time(),
            "reason": reason,
        }

    def clear_stale_threats(self, max_age: int = 3600) -> int:
        """Remove threat IPs older than max_age seconds. Returns count removed."""
        now = time.time()
        stale = [ip for ip, data in self._threat_ips.items() if now - data["first_seen"] > max_age]
        for ip in stale:
            del self._threat_ips[ip]
        return len(stale)

    def export_threats(self) -> dict:
        """Export current threat intelligence for dashboard."""
        return {
            "threat_ips": len(self._threat_ips),
            "injection_cache": len(self._injection_cache),
            "block_threshold": self.block_threshold,
            "rate_limit_per_min": self.rate_limit,
        }
