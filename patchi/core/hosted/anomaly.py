"""
Anomaly detection for Patchi hosted mode.

Two layers:
  1. Statistical: rolling windows — request rate spikes, error rate spikes,
     status code distribution shifts, path enumeration patterns.
  2. ML: IsolationForest on request feature vectors — catches what statistics miss.

Detects: brute force, credential stuffing, scanner sweeps, injection probes,
         error spikes, path traversal attempts.
"""

from __future__ import annotations

import collections
import time
from dataclasses import dataclass, field

from patchi.core.hosted.log_parsers import LogEntry


@dataclass
class AnomalyFinding:
    detector: str
    severity: str  # critical / high / medium
    title: str
    detail: str
    ip: str = ""
    evidence: dict = field(default_factory=dict)
    detected_at: float = field(default_factory=time.time)


# ── Statistical detectors ──────────────────────────────────────────────────────


class _RollingWindow:
    """Fixed-size time window for rate tracking."""

    def __init__(self, window_secs: int = 60) -> None:
        self._window = window_secs
        self._events: collections.deque = collections.deque()

    def add(self, value: float = 1.0) -> None:
        now = time.time()
        self._events.append((now, value))
        self._trim(now)

    def _trim(self, now: float) -> None:
        while self._events and now - self._events[0][0] > self._window:
            self._events.popleft()

    def rate(self) -> float:
        """Events per second in the current window."""
        if not self._events:
            return 0.0
        self._trim(time.time())
        if not self._events:
            return 0.0
        # Compute actual time span of events in window
        span = self._events[-1][0] - self._events[0][0]
        if span <= 0:
            return float(len(self._events))
        return sum(v for _, v in self._events) / span

    def count(self) -> int:
        self._trim(time.time())
        return len(self._events)


class StatisticalDetector:
    """
    Rolling window detectors for common attack patterns.
    Maintains per-IP and global counters.
    Accepts optional config dict for threshold overrides.
    """

    # Defaults
    _DEFAULT_RATE_SPIKE_RPS = 50
    _DEFAULT_BRUTE_FORCE_AUTH = 20
    _DEFAULT_SCANNER_PATHS = 30
    _DEFAULT_ERROR_RATE_PCT = 0.40
    _INJECTION_PATTERNS = [
        "../",
        "..\\",
        "%2e%2e",
        "'%20OR%20",
        " OR ",
        "UNION SELECT",
        "<script",
        "javascript:",
        "${jndi:",
        "etc/passwd",
    ]
    _MAX_IP_TRACKERS = 10_000

    def __init__(self, config: dict | None = None) -> None:
        hosted = (config or {}).get("hosted", {})
        self._RATE_SPIKE_RPS = hosted.get("rate_spike_rps", self._DEFAULT_RATE_SPIKE_RPS)
        self._BRUTE_FORCE_AUTH = hosted.get("brute_force_auth", self._DEFAULT_BRUTE_FORCE_AUTH)
        self._SCANNER_PATHS = hosted.get("scanner_paths", self._DEFAULT_SCANNER_PATHS)
        self._ERROR_RATE_PCT = hosted.get("error_rate_pct", self._DEFAULT_ERROR_RATE_PCT)
        self._whitelist: set[str] = set(hosted.get("ip_whitelist", []))

        self._global_rate = _RollingWindow(60)
        self._error_count = _RollingWindow(60)
        self._total_count = _RollingWindow(60)
        self._ip_auth_hits: dict[str, _RollingWindow] = {}
        self._ip_paths: dict[str, set] = {}
        self._ip_path_times: dict[str, float] = {}
        self._ip_lru_order: list[str] = []

    def feed(self, entry: LogEntry) -> list[AnomalyFinding]:
        findings: list[AnomalyFinding] = []

        # Skip whitelisted IPs
        if entry.ip and entry.ip in self._whitelist:
            return findings

        self._global_rate.add()
        self._total_count.add()
        if entry.status >= 400:
            self._error_count.add()

        # Rate spike
        if self._global_rate.rate() > self._RATE_SPIKE_RPS:
            findings.append(
                AnomalyFinding(
                    detector="rate_spike",
                    severity="high",
                    title=f"Request rate spike: {self._global_rate.rate():.0f} req/s",
                    detail="Sustained high request rate — possible DDoS or scanner.",
                )
            )

        # Error rate
        total = self._total_count.count()
        if total > 20:
            err_pct = self._error_count.count() / total
            if err_pct > self._ERROR_RATE_PCT:
                findings.append(
                    AnomalyFinding(
                        detector="error_spike",
                        severity="medium",
                        title=f"High error rate: {err_pct:.0%}",
                        detail=f"{self._error_count.count()} errors in last 60s.",
                    )
                )

        # Per-IP checks
        if entry.ip:
            findings.extend(self._check_ip(entry))

        # Injection patterns in path
        path_lower = entry.path.lower()
        for pattern in self._INJECTION_PATTERNS:
            if pattern.lower() in path_lower:
                findings.append(
                    AnomalyFinding(
                        detector="injection_probe",
                        severity="critical",
                        title=f"Injection probe detected: {pattern}",
                        detail=f"IP {entry.ip} sent probe in path: {entry.path[:120]}",
                        ip=entry.ip,
                        evidence={"path": entry.path, "pattern": pattern},
                    )
                )

        return findings

    def _check_ip(self, entry: LogEntry) -> list[AnomalyFinding]:
        findings: list[AnomalyFinding] = []
        ip = entry.ip

        # LRU eviction if tracking too many IPs
        if ip not in self._ip_auth_hits and len(self._ip_auth_hits) >= self._MAX_IP_TRACKERS:
            self._evict_lru()

        # Brute force on auth endpoints
        auth_paths = ("/auth/login", "/login", "/signin", "/api/token", "/admin")
        if any(entry.path.startswith(p) for p in auth_paths) and entry.method == "POST":
            if ip not in self._ip_auth_hits:
                self._ip_auth_hits[ip] = _RollingWindow(60)
                self._ip_lru_order.append(ip)
            self._ip_auth_hits[ip].add()
            if self._ip_auth_hits[ip].count() >= self._BRUTE_FORCE_AUTH:
                findings.append(
                    AnomalyFinding(
                        detector="brute_force",
                        severity="critical",
                        title=f"Brute force: {ip} → {entry.path}",
                        detail=f"{self._ip_auth_hits[ip].count()} auth attempts in 60s.",
                        ip=ip,
                        evidence={"count": self._ip_auth_hits[ip].count()},
                    )
                )

        # Path enumeration (scanner sweep)
        now = time.time()
        last_reset = self._ip_path_times.get(ip, 0)
        if now - last_reset > 60:
            self._ip_paths[ip] = set()
            self._ip_path_times[ip] = now
            if ip not in self._ip_lru_order:
                self._ip_lru_order.append(ip)
        self._ip_paths[ip].add(entry.path)
        if len(self._ip_paths[ip]) >= self._SCANNER_PATHS:
            findings.append(
                AnomalyFinding(
                    detector="scanner_sweep",
                    severity="high",
                    title=f"Scanner sweep: {ip} probing {len(self._ip_paths[ip])} paths",
                    detail="Rapid path enumeration — possible automated scanner.",
                    ip=ip,
                    evidence={"distinct_paths": len(self._ip_paths[ip])},
                )
            )

        return findings

    def _evict_lru(self) -> None:
        """Evict oldest tracked IPs to bound memory usage."""
        while len(self._ip_auth_hits) >= self._MAX_IP_TRACKERS and self._ip_lru_order:
            old_ip = self._ip_lru_order.pop(0)
            self._ip_auth_hits.pop(old_ip, None)
            self._ip_paths.pop(old_ip, None)
            self._ip_path_times.pop(old_ip, None)


class MLDetector:
    """
    IsolationForest anomaly detector on request feature vectors.
    Trains on a baseline window, then flags outliers.
    Requires sklearn — gracefully no-ops if not available.
    """

    MIN_SAMPLES = 100  # minimum before ML kicks in
    _MAX_SAMPLES = 10_000  # cap memory usage

    def __init__(self) -> None:
        self._samples: list[list[float]] = []
        self._model = None
        self._trained = False

    def _to_vector(self, entry: LogEntry) -> list[float]:
        """Convert a log entry to a numeric feature vector."""
        return [
            float(entry.status),
            float(len(entry.path)),
            float(entry.path.count("/")),
            float(1 if entry.method == "POST" else 0),
            float(1 if entry.status >= 500 else 0),
            float(1 if entry.status == 404 else 0),
            float(len(entry.path.split("?")[1]) if "?" in entry.path else 0),
        ]

    def feed(self, entry: LogEntry) -> list[AnomalyFinding]:
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            return []

        vec = self._to_vector(entry)
        self._samples.append(vec)

        # Cap memory usage
        if len(self._samples) > self._MAX_SAMPLES:
            self._samples = self._samples[-self._MAX_SAMPLES :]

        if len(self._samples) < self.MIN_SAMPLES:
            return []

        # Retrain every 500 samples
        if len(self._samples) % 500 == 0 or not self._trained:
            self._model = IsolationForest(contamination=0.05, random_state=42, n_estimators=50)
            self._model.fit(self._samples[-1000:])
            self._trained = True

        if not self._model:
            return []

        score = self._model.decision_function([vec])[0]
        pred = self._model.predict([vec])[0]

        if pred == -1 and score < -0.2:
            return [
                AnomalyFinding(
                    detector="ml_outlier",
                    severity="medium",
                    title="ML anomaly detected",
                    detail=(
                        f"Request to {entry.path} from {entry.ip} has anomaly score {score:.3f}."
                    ),
                    ip=entry.ip,
                    evidence={"score": round(score, 3), "status": entry.status},
                )
            ]

        return []
