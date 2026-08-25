"""
Stress Orchestrator — Load testing engine for web applications.

Supports:
- Load testing (steady state)
- Spike testing (sudden bursts)
- Soak testing (long duration)
- Breakpoint testing (find limits)
- Custom scenarios
"""

from __future__ import __future__

import asyncio
import logging
import random
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

_log = logging.getLogger("patchi.testing.stress_orchestrator")


@dataclass
class StressConfig:
    """Configuration for a stress test."""
    base_url: str
    scenario: str = "load"  # load, spike, soak, breakpoint
    users: int = 10
    duration_seconds: int = 60
    ramp_up_seconds: int = 10
    # Spike config
    spike_multiplier: float = 3.0
    spike_duration_seconds: int = 10
    # Soak config
    soak_check_interval: int = 300  # seconds
    # Breakpoint config
    max_users: int = 1000
    step_users: int = 50
    step_duration: int = 30
    # Request config
    requests_per_second: float | None = None  # None = as fast as possible
    think_time_ms: int = 100
    # Endpoints to test
    endpoints: list[dict] = field(default_factory=list)
    # Custom scenario function
    custom_scenario: Callable | None = None


@dataclass
class RequestResult:
    """Result of a single HTTP request."""
    timestamp: float
    method: str
    url: str
    status_code: int
    response_time_ms: float
    success: bool
    error: str = ""
    response_size: int = 0


@dataclass
class UserSession:
    """A single virtual user's session."""
    user_id: int
    start_time: float
    results: list[RequestResult] = field(default_factory=list)
    active: bool = True


@dataclass
class StressTestReport:
    """Complete stress test report."""
    config: StressConfig
    started_at: str
    completed_at: str
    duration_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    requests_per_second: float
    latency: dict  # min, max, mean, median, p50, p90, p95, p99
    status_codes: dict[str, int]
    errors: dict[str, int]
    throughput_over_time: list[dict]  # time series
    latency_over_time: list[dict]
    user_sessions: int
    peak_users: int
    # Scenario-specific
    breakpoint_found: bool = False
    breakpoint_users: int = 0
    soak_stability: bool = True


class StressOrchestrator:
    """
    Orchestrates load/stress tests against a web application.
    
    Usage:
        config = StressConfig(
            base_url="https://api.example.com",
            scenario="spike",
            users=100,
            duration_seconds=60,
        )
        orchestrator = StressOrchestrator(config)
        report = await orchestrator.run()
    """
    
    def __init__(
        self,
        config: StressConfig,
        on_progress: Callable[[str], None] = None,
    ):
        self.config = config
        self.on_progress = on_progress or (lambda _: None)
        self._session: Any = None
        self._users: list[UserSession] = []
        self._running = False
        self._start_time = 0
        self._results: list[RequestResult] = []
        self._time_series: list[dict] = []
    
    async def run(self) -> StressTestReport:
        """Run the stress test based on scenario."""
        self._start_time = time.time()
        started_at = datetime.now(timezone.utc).isoformat()
        
        # Initialize HTTP session
        await self._init_session()
        
        try:
            if self.config.scenario == "load":
                await self._run_load_test()
            elif self.config.scenario == "spike":
                await self._run_spike_test()
            elif self.config.scenario == "soak":
                await self._run_soak_test()
            elif self.config.scenario == "breakpoint":
                await self._run_breakpoint_test()
            elif self.config.scenario == "custom" and self.config.custom_scenario:
                await self.config.custom_scenario(self)
            else:
                raise ValueError(f"Unknown scenario: {self.config.scenario}")
        finally:
            await self._close_session()
        
        completed_at = datetime.now(timezone.utc).isoformat()
        duration = time.time() - self._start_time
        
        return self._generate_report(started_at, completed_at, duration)
    
    async def _init_session(self):
        """Initialize aiohttp session."""
        try:
            import aiohttp
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(limit=1000),
            )
        except ImportError:
            _log.error("aiohttp not installed. Install with: pip install aiohttp")
            raise
    
    async def _close_session(self):
        """Close aiohttp session."""
        if self._session:
            await self._session.close()
    
    async def _run_load_test(self):
        """Run steady-state load test."""
        self.on_progress(f"🚀 Starting load test: {self.config.users} users for {self.config.duration_seconds}s")
        
        # Ramp up users
        await self._ramp_up_users(self.config.users, self.config.ramp_up_seconds)
        
        # Steady state
        steady_duration = self.config.duration_seconds - self.config.ramp_up_seconds
        if steady_duration > 0:
            await self._run_steady_state(steady_duration)
        
        # Ramp down
        await self._ramp_down_users()
    
    async def _run_spike_test(self):
        """Run spike test: baseline -> spike -> baseline."""
        self.on_progress(f"⚡ Starting spike test: {self.config.users} baseline -> {int(self.config.users * self.config.spike_multiplier)} spike")
        
        # Baseline
        await self._ramp_up_users(self.config.users, self.config.ramp_up_seconds)
        baseline_duration = (self.config.duration_seconds - self.config.spike_duration_seconds) // 2
        await self._run_steady_state(baseline_duration)
        
        # Spike
        spike_users = int(self.config.users * self.config.spike_multiplier)
        self.on_progress(f"📈 Spiking to {spike_users} users")
        await self._ramp_up_users(spike_users, 5)  # Fast ramp
        await self._run_steady_state(self.config.spike_duration_seconds)
        
        # Return to baseline
        self.on_progress(f"📉 Returning to baseline")
        await self._ramp_down_users(spike_users - self.config.users)
        await self._run_steady_state(baseline_duration)
        
        # Final ramp down
        await self._ramp_down_users()
    
    async def _run_soak_test(self):
        """Run long-duration soak test."""
        self.on_progress(f"🏃 Starting soak test: {self.config.users} users for {self.config.duration_seconds}s")
        
        await self._ramp_up_users(self.config.users, self.config.ramp_up_seconds)
        
        # Run with periodic checks
        elapsed = 0
        check_interval = self.config.soak_check_interval
        
        while elapsed < self.config.duration_seconds - self.config.ramp_up_seconds:
            remaining = min(check_interval, self.config.duration_seconds - self.config.ramp_up_seconds - elapsed)
            await self._run_steady_state(remaining)
            elapsed += remaining
            
            # Check for degradation
            await self._check_soak_health()
        
        await self._ramp_down_users()
    
    async def _run_breakpoint_test(self):
        """Run breakpoint test: gradually increase load until failure."""
        self.on_progress(f"🔍 Starting breakpoint test: up to {self.config.max_users} users")
        
        current_users = self.config.step_users
        breakpoint_found = False
        
        while current_users <= self.config.max_users and not breakpoint_found:
            self.on_progress(f"  Testing {current_users} users...")
            
            await self._ramp_up_users(current_users, self.config.ramp_up_seconds)
            await self._run_steady_state(self.config.step_duration)
            
            # Check if system is degrading
            if await self._check_breakpoint():
                breakpoint_found = True
                self.on_progress(f"💥 Breakpoint found at {current_users} users")
                break
            
            # Ramp down before next step
            await self._ramp_down_users()
            current_users += self.config.step_users
        
        if not breakpoint_found:
            self.on_progress(f"✅ No breakpoint found up to {self.config.max_users} users")
    
    async def _ramp_up_users(self, target_users: int, duration: float):
        """Gradually ramp up virtual users."""
        if target_users <= len(self._users):
            return
        
        users_to_add = target_users - len(self._users)
        interval = duration / users_to_add if users_to_add > 0 else 0
        
        for i in range(users_to_add):
            user_id = len(self._users) + 1
            self._users.append(UserSession(user_id=user_id, start_time=time.time()))
            
            # Start user task
            asyncio.create_task(self._run_user(user_id))
            
            if interval > 0:
                await asyncio.sleep(interval)
        
        self.on_progress(f"  Ramped up to {target_users} users")
    
    async def _ramp_down_users(self, count: int = None):
        """Ramp down virtual users."""
        if count is None:
            count = len(self._users)
        
        for _ in range(min(count, len(self._users))):
            if self._users:
                user = self._users.pop()
                user.active = False
        
        self.on_progress(f"  Ramped down to {len(self._users)} users")
    
    async def _run_steady_state(self, duration: float):
        """Run steady state for specified duration."""
        end_time = time.time() + duration
        
        while time.time() < end_time and self._running:
            # Collect time series data
            await self._collect_time_series()
            await asyncio.sleep(1)
    
    async def _run_user(self, user_id: int):
        """Run a single virtual user's workload."""
        user = next((u for u in self._users if u.user_id == user_id), None)
        if not user:
            return
        
        endpoints = self.config.endpoints or [{"method": "GET", "path": "/"}]
        
        while user.active and self._running:
            # Select endpoint
            endpoint = random.choice(endpoints)
            method = endpoint.get("method", "GET")
            path = endpoint.get("path", "/")
            url = f"{self.config.base_url.rstrip('/')}{path}"
            
            # Execute request
            result = await self._make_request(method, url)
            user.results.append(result)
            self._results.append(result)
            
            # Think time
            if self.config.think_time_ms > 0:
                await asyncio.sleep(self.config.think_time_ms / 1000)
            
            # Rate limiting
            if self.config.requests_per_second:
                await asyncio.sleep(1.0 / self.config.requests_per_second)
    
    async def _make_request(self, method: str, url: str) -> RequestResult:
        """Make an HTTP request and record result."""
        start = time.time()
        
        try:
            async with self._session.request(method, url) as response:
                await response.read()
                response_time = (time.time() - start) * 1000
                
                return RequestResult(
                    timestamp=time.time(),
                    method=method,
                    url=url,
                    status_code=response.status,
                    response_time_ms=response_time,
                    success=200 <= response.status < 400,
                    response_size=len(response.body) if hasattr(response, 'body') else 0,
                )
        except Exception as e:
            response_time = (time.time() - start) * 1000
            return RequestResult(
                timestamp=time.time(),
                method=method,
                url=url,
                status_code=0,
                response_time_ms=response_time,
                success=False,
                error=str(e),
            )
    
    async def _collect_time_series(self):
        """Collect time series metrics."""
        now = time.time()
        recent = [r for r in self._results if now - r.timestamp < 5]
        
        if recent:
            latencies = [r.response_time_ms for r in recent]
            self._time_series.append({
                "timestamp": now,
                "requests_per_sec": len(recent) / 5,
                "latency_p50": statistics.median(latencies),
                "latency_p95": self._percentile(latencies, 95),
                "error_rate": sum(1 for r in recent if not r.success) / len(recent),
                "active_users": len([u for u in self._users if u.active]),
            })
    
    async def _check_soak_health(self) -> bool:
        """Check system health during soak test."""
        # Check for memory leaks, error rate increase, latency degradation
        recent = [r for r in self._results if time.time() - r.timestamp < 60]
        if not recent:
            return True
        
        error_rate = sum(1 for r in recent if not r.success) / len(recent)
        if error_rate > 0.05:  # 5% error rate
            self.on_progress(f"⚠️ High error rate: {error_rate:.1%}")
            return False
        
        latencies = [r.response_time_ms for r in recent]
        p99 = self._percentile(latencies, 99)
        if p99 > 10000:  # 10 seconds
            self.on_progress(f"⚠️ High latency P99: {p99:.0f}ms")
            return False
        
        return True
    
    async def _check_breakpoint(self) -> bool:
        """Check if breakpoint has been reached."""
        recent = [r for r in self._results if time.time() - r.timestamp < 10]
        if not recent:
            return False
        
        error_rate = sum(1 for r in recent if not r.success) / len(recent)
        if error_rate > 0.10:  # 10% error rate
            return True
        
        latencies = [r.response_time_ms for r in recent]
        p99 = self._percentile(latencies, 99)
        if p99 > 30000:  # 30 seconds
            return True
        
        return False
    
    def _percentile(self, data: list[float], percentile: int) -> float:
        """Calculate percentile."""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    def _generate_report(
        self,
        started_at: str,
        completed_at: str,
        duration: float,
    ) -> StressTestReport:
        """Generate final stress test report."""
        if not self._results:
            return StressTestReport(
                config=self.config,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                total_requests=0,
                successful_requests=0,
                failed_requests=0,
                requests_per_second=0,
                latency={},
                status_codes={},
                errors={},
                throughput_over_time=[],
                latency_over_time=[],
                user_sessions=len(self._users),
                peak_users=max(len(self._users), 1),
            )
        
        latencies = [r.response_time_ms for r in self._results]
        status_codes = {}
        errors = {}
        
        for r in self._results:
            status_codes[str(r.status_code)] = status_codes.get(str(r.status_code), 0) + 1
            if not r.success:
                errors[r.error or "unknown"] = errors.get(r.error or "unknown", 0) + 1
        
        return StressTestReport(
            config=self.config,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            total_requests=len(self._results),
            successful_requests=sum(1 for r in self._results if r.success),
            failed_requests=sum(1 for r in self._results if not r.success),
            requests_per_second=len(self._results) / duration if duration > 0 else 0,
            latency={
                "min": min(latencies),
                "max": max(latencies),
                "mean": statistics.mean(latencies),
                "median": statistics.median(latencies),
                "p50": self._percentile(latencies, 50),
                "p90": self._percentile(latencies, 90),
                "p95": self._percentile(latencies, 95),
                "p99": self._percentile(latencies, 99),
            },
            status_codes=status_codes,
            errors=errors,
            throughput_over_time=[{"timestamp": ts["timestamp"], "rps": ts["requests_per_sec"]} for ts in self._time_series],
            latency_over_time=[{"timestamp": ts["timestamp"], "p50": ts["latency_p50"], "p95": ts["latency_p95"]} for ts in self._time_series],
            user_sessions=len(self._users),
            peak_users=max(len(self._users), 1),
        )


# Convenience function
async def run_stress_test(
    base_url: str,
    scenario: str = "load",
    users: int = 10,
    duration_seconds: int = 60,
    **kwargs,
) -> StressTestReport:
    """Run a stress test with simple parameters."""
    config = StressConfig(
        base_url=base_url,
        scenario=scenario,
        users=users,
        duration_seconds=duration_seconds,
        **kwargs,
    )
    orchestrator = StressOrchestrator(config)
    return await orchestrator.run()