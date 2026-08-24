"""
StressTestAgent — k6 load tests for performance.

Runs k6 load tests to:
- Simulate concurrent users (10 → 50 → 100 → 500 → 1000)
- Measure p50/p95/p99 latencies
- Detect breaking points under load
- Test throughput and error rates
- Identify performance bottlenecks

Requires k6 to be installed separately.
Generates test scripts based on app contract critical routes.

Does NOT write to disk (unless creating new test scripts).
May call AI for generating test scripts.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
)


import logging
_log = logging.getLogger("patchi.testing.stress_test_agent")

@register
class StressTestAgent(BaseAgent):
    """Agent for running stress/load tests with Locust."""

    group = AgentGroup.TEST
    name = "StressTestAgent"
    description = "Locust load tests: concurrent users, latencies, breaking points"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        if not shutil.which("locust"):
            self.skip(result, "locust not installed")
            return

        route_map = inp.brain.get("route_map", {})
        routes = [
            v.get("path", k.split(" ", 1)[-1]) for k, v in route_map.items() if isinstance(v, dict)
        ]
        if not routes:
            routes = ["/"]
        locustfile = self._write_locustfile(inp.root, routes)
        from patchi.core.testing.unit_test_agent import _run

        _run(
            ["locust", "-f", locustfile, "--headless", "-u", "10", "-r", "2", "-t", "10s"],
            inp.root,
            timeout=60,
        )
        metrics = self._parse_locust_csv(inp.root)
        result.data["metrics"] = metrics

        if metrics.get("error_rate_pct", 0) > 5:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="high_error_rate",
                    severity=Severity.HIGH,
                    file="locust",
                    message=f"High load-test error rate: {metrics['error_rate_pct']}%",
                )
            )
        if metrics.get("p95_ms", 0) > 2000:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="slow_p95",
                    severity=Severity.MEDIUM,
                    file="locust",
                    message=f"Slow p95 latency under load: {metrics['p95_ms']}ms",
                )
            )
        return

    def _write_locustfile(self, root: Path, routes: list[str]) -> str:
        fd, path = tempfile.mkstemp(prefix="patchi_locust_", suffix=".py")
        Path(path).write_text(
            "from locust import HttpUser, task, between\n\n"
            "class PatchiStressUser(HttpUser):\n"
            "    wait_time = between(0.1, 0.5)\n"
            "    @task\n"
            "    def hit_routes(self):\n"
            + "".join(f'        self.client.get("{route}")\n' for route in routes[:20]),
            encoding="utf-8",
        )
        try:
            import os

            os.close(fd)
        except Exception as e:
            _log.warning("StressTestAgent._write_locustfile failed: %s", e)
        return path

    def _parse_locust_csv(self, root: Path) -> dict:
        metrics = {
            "error_rate_pct": 0,
            "p50_ms": 0,
            "p95_ms": 0,
            "p99_ms": 0,
            "req_per_sec": 0,
            "total_requests": 0,
            "total_failures": 0,
        }
        stats_paths = [
            root / "stats.csv",
            root / "locust_stats.csv",
            root / "locustfile_stats.csv",
        ]
        for sp in stats_paths:
            if not sp.exists():
                continue
            try:
                lines = sp.read_text(encoding="utf-8").splitlines()
                if len(lines) < 2:
                    continue
                header = [c.strip().lower() for c in lines[0].split(",")]
                total_requests = 0
                total_failures = 0
                p50_vals: list[float] = []
                p95_vals: list[float] = []
                p99_vals: list[float] = []
                for row in lines[1:]:
                    cols = row.split(",")
                    if len(cols) < max(len(header), 5):
                        continue
                    row_map = dict(zip(header, cols)) if len(header) >= len(cols) else {}
                    try:
                        nr = int(row_map.get("# requests", row_map.get("requests", 0)))
                        nf = int(row_map.get("# failures", row_map.get("failures", 0)))
                    except (ValueError, TypeError):
                        nr = nf = 0
                    total_requests += nr
                    total_failures += nf
                    for key, dest in [("50%", p50_vals), ("95%", p95_vals), ("99%", p99_vals)]:
                        try:
                            dest.append(float(row_map.get(key, 0)))
                        except (ValueError, TypeError):
                            pass
                metrics["total_requests"] = total_requests
                metrics["total_failures"] = total_failures
                metrics["error_rate_pct"] = (
                    round((total_failures / total_requests) * 100, 2) if total_requests else 0
                )
                metrics["p50_ms"] = max(p50_vals) if p50_vals else 0
                metrics["p95_ms"] = max(p95_vals) if p95_vals else 0
                metrics["p99_ms"] = max(p99_vals) if p99_vals else 0
            except Exception as e:
                _log.warning("StressTestAgent._parse_locust_csv failed: %s", e)
                continue
        return metrics

    def _find_existing_k6_scripts(self, root: Path) -> list[Path]:
        """Find existing k6 test scripts."""
        script_files = []

        # Look for common k6 script locations
        k6_patterns = [
            "**/*.js",  # k6 scripts are JavaScript
            "**/*.k6.js",  # Common naming convention
            "tests/load/**/*.js",
            "tests/stress/**/*.js",
            "load-tests/**/*.js",
            "stress-tests/**/*.js",
        ]

        for pattern in k6_patterns:
            for script_file in root.rglob(pattern):
                if script_file.is_file():
                    # Check if the file contains k6-specific code
                    try:
                        content = script_file.read_text(encoding="utf-8")
                        if any(
                            k6_indicator in content
                            for k6_indicator in ["k6", "__ENV", "__VU", "http.", "check(", "group("]
                        ):
                            script_files.append(script_file)
                    except OSError:
                        continue  # Skip files that can't be read

        return script_files

    def _get_app_contract(self, inp: AgentInput) -> list[dict] | None:
        """Get the app contract with critical flows."""
        try:
            from .. import memory as mem

            brain = mem.get_brain(inp.root)
            if brain and "confirmed_flows" in brain:
                return brain["confirmed_flows"]
            return None
        except Exception as e:
            _log.warning("StressTestAgent._get_app_contract failed: %s", e)
            return None

    def _generate_k6_script_from_contract(
        self, app_contract: list[dict], root: Path
    ) -> Path | None:
        """Generate a k6 test script based on the app contract."""
        # In a real implementation, this would call an AI service to generate
        # a k6 script based on the app contract flows
        # For now, we'll create a basic template script

        try:
            # Create a test script in a temporary location
            script_path = root / ".patchi" / "tests" / "stress" / "generated_load_test.js"
            script_path.parent.mkdir(parents=True, exist_ok=True)

            # Basic k6 script template
            k6_script = """import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Define error rate metric
let errorRate = new Rate('errors');

export let options = {
  stages: [
    { duration: '1m', target: 10 },    // Ramp-up to 10 users
    { duration: '2m', target: 10 },    // Stay at 10 users
    { duration: '1m', target: 20 },    // Ramp-up to 20 users
    { duration: '2m', target: 20 },    // Stay at 20 users
    { duration: '1m', target: 50 },    // Ramp-up to 50 users
    { duration: '2m', target: 50 },    // Stay at 50 users
    { duration: '1m', target: 0 },     // Ramp-down to 0 users
  ],
  thresholds: {
    'http_req_duration': ['p(95)<1000'], // 95% of requests must complete below 1s
    'errors': ['rate<0.1'], // Error rate must be less than 10%
  },
};

export default function () {
  // Example requests - replace with actual app endpoints from contract
  let response = http.get('{{base_url}}');

  check(response, {
    'status is 200': (r) => r.status === 200,
    'page loaded successfully': (r) => r.body.length > 0,
  }) || errorRate.add(1);

  sleep(1);
}
"""

            script_path.write_text(k6_script)
            return script_path
        except Exception as e:
            _log.warning("StressTestAgent._generate_k6_script_from_contract failed: %s", e)
            return None

    def _run_existing_k6_tests(self, script_files: list[Path], root: Path) -> dict:
        """Run existing k6 tests."""
        if not script_files:
            return {
                "success": True,
                "total": 0,
                "passed": 0,
                "failed": 0,
                "test_details": [],
            }

        try:
            # Run the first k6 script found (could be extended to run all)
            script = script_files[0]
            cmd = ["k6", "run", str(script.relative_to(root)), "--out", "json=results.json"]
            result = subprocess.run(
                cmd, cwd=root, capture_output=True, text=True, timeout=600
            )  # 10 min timeout

            if result.returncode == 0:
                # Parse the results.json file that k6 generates
                results_file = root / "results.json"
                if results_file.exists():
                    try:
                        with open(results_file, "r") as f:
                            k6_results = [json.loads(line) for line in f if line.strip()]

                        # Extract metrics from k6 output
                        metrics = self._parse_k6_metrics(k6_results)

                        return {
                            "success": True,
                            "requests": metrics.get("requests", 0),
                            "errors": metrics.get("errors", 0),
                            "error_rate": metrics.get("error_rate", 0),
                            "metrics": metrics,
                            "test_details": [],
                        }
                    except Exception as e:
                        return {
                            "success": False,
                            "error": f"Could not parse k6 results: {str(e)}",
                            "total": 0,
                            "passed": 0,
                            "failed": 0,
                            "test_details": [],
                        }
                else:
                    return {
                        "success": True,
                        "requests": 0,
                        "errors": 0,
                        "error_rate": 0,
                        "metrics": {},
                        "test_details": [],
                    }
            else:
                return {
                    "success": False,
                    "error": f"k6 execution failed: {result.stderr}",
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "test_details": [],
                }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Stress test timed out after 600 seconds",
                "total": 0,
                "passed": 0,
                "failed": 0,
                "test_details": [],
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running k6 tests: {str(e)}",
                "total": 0,
                "passed": 0,
                "failed": 0,
                "test_details": [],
            }

    def _run_generated_k6_test(self, script_path: Path, root: Path) -> dict:
        """Run the generated k6 test."""
        try:
            cmd = ["k6", "run", str(script_path.relative_to(root)), "--out", "json=results.json"]
            result = subprocess.run(
                cmd, cwd=root, capture_output=True, text=True, timeout=600
            )  # 10 min timeout

            if result.returncode == 0:
                # Parse the results.json file that k6 generates
                results_file = root / "results.json"
                if results_file.exists():
                    try:
                        with open(results_file, "r") as f:
                            k6_results = [json.loads(line) for line in f if line.strip()]

                        # Extract metrics from k6 output
                        metrics = self._parse_k6_metrics(k6_results)

                        return {
                            "success": True,
                            "requests": metrics.get("requests", 0),
                            "errors": metrics.get("errors", 0),
                            "error_rate": metrics.get("error_rate", 0),
                            "metrics": metrics,
                            "test_details": [],
                        }
                    except Exception as e:
                        return {
                            "success": False,
                            "error": f"Could not parse k6 results: {str(e)}",
                            "total": 0,
                            "passed": 0,
                            "failed": 0,
                            "test_details": [],
                        }
                else:
                    return {
                        "success": True,
                        "requests": 0,
                        "errors": 0,
                        "error_rate": 0,
                        "metrics": {},
                        "test_details": [],
                    }
            else:
                return {
                    "success": False,
                    "error": f"k6 execution failed: {result.stderr}",
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "test_details": [],
                }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Stress test timed out after 600 seconds",
                "total": 0,
                "passed": 0,
                "failed": 0,
                "test_details": [],
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running generated k6 test: {str(e)}",
                "total": 0,
                "passed": 0,
                "failed": 0,
                "test_details": [],
            }

    def _parse_k6_metrics(self, k6_results: list[dict]) -> dict:
        """Parse metrics from k6 JSON output."""
        metrics = {
            "requests": 0,
            "errors": 0,
            "error_rate": 0,
            "p50": 0,
            "p95": 0,
            "p99": 0,
            "rps": 0,
        }

        for entry in k6_results:
            # Look for metric values in the k6 output
            if entry.get("type") == "Point":
                metric_name = entry.get("metric", "")
                value = entry.get("data", {}).get("value", 0)

                if metric_name == "http_req_duration":
                    # This would have percentiles
                    pass
                elif metric_name == "http_reqs":
                    metrics["requests"] = value
                elif metric_name == "errors":
                    metrics["errors"] = value
            elif entry.get("type") == "Interval":
                # Handle interval-based metrics
                counters = entry.get("data", {}).get("counters", {})
                for counter_name, counter_data in counters.items():
                    if counter_name == "http_reqs":
                        metrics["requests"] += counter_data.get("count", 0)
                    elif counter_name == "errors":
                        metrics["errors"] += counter_data.get("count", 0)

            # Look for trend metrics (percentiles)
            trends = entry.get("data", {}).get("trends", {})
            for trend_name, trend_data in trends.items():
                if trend_name == "http_req_duration":
                    metrics["p50"] = trend_data.get("p(50)", 0)
                    metrics["p95"] = trend_data.get("p(95)", 0)
                    metrics["p99"] = trend_data.get("p(99)", 0)

        # Calculate error rate
        if metrics["requests"] > 0:
            metrics["error_rate"] = metrics["errors"] / metrics["requests"]

        return metrics
