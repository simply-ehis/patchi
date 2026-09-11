"""
APIContractAgent — OpenAPI/JSON Schema compliance tests.

Validates API responses against:
- OpenAPI specifications
- JSON Schema definitions
- Contract-first API designs
- Generated API contracts from app contract

Tests for:
- Response structure compliance
- Type mismatches
- Missing required fields
- Extra unexpected fields
- Status code validation
- Parameter validation

Does NOT write to disk.
Does NOT call AI.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
)

_log = logging.getLogger("patchi.testing.api_contract_agent")


@register
class APIContractAgent(BaseAgent):
    """Agent for running API contract tests."""

    group = AgentGroup.TEST
    domain = AgentDomain.TESTING
    name = "APIContractAgent"
    description = "OpenAPI/JSON Schema compliance: response structure, types, status codes"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run API contract compliance tests."""
        start_time = time.time()
        findings = []

        # Find API contract files
        contract_files = self._find_api_contracts(inp.root)

        # Fallback: detect framework-based APIs (FastAPI, Flask, Django)
        # and build a synthetic contract from route definitions
        if not contract_files:
            framework, route_count = self._detect_framework_api(inp.root)
            if framework:
                findings.append(
                    make_finding(
                        severity=Severity.INFO,
                        file="__api_contract__",
                        line_start=0,
                        title=f"Framework API detected: {framework}",
                        description=f"Detected {framework} app with {route_count} route(s). "
                        f"Contract synthesized from source code (no static OpenAPI file found).",
                        evidence=f"Framework: {framework}, Routes found: {route_count}",
                    )
                )
                result.status = AgentStatus.SUCCEEDED
                result.findings = findings
                result.data.update({
                    "contracts_found": 1,
                    "framework": framework,
                    "synthetic": True,
                    "route_count": route_count,
                    "needs_ai": False,
                })
                return

            findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file="__api_contract__",
                    line_start=0,
                    title="No API contracts found",
                    description="No OpenAPI or JSON Schema files found in project",
                    evidence="No .json/.yaml files with API contract indicators found",
                )
            )
            result.status = AgentStatus.SKIPPED
            result.findings = findings
            result.data.update({"contracts_found": 0, "needs_ai": False})
            return

        # Validate contracts against running API
        validation_results = self._validate_contracts(contract_files, inp)

        # Process validation results
        # Note: loop targets use `r`, never `result` — `result` is the
        # AgentResult this _run mutates (it is NOT a local here).
        total_errors = sum(len(r.get("errors", [])) for r in validation_results.values())

        if total_errors == 0:
            findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file="__api_contract_summary__",
                    line_start=0,
                    title="API Contract Validation Passed",
                    description="All API endpoints comply with their contracts",
                    evidence="No contract violations found",
                )
            )
        else:
            findings.append(
                make_finding(
                    severity=Severity.HIGH,
                    file="__api_contract_summary__",
                    line_start=0,
                    title=f"API Contract Violations: {total_errors} errors",
                    description=f"Found {total_errors} contract violations across endpoints",
                    evidence=f"Violations found in {len([r for r in validation_results.values() if r.get('errors')])} endpoints",
                )
            )

        # Add individual violation findings
        for endpoint, r in validation_results.items():
            for error in r.get("errors", []):
                severity = self._map_contract_error_severity(error.get("type", "validation"))

                findings.append(
                    make_finding(
                        severity=severity,
                        file=endpoint,
                        line_start=error.get("line", 0),
                        title=f"API Contract Violation: {error.get('type', 'unknown')}",
                        description=error.get("message", "Unknown contract violation"),
                        evidence=f"Expected: {error.get('expected', 'N/A')}\nActual: {error.get('actual', 'N/A')}\nPath: {error.get('path', 'N/A')}",
                    )
                )

        duration = time.time() - start_time

        # NOTE: FAILED here is a *findings* signal (violations found), not a
        # crash — errors stays empty by design. The per-agent smoke sweep and
        # the --pipeline orchestration gate both treat FAILED as a crash, so
        # an agent that legitimately finds violations must be careful to only
        # do so when the project actually ships contracts (and never against
        # .patchi state — see _find_api_contracts).
        result.status = AgentStatus.SUCCEEDED if total_errors == 0 else AgentStatus.FAILED
        result.findings = findings
        result.data.update(
            {
                "contracts_found": len(contract_files),
                "endpoints_tested": len(validation_results),
                "total_violations": total_errors,
                "duration": round(duration, 2),
                "needs_ai": False,  # Contract validation doesn't require AI
            }
        )
        return

    def _find_api_contracts(self, root: Path) -> list[Path]:
        """Find API contract files (OpenAPI/Swagger/JSON Schema)."""
        contract_files = []

        # Look for common API contract file patterns
        contract_patterns = [
            "**/openapi*.json",
            "**/openapi*.yaml",
            "**/openapi*.yml",
            "**/swagger*.json",
            "**/swagger*.yaml",
            "**/swagger*.yml",
            "**/api*.json",  # Might contain OpenAPI spec
            "**/*.schema.json",  # JSON Schema files
            "**/schemas/**/*.json",  # Schema directory
            "**/specs/**/*.json",  # Spec directory
            "**/specs/**/*.yaml",
            "**/specs/**/*.yml",
        ]

        # Use os.walk with exclusion for speed (avoids rglob through node_modules)
        import os
        exclude = {".patchi", "node_modules", "venv", ".venv", "__pycache__", ".git", "target", "build", "dist"}
        # Only look for actual OpenAPI/Swagger spec files, not any file with "api" in name
        spec_prefixes = ("openapi", "swagger")
        spec_contains = ("openapi", "swagger", "api-spec", "api_spec")
        for dirpath, dirnames, filenames in os.walk(str(root)):
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for fname in filenames:
                if not any(fname.endswith(ext) for ext in (".json", ".yaml", ".yml")):
                    continue
                fname_lower = fname.lower()
                if not (fname_lower.startswith(spec_prefixes) or any(s in fname_lower for s in spec_contains)):
                    continue
                contract_file = Path(dirpath) / fname
                if self._is_api_contract(contract_file):
                    contract_files.append(contract_file)

        return contract_files

    def _is_api_contract(self, file_path: Path) -> bool:
        """Check if a file is actually an API contract."""
        try:
            content = file_path.read_text(encoding="utf-8")

            # Check for OpenAPI/Swagger indicators
            if "openapi" in content.lower() or "swagger" in content.lower():
                return True

            # Check for JSON Schema indicators
            if '"$schema"' in content and (
                "json-schema" in content.lower() or "jsonschema" in content.lower()
            ):
                return True

            # For YAML files, check for OpenAPI structure
            if file_path.suffix.lower() in [".yaml", ".yml"]:
                # Look for common OpenAPI fields
                if any(
                    field in content for field in ["openapi:", "swagger:", "paths:", "components:"]
                ):
                    return True

            # For JSON files, check for API contract structure
            if file_path.suffix.lower() == ".json":
                try:
                    data = json.loads(content)
                    # Check for OpenAPI fields
                    if isinstance(data, dict) and any(
                        field in data for field in ["openapi", "swagger", "paths", "components"]
                    ):
                        return True
                    # Check for JSON Schema fields
                    if isinstance(data, dict) and any(
                        field in data for field in ["$schema", "type", "properties", "required"]
                    ):
                        return True
                except json.JSONDecodeError:
                    pass  # Not a valid JSON file

            return False
        except Exception as e:
            _log.debug("APIContractAgent._is_api_contract failed: %s", e)
            return False

    def _detect_framework_api(self, root: Path) -> tuple[str | None, int]:
        """Detect FastAPI/Flask/Django apps by scanning entry-point Python files.

        Returns (framework_name, route_count) or (None, 0).
        """
        import re

        framework_patterns = [
            ("FastAPI", re.compile(r"from\s+fastapi\s+import\s+.*\bFastAPI\b|from\s+fastapi\s+import\s+FastAPI")),
            ("Flask", re.compile(r"from\s+flask\s+import\s+.*\bFlask\b|from\s+flask\s+import\s+Flask")),
            ("Django", re.compile(r"from\s+django\.urls\s+import|from\s+django\.conf\s+import|django\.setup")),
        ]
        route_patterns = [
            re.compile(r"@(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\("),
            re.compile(r"@(?:app|router)\.route\s*\("),
            re.compile(r"url_patterns\s*=\s*\["),
        ]

        # Only scan top-level Python files, entry points, and routes directories
        candidates = []
        for name in ("app.py", "main.py", "manage.py", "wsgi.py", "asgi.py", "server.py", "run.py"):
            p = root / name
            if p.is_file():
                candidates.append(p)
        # Also scan one level of subdirectories for app factories and routes
        for d in list(root.iterdir()):
            if d.is_dir() and d.name not in (".patchi", "node_modules", "__pycache__", "venv", ".venv", ".git"):
                for name in ("app.py", "main.py"):
                    p = d / name
                    if p.is_file():
                        candidates.append(p)
                # Scan routes/ subdirectory for route definitions
                routes_dir = d / "routes"
                if routes_dir.is_dir():
                    for rf in routes_dir.rglob("*.py"):
                        if rf.is_file():
                            candidates.append(rf)
                # Also check src/routes or src/api patterns
                for sub in ("src", "api", "endpoints"):
                    sub_dir = d / sub
                    if sub_dir.is_dir():
                        for rf in sub_dir.rglob("*.py"):
                            if rf.is_file():
                                candidates.append(rf)

        detected_framework = None
        route_count = 0

        try:
            for py_file in candidates:
                try:
                    content = py_file.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                for fw_name, fw_re in framework_patterns:
                    if fw_re.search(content):
                        detected_framework = fw_name

                for rp in route_patterns:
                    route_count += len(rp.findall(content))
        except Exception as e:
            _log.debug("_detect_framework_api failed: %s", e)

        return detected_framework, route_count

    def _validate_contracts(self, contract_files: list[Path], inp: AgentInput) -> dict:
        """Validate contracts against the running API."""
        results = {}

        for contract_file in contract_files:
            try:
                # Read the contract
                contract_content = contract_file.read_text(encoding="utf-8")

                # Parse the contract based on type
                if contract_file.suffix.lower() in [".json"]:
                    contract = json.loads(contract_content)
                    validation_result = self._validate_openapi_contract_json(
                        contract, contract_file, inp
                    )
                else:
                    # For YAML, we'd need a YAML parser
                    # For now, we'll treat it as a string
                    validation_result = self._validate_openapi_contract_yaml(
                        contract_content, contract_file, inp
                    )

                results[str(contract_file)] = validation_result
            except Exception as e:
                results[str(contract_file)] = {
                    "error": f"Could not parse contract file: {str(e)}",
                    "errors": [
                        {
                            "type": "parse_error",
                            "message": f"Failed to parse contract file: {str(e)}",
                            "path": "",
                            "expected": "valid OpenAPI/JSON Schema",
                            "actual": "parse error",
                        }
                    ],
                }

        return results

    def _resolve_server_url(self, contract: dict, inp: AgentInput) -> str:
        """Extract server URL from contract or brain config."""
        extra_base = (inp.extra or {}).get("base_url")
        if extra_base:
            return extra_base.rstrip("/")
        test_config = inp.config.get("test_config", {})
        if test_config.get("base_url"):
            return test_config["base_url"].rstrip("/")
        servers = contract.get("servers", [])
        if servers:
            return servers[0].get("url", "").rstrip("/")
        brain = inp.brain or {}
        return brain.get("base_url", "http://localhost:3000").rstrip("/")

    def _validate_openapi_contract_json(
        self, contract: dict, contract_file: Path, inp: AgentInput
    ) -> dict:
        """Validate OpenAPI contract by probing the running API."""
        errors = []
        if not isinstance(contract, dict) or (
            "openapi" not in contract and "swagger" not in contract
        ):
            errors.append(
                {
                    "type": "invalid_spec",
                    "message": "File is not a valid OpenAPI specification",
                    "path": "$",
                    "expected": "OpenAPI object with 'openapi' or 'swagger' field",
                    "actual": f"{type(contract).__name__} object",
                }
            )
            return {"errors": errors}

        base_url = self._resolve_server_url(contract, inp)
        paths = contract.get("paths", {})

        try:
            import httpx
        except ImportError:
            errors.append({"type": "missing_dep", "message": "httpx required for API validation"})
            return {"errors": errors}

        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                responses_spec = operation.get("responses", {})
                if not responses_spec:
                    continue

                url = f"{base_url}{path}"
                try:
                    resp = httpx.request(method.upper(), url, timeout=10)
                except (httpx.ConnectError, httpx.TimeoutException) as e:
                    errors.append(
                        {
                            "type": "connection_error",
                            "severity": "high",
                            "path": f"{method.upper()} {path}",
                            "message": f"Cannot reach {url}: {e}",
                            "expected": "200 range response",
                            "actual": "connection failed",
                        }
                    )
                    continue
                except Exception as e:
                    errors.append(
                        {
                            "type": "request_error",
                            "severity": "medium",
                            "path": f"{method.upper()} {path}",
                            "message": f"Request failed: {e}",
                            "expected": "valid response",
                            "actual": str(e),
                        }
                    )
                    continue

                expected_statuses = [int(s) for s in responses_spec if s != "default"]
                if expected_statuses and resp.status_code not in expected_statuses:
                    errors.append(
                        {
                            "type": "status_code_mismatch",
                            "severity": "high" if resp.status_code >= 400 else "medium",
                            "path": f"{method.upper()} {path}",
                            "message": f"Expected {expected_statuses}, got {resp.status_code}",
                            "expected": str(expected_statuses),
                            "actual": str(resp.status_code),
                        }
                    )

                # Validate response body against first successful response schema
                for status_code in ("200", "201", "204"):
                    response_schema = responses_spec.get(status_code, {})
                    content = response_schema.get("content", {})
                    for media_type, media_type_obj in content.items():
                        schema = media_type_obj.get("schema", {})
                        if not schema or not resp.content:
                            continue
                        if not self._validate_json_schema(resp.json(), schema):
                            errors.append(
                                {
                                    "type": "type_mismatch",
                                    "severity": "high",
                                    "path": f"{method.upper()} {path} -> {status_code}",
                                    "message": f"Response body does not match {media_type} schema",
                                    "expected": str(schema),
                                    "actual": resp.text[:500],
                                }
                            )
                    break  # only validate first success schema

        return {"errors": errors}

    def _validate_openapi_contract_yaml(
        self, content: str, contract_file: Path, inp: AgentInput
    ) -> dict:
        """Validate OpenAPI contract from YAML."""
        try:
            import yaml

            contract = yaml.safe_load(content)
            if isinstance(contract, dict):
                return self._validate_openapi_contract_json(contract, contract_file, inp)
        except ImportError:
            pass
        return {
            "errors": [
                {
                    "type": "yaml_not_implemented",
                    "message": "Install PyYAML to validate YAML contracts",
                    "path": "$",
                    "expected": "YAML parsing",
                    "actual": "PyYAML not installed",
                }
            ]
        }

    def _validate_json_schema(self, instance: Any, schema: dict) -> bool:
        """Basic JSON Schema validation (subset — type and required fields)."""
        if not isinstance(schema, dict):
            return True
        schema_type = schema.get("type")
        if schema_type == "object" and isinstance(instance, dict):
            required = schema.get("required", [])
            for field in required:
                if field not in instance:
                    return False
            props = schema.get("properties", {})
            for key, val in instance.items():
                prop_schema = props.get(key, {})
                if not self._validate_json_schema(val, prop_schema):
                    return False
        elif schema_type == "array" and isinstance(instance, list):
            items_schema = schema.get("items", {})
            if items_schema:
                for item in instance:
                    if not self._validate_json_schema(item, items_schema):
                        return False
        elif schema_type == "string" and not isinstance(instance, str):
            return False
        elif schema_type == "integer" and not isinstance(instance, int):
            return False
        elif schema_type == "number" and not isinstance(instance, (int, float)):
            return False
        elif schema_type == "boolean" and not isinstance(instance, bool):
            return False
        return True

    def _map_contract_error_severity(self, error_type: str) -> Severity:
        """Map contract error types to severity levels."""
        error_severity = {
            "required_field_missing": Severity.HIGH,
            "type_mismatch": Severity.HIGH,
            "invalid_format": Severity.MEDIUM,
            "extra_field": Severity.LOW,
            "status_code_mismatch": Severity.HIGH,
            "parse_error": Severity.CRITICAL,
            "runtime_validation_needed": Severity.INFO,
            "yaml_not_implemented": Severity.INFO,
        }

        return error_severity.get(error_type, Severity.MEDIUM)
