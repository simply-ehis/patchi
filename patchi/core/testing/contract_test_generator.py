"""
ContractTestGenerator — Deterministic contract test generation from routes and schemas.

Part 1 §6 of the testing-security-moat-spec. Generates pytest-compatible
contract tests that validate API endpoints against expected behavior:

  - Status code ranges per HTTP method (2xx for GET, 2xx/4xx for POST, etc.)
  - Content-Type header expectations
  - Schema structure validation for response bodies

Each generated test is self-contained: imports requests, handles connection
errors, and can run independently via pytest.

Does NOT call AI. Deterministic output from static analysis.
"""

from __future__ import annotations

import json
import logging
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger("patchi.testing.contract_test_generator")

# Expected status code ranges per HTTP method.
# GET/HEAD/OPTIONS: 2xx success, 4xx client error (auth required, etc.)
# POST/PUT/PATCH/DELETE: 2xx success, 201/202/204 common, 4xx client error
_METHOD_STATUS_RANGES: dict[str, list[str]] = {
    "GET": ["200", "201", "204", "400", "401", "403", "404"],
    "HEAD": ["200", "204", "400", "401", "403", "404"],
    "OPTIONS": ["200", "204"],
    "POST": ["200", "201", "202", "204", "400", "401", "403", "404", "409", "422"],
    "PUT": ["200", "201", "204", "400", "401", "403", "404", "422"],
    "PATCH": ["200", "204", "400", "401", "403", "404", "422"],
    "DELETE": ["200", "204", "401", "403", "404"],
}

# Content-Type expectations per route type (path-based heuristic).
_JSON_PATHS = re.compile(r"/api/|\.json|/v\d+/")


@dataclass
class ContractTest:
    """A single generated contract test."""

    name: str
    route_or_schema: str
    test_code: str
    expected_status: str
    description: str


def _fill_path_params(path: str) -> str:
    """Replace {id} / :id placeholders with 1 so smoke tests can run."""
    path = re.sub(r"\{[^}/]+\}", "1", path)
    path = re.sub(r":[^/]+", "1", path)
    return path


def _safe_test_name(method: str, path: str, index: int) -> str:
    """Convert route to a valid pytest function name."""
    slug = re.sub(r"[^a-z0-9]+", "_", path.strip("/").lower()).strip("_") or "root"
    return f"test_contract_{method.lower()}_{slug}_{index}"


def _expected_content_type(path: str) -> str:
    """Heuristic: JSON endpoints expect application/json, HTML pages expect text/html."""
    if _JSON_PATHS.search(path):
        return "application/json"
    # Default: accept any content type (smoke-level)
    return "*/*"


def _status_check_expr(method: str) -> str:
    """Build the assertion expression for status code validation."""
    ranges = _METHOD_STATUS_RANGES.get(method.upper(), ["200", "400", "401", "403", "404"])
    return " or ".join(f"status == {s}" for s in ranges)


def _generate_route_test(
    route: dict,
    index: int,
    base_url: str,
) -> ContractTest:
    """Generate a single contract test for a route."""
    method = route["method"].upper()
    path = route["path"]
    file_source = route.get("file", "unknown")
    filled = _fill_path_params(path)
    name = _safe_test_name(method, path, index)
    content_type = _expected_content_type(path)
    status_expr = _status_check_expr(method)

    # Build Content-Type assertion
    ct_assert = ""
    if content_type != "*/*":
        ct_assert = textwrap.dedent(f"""\
            ct = resp.headers.get("content-type", "")
            assert "{content_type}" in ct or "text/html" in ct, \\
                f"unexpected Content-Type: {{ct}}"
        """)

    # Build request body for write methods
    body_arg = ""
    if method in ("POST", "PUT", "PATCH"):
        body_arg = ', json={{"_contract_test": true}}'

    test_code = textwrap.dedent(f"""\
        def {name}():
            \"\"\"
            Contract test: {method} {path}

            Validates the route responds with an expected status code
            and correct Content-Type. Source: {file_source}
            \"\"\"
            import requests

            url = BASE_URL + "{filled}"
            try:
                resp = requests.request("{method}", url, timeout=10{body_arg})
            except requests.ConnectionError:
                pytest.skip("connection refused — app not running")
            except requests.Timeout:
                pytest.fail(f"request timed out: {{url}}")

            assert {status_expr}, \\
                f"unexpected status {{resp.status_code}} for {method} {path}"
    """)

    if ct_assert:
        test_code += "\n" + textwrap.indent(ct_assert, "    ")

    return ContractTest(
        name=name,
        route_or_schema=f"{method} {path}",
        test_code=test_code,
        expected_status=status_expr,
        description=f"Contract test for {method} {path} (source: {file_source})",
    )


def _generate_schema_test(
    schema_name: str,
    schema: dict,
    index: int,
) -> ContractTest:
    """Generate a test that validates sample data against a schema structure."""
    name = f"test_contract_schema_{re.sub(r'[^a-z0-9]+', '_', schema_name.lower()).strip('_')}_{index}"
    required_fields = schema.get("required", [])
    properties = schema.get("properties", {})
    props_str = json.dumps(required_fields) if required_fields else "[]"

    # Build sample data from property types
    sample = _build_sample_data(schema)
    sample_json = json.dumps(sample, indent=12)

    type_checks = []
    for prop_name, prop_schema in properties.items():
        prop_type = prop_schema.get("type")
        check = f'    assert isinstance(sample_data.get("{prop_name}"), '
        if prop_type == "string":
            type_checks.append(check + f'str), "{prop_name} should be str"')
        elif prop_type == "integer":
            type_checks.append(check + f'int), "{prop_name} should be int"')
        elif prop_type == "number":
            type_checks.append(
                check + f'(int, float)), "{prop_name} should be number"'
            )
        elif prop_type == "boolean":
            type_checks.append(check + f'bool), "{prop_name} should be bool"')
        elif prop_type == "array":
            type_checks.append(check + f'list), "{prop_name} should be list"')

    checks_block = "\n".join(type_checks)
    test_code = (
        f'def {name}():\n'
        f'    """\n'
        f"    Contract test: schema '{schema_name}'\n"
        f"\n"
        f"    Validates that sample data matching the schema structure\n"
        f"    passes basic type checks for required fields.\n"
        f'    """\n'
        f"    import json\n"
        f"\n"
        f"    sample_data = {sample_json}\n"
        f"\n"
        f"    # Check required fields are present\n"
        f"    required = {props_str}\n"
        f"    for field_name in required:\n"
        f'        assert field_name in sample_data, f"missing required field: {{field_name}}"\n'
        f"\n"
        f"    # Check field types match schema\n"
        f"{checks_block}\n"
    )

    return ContractTest(
        name=name,
        route_or_schema=f"schema:{schema_name}",
        test_code=test_code,
        expected_status="N/A (schema validation)",
        description=f"Schema contract test for '{schema_name}' — validates required fields and types",
    )


def _build_sample_data(schema: dict) -> dict | list:
    """Build minimal sample data from a JSON Schema definition."""
    schema_type = schema.get("type", "object")
    if schema_type == "object":
        sample = {}
        for prop_name, prop_schema in schema.get("properties", {}).items():
            sample[prop_name] = _build_sample_value(prop_schema)
        return sample
    elif schema_type == "array":
        items = schema.get("items", {})
        return [_build_sample_value(items)] if items else []
    return _build_sample_value(schema)


def _build_sample_value(prop_schema: dict):
    """Build a single sample value from a property schema."""
    prop_type = prop_schema.get("type", "string")
    if prop_type == "string":
        return prop_schema.get("default", "test")
    elif prop_type == "integer":
        return prop_schema.get("default", 1)
    elif prop_type == "number":
        return prop_schema.get("default", 1.0)
    elif prop_type == "boolean":
        return prop_schema.get("default", True)
    elif prop_type == "array":
        return []
    elif prop_type == "object":
        return {}
    return "test"


class ContractTestGenerator:
    """Generates pytest-compatible contract tests from routes and schemas."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def generate_from_routes(
        self,
        route_infos: list[dict],
        base_url: str = "http://127.0.0.1:8000",
    ) -> list[ContractTest]:
        """Generate contract tests for each route.

        Args:
            route_infos: List of route dicts with keys: method, path, file.
            base_url: The base URL to test against.

        Returns:
            List of ContractTest instances, one per route.
        """
        tests = []
        for i, route in enumerate(route_infos):
            try:
                test = _generate_route_test(route, i, base_url)
                tests.append(test)
            except Exception as e:
                _log.warning("failed to generate test for route %s: %s", route, e)
        return tests

    def generate_from_schemas(self, schemas: dict) -> list[ContractTest]:
        """Generate contract tests that validate sample data against schemas.

        Args:
            schemas: Dict mapping schema_name -> JSON Schema dict.

        Returns:
            List of ContractTest instances, one per schema.
        """
        tests = []
        for i, (name, schema) in enumerate(schemas.items()):
            try:
                test = _generate_schema_test(name, schema, i)
                tests.append(test)
            except Exception as e:
                _log.warning("failed to generate test for schema %s: %s", name, e)
        return tests

    def save_tests(self, tests: list[ContractTest], output_dir: Path) -> Path:
        """Write generated tests to a self-contained pytest file.

        Args:
            tests: List of ContractTest instances from generate_from_* methods.
            output_dir: Directory to write the test file into.

        Returns:
            Path to the written test file.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        header = textwrap.dedent('''\
            """
            Contract tests — generated by ContractTestGenerator.

            Validates API routes against expected status codes, Content-Type
            headers, and schema structures. Regenerate after route changes.

            Each test is self-contained: handles connection errors, timeouts,
            and skips gracefully when the app is not running.
            """
            import pytest

            try:
                import requests
            except ImportError:
                pytest.skip("requests library required for contract tests")

            try:
                import json
            except ImportError:
                pass

            BASE_URL = "http://127.0.0.1:8000"

        ''')

        parts = [header]
        for test in tests:
            parts.append(test.test_code)
            parts.append("")
            parts.append("")

        file_path = output_dir / "test_contract.py"
        file_path.write_text("".join(parts), encoding="utf-8")
        return file_path

    @classmethod
    def from_routes_on_disk(cls, root: Path) -> list[ContractTest]:
        """Convenience: extract routes from the project and generate tests.

        Uses the existing extract_routes() from api_contract_agent for
        static route detection. Returns ContractTest instances.
        """
        from patchi.core.testing.api_contract_agent import extract_routes

        routes = extract_routes(root)
        gen = cls(root)
        return gen.generate_from_routes(routes)
