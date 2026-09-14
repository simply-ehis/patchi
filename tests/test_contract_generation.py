"""Tests for ContractTestGenerator — contract test generation from routes and schemas."""

from __future__ import annotations

import tempfile
from pathlib import Path

from patchi.core.testing.contract_test_generator import (
    ContractTest,
    ContractTestGenerator,
    _build_sample_data,
    _expected_content_type,
    _fill_path_params,
    _generate_route_test,
    _generate_schema_test,
    _safe_test_name,
    _status_check_expr,
)


def _make_route(
    method: str = "GET",
    path: str = "/items",
    file: str = "routes/items.py",
) -> dict:
    return {"method": method, "path": path, "file": file}


def _make_schema(name: str = "User", props: dict | None = None) -> dict:
    props = props or {
        "id": {"type": "integer"},
        "name": {"type": "string"},
        "active": {"type": "boolean"},
    }
    return {
        name: {
            "type": "object",
            "required": list(props.keys()),
            "properties": props,
        }
    }


# ── Unit tests: helpers ─────────────────────────────────────────────────────


def test_fill_path_params_replaces_placeholders():
    assert _fill_path_params("/items/{item_id}") == "/items/1"
    assert _fill_path_params("/users/:id/posts") == "/users/1/posts"
    assert _fill_path_params("/plain") == "/plain"
    assert _fill_path_params("/items/{id}/comments/{cid}") == "/items/1/comments/1"


def test_safe_test_name_produces_valid_identifier():
    name = _safe_test_name("GET", "/items/{item_id}", 0)
    assert name.startswith("test_contract_")
    assert name.isidentifier()


def test_safe_test_name_root_slash():
    name = _safe_test_name("GET", "/", 5)
    assert name == "test_contract_get_root_5"


def test_expected_content_type_json_path():
    assert _expected_content_type("/api/items") == "application/json"
    assert _expected_content_type("/v2/users") == "application/json"
    assert _expected_content_type("/items.json") == "application/json"


def test_expected_content_type_html_path():
    assert _expected_content_type("/dashboard") == "*/*"
    assert _expected_content_type("/settings") == "*/*"


def test_status_check_expr_get():
    expr = _status_check_expr("GET")
    assert "status == 200" in expr
    assert "status == 404" in expr


def test_status_check_expr_post():
    expr = _status_check_expr("POST")
    assert "status == 201" in expr
    assert "status == 422" in expr


def test_build_sample_data_object():
    schema = {
        "type": "object",
        "required": ["id", "name"],
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
        },
    }
    sample = _build_sample_data(schema)
    assert isinstance(sample, dict)
    assert "id" in sample
    assert "name" in sample
    assert isinstance(sample["id"], int)
    assert isinstance(sample["name"], str)


def test_build_sample_data_array():
    schema = {"type": "array", "items": {"type": "string"}}
    sample = _build_sample_data(schema)
    assert isinstance(sample, list)


# ── Unit tests: test generation ─────────────────────────────────────────────


def test_generate_route_test_produces_valid_python():
    route = _make_route("GET", "/items")
    test = _generate_route_test(route, 0, "http://127.0.0.1:8000")
    assert isinstance(test, ContractTest)
    assert test.name.startswith("test_contract_")
    assert "def " in test.test_code
    # Must compile
    compile(test.test_code, "<test>", "exec")


def test_generate_route_test_post_includes_body():
    route = _make_route("POST", "/items")
    test = _generate_route_test(route, 0, "http://127.0.0.1:8000")
    assert "json=" in test.test_code
    assert "requests.request" in test.test_code
    compile(test.test_code, "<test>", "exec")


def test_generate_route_test_connection_error_handling():
    route = _make_route("GET", "/health")
    test = _generate_route_test(route, 0, "http://127.0.0.1:8000")
    assert "ConnectionError" in test.test_code
    assert "Timeout" in test.test_code
    assert "pytest.skip" in test.test_code


def test_generate_route_test_content_type_assertion():
    route = _make_route("GET", "/api/items")
    test = _generate_route_test(route, 0, "http://127.0.0.1:8000")
    assert "content-type" in test.test_code.lower() or "content_type" in test.test_code.lower()
    compile(test.test_code, "<test>", "exec")


def test_generate_schema_test_produces_valid_python():
    schemas = _make_schema("User")
    name, schema = next(iter(schemas.items()))
    test = _generate_schema_test(name, schema, 0)
    assert isinstance(test, ContractTest)
    assert "required" in test.test_code
    compile(test.test_code, "<test>", "exec")


def test_generate_schema_test_checks_types():
    schemas = _make_schema("Item", {"count": {"type": "integer"}, "label": {"type": "string"}})
    name, schema = next(iter(schemas.items()))
    test = _generate_schema_test(name, schema, 0)
    assert "isinstance" in test.test_code


# ── Integration tests: ContractTestGenerator ────────────────────────────────


def test_generator_from_routes():
    root = Path(tempfile.mkdtemp())
    gen = ContractTestGenerator(root)
    routes = [
        _make_route("GET", "/items"),
        _make_route("POST", "/items"),
        _make_route("GET", "/items/{item_id}"),
    ]
    tests = gen.generate_from_routes(routes)
    assert len(tests) == 3
    assert all(isinstance(t, ContractTest) for t in tests)
    assert tests[0].name != tests[1].name


def test_generator_from_schemas():
    root = Path(tempfile.mkdtemp())
    gen = ContractTestGenerator(root)
    schemas = {
        "User": {
            "type": "object",
            "required": ["id", "name"],
            "properties": {"id": {"type": "integer"}, "name": {"type": "string"}},
        },
        "Item": {
            "type": "object",
            "required": ["title"],
            "properties": {"title": {"type": "string"}},
        },
    }
    tests = gen.generate_from_schemas(schemas)
    assert len(tests) == 2
    assert all("schema" in t.route_or_schema for t in tests)


def test_generator_from_routes_empty():
    root = Path(tempfile.mkdtemp())
    gen = ContractTestGenerator(root)
    tests = gen.generate_from_routes([])
    assert tests == []


def test_generator_from_schemas_empty():
    root = Path(tempfile.mkdtemp())
    gen = ContractTestGenerator(root)
    tests = gen.generate_from_schemas({})
    assert tests == []


def test_save_tests_writes_file():
    root = Path(tempfile.mkdtemp())
    gen = ContractTestGenerator(root)
    routes = [_make_route("GET", "/items")]
    tests = gen.generate_from_routes(routes)

    out_dir = root / ".patchi" / "generated_tests"
    path = gen.save_tests(tests, out_dir)

    assert path.exists()
    assert path.name == "test_contract.py"
    content = path.read_text(encoding="utf-8")
    assert "import pytest" in content
    assert "def test_contract_" in content
    assert "BASE_URL" in content


def test_save_tests_compiles():
    root = Path(tempfile.mkdtemp())
    gen = ContractTestGenerator(root)
    routes = [
        _make_route("GET", "/items"),
        _make_route("POST", "/items"),
    ]
    schemas = _make_schema("User")
    tests = gen.generate_from_routes(routes) + gen.generate_from_schemas(schemas)

    out_dir = root / "tests"
    path = gen.save_tests(tests, out_dir)
    content = path.read_text(encoding="utf-8")
    compile(content, str(path), "exec")


def test_from_routes_on_disk():
    """Integration with existing extract_routes from api_contract_agent."""
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    (root / "backend" / "routes").mkdir(parents=True, exist_ok=True)
    (root / "backend" / "routes" / "items.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.get("/items")\n'
        "def list_items(): return []\n"
        '@router.post("/items")\n'
        "def create_item(): return {}\n",
        encoding="utf-8",
    )
    tests = ContractTestGenerator.from_routes_on_disk(root)
    assert len(tests) == 2
    paths = {t.route_or_schema for t in tests}
    assert "GET /items" in paths
    assert "POST /items" in paths


# ── Self-contained generated test validation ────────────────────────────────


def test_generated_tests_are_self_contained():
    """Generated test files must not depend on project imports."""
    root = Path(tempfile.mkdtemp())
    gen = ContractTestGenerator(root)
    routes = [_make_route("GET", "/api/health")]
    tests = gen.generate_from_routes(routes)

    out_dir = root / ".patchi" / "generated_tests"
    path = gen.save_tests(tests, out_dir)
    content = path.read_text(encoding="utf-8")

    # Must import requests and pytest directly, not via patchi
    assert "import requests" in content
    assert "import pytest" in content
    # Must not import from patchi
    assert "from patchi" not in content
    assert "import patchi" not in content


def test_generated_tests_handle_missing_app():
    """Each generated test must skip gracefully when app is not running."""
    root = Path(tempfile.mkdtemp())
    gen = ContractTestGenerator(root)
    routes = [_make_route("GET", "/test")]
    tests = gen.generate_from_routes(routes)

    content = tests[0].test_code
    assert "pytest.skip" in content
    assert "ConnectionError" in content
