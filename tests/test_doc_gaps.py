"""Tests for documentation gap detection (Item 49)."""

from __future__ import annotations

import time
from pathlib import Path

from patchi.core.brain.doc_gaps import detect_doc_gaps

# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_scan_result(
    *,
    file_infos: list | None = None,
    routes: list | None = None,
    security_findings: list | None = None,
    scan_results: dict | None = None,
) -> dict:
    result: dict = {}
    if file_infos is not None:
        result["file_infos"] = file_infos
    if routes is not None:
        result["routes"] = routes
    if security_findings is not None:
        result["security_findings"] = security_findings
    if scan_results is not None:
        result["scan_results"] = scan_results
    return result


def _fi(path: str) -> dict:
    return {"path": path}


def _finding(agent: str = "secrets", severity: str = "high") -> dict:
    return {"agent": agent, "severity": severity, "type": "test", "file": "x.py", "line": 1, "message": "test"}


# ── Tests: no gaps ─────────────────────────────────────────────────────────────

class TestNoGaps:
    def test_empty_project_no_gaps(self, tmp_path: Path) -> None:
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert gaps == []

    def test_no_gaps_when_docs_present_and_project_lacks_triggers(self, tmp_path: Path) -> None:
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "ARCHITECTURE.md").write_text("# Arch\n\nHello\nWorld\nFoo\nBar\nBaz\n")
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert gaps == []


# ── Tests: missing API surface ─────────────────────────────────────────────────

class TestMissingApiSurface:
    def test_routes_dir_no_doc(self, tmp_path: Path) -> None:
        (tmp_path / "routes").mkdir()
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert len(gaps) == 1
        assert gaps[0].status == "missing"
        assert gaps[0].expected_doc == "docs/API_SURFACE.md"

    def test_api_dir_no_doc(self, tmp_path: Path) -> None:
        (tmp_path / "api").mkdir()
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert len(gaps) == 1
        assert gaps[0].expected_doc == "docs/API_SURFACE.md"

    def test_routes_in_scan_result_no_doc(self, tmp_path: Path) -> None:
        scan = _make_scan_result(routes=[{"method": "GET", "path": "/health"}])
        gaps = detect_doc_gaps(tmp_path, scan)
        assert any(g.expected_doc == "docs/API_SURFACE.md" for g in gaps)

    def test_no_flag_when_doc_exists(self, tmp_path: Path) -> None:
        (tmp_path / "routes").mkdir()
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "API_SURFACE.md").write_text("# API\nRoute1\nRoute2\nRoute3\nRoute4\nRoute5\n")
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert not any(g.expected_doc == "docs/API_SURFACE.md" for g in gaps)


# ── Tests: missing test coverage ───────────────────────────────────────────────

class TestMissingTestCoverage:
    def test_test_dir_no_doc(self, tmp_path: Path) -> None:
        scan = _make_scan_result(file_infos=[_fi("tests/test_foo.py")])
        gaps = detect_doc_gaps(tmp_path, scan)
        assert any(g.expected_doc == "docs/TEST_COVERAGE.md" and g.status == "missing" for g in gaps)

    def test_test_prefix_no_doc(self, tmp_path: Path) -> None:
        scan = _make_scan_result(file_infos=[_fi("src/test_utils.py")])
        gaps = detect_doc_gaps(tmp_path, scan)
        assert any(g.expected_doc == "docs/TEST_COVERAGE.md" for g in gaps)

    def test_no_flag_when_no_tests(self, tmp_path: Path) -> None:
        scan = _make_scan_result(file_infos=[_fi("src/app.py")])
        gaps = detect_doc_gaps(tmp_path, scan)
        assert not any(g.expected_doc == "docs/TEST_COVERAGE.md" for g in gaps)


# ── Tests: missing security domains ────────────────────────────────────────────

class TestMissingSecurityDomains:
    def test_findings_no_doc(self, tmp_path: Path) -> None:
        scan = _make_scan_result(security_findings=[_finding()])
        gaps = detect_doc_gaps(tmp_path, scan)
        assert any(g.expected_doc == "docs/SECURITY_DOMAINS.md" and g.status == "missing" for g in gaps)

    def test_scan_results_format(self, tmp_path: Path) -> None:
        scan = _make_scan_result(scan_results={"secrets": {"findings": [_finding()]}})
        gaps = detect_doc_gaps(tmp_path, scan)
        assert any(g.expected_doc == "docs/SECURITY_DOMAINS.md" for g in gaps)

    def test_no_flag_when_no_findings(self, tmp_path: Path) -> None:
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert not any(g.expected_doc == "docs/SECURITY_DOMAINS.md" for g in gaps)


# ── Tests: stale architecture doc ──────────────────────────────────────────────

class TestStaleArchitecture:
    def test_old_arch_doc_flagged(self, tmp_path: Path) -> None:
        docs = tmp_path / "docs"
        docs.mkdir()
        arch = docs / "ARCHITECTURE.md"
        arch.write_text("# Arch\n")
        # Backdate mtime to 10 days ago.
        old_time = time.time() - 10 * 86400
        os.utime(arch, (old_time, old_time))
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert any(g.expected_doc == "docs/ARCHITECTURE.md" and g.status == "stale" for g in gaps)

    def test_recent_arch_doc_not_flagged(self, tmp_path: Path) -> None:
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "ARCHITECTURE.md").write_text("# Arch\n")
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert not any(g.expected_doc == "docs/ARCHITECTURE.md" for g in gaps)


# ── Tests: partial docs ────────────────────────────────────────────────────────

class TestPartialDocs:
    def test_thin_doc_flagged_partial(self, tmp_path: Path) -> None:
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "API_SURFACE.md").write_text("# API\n\nMinimal.\n")
        (tmp_path / "routes").mkdir()
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert any(g.status == "partial" and g.expected_doc == "docs/API_SURFACE.md" for g in gaps)

    def test_full_doc_not_flagged_partial(self, tmp_path: Path) -> None:
        docs = tmp_path / "docs"
        docs.mkdir()
        content = "# API\n\n" + "\n".join(f"- route {i}" for i in range(10))
        (docs / "API_SURFACE.md").write_text(content)
        (tmp_path / "routes").mkdir()
        gaps = detect_doc_gaps(tmp_path, _make_scan_result())
        assert not any(g.status == "partial" and g.expected_doc == "docs/API_SURFACE.md" for g in gaps)


# ── Tests: ordering and combined scenarios ─────────────────────────────────────

class TestCombined:
    def test_missing_before_stale_in_output(self, tmp_path: Path) -> None:
        (tmp_path / "routes").mkdir()
        docs = tmp_path / "docs"
        docs.mkdir()
        arch = docs / "ARCHITECTURE.md"
        arch.write_text("# Arch\n")
        old_time = time.time() - 20 * 86400
        os.utime(arch, (old_time, old_time))
        scan = _make_scan_result(security_findings=[_finding()])
        gaps = detect_doc_gaps(tmp_path, scan)
        statuses = [g.status for g in gaps]
        # missing entries should come before stale
        if "missing" in statuses and "stale" in statuses:
            assert statuses.index("missing") < statuses.index("stale")

    def test_multiple_triggers(self, tmp_path: Path) -> None:
        (tmp_path / "routes").mkdir()
        scan = _make_scan_result(
            file_infos=[_fi("tests/test_a.py")],
            security_findings=[_finding()],
        )
        gaps = detect_doc_gaps(tmp_path, scan)
        docs_found = {g.expected_doc for g in gaps}
        assert "docs/API_SURFACE.md" in docs_found
        assert "docs/TEST_COVERAGE.md" in docs_found
        assert "docs/SECURITY_DOMAINS.md" in docs_found


# Need os for utime
import os  # noqa: E402
