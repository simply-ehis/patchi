"""Tests for Item 58 — SBOM performance safeguard (truncation for large dep trees)."""

from pathlib import Path

from patchi.core.agents.sbom_generator import _MAX_DEPS, _build_cyclonedx


class TestSBOMTruncation:
    def test_max_deps_constant(self):
        assert _MAX_DEPS == 5000

    def test_truncation_when_over_limit(self):
        deps = {"npm": [{"name": f"pkg-{i:04d}", "version": "1.0"} for i in range(100)]}
        sbom = _build_cyclonedx(Path("/fake"), deps, max_deps=50)
        assert len(sbom["components"]) == 50
        assert sbom["metadata"]["truncated"] is True
        assert sbom["metadata"]["truncated_original_count"] == 100
        assert sbom["metadata"]["truncated_limit"] == 50

    def test_sorted_alphabetically(self):
        deps = {"npm": [{"name": "zzz", "version": "1.0"}, {"name": "aaa", "version": "2.0"}]}
        sbom = _build_cyclonedx(Path("/fake"), deps, max_deps=1)
        assert len(sbom["components"]) == 1
        assert sbom["components"][0]["name"] == "aaa"

    def test_no_truncation_under_limit(self):
        deps = {"npm": [{"name": f"pkg-{i}", "version": "1.0"} for i in range(10)]}
        sbom = _build_cyclonedx(Path("/fake"), deps, max_deps=50)
        assert len(sbom["components"]) == 10
        assert "truncated" not in sbom["metadata"]

    def test_unlimited_when_zero(self):
        deps = {"npm": [{"name": f"pkg-{i}", "version": "1.0"} for i in range(200)]}
        sbom = _build_cyclonedx(Path("/fake"), deps, max_deps=0)
        assert len(sbom["components"]) == 200
        assert "truncated" not in sbom["metadata"]

    def test_exact_limit_no_truncation(self):
        deps = {"npm": [{"name": f"pkg-{i}", "version": "1.0"} for i in range(50)]}
        sbom = _build_cyclonedx(Path("/fake"), deps, max_deps=50)
        assert len(sbom["components"]) == 50
        assert "truncated" not in sbom["metadata"]

    def test_multi_ecosystem_truncation(self):
        deps = {
            "npm": [{"name": f"npm-{i}", "version": "1.0"} for i in range(60)],
            "pypi": [{"name": f"pip-{i}", "version": "2.0"} for i in range(60)],
        }
        sbom = _build_cyclonedx(Path("/fake"), deps, max_deps=30)
        assert len(sbom["components"]) == 30
        assert sbom["metadata"]["truncated"] is True
        assert sbom["metadata"]["truncated_original_count"] == 120
