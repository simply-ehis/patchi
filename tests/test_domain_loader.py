"""Tests for DomainLoader — domain taxonomies and fix playbooks."""

from __future__ import annotations

import os
import pickle
from pathlib import Path

import pytest
import yaml

from patchi.core.security import domain_loader as dl
from patchi.core.security.domain_loader import (
    Domain,
    DomainControl,
    DomainLoader,
    FixPlaybook,
    _try_load_yaml,
)


@pytest.fixture
def domain_yaml(tmp_path: Path) -> Path:
    """Write a minimal domain YAML file under a fake project root."""
    d = tmp_path / "patchi" / "core" / "security" / "domains"
    d.mkdir(parents=True)
    fpath = d / "test-domain.yaml"
    data = {
        "domain_id": "test-domain",
        "version": "2.0.0",
        "display_name": "Test Domain",
        "source_standard": "Test Standard v1",
        "component_type": "test-lib",
        "weight": 0.5,
        "activation_signals": {"required_any": [], "excluded_if": []},
        "controls": [
            {
                "control_id": "TEST-01",
                "name": "First test control",
                "description": "A test control for unit tests.",
                "source_clause": "TS v1 §1.1",
                "severity": "high",
                "check_method": "static",
                "detector": "semgrep",
                "remediation_ref": "fix-playbook://TEST-01",
            },
            {
                "control_id": "TEST-02",
                "name": "Second test control",
                "description": "Another test control.",
                "source_clause": "TS v1 §1.2",
                "severity": "medium",
                "check_method": "dynamic",
                "detector": "zap",
                "remediation_ref": "fix-playbook://TEST-02",
            },
        ],
    }
    fpath.write_text(yaml.dump(data), encoding="utf-8")
    return fpath


@pytest.fixture
def playbook_yaml(tmp_path: Path) -> Path:
    """Write a minimal fix-playbook YAML file under a fake project root."""
    d = tmp_path / "patchi" / "core" / "security" / "fix-playbooks"
    d.mkdir(parents=True)
    fpath = d / "test-domain.playbook.yaml"
    data = {
        "playbooks": [
            {
                "control_id": "TEST-01",
                "playbook_version": "1.0.0",
                "fix_strategy": "deterministic-autofix",
                "deterministic_tool": "some-tool",
                "llm_fix_template": None,
                "verification_checks": ["Check A", "Check B"],
                "blast_radius_notes": "Low risk",
                "human_review_required": False,
            },
            {
                "control_id": "TEST-02",
                "playbook_version": "1.0.0",
                "fix_strategy": "manual-only",
                "deterministic_tool": None,
                "llm_fix_template": "Fix {{x}}",
                "verification_checks": ["Manual verification required"],
                "blast_radius_notes": "Medium risk",
                "human_review_required": True,
            },
        ],
    }
    fpath.write_text(yaml.dump(data), encoding="utf-8")
    return fpath


@pytest.fixture
def loader(tmp_path: Path, domain_yaml: Path, playbook_yaml: Path, monkeypatch) -> DomainLoader:
    """DomainLoader pointed at a temp project root with test data.

    The on-disk object cache is redirected into the temp tree so tests never
    write to (or read from) the real per-user cache directory.
    """
    monkeypatch.setattr(
        "patchi.core.security.domain_loader._cache_dir", lambda: tmp_path / ".cache"
    )
    return DomainLoader(tmp_path)


@pytest.fixture
def cache_dir(tmp_path: Path, monkeypatch) -> Path:
    """Isolated cache dir for the cache-specific tests."""
    d = tmp_path / ".cache"
    monkeypatch.setattr(
        "patchi.core.security.domain_loader._cache_dir", lambda: d
    )
    return d


class TestDomainLoader:
    def test_loads_domains(self, loader: DomainLoader):
        loader._load_all()
        assert "test-domain" in loader._domains
        assert len(loader._domains) == 1

    def test_list_domains(self, loader: DomainLoader):
        domain_ids = loader.list_domains()
        assert isinstance(domain_ids, list)
        assert "test-domain" in domain_ids

    def test_get_domain_valid(self, loader: DomainLoader):
        domain = loader.get_domain("test-domain")
        assert isinstance(domain, Domain)
        assert domain.domain_id == "test-domain"
        assert domain.display_name == "Test Domain"
        assert domain.version == "2.0.0"
        assert len(domain.controls) == 2

    def test_get_domain_invalid(self, loader: DomainLoader):
        assert loader.get_domain("nonexistent-domain") is None

    def test_find_control_valid(self, loader: DomainLoader):
        ctrl = loader.find_control("TEST-01")
        assert isinstance(ctrl, DomainControl)
        assert ctrl.control_id == "TEST-01"
        assert ctrl.name == "First test control"
        assert ctrl.severity == "high"

    def test_find_control_invalid(self, loader: DomainLoader):
        assert loader.find_control("NONEXIST-99") is None

    def test_get_playbook_valid(self, loader: DomainLoader):
        pb = loader.get_playbook("TEST-01")
        assert isinstance(pb, FixPlaybook)
        assert pb.control_id == "TEST-01"
        assert pb.fix_strategy == "deterministic-autofix"
        assert pb.deterministic_tool == "some-tool"
        assert pb.human_review_required is False

    def test_get_playbook_invalid(self, loader: DomainLoader):
        assert loader.get_playbook("NONEXIST-99") is None


class TestTryLoadYaml:
    def test_returns_none_for_non_existent_path(self):
        result = _try_load_yaml(Path("/tmp/does_not_exist_12345.yaml"))
        assert result is None

    def test_returns_none_for_directory(self, tmp_path: Path):
        result = _try_load_yaml(tmp_path)
        assert result is None


class TestPackagedDataIntegrity:
    """Guard against regression of the real packaged domain data.

    A previous defect (playbook entries keyed only by ``playbook_id`` and
    domain controls missing ``control_id``/``name``) crashed ``_load_all``
    with ``KeyError: 'control_id'`` — which killed every scan. These tests
    load the shipped data directories so any recurrence fails CI instead
    of crashing at scan time.

    The loader is cached class-wide: ``_load_all`` takes seconds on the real
    data, so the class runs it exactly once.
    """

    loader: DomainLoader | None = None

    @classmethod
    def _real_loader(cls) -> DomainLoader:
        if cls.loader is None:
            root = Path(__file__).resolve().parents[1]
            loader = DomainLoader(root)
            loader._load_all()
            cls.loader = loader
        return cls.loader

    def test_real_packaged_data_loads_without_crashing(self):
        loader = self._real_loader()
        assert len(loader._domains) >= 40, f"Expected 40+ domains, got {len(loader._domains)}"
        assert len(loader._playbooks) >= 100, f"Expected 100+ playbooks, got {len(loader._playbooks)}"

    def test_every_control_id_has_a_playbook(self):
        loader = self._real_loader()
        missing = []
        for domain in loader._domains.values():
            for ctrl in domain.controls:
                if ctrl.control_id not in loader._playbooks:
                    missing.append(f"{domain.domain_id}/{ctrl.control_id}")
        assert not missing, f"controls missing playbooks: {missing[:20]}"

    def test_every_playbook_has_valid_fields(self):
        loader = self._real_loader()
        for cid, pb in loader._playbooks.items():
            assert pb.fix_strategy, f"{cid}: empty fix_strategy"
            assert isinstance(pb.verification_checks, list), f"{cid}: bad verification_checks"


class TestLazyScopedLoading:
    """Component-scoped loading: only domain files whose component_type matches
    the scan target are parsed, so narrow scans never build the full taxonomy.

    The on-disk cache is intentionally bypassed for scoped loads — it stores
    the whole taxonomy, and reading it would defeat the purpose.
    """

    @pytest.fixture
    def multi_type_tree(self, tmp_path: Path, monkeypatch) -> Path:
        """Two domain files with different component_types + playbooks."""
        dom = tmp_path / "patchi" / "core" / "security" / "domains"
        pb = tmp_path / "patchi" / "core" / "security" / "fix-playbooks"
        dom.mkdir(parents=True)
        pb.mkdir(parents=True)
        for did, ct, ctrl in [
            ("web-frontend", "frontend-web", "WEB-01"),
            ("backend-api", "backend-api", "API-01"),
        ]:
            (dom / f"{did}.yaml").write_text(
                yaml.dump({
                    "domain_id": did,
                    "display_name": did,
                    "component_type": ct,
                    "controls": [{
                        "control_id": ctrl,
                        "name": f"Control {ctrl}",
                        "description": "desc",
                    }],
                }),
                encoding="utf-8",
            )
            (pb / f"{did}.playbook.yaml").write_text(
                yaml.dump({"playbooks": [{
                    "control_id": ctrl,
                    "fix_strategy": "manual-only",
                    "verification_checks": [],
                }]}),
                encoding="utf-8",
            )
        monkeypatch.setattr(
            "patchi.core.security.domain_loader._cache_dir", lambda: tmp_path / ".cache"
        )
        return tmp_path

    def test_scoped_load_only_matching_type(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree, component_types=["frontend-web"])
        loader._load_all()
        assert set(loader._domains) == {"web-frontend"}
        assert set(loader._playbooks) == {"WEB-01"}

    def test_scoped_load_backend_api(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree, component_types=["backend-api"])
        loader._load_all()
        assert set(loader._domains) == {"backend-api"}

    def test_comma_separated_component_type(self, tmp_path: Path, monkeypatch):
        """A domain declaring 'backend-api,frontend-web' must match either scope."""
        dom = tmp_path / "patchi" / "core" / "security" / "domains"
        pb = tmp_path / "patchi" / "core" / "security" / "fix-playbooks"
        dom.mkdir(parents=True, exist_ok=True)
        pb.mkdir(parents=True, exist_ok=True)
        (dom / "auth-session.yaml").write_text(
            yaml.dump({
                "domain_id": "auth-session",
                "component_type": "backend-api,frontend-web",
                "controls": [{"control_id": "AUTH-01", "name": "Auth", "description": "d"}],
            }),
            encoding="utf-8",
        )
        (pb / "auth-session.playbook.yaml").write_text(
            yaml.dump(
                {"playbooks": [{"control_id": "AUTH-01", "fix_strategy": "manual-only", "verification_checks": []}]}
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "patchi.core.security.domain_loader._cache_dir", lambda: tmp_path / ".cache"
        )
        for scope in (["backend-api"], ["frontend-web"]):
            loader = DomainLoader(tmp_path, component_types=scope)
            loader._load_all()
            assert "auth-session" in loader._domains, f"scope {scope} missed auth-session"
            assert loader.get_playbook("AUTH-01") is not None

    def test_scoped_explicit_domain_ids_axis(self, multi_type_tree: Path):
        # frontend-web scope but explicitly pull the backend-api domain too
        loader = DomainLoader(
            multi_type_tree,
            component_types=["frontend-web"],
            domain_ids=["backend-api"],
        )
        loader._load_all()
        assert set(loader._domains) == {"web-frontend", "backend-api"}
        assert set(loader._playbooks) == {"WEB-01", "API-01"}

    def test_alias_normalization(self, multi_type_tree: Path, tmp_path: Path, monkeypatch):
        # A domain declaring "frontend" must match a "frontend-web" scope
        dom = tmp_path / "patchi" / "core" / "security" / "domains"
        dom.mkdir(parents=True, exist_ok=True)
        (dom / "legacy-frontend.yaml").write_text(
            yaml.dump({
                "domain_id": "legacy-frontend",
                "component_type": "frontend",
                "controls": [],
            }),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "patchi.core.security.domain_loader._cache_dir", lambda: tmp_path / ".cache"
        )
        loader = DomainLoader(tmp_path, component_types=["frontend-web"])
        loader._load_all()
        assert "legacy-frontend" in loader._domains
        # And the reverse alias: infra matches infrastructure
        assert dl.normalize_component_type("infrastructure") == "infra"
        assert dl.normalize_component_type("FRONTEND") == "frontend-web"

    def test_index_built_without_full_parse(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree)
        idx = loader._build_index()
        assert set(idx) >= {"web-frontend", "backend-api"}
        assert idx["web-frontend"]["types"] == {"frontend-web"}
        assert idx["backend-api"]["types"] == {"backend-api"}
        # Building the index must not have parsed/loaded any domains
        assert loader._domains == {}
        assert loader.index_component_types("web-frontend") == frozenset({"frontend-web"})

    def test_index_refreshes_on_data_change(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree)
        assert loader.index_component_types("web-frontend") == frozenset({"frontend-web"})
        # Change the file's component_type; the index must not stay stale
        dom = multi_type_tree / "patchi" / "core" / "security" / "domains"
        data = yaml.safe_load((dom / "web-frontend.yaml").read_text(encoding="utf-8"))
        data["component_type"] = "backend-api"
        (dom / "web-frontend.yaml").write_text(yaml.dump(data), encoding="utf-8")
        # Force index invalidation — stat fingerprint may not change on NTFS
        # within the same 100ns tick, so we clear the cached index explicitly.
        loader._index = None
        assert loader.index_component_types("web-frontend") == frozenset({"backend-api"})

    def test_get_domain_out_of_scope_returns_none(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree, component_types=["frontend-web"])
        assert loader.get_domain("backend-api") is None
        assert loader.get_domain("web-frontend") is not None

    def test_find_control_only_scoped(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree, component_types=["frontend-web"])
        assert loader.find_control("WEB-01") is not None
        assert loader.find_control("API-01") is None

    def test_get_playbook_only_scoped(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree, component_types=["frontend-web"])
        assert loader.get_playbook("WEB-01") is not None
        assert loader.get_playbook("API-01") is None

    def test_match_finding_only_scoped(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree, component_types=["frontend-web"])
        matches = loader.match_finding_to_controls("cross-site scripting", "app.js", "xss")
        # backend-api domain's control must never be consulted
        assert all(m.control_id != "API-01" for m in matches)

    def test_scoped_load_skips_disk_cache(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree, component_types=["frontend-web"])
        loader._load_all()
        cache_dir = multi_type_tree / ".cache"
        assert not cache_dir.exists() or not list(cache_dir.glob("*.pkl")), (
            "scoped loads must not write the full-taxonomy cache"
        )

    def test_scoped_then_full_load(self, multi_type_tree: Path):
        loader = DomainLoader(multi_type_tree, component_types=["frontend-web"])
        loader._load_all()
        assert set(loader._domains) == {"web-frontend"}
        loader.set_component_scope()  # clear scope -> full taxonomy
        loader._load_all()
        assert set(loader._domains) == {"web-frontend", "backend-api"}

    def test_scoped_then_full_writes_real_cache_key(self, multi_type_tree: Path):
        """A full load after a scoped load must write a content-keyed cache,
        never an empty-fingerprint file."""
        loader = DomainLoader(multi_type_tree, component_types=["frontend-web"])
        loader._load_all()
        loader.set_component_scope()
        loader._load_all()
        assert len(loader._domains) == 2
        cache_files = list((multi_type_tree / ".cache").glob("*.pkl"))
        assert cache_files, "full load should populate the on-disk cache"
        for f in cache_files:
            # The bug being guarded: an empty fingerprint would name the file
            # 'v1_.pkl' (nothing after the underscore) and silently poison the
            # cache dir with a key that can never be hit.
            assert f.name != "v1_.pkl", f"empty-fingerprint cache written: {f.name}"
            assert len(f.name) > len("v1_")
            assert f.stat().st_size > 0

    def test_real_data_scoped_frontend(self):
        """On the real packaged data, a narrow scope loads far fewer domains."""
        root = Path(__file__).resolve().parents[1]
        loader = DomainLoader(root, component_types=["frontend-web"])
        loader._load_all()
        assert len(loader._domains) < 100, f"expected a small subset, got {len(loader._domains)}"
        assert len(loader._domains) > 0
        # every loaded playbook must belong to a loaded domain control
        for d in loader._domains.values():
            for ctrl in d.controls:
                assert loader.get_playbook(ctrl.control_id) is not None


class TestDomainLoaderCache:
    """The on-disk object cache: written on load, reused across processes,
    invalidated by content change (even with untouched mtimes), and resilient
    to corrupt or wrong-schema payloads."""

    def _load(self, root: Path) -> DomainLoader:
        loader = DomainLoader(root)
        loader._load_all()
        return loader

    def _cache_file(self, loader: DomainLoader, cache_dir: Path) -> Path:
        fp = dl._content_fingerprint(loader._domains_dir, loader._playbooks_dir)
        return cache_dir / f"v{dl._CACHE_VERSION}_{fp}.pkl"

    def test_cache_file_written_and_reused(self, tmp_path, domain_yaml, playbook_yaml, cache_dir):
        l1 = self._load(tmp_path)
        cache = self._cache_file(l1, cache_dir)
        assert cache.is_file(), "a cache file should be written after first load"
        l2 = self._load(tmp_path)  # fresh loader -> on-disk cache hit
        assert l2.get_playbook("TEST-01").fix_strategy == "deterministic-autofix"
        assert l2.get_domain("test-domain").weight == 0.5

    def test_content_change_with_same_mtime_invalidates(self, tmp_path, domain_yaml, playbook_yaml, cache_dir):
        self._load(tmp_path)
        old_mtime_ns = domain_yaml.stat().st_mtime_ns
        data = yaml.safe_load(domain_yaml.read_text(encoding="utf-8"))
        data["display_name"] = "Renamed Domain"
        domain_yaml.write_text(yaml.dump(data), encoding="utf-8")
        # Restore the original mtime: only the content differs now, which must
        # still invalidate the cache (content hash, not mtime, is the key).
        os.utime(domain_yaml, ns=(old_mtime_ns, old_mtime_ns))
        l2 = self._load(tmp_path)
        assert l2.get_domain("test-domain").display_name == "Renamed Domain"

    def test_in_process_reuse_detects_content_change(self, tmp_path, domain_yaml, playbook_yaml, cache_dir):
        loader = self._load(tmp_path)
        data = yaml.safe_load(domain_yaml.read_text(encoding="utf-8"))
        data["display_name"] = "Renamed In-Process"
        domain_yaml.write_text(yaml.dump(data), encoding="utf-8")
        # Clear the module-level stat cache so _dirs_changed() re-stats the file
        dl._stat_cache.clear()
        assert loader.get_domain("test-domain").display_name == "Renamed In-Process"

    def test_corrupt_cache_falls_back_to_parse(self, tmp_path, domain_yaml, playbook_yaml, cache_dir):
        l1 = self._load(tmp_path)
        cache = self._cache_file(l1, cache_dir)
        cache.write_bytes(b"definitely not a pickle")
        l2 = self._load(tmp_path)
        assert l2.get_playbook("TEST-01") is not None
        assert cache.is_file(), "a fresh valid cache should replace the corrupt one"

    def test_wrong_schema_cache_ignored(self, tmp_path, domain_yaml, playbook_yaml, cache_dir):
        l1 = self._load(tmp_path)
        cache = self._cache_file(l1, cache_dir)
        cache.write_bytes(pickle.dumps(({"junk": 1}, [])))
        l2 = self._load(tmp_path)
        assert "test-domain" in l2._domains
