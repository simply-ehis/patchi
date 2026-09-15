"""Taxonomy health: doctor catches a partial/corrupt taxonomy before scans
silently narrow (missing domain YAMLs are skipped without error by the
loader, so fewer findings would arrive with nothing to explain why).
"""

import json
from pathlib import Path

import pytest

from patchi.core.security import taxonomy_health
from patchi.core.security.taxonomy_health import (
    EXPECTED_DOMAIN_COUNT,
    TaxonomyHealth,
    check_taxonomy_health,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── The shipped expected set tracks the generator (source of truth) ──────────


def test_expected_count_matches_generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gd", REPO_ROOT / "tools" / "taxonomy" / "generate_domains.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    gen_ids = {row[0] for row in mod.DOMAINS}
    assert len(gen_ids) == EXPECTED_DOMAIN_COUNT, (
        f"generator has {len(gen_ids)} unique domains but the shipped constant "
        f"says {EXPECTED_DOMAIN_COUNT} — regenerate taxonomy_health._EXPECTED_IDS"
    )
    assert taxonomy_health._EXPECTED_IDS == gen_ids, (
        "shipped _EXPECTED_IDS drifted from the generator's DOMAINS table — "
        "regenerate taxonomy_health._EXPECTED_IDS"
    )


# ── The checker against the real, healthy in-repo taxonomy ───────────────────


def test_default_package_root_resolves_to_the_shipped_taxonomy():
    """The no-args call must find the real shipped taxonomy — a wrong default
    here reports 0/800 and tells every user their scans are narrowing."""
    th = check_taxonomy_health()
    assert th.status == "ok", f"default root wrong: {th.summary}"
    assert th.domains_found == EXPECTED_DOMAIN_COUNT


def test_real_repo_taxonomy_is_healthy():
    th = check_taxonomy_health(REPO_ROOT / "patchi")
    assert th.status == "ok", f"unexpected drift in the repo: {th.summary}"
    assert th.domains_found == EXPECTED_DOMAIN_COUNT
    assert th.playbooks_found == EXPECTED_DOMAIN_COUNT
    assert th.unparsable == []
    assert th.summary.endswith("complete")


# ── Seeded-drift fixtures (copy a slice of the real taxonomy, then break it) ──


SEED_IDS = (
    "owasp-a01-broken-access-control",
    "owasp-a03-injection",
    "owasp-a10-ssrf",
)


@pytest.fixture()
def seeded_pkg(tmp_path: Path) -> Path:
    """A patchi/ package skeleton with a known slice of real taxonomy files
    (domain + playbook pair for each seed ID)."""
    src = REPO_ROOT / "patchi" / "core" / "security"
    pkg = tmp_path / "patchi"
    for did in SEED_IDS:
        domain = src / "domains" / f"{did}.yaml"
        playbook = src / "fix-playbooks" / f"{did}.playbook.yaml"
        assert domain.is_file() and playbook.is_file(), f"seed file missing: {did}"
        dd = pkg / "core" / "security" / "domains"
        pd = pkg / "core" / "security" / "fix-playbooks"
        dd.mkdir(parents=True, exist_ok=True)
        pd.mkdir(parents=True, exist_ok=True)
        (dd / domain.name).write_bytes(domain.read_bytes())
        (pd / playbook.name).write_bytes(playbook.read_bytes())
    # Tests pair this slice with a matching monkeypatched expected set.
    return pkg


def _with_expected(monkeypatch, ids: set[str]):
    monkeypatch.setattr(taxonomy_health, "_EXPECTED_IDS", frozenset(ids))
    monkeypatch.setattr(taxonomy_health, "EXPECTED_DOMAIN_COUNT", len(ids))


def test_missing_domain_is_detected(seeded_pkg, monkeypatch):
    ids = {"owasp-a01-broken-access-control", "owasp-a02-cryptographic-failures"}
    _with_expected(monkeypatch, ids)
    th = check_taxonomy_health(seeded_pkg)
    assert "owasp-a02-cryptographic-failures" in th.missing_domains
    assert th.status == "error"
    assert any("missing domain" in line for line in th.detail_lines())


def test_corrupt_yaml_is_detected_not_counted_as_present(seeded_pkg, monkeypatch):
    ids = {"owasp-a01-broken-access-control", "owasp-a03-injection"}
    _with_expected(monkeypatch, ids)
    # Truncate one file — present on disk, parses as nothing
    victim = seeded_pkg / "core" / "security" / "domains" / "owasp-a03-injection.yaml"
    victim.write_text("{ not: [valid", encoding="utf-8")
    th = check_taxonomy_health(seeded_pkg)
    # the corrupt file is still counted as present (count checks alone lie)...
    assert th.domains_found == 3
    assert any(name == "owasp-a03-injection.yaml" for name, _err in th.unparsable)
    assert th.status == "error"  # ...but the verdict is error: the loader skips it


def test_unparsable_detail_shows_reason(seeded_pkg, monkeypatch):
    ids = {"owasp-a01-broken-access-control"}
    _with_expected(monkeypatch, ids)
    victim = seeded_pkg / "core" / "security" / "domains" / "owasp-a01-broken-access-control.yaml"
    victim.write_text("key: [unclosed", encoding="utf-8")
    th = check_taxonomy_health(seeded_pkg)
    assert th.unparsable, "corrupt file produced no unparsable record"
    assert th.unparsable[0][1], "unparsable record without a reason"
    assert any("unparsable" in line for line in th.detail_lines())


def test_extra_file_warns_not_errors(seeded_pkg, monkeypatch):
    # expect the FULL seeded slice, so only the planted file counts as extra
    _with_expected(monkeypatch, set(SEED_IDS))
    extra = seeded_pkg / "core" / "security" / "domains" / "custom-domain.yaml"
    extra.write_text("id: custom-domain\n", encoding="utf-8")
    th = check_taxonomy_health(seeded_pkg)
    assert th.extra_domains == ["custom-domain.yaml"]
    assert th.status == "warn"
    # the summary reports counts; the filename shows in the detail rows
    assert "1 file(s) not in the expected set" in th.summary
    assert any("custom-domain.yaml" in line for line in th.detail_lines())


def test_missing_playbook_pairing_is_detected(seeded_pkg, monkeypatch):
    ids = {"owasp-a01-broken-access-control"}
    _with_expected(monkeypatch, ids)
    # delete one playbook from the seeded slice
    victim = (
        seeded_pkg / "core" / "security" / "fix-playbooks" / "owasp-a01-broken-access-control.playbook.yaml"
    )
    victim.unlink()
    th = check_taxonomy_health(seeded_pkg)
    assert "owasp-a01-broken-access-control" in th.missing_playbooks
    assert th.status == "error"


def test_missing_directory_is_total_drift(tmp_path):
    th = check_taxonomy_health(tmp_path)
    assert th.status == "error"
    assert th.domains_found == 0


def test_never_raises_on_weird_input(tmp_path):
    """A file where a directory should be must not crash the checker."""
    (tmp_path / "core").write_text("not a dir", encoding="utf-8")
    th = check_taxonomy_health(tmp_path)
    assert isinstance(th, TaxonomyHealth)


# ── Doctor integration ────────────────────────────────────────────────────────


def test_doctor_reports_taxonomy_check(monkeypatch, capsys):
    """p doctor --json includes the taxonomy check with honest status."""
    # run() imports inside the function body, so patching the module
    # attribute redirects the check to our deterministic stub.
    import patchi.core.security.taxonomy_health as real_th
    from patchi.cli.commands import doctor_cmd

    def stub():
        return TaxonomyHealth(
            domains_found=798,
            playbooks_found=800,
            missing_domains=["owasp-a03-injection", "owasp-a04-insecure-design"],
        )

    monkeypatch.setattr(real_th, "check_taxonomy_health", stub)
    doctor_cmd.run(json_output=True)
    doc = json.loads(capsys.readouterr().out)
    labels = [c["label"] for c in doc["checks"]]
    assert "Taxonomy" in labels
    tax = [c for c in doc["checks"] if c["label"] == "Taxonomy"][0]
    assert tax["status"] == "✗"
    assert "798/800" in tax["note"]
    assert "MISSING" in tax["note"]
    assert doc["errors"] >= 1
