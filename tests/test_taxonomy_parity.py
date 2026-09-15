"""Taxonomy parity: the committed YAMLs must equal a fresh regeneration.

Byte-equality between ``patchi/core/security/{domains,fix-playbooks}`` and a
clean run of ``tools/taxonomy/generate_domains.py --out <tempdir>`` means the
generator is the live source of truth. If someone edits a committed YAML by
hand (or bumps the generator without regenerating), these tests fail with the
exact file list to regenerate.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "tools" / "taxonomy" / "generate_domains.py"
COMMITTED_DOMAINS = REPO_ROOT / "patchi" / "core" / "security" / "domains"
COMMITTED_PLAYBOOKS = REPO_ROOT / "patchi" / "core" / "security" / "fix-playbooks"


def _load_generator():
    """Import the generator module without executing main()."""
    spec = importlib.util.spec_from_file_location("generate_domains", GENERATOR)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def regenerated(tmp_path_factory):
    """Run the real generator once into a scratch dir; return its two dirs."""
    out = tmp_path_factory.mktemp("taxonomy-regen")
    proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [sys.executable, str(GENERATOR), "--out", str(out)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"generator failed: {proc.stderr[-400:]}"
    return out / "domains", out / "fix-playbooks"


def _drift_report(committed: Path, fresh: Path, suffix: str) -> str:
    """Human-readable drift list: missing / extra / byte-different files."""
    committed_files = {p.name for p in committed.glob(f"*{suffix}")}
    fresh_files = {p.name for p in fresh.glob(f"*{suffix}")}
    missing = sorted(committed_files - fresh_files)
    extra = sorted(fresh_files - committed_files)
    changed = sorted(
        name
        for name in committed_files & fresh_files
        if (committed / name).read_bytes() != (fresh / name).read_bytes()
    )
    parts = []
    if missing:
        parts.append(f"missing from regeneration (deleted upstream?): {missing[:5]}")
    if extra:
        parts.append(f"not committed (generator moved ahead): {extra[:5]}")
    if changed:
        parts.append(
            f"byte-different (run: python tools/taxonomy/generate_domains.py): {changed[:5]}"
        )
    return "; ".join(parts)


def test_committed_domains_match_regeneration(regenerated):
    fresh_domains, _ = regenerated
    assert COMMITTED_DOMAINS.is_dir()
    drift = _drift_report(COMMITTED_DOMAINS, fresh_domains, ".yaml")
    assert not drift, f"domains/ drifted from the generator — {drift}"


def test_committed_playbooks_match_regeneration(regenerated):
    _, fresh_playbooks = regenerated
    assert COMMITTED_PLAYBOOKS.is_dir()
    drift = _drift_report(COMMITTED_PLAYBOOKS, fresh_playbooks, ".playbook.yaml")
    assert not drift, f"fix-playbooks/ drifted from the generator — {drift}"


def test_generator_has_no_silent_duplicate_ids():
    """Duplicate domain IDs are skipped silently by main() — that is data loss
    dressed as success. The source table must be duplicate-free."""
    mod = _load_generator()
    seen, dupes = set(), []
    for row in mod.DOMAINS:
        did = row[0]
        if did in seen:
            dupes.append(did)
        seen.add(did)
    assert not dupes, (
        f"duplicate domain IDs in the generator "
        f"(second one is silently dropped): {sorted(set(dupes))[:5]}"
    )


def test_every_generated_id_has_both_files(regenerated):
    """A domain without its playbook (or vice versa) would silently narrow
    the scanner's fix guidance."""
    fresh_domains, fresh_playbooks = regenerated
    domain_ids = {p.name[: -len(".yaml")] for p in fresh_domains.glob("*.yaml")}
    playbook_ids = {p.name[: -len(".playbook.yaml")] for p in fresh_playbooks.glob("*.playbook.yaml")}
    assert domain_ids == playbook_ids, (
        f"domain/playbook mismatch: only-domains={sorted(domain_ids - playbook_ids)[:5]} "
        f"only-playbooks={sorted(playbook_ids - domain_ids)[:5]}"
    )
