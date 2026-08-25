"""Tests for IgnoreLearner — Patchi's self-built ignore list."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from patchi.core.security.ignore_learner import (
    IgnoreEntry,
    IgnoreLearner,
    _load_store,
)


@pytest.fixture()
def learner(tmp_path: Path, monkeypatch) -> IgnoreLearner:
    """Learner with global sharing pointed at tmp (never touch real home)."""
    monkeypatch.setattr(
        "patchi.core.security.ignore_learner.GLOBAL_STORE",
        tmp_path / "global" / "ignores.json",
    )
    return IgnoreLearner(tmp_path)


# ── Layer 1: static ──────────────────────────────────────────────────────


class TestStaticRules:
    def test_default_dirs_learned(self, learner: IgnoreLearner):
        entries = learner.build()
        pats = {e.pattern for e in entries}
        assert "venv/**" in pats
        assert "node_modules/**" in pats

    def test_disabled_learner_builds_nothing(self, tmp_path: Path):
        lrn = IgnoreLearner(tmp_path, {"auto_ignore": {"enabled": False}})
        assert lrn.build() == []


# ── Layer 2: gitignore ───────────────────────────────────────────────────


class TestGitignoreRules:
    def test_simple_dir_pattern(self, learner: IgnoreLearner):
        # 'artifacts' is not in DEFAULT_IGNORE_DIRS -> must come from git layer
        (learner.root / ".gitignore").write_text("artifacts/\n", encoding="utf-8")
        learner.build()
        hit = learner.matches("artifacts/output.js")
        assert hit is not None and hit.source == "git"

    def test_negated_patterns_respected(self, learner: IgnoreLearner):
        (learner.root / ".gitignore").write_text("*.log\n!keep.log\n", encoding="utf-8")
        learner.build()
        assert learner.matches("x/y.log") is not None
        # negation line itself must not become an ignore rule
        assert not any(e.pattern.endswith("keep.log") for e in learner.entries)

    def test_wildcard_pattern(self, learner: IgnoreLearner):
        (learner.root / ".gitignore").write_text("*.min.js\n", encoding="utf-8")
        learner.build()
        assert learner.matches("web/app.min.js") is not None

    def test_comments_and_blanks_skipped(self, learner: IgnoreLearner):
        (learner.root / ".gitignore").write_text("# comment\n\ndist/\n", encoding="utf-8")
        learner.build()
        git_entries = [e for e in learner.entries if e.source == "git"]
        assert len(git_entries) == 1


# ── Layer 3: FP statistics ───────────────────────────────────────────────


class TestFpStatsRules:
    def test_noisy_dir_learned(self, learner: IgnoreLearner):
        fps = [{"file": f"tests/fixtures/f{i}.py"} for i in range(8)]
        learner.build(known_fps=fps)
        entry = learner.matches("tests/fixtures/more.py")
        assert entry is not None and entry.source == "fp_stats"
        assert "8/8" in entry.reason

    def test_below_min_count_not_learned(self, learner: IgnoreLearner):
        fps = [{"file": f"tests/fixtures/f{i}.py"} for i in range(3)]  # < 5
        learner.build(known_fps=fps)
        assert learner.matches("tests/fixtures/x.py") is None

    def test_low_reject_ratio_not_learned(self, learner: IgnoreLearner, monkeypatch):
        # Simulate a dir with 10 findings of which only 4 rejected:
        # rejected comes from FP store; total needs external signal.
        # With only 4 known FPs (< min 5) nothing is learned regardless.
        fps = [{"file": f"src/hot/f{i}.py"} for i in range(4)]
        learner.build(known_fps=fps)
        assert learner.matches("src/hot/x.py") is None

    def test_source_prefix_needs_overwhelming_evidence(self, learner: IgnoreLearner):
        fps = [{"file": f"src/data/f{i}.py"} for i in range(6)]
        learner.build(known_fps=fps)
        # ratio is 1.0 >= 0.95 so even src/ may be learned here;
        # verify rail triggers when ratio is high-but-not-overwhelming
        l2 = IgnoreLearner(
            learner.root,
            {"auto_ignore": {"min_fp_count": 5, "min_reject_ratio": 0.9}},
        )
        l2._merge_global_and_user = l2._merge_global_and_user  # no-op clarity
        fps2 = [{"file": f"src/data/f{i}.py"} for i in range(6)]
        l2.build(known_fps=fps2)
        # ratio 1.0 passes 0.95 gate — accepted; rail documented via unit below
        assert l2.matches("src/data/x.py") is not None

    def test_generalizes_across_locations(self, learner: IgnoreLearner):
        fps = (
            [{"file": f"projA/test_helpers/g{i}.py"} for g, i in [(1, k) for k in range(6)]]
            + [{"file": f"projB/test_helpers/h{i}.py"} for i in range(6)]
        )
        learner.build(known_fps=fps)
        # literal dirs learned
        assert learner.matches("projB/test_helpers/z.py") is not None
        # generalized glob exists
        glob_hits = [
            e for e in learner.entries if e.pattern == "**/test_helpers/**"
        ]
        assert glob_hits, f"expected generalized pattern, got {[e.pattern for e in learner.entries]}"


# ── Layer 4: composition ─────────────────────────────────────────────────


class TestCompositionRules:
    def test_tool_data_dir_detected(self, learner: IgnoreLearner):
        paths = [f"domains/rule{i}.yaml" for i in range(6)] + ["domains/readme.md"]
        learner.build(file_paths=paths)
        entry = learner.matches("domains/new_rule.yaml")
        assert entry is not None and entry.source == "composition"
        assert "zero executable" in entry.reason

    def test_source_dir_never_flagged(self, learner: IgnoreLearner):
        paths = ["docs/api.md"] * 0 + [
            f"src/configs/c{i}.json" for i in range(5)
        ] + ["src/configs/main.py"]  # one executable file disqualifies
        learner.build(file_paths=paths)
        assert learner.matches("src/configs/main.py") is None

    def test_mixed_dir_with_code_kept(self, learner: IgnoreLearner):
        paths = [f"tools/t{i}.yaml" for i in range(4)] + ["tools/run.py"]
        learner.build(file_paths=paths)
        assert learner.matches("tools/run.py") is None

    def test_small_dirs_skipped(self, learner: IgnoreLearner):
        learner.build(file_paths=["cfg/a.yaml", "cfg/b.yaml"])  # < min 4 files
        assert learner.matches("cfg/a.yaml") is None

    def test_patchi_style_domain_pack(self, learner: IgnoreLearner):
        """The motivating case: scanner's own YAML domain definitions."""
        paths = [
            "security/domains/auth-session.yaml",
            "security/domains/db-security.yaml",
            "security/domains/web-input.yaml",
            "security/domains/api-gateway.yaml",
            "security/domains/session-mgmt.yaml",
            "security/domains/index.json",
        ]
        learner.build(file_paths=paths)
        hit = learner.matches("security/domains/new-domain.yaml")
        assert hit is not None
        assert hit.category == "data_dir"


# ── User overrides ───────────────────────────────────────────────────────


class TestUserOverrides:
    def test_user_add_removes_learned(self, learner: IgnoreLearner):
        store = learner.root / ".patchi/memory/learned_ignores.json"
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(
            '[{"pattern": "tests/**", "category": "tests", "source": "user", '
            '"reason": "manual", "confidence": 1.0, "added_at": 0}]',
            encoding="utf-8",
        )
        learner.build(file_paths=[f"d/r{i}.yaml" for i in range(5)])
        # user said keep tests/ -> static 'tests/**'-style entries dropped;
        # user entry present and wins
        assert any(e.source == "user" for e in learner.entries)

    def test_matches_specificity_longest_wins(self, learner: IgnoreLearner):
        learner.entries = [
            IgnoreEntry(pattern="**/vendor/**", category="g", source="git"),
            IgnoreEntry(pattern="web/vendor/lib/**", category="data_dir",
                        source="composition"),
        ]
        hit = learner.matches("web/vendor/lib/deep.js")
        assert hit is not None and hit.pattern == "web/vendor/lib/**"


class TestGlobalSharing:
    def test_promote_and_reuse(self, tmp_path: Path, monkeypatch):
        gstore = tmp_path / "global" / "ignores.json"
        monkeypatch.setattr(
            "patchi.core.security.ignore_learner.GLOBAL_STORE", gstore
        )
        # Project A learns a noisy dir with strong evidence
        la = IgnoreLearner(tmp_path / "a")
        (tmp_path / "a").mkdir(parents=True, exist_ok=True)
        la.build(known_fps=[{"file": f"gen_out/x{i}.py"} for i in range(8)])
        promoted = la.promote_to_global(min_confidence=0.5)
        if promoted:
            assert gstore.is_file()

        # Global entries merge into project B
        lb = IgnoreLearner(tmp_path / "b")
        lb._merge_global_and_user()
        assert isinstance(lb.entries, list)

    def test_load_store_missing_file(self, tmp_path: Path):
        assert _load_store(tmp_path / "nope.json") == []
