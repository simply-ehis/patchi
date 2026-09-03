"""Tests for FileCorpus noise exclusion (pre-scan file filtering)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchi.core.brain.file_corpus import FileCorpus


def _make_project(tmp_path: Path) -> Path:
    """Build a tiny project with source + noise files."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    (src / "util.ts").write_text("export const y = 2;\n", encoding="utf-8")

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text("def test_x():\n    assert True\n", encoding="utf-8")

    web = tmp_path / "web"
    web.mkdir()
    (web / "bundle.min.js").write_text("var a=1;", encoding="utf-8")
    (web / "package-lock.json").write_text('{"lockfileVersion": 3}', encoding="utf-8")

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "guide.md").write_text("# Guide\n", encoding="utf-8")
    return tmp_path


class TestCorpusNoiseExclusion:
    def test_default_keeps_everything_except_builtins(self, tmp_path: Path):
        root = _make_project(tmp_path)
        corpus = FileCorpus(root)
        # 4 scannable files: guide.md is dropped by language detection, and
        # minified/bundled assets are excluded by default (single-line giants
        # freeze the scan loop — see is_minified_asset in languages.py).
        assert len(corpus) == 4
        assert "web/bundle.min.js" not in corpus
        assert "tests/test_app.py" in corpus
        assert "web/package-lock.json" in corpus
        assert corpus.noise_excluded == {}

    def test_exclude_noise_drops_locks_generated_docs(self, tmp_path: Path):
        root = _make_project(tmp_path)
        corpus = FileCorpus(root, exclude_noise=True)
        paths = set(corpus.entries.keys())
        assert "web/package-lock.json" not in paths
        assert "web/bundle.min.js" not in paths
        assert "docs/guide.md" not in paths
        # source and tests untouched
        assert "src/app.py" in paths
        assert "tests/test_app.py" in paths
        assert corpus.noise_excluded.get("lockfile") == 1
        assert corpus.noise_excluded.get("docs") == 1
        # bundle.min.js is pruned as a built-in before noise classification,
        # so it never reaches the classifier's "generated" counter.
        assert corpus.noise_excluded.get("generated") is None

    def test_exclude_tests_opt_in(self, tmp_path: Path):
        root = _make_project(tmp_path)
        corpus = FileCorpus(root, exclude_noise=True, exclude_tests=True)
        paths = set(corpus.entries.keys())
        assert "tests/test_app.py" not in paths
        assert "src/app.py" in paths
        assert corpus.noise_excluded.get("tests") == 1

    def test_by_glob_respects_exclusion(self, tmp_path: Path):
        root = _make_project(tmp_path)
        corpus = FileCorpus(root, exclude_noise=True)
        assert corpus.by_glob("*.min.js") == []
        assert any(e.path == "src/util.ts" for e in corpus.by_glob("*.ts"))

    def test_read_still_works_for_kept_files(self, tmp_path: Path):
        root = _make_project(tmp_path)
        corpus = FileCorpus(root, exclude_noise=True)
        assert "x = 1" in corpus.read("src/app.py")


class TestCorpusLearnerWiring:
    def test_learner_skips_paths_at_discovery(self, tmp_path: Path):
        from patchi.core.security.ignore_learner import IgnoreEntry, IgnoreLearner

        root = _make_project(tmp_path)
        learner = IgnoreLearner(root)
        # Simulate a learned rule for a dir the corpus would otherwise keep
        learner.entries = [
            IgnoreEntry(pattern="docs/**", category="data_dir",
                        source="composition", reason="test rule")
        ]
        corpus = FileCorpus(root, ignore_learner=learner)
        assert "docs/guide.md" not in corpus.entries
        assert corpus.learner_excluded >= 1
        assert "src/app.py" in corpus.entries

    def test_learner_crash_never_blocks_scan(self, tmp_path: Path):
        class ExplodingLearner:
            def matches(self, _p):
                raise RuntimeError("boom")

        root = _make_project(tmp_path)
        corpus = FileCorpus(root, ignore_learner=ExplodingLearner())
        assert len(corpus) == 4  # source kept; built-in excludes still apply

    def test_full_learning_loop(self, tmp_path: Path, monkeypatch):
        """FP memory -> learner -> corpus pruning, the real scan sequence."""
        from patchi.core.security.ignore_learner import IgnoreLearner

        monkeypatch.setattr(
            "patchi.core.security.ignore_learner.GLOBAL_STORE",
            tmp_path / "global.json",
        )
        root = _make_project(tmp_path)
        # Chronic FP history AND matching real files on disk
        fx = root / "tests" / "fixtures"
        fx.mkdir(parents=True, exist_ok=True)
        for i in range(3):
            (fx / f"bad{i}.py").write_text("x = 1\n", encoding="utf-8")
        fp_dir = root / ".patchi" / "memory"
        fp_dir.mkdir(parents=True, exist_ok=True)
        fps = [{"file": f"tests/fixtures/bad{i}.py"} for i in range(6)]
        (fp_dir / "known_false_positives.json").write_text(
            __import__("json").dumps(fps), encoding="utf-8"
        )

        learner = IgnoreLearner(root)
        known_fps = __import__("json").loads(
            (fp_dir / "known_false_positives.json").read_text(encoding="utf-8")
        )
        learner.build(known_fps=known_fps)
        assert learner.matches("tests/fixtures/anything.py") is not None

        corpus = FileCorpus(root, exclude_noise=True, ignore_learner=learner)
        learner.build(
            known_fps=known_fps,
            file_paths=list(corpus.entries.keys()),
        )
        corpus.prune_with(learner)
        # Noisy fixture files never entered the corpus (discovery-time skip)
        # or were removed by the composition pass — either way they're gone.
        total_gone = (
            sum(1 for p in ["tests/fixtures/bad0.py", "tests/fixtures/bad1.py"]
                if p not in corpus.entries)
        )
        assert total_gone == 2
        assert "src/app.py" in corpus.entries
