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
    def test_default_keeps_everything(self, tmp_path: Path):
        root = _make_project(tmp_path)
        corpus = FileCorpus(root)
        # 5 scannable files (guide.md is not a detectable language and is
        # dropped by language detection long before noise classification).
        assert len(corpus) == 5
        assert "web/bundle.min.js" in corpus
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
        assert corpus.noise_excluded.get("generated") == 1
        assert corpus.noise_excluded.get("docs") == 1

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
