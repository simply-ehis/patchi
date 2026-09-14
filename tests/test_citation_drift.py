"""Tests for citation drift detection in doc_validator."""

from pathlib import Path
from tempfile import TemporaryDirectory

from patchi.core.brain.doc_validator import (
    DriftIssue,
    _build_symbol_index,
    _check_citation_drift,
    _extract_citations,
    _find_closest,
    validate_project_docs,
)
from patchi.core.brain.languages import Lang
from patchi.core.brain.scanner import ClassInfo, FileInfo, FunctionInfo

# ── Helpers ──────────────────────────────────────────────────────────────────────


def _make_fi(
    path: str,
    functions: list[str] | None = None,
    classes: list[str] | None = None,
) -> FileInfo:
    return FileInfo(
        path=path,
        language=Lang.PYTHON,
        size_bytes=100,
        lines=10,
        functions=[FunctionInfo(name=f, line=1) for f in (functions or [])],
        classes=[ClassInfo(name=c, line=1) for c in (classes or [])],
    )


# ── _extract_citations ──────────────────────────────────────────────────────────


class TestExtractCitations:
    def test_extracts_backtick_file_paths(self):
        text = "See `patchi/core/scanner.py` for details."
        paths, syms = _extract_citations(text)
        assert paths == ["patchi/core/scanner.py"]
        assert syms == []

    def test_extracts_quoted_file_paths(self):
        text = 'Check "src/utils.js" and \'lib/main.ts\'.'
        paths, syms = _extract_citations(text)
        assert "src/utils.js" in paths
        assert "lib/main.ts" in paths

    def test_extracts_go_and_rs_paths(self):
        text = "See cmd/server.go and src/lib.rs for the implementation."
        paths, syms = _extract_citations(text)
        assert "cmd/server.go" in paths
        assert "src/lib.rs" in paths

    def test_extracts_backtick_symbols(self):
        text = "Use `verify_jwt` to check tokens."
        paths, syms = _extract_citations(text)
        assert paths == []
        assert "verify_jwt" in syms

    def test_extracts_function_call_pattern(self):
        text = "Call process_data() to transform input."
        paths, syms = _extract_citations(text)
        assert "process_data" in syms

    def test_extracts_class_names(self):
        text = "The `JwtMiddleware` class handles auth."
        paths, syms = _extract_citations(text)
        assert "JwtMiddleware" in syms

    def test_deduplicates(self):
        text = "`verify_jwt` is used. Call verify_jwt() again."
        _, syms = _extract_citations(text)
        assert syms.count("verify_jwt") == 1

    def test_mixed_citations(self):
        text = "See `patchi/auth.py` — the `login` function (login()) handles it."
        paths, syms = _extract_citations(text)
        assert "patchi/auth.py" in paths
        assert "login" in syms

    def test_no_citations_in_plain_text(self):
        text = "This is just a paragraph with no code references."
        paths, syms = _extract_citations(text)
        assert paths == []
        assert syms == []


# ── _build_symbol_index ─────────────────────────────────────────────────────────


class TestBuildSymbolIndex:
    def test_indexes_functions(self):
        fi = _make_fi("a.py", functions=["foo", "bar"])
        idx = _build_symbol_index([fi])
        assert "foo" in idx
        assert "bar" in idx
        assert idx["foo"] == ["a.py"]

    def test_indexes_classes(self):
        fi = _make_fi("b.py", classes=["MyClass"])
        idx = _build_symbol_index([fi])
        assert "myclass" in idx

    def test_case_insensitive_keys(self):
        fi = _make_fi("c.py", functions=["CamelCase"])
        idx = _build_symbol_index([fi])
        assert "camelcase" in idx

    def test_multiple_files_same_symbol(self):
        fi1 = _make_fi("a.py", functions=["shared"])
        fi2 = _make_fi("b.py", functions=["shared"])
        idx = _build_symbol_index([fi1, fi2])
        assert idx["shared"] == ["a.py", "b.py"]


# ── _find_closest ───────────────────────────────────────────────────────────────


class TestFindClosest:
    def test_exact_match(self):
        assert _find_closest("foo", ["foo", "bar"]) == "foo"

    def test_close_match(self):
        assert _find_closest("verfiy", ["verify", "validate"]) == "verify"

    def test_no_close_match(self):
        assert _find_closest("xyz", ["abc", "def"]) == ""

    def test_empty_candidates(self):
        assert _find_closest("foo", []) == ""


# ── _check_citation_drift ───────────────────────────────────────────────────────


class TestCheckCitationDrift:
    def test_valid_file_path(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("# app")
            fi = _make_fi("src/app.py")
            doc = "See `src/app.py` for the entry point."
            issues = _check_citation_drift(doc, root, [fi])
            assert issues == []

    def test_missing_file_path(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fi = _make_fi("src/app.py")
            doc = "See `src/deleted.py` for the old logic."
            issues = _check_citation_drift(doc, root, [fi])
            assert len(issues) == 1
            assert issues[0].status == "missing"
            assert issues[0].reference == "src/deleted.py"

    def test_moved_file_path(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fi = _make_fi("src/new/app.py")
            doc = "See `src/old/app.py` for the entry point."
            issues = _check_citation_drift(doc, root, [fi])
            assert len(issues) == 1
            assert issues[0].status == "moved"
            assert "src/new/app.py" in issues[0].suggestion

    def test_valid_symbol(self):
        fi = _make_fi("a.py", functions=["verify_jwt"])
        doc = "Use `verify_jwt` to validate tokens."
        issues = _check_citation_drift(doc, Path("."), [fi])
        assert issues == []

    def test_missing_symbol(self):
        fi = _make_fi("a.py", functions=["verify_jwt"])
        doc = "Use `deleted_func` to do things."
        issues = _check_citation_drift(doc, Path("."), [fi])
        assert len(issues) == 1
        assert issues[0].status == "missing"
        assert issues[0].reference == "deleted_func"

    def test_missing_symbol_with_suggestion(self):
        fi = _make_fi("a.py", functions=["verify_jwt"])
        doc = "Use `verfiy_jwt` (typo)."
        issues = _check_citation_drift(doc, Path("."), [fi])
        assert len(issues) == 1
        assert "verify_jwt" in issues[0].suggestion

    def test_valid_class(self):
        fi = _make_fi("a.py", classes=["JwtMiddleware"])
        doc = "The `JwtMiddleware` class handles auth."
        issues = _check_citation_drift(doc, Path("."), [fi])
        assert issues == []

    def test_mixed_valid_and_drifted(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "auth.py").write_text("# auth")
            fi = _make_fi("src/auth.py", functions=["login"])
            doc = "See `src/auth.py`. Use `login()` to auth. Old `src/deleted.py` is gone."
            issues = _check_citation_drift(doc, root, [fi])
            # src/auth.py valid, login() valid, src/deleted.py missing
            assert len(issues) == 1
            assert issues[0].reference == "src/deleted.py"

    def test_empty_doc(self):
        issues = _check_citation_drift("", Path("."), [])
        assert issues == []

    def test_source_field_populated(self):
        fi = _make_fi("a.py")
        doc = "See `missing.py`."
        issues = _check_citation_drift(doc, Path("."), [fi], doc_source="docs/readme.md")
        assert issues[0].source == "docs/readme.md"

    def test_drift_issue_dataclass(self):
        d = DriftIssue(type="citation", reference="x.py", status="missing",
                       suggestion="not found", source="README.md")
        assert d.type == "citation"
        assert d.status == "missing"


# ── validate_project_docs integration ───────────────────────────────────────────


class TestValidateProjectDocsCitationDrift:
    def test_result_contains_citation_drift_key(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("See `nonexistent.py`.")
            result = validate_project_docs(root, [], [])
            assert "citation_drift" in result
            assert isinstance(result["citation_drift"], list)

    def test_drift_detected_in_readme(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("The `old_module.py` file handles it.")
            result = validate_project_docs(root, [], [])
            assert len(result["citation_drift"]) == 1
            assert result["citation_drift"][0]["reference"] == "old_module.py"

    def test_no_drift_when_refs_valid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fi = _make_fi("src/app.py", functions=["main"])
            (root / "README.md").write_text("See `src/app.py` and call `main()`.")
            result = validate_project_docs(root, [fi], [])
            assert result["citation_drift"] == []

    def test_summary_includes_drift_count(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("See `missing.py`.")
            result = validate_project_docs(root, [], [])
            assert "citation drift" in result["summary"].lower()


# ── Edge cases ──────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_only_non_code_extensions_ignored(self):
        text = "See `image.png` and `style.css`."
        paths, syms = _extract_citations(text)
        assert paths == []

    def test_relative_dot_paths(self):
        text = "See `./src/app.py`."
        paths, _ = _extract_citations(text)
        assert "./src/app.py" in paths

    def test_windows_backslash_paths(self):
        text = r"See `src\\app.py` for the entry."
        paths, _ = _extract_citations(text)
        assert len(paths) == 1

    def test_no_false_positives_from_english_words(self):
        text = "The algorithm processes data efficiently."
        paths, syms = _extract_citations(text)
        assert paths == []
        # "algorithm" ends in "m" not a code extension — no match
        # "processes" ends in "s" — no match
