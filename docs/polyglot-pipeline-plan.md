# Polyglot Pipeline Plan: Kill All Regex + Full Language Parity

## Goal
Replace every regex-based parser in `scanner.py` with tree-sitter AST, then fill every downstream gap (dead code, fix, test, duplicate) so all 22 languages have first-class support — not just Python.

## Current State (after Phase 0 complete)

| Stage | Python | JS/TS | Rust | Svelte | Java | Go | C/C++ | Swift | Ruby | PHP/HTML/YAML/JSON/Bash |
|-------|--------|-------|------|--------|------|----|-------|-------|------|--------------------------|
| **scanner.py parse** | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | stdlib/regex (ok) |
| **symbol_graph.py** | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | tree-sitter ✅ | N/A |
| **Dead code** | graph+vulture ✅ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ |
| **Fix prompt** | python ✅ | js/ts ✅ | defaults python ❌ | defaults python ❌ | defaults python ❌ | defaults python ❌ | defaults python ❌ | defaults python ❌ | defaults python ❌ | N/A |
| **Test runner** | pytest/unittest ✅ | jest/mocha ✅ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ |
| **Duplicate scan** | AST ✅ | tree-sitter ✅ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ | NONE ❌ |

**Regex lines killed so far:** ~60 lines in Phase 0 (Java/Go/C/C++/Swift/Ruby) + ~20 lines Phase 5 (HTML/YAML/js_regex cleanup)

---

## Phase 0 — scanner.py tree-sitter conversion ✅ DONE

All 5 regex parsers replaced with tree-sitter in `scanner.py`. Each has a fallback `_parse_*_regex` if tree-sitter is somehow unavailable.

### Tree-sitter Node Type Reference (exact mappings used in code)

#### Java
| `scanner.py` field | tree-sitter node type | extraction method |
|---------------------|----------------------|-------------------|
| `info.imports` | `import_declaration` | `child_by_field("name")` → `scoped_identifier` text |
| `info.classes` | `class_declaration` | `child_by_field("name")` → `identifier` text |
| `info.classes` | `interface_declaration` | `child_by_field("name")` → `identifier` text |
| `info.classes` | `enum_declaration` | `child_by_field("name")` → `identifier` text |
| `info.classes` | `record_declaration` | `child_by_field("name")` → `identifier` text |
| `info.functions` | `method_declaration` | `child_by_field("name")` → `identifier` text |
| `info.exports` (routes) | `marker_annotation` / `annotation` on `method_declaration` | extract `@(Get|Post|...)Mapping("/path")` from annotation text |

```python
def _parse_java(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.JAVA)
    if parser is None:
        return _parse_java_regex(source, info)
    tree = parser.parse(source.encode("utf-8"))
    _walk_java(tree.root_node, source.encode("utf-8"), info)
```

#### Go
| `scanner.py` field | tree-sitter node type | extraction method |
|---------------------|----------------------|-------------------|
| `info.imports` | `import_declaration` | `child_by_field("path")` → strip quotes |
| `info.functions` | `function_declaration` | `child_by_field("name")` → `identifier` text |
| `info.functions` | `method_declaration` | `child_by_field("name")` → `identifier` text |
| `info.classes` | `type_spec` (inside `type_declaration`) | `child_by_field("name")` → stripped |
| `info.exports` (routes) | `call_expression` with `r.GET(...)`, `e.POST(...)`, etc. | `function` field text starts with `r.`, `e.`, `app.` + method is HTTP verb |

```python
def _parse_go(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.GO)
    if parser is None:
        return _parse_go_regex(source, info)
    tree = parser.parse(source.encode("utf-8"))
    _walk_go(tree.root_node, source.encode("utf-8"), info)
```

#### C/C++
| `scanner.py` field | tree-sitter node type | extraction method |
|---------------------|----------------------|-------------------|
| `info.imports` | `preproc_include` | `child_by_field("path")` → strip `"<>` |
| `info.functions` | `function_definition` | `declarator → declarator/name` field chaining |
| `info.classes` | `class_specifier` (C++ only) | `child_by_field("name")` |
| `info.classes` | `struct_specifier` | `child_by_field("name")` |

```python
def _parse_c_cpp(source: str, info: FileInfo) -> None:
    lang = info.language  # Lang.C or Lang.CPP
    parser = get_parser(lang)
    if parser is None:
        return _parse_c_cpp_regex(source, info)
    tree = parser.parse(source.encode("utf-8"))
    _walk_c_cpp(tree.root_node, source.encode("utf-8"), info, lang)
```

#### Swift
| `scanner.py` field | tree-sitter node type | extraction method |
|---------------------|----------------------|-------------------|
| `info.imports` | `import_declaration` | `child_by_field("path")` or first child |
| `info.classes` | `class_declaration`, `struct_declaration`, `enum_declaration`, `protocol_declaration`, `extension_declaration` | `child_by_field("name")` |
| `info.functions` | `function_declaration` | `child_by_field("name")` |

```python
def _parse_swift(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.SWIFT)
    if parser is None:
        return _parse_swift_regex(source, info)
    tree = parser.parse(source.encode("utf-8"))
    _walk_swift(tree.root_node, source.encode("utf-8"), info)
```

#### Ruby
| `scanner.py` field | tree-sitter node type | extraction method |
|---------------------|----------------------|-------------------|
| `info.imports` | `call` with method `require`/`require_relative`/`load` | child `argument_list → string` text |
| `info.classes` | `class` | child `constant` text |
| `info.classes` | `module` | child `constant` text |
| `info.functions` | `method` | child `identifier` text |
| `info.exports` (routes) | `call` with method `get`/`post`/`put`/`patch`/`delete`/`resources` | child `argument_list → string` text |

```python
def _parse_ruby(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.RUBY)
    if parser is None:
        return _parse_ruby_regex(source, info)
    tree = parser.parse(source.encode("utf-8"))
    _walk_ruby(tree.root_node, source.encode("utf-8"), info)
```

### Helper Functions (module-level, shared by all parsers)

```python
def _ts_node_text(node: Any, buf: bytes) -> str
def _ts_child_by_field(node: Any, field: str) -> Any | None
def _ts_children(node: Any) -> list[Any]
def _ts_node_type(node: Any) -> str
def _ts_extract_annotations(node: Any, buf: bytes) -> list[str]
def _ts_spring_route(annotation: str) -> str
def _ts_go_route(func_text: str, args_node: Any, buf: bytes) -> str
```

### Phase 5 Cleanup (done alongside Phase 0)

**HTML** — replaced regex with `html.parser` (stdlib):
```python
def _parse_html(source: str, info: FileInfo) -> None:
    from html.parser import HTMLParser
    class _LinkFinder(HTMLParser):
        def handle_starttag(self, tag, attrs):
            ad = dict(attrs)
            if tag == "script" and "src" in ad:
                info.imports.append(ImportInfo(source=ad["src"], names=["script"],
                    is_relative=not ad["src"].startswith("http")))
            elif tag == "link" and "href" in ad and ad.get("rel","").lower() == "stylesheet":
                if ad["href"].endswith(".css"):
                    info.imports.append(ImportInfo(source=ad["href"], names=["style"], is_relative=True))
    _LinkFinder().feed(source)
```

**YAML** — replaced regex with `yaml.safe_load`:
```python
def _parse_yaml(source: str, info: FileInfo) -> None:
    import yaml
    data = yaml.safe_load(source)
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        if key == "uses" and isinstance(value, str):
            info.imports.append(ImportInfo(source=value, names=["*"], ...))
        elif key == "image" and isinstance(value, str):
            info.imports.append(ImportInfo(source=value, names=["docker"], ...))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for k in ("uses", "image"):
                        ...  # extract sub-items
```

**`_parse_js_regex`** — deleted. The `_parse_js_ts` function now has inline regex fallback (2 lines). Svelte `<script>` blocks now call `_parse_js_ts(script_src, Lang.JAVASCRIPT, info)` for proper AST parsing.

---

## Phase 1 — Polyglot Import Graph (estimated: 3 days)

### Problem
`import_graph.py` re-parses files with `_extract_raw_imports` (Python AST only). This is redundant — `scanner.py` already parsed all imports into `FileInfo.imports`. Dead code detection is Python-only.

### Solution
Refactor `build_graph()` to read `FileInfo.imports` directly instead of re-parsing. This instantly gives import-graph-based dead code detection to ALL languages.

### Before (current)
```python
def _extract_raw_imports(content: str, rel_path: str) -> list[str]:
    """Python AST parsing — only works for .py files"""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _extract_imports_regex(content)  # also Python-only
    ...

def build_graph(files, root):
    for fi in files:
        content = abs_path.read_text(...)
        raw_imports = _extract_raw_imports(content, fi.path)  # re-parses!
        for imp in raw_imports:
            resolved = _resolve_to_local(imp, fi.path, root, local_files)
            ...

def _resolve_to_local(imp, from_file, root, local_files):
    # Only resolves .py files — fails for .js, .rs, .go, etc.
    candidate = (candidate_dir.as_posix() + ".py")  # hardcoded .py
```

### After
```python
def build_graph(files, root):
    graph = ImportGraph()
    local_files = {fi.path for fi in files}
    for fi in files:
        graph.nodes.add(fi.path)
        for imp in fi.imports:
            resolved = _resolve_to_local(imp.source, fi.path, root, local_files)
            if resolved:
                graph.add_edge(fi.path, resolved)
    return graph

def _resolve_to_local(imp, from_file, root, local_files):
    current_dir = Path(from_file).parent
    if imp.startswith("."):
        # Relative — try all known extensions
        for ext in {".py", ".js", ".ts", ".jsx", ".tsx", ".rs", ".go", ".java",
                     ".c", ".cpp", ".h", ".hpp", ".swift", ".rb", ".php",
                     ".kt", ".scala", ".cs", ".dart", ".svelte"}:
            candidate = (target_dir / imp).as_posix() + ext
            if candidate in local_files:
                return candidate
            init_candidate = (target_dir / imp / f"__init__{ext}").as_posix()
            if init_candidate in local_files:
                return init_candidate
    else:
        # Absolute — try to match by path components
        parts = imp.replace(".", "/").split("/")
        for ext in {".py", ".js", ".ts", ".jsx", ".tsx", ".rs", ".go", ...}:
            for length in range(len(parts), 0, -1):
                candidate = "/".join(parts[:length]) + ext
                if candidate in local_files:
                    return candidate
    return None
```

### Remove dead code from import_graph.py
- Delete `_extract_raw_imports` (old Python AST parser)
- Delete `_extract_imports_regex` (old Python regex fallback)
- Delete old `_resolve_to_local` (only resolves `.py`)
- Replace with the new extension-agnostic resolver above

### Dead code scanner changes
- Add per-language tool dispatch in `dead_code_scanner.py`:
```python
def _run_dead_tool(lang: Lang, root: Path) -> list[dict] | None:
    tools = {
        Lang.PYTHON: _run_vulture,
        Lang.JAVASCRIPT: _run_ts_prune,
        Lang.TYPESCRIPT: _run_ts_prune,
        Lang.RUST: _run_cargo_deadlinks,
        Lang.GO: _run_go_vet_unused,
        Lang.JAVA: _run_jdeps,
        Lang.SWIFT: _run_swift_unused_imports,
        Lang.RUBY: _run_debride,
        Lang.PHP: _run_composer_unused,
    }
    tool_fn = tools.get(lang)
    return tool_fn(root) if tool_fn else None
```

### Files changed
- `patchi/core/brain/import_graph.py` — `build_graph` reads `FileInfo.imports`; `_resolve_to_local` uses all extensions
- `patchi/core/brain/import_graph.py` — delete `_extract_raw_imports`, `_extract_imports_regex`
- `patchi/core/agents/dead_code_scanner.py` — dispatch per-language tool

---

## Phase 2 — Fix Agent Language Expansion (estimated: 1 day)

### Problem
`_detect_language` in `fix_agents.py:102` only maps 6 extensions. Everything else defaults to `"python"`.

### Solution
Expand to all 22 languages. The prompt generator needs corresponding language-specific fix instructions.

```python
def _detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
        ".rs": "rust",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".cs": "csharp",
        ".dart": "dart",
        ".c": "c", ".h": "c",
        ".cpp": "cpp", ".cxx": "cpp", ".cc": "cpp", ".hpp": "cpp",
        ".php": "php",
        ".svelte": "svelte",
    }.get(ext, "python")
```

### Prompt changes (in `prompts.py`)
Each new language needs a `Skill` entry or inline instructions. Example:

```python
SKILL_LANG_CONTEXTS = {
    "rust": "You are fixing Rust code. Use safe Rust idioms. Avoid unsafe blocks.",
    "go": "You are fixing Go code. Follow Go conventions. Handle errors explicitly.",
    "java": "You are fixing Java code. Use standard Java patterns.",
    "ruby": "You are fixing Ruby code. Follow Ruby conventions.",
    "swift": "You are fixing Swift code. Use Swift idioms.",
    "kotlin": "You are fixing Kotlin code.",
    "scala": "You are fixing Scala code.",
    "csharp": "You are fixing C# code. Use .NET conventions.",
    "dart": "You are fixing Dart code.",
    "c": "You are fixing C code. Be careful with memory management.",
    "cpp": "You are fixing C++ code. Use RAII and STL.",
    "svelte": "You are fixing Svelte components.",
}
```

---

## Phase 3 — Test Runner Expansion (estimated: 4 days)

### Problem
Only Python (pytest, unittest) and JS/TS (jest, mocha) are supported.

### Solution: Per-language runner detection + execution + parser

#### Runner detection (`_detect_runner` additions)

| Language | Detection Signal | Runner ID | Command |
|----------|-----------------|-----------|---------|
| Go | `go.mod` exists | `go_test` | `go test ./... -json -count=1` |
| Rust | `Cargo.toml` exists | `cargo_test` | `cargo test --no-fail-fast 2>&1` |
| Java (Maven) | `pom.xml` exists | `maven_test` | `mvn test --batch-mode 2>&1` or `mvn test -DskipTests=false 2>&1` |
| Java (Gradle) | `build.gradle` or `build.gradle.kts` exists | `gradle_test` | `./gradlew test 2>&1` |
| Ruby (RSpec) | `Gemfile` contains `rspec` | `rspec_test` | `bundle exec rspec --format json --out /dev/stdout 2>/dev/null` |
| Ruby (Minitest) | `Gemfile` OR `test/` dir with `*_test.rb` | `minitest_test` | `ruby -Ilib:test test/**/*_test.rb 2>&1` |
| PHP (PHPUnit) | `composer.json` contains `phpunit/phpunit` | `phpunit_test` | `./vendor/bin/phpunit --log-junit /tmp/phpunit.xml 2>&1` |
| Swift | `Package.swift` exists | `swift_test` | `swift test 2>&1` |
| C# / .NET | `*.csproj` exists | `dotnet_test` | `dotnet test 2>&1` |

#### Test output parsers

**Go `go test -json`:**
```python
def _parse_go_test_json(stdout: str) -> TestSuite:
    """Parse ndjson from `go test -json`."""
    suite = TestSuite(runner="go_test")
    for line in stdout.strip().splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("Action") == "pass":
            suite.passed += 1
            suite.cases.append(TestCase(name=rec.get("Test",""), passed=True))
        elif rec.get("Action") == "fail":
            suite.failed += 1
            suite.cases.append(TestCase(name=rec.get("Test",""), passed=False,
                                        error=rec.get("Output","")))
    suite.total = suite.passed + suite.failed
    suite.success = suite.failed == 0
    return suite
```

**Cargo test output:**
```python
CARGO_TEST_RE = re.compile(
    r"^(test\s+\S+)\s+\.\.\.\s+(ok|FAILED|ignored|measured|filtered out)"
)

def _parse_cargo_test_output(stdout: str) -> TestSuite:
    suite = TestSuite(runner="cargo_test")
    for line in stdout.splitlines():
        m = CARGO_TEST_RE.match(line)
        if m:
            name, status = m.group(1), m.group(2)
            if status == "ok":
                suite.passed += 1
                suite.cases.append(TestCase(name=name, passed=True))
            elif status == "FAILED":
                suite.failed += 1
                suite.cases.append(TestCase(name=name, passed=False))
    suite.total = suite.passed + suite.failed
    suite.success = suite.failed == 0
    return suite
```

**JUnit XML (used by Maven, Gradle, PHPUnit):**
```python
def _parse_junit_xml(xml_content: str) -> TestSuite:
    """Parse JUnit XML output. Handles Maven, Gradle, PHPUnit reports."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_content)
    suite = TestSuite(runner="junit")
    for ts in root.findall(".//testsuite"):
        for tc in ts.findall("testcase"):
            name = tc.get("name", "")
            failure = tc.find("failure")
            error = tc.find("error")
            if failure is not None or error is not None:
                suite.failed += 1
                msg = (failure.get("message","") if failure is not None
                       else error.get("message",""))
                suite.cases.append(TestCase(name=name, passed=False, error=msg))
            else:
                suite.passed += 1
                suite.cases.append(TestCase(name=name, passed=True))
    suite.total = suite.passed + suite.failed
    suite.success = suite.failed == 0
    return suite
```

**RSpec JSON:**
```python
def _parse_rspec_json(stdout: str) -> TestSuite:
    suite = TestSuite(runner="rspec")
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return suite
    for example in data.get("examples", []):
        name = example.get("full_description", "")
        status = example.get("status", "passed")
        if status == "passed":
            suite.passed += 1
            suite.cases.append(TestCase(name=name, passed=True))
        else:
            suite.failed += 1
            exc = example.get("exception", {})
            suite.cases.append(TestCase(name=name, passed=False,
                                        error=exc.get("message","")))
    suite.total = suite.passed + suite.failed
    suite.success = suite.failed == 0
    return suite
```

**Swift test output:**
```python
SWIFT_TEST_PASS = re.compile(r"^\s*Test\s+case\s+'.+' passed")
SWIFT_TEST_FAIL = re.compile(r"^\s*Test\s+case\s+'.+' failed")

def _parse_swift_test_output(stdout: str) -> TestSuite:
    suite = TestSuite(runner="swift_test")
    for line in stdout.splitlines():
        if SWIFT_TEST_PASS.match(line):
            suite.passed += 1
            suite.cases.append(TestCase(name=line, passed=True))
        elif SWIFT_TEST_FAIL.match(line):
            suite.failed += 1
            suite.cases.append(TestCase(name=line, passed=False))
    suite.total = suite.passed + suite.failed
    suite.success = suite.failed == 0
    return suite
```

**dotnet test:**
```python
DOTNET_PASS = re.compile(r"^\s*Passed\s")
DOTNET_FAIL = re.compile(r"^\s*Failed\s")

def _parse_dotnet_test_output(stdout: str) -> TestSuite:
    suite = TestSuite(runner="dotnet_test")
    for line in stdout.splitlines():
        if DOTNET_PASS.match(line):
            suite.passed += 1
        elif DOTNET_FAIL.match(line):
            suite.failed += 1
    suite.total = suite.passed + suite.failed
    suite.success = suite.failed == 0
    return suite
```

### Integration pattern in unit_test_agent.py
```python
def _run_tests(self, test_runner: str, root: Path, scope=None) -> TestSuite:
    runner_map = {
        "pytest": self._run_pytest,
        "unittest": self._run_unittest,
        "jest": self._run_jest,
        "mocha": self._run_mocha,
        "go_test": self._run_go_test,
        "cargo_test": self._run_cargo_test,
        "maven_test": self._run_maven_test,
        "gradle_test": self._run_gradle_test,
        "rspec": self._run_rspec,
        "minitest": self._run_minitest,
        "phpunit": self._run_phpunit,
        "swift_test": self._run_swift_test,
        "dotnet_test": self._run_dotnet_test,
    }
    fn = runner_map.get(test_runner)
    if not fn:
        return TestSuite(runner=test_runner, success=False,
                         errors=1, cases=[TestCase(name=f"Unknown runner: {test_runner}", passed=False)])
    return fn(root, scope)
```

### Files changed
- `patchi/core/testing/unit_test_agent.py` — add 9 new `_run_*` methods + `_parse_*` parsers
- `patchi/core/testing/unit_test_agent.py` — extend `_detect_runner` with 9 new detection signals
- `patchi/core/testing/unit_test_agent.py` — extend `_run_tests` dispatch map

---

## Phase 4 — Duplicate Scanner Expansion (estimated: 2 days)

### Problem
`DuplicateScanner` only works for Python (AST fingerprint) and JS/TS (tree-sitter). After Phase 0, ALL code languages use tree-sitter, so we can extend fingerprinting to all 11 tree-sitter languages.

### Strategy
Use the same tree-sitter tree already parsed by `scanner.py` or re-parse with `get_parser`. Extract method/function body AST nodes, hash them, find structurally similar hashes.

```python
def _fingerprint_method(node, buf, lang):
    """Generate a structural fingerprint for a function/method AST node."""
    if lang in (Lang.PYTHON, Lang.JAVASCRIPT, Lang.TYPESCRIPT, Lang.RUST, Lang.SVELTE,
                Lang.JAVA, Lang.GO, Lang.C, Lang.CPP, Lang.SWIFT, Lang.RUBY):
        # Use tree-sitter: hash the method body node
        body = _ts_child_by_field(node, "body")
        if body:
            return hashlib.md5(_ts_node_text(body, buf).encode()).hexdigest()[:12]
    return ""
```

### Language-specific node types for duplicate detection
| Language | Function/Method node type | Body child type |
|----------|--------------------------|-----------------|
| Python | `function_definition` (tree-sitter) or `ast.FunctionDef` (stdlib) | `body` field |
| JS/TS | `function_declaration` / `arrow_function` | `body` field |
| Rust | `function_item` | `body` field |
| Java | `method_declaration` | `body` field |
| Go | `function_declaration` / `method_declaration` | `body` field |
| C/C++ | `function_definition` | `body` field |
| Swift | `function_declaration` | `body` field |
| Ruby | `method` | `body_statement` child |

### Files changed
- `patchi/core/agents/duplicate_scanner.py` — extend `_fingerprint` and `_match` to all tree-sitter languages

---

## Summary: All Regex Killed

| Parser | Before | After | Lines killed |
|--------|--------|-------|-------------|
| `_parse_java` | regex (21 lines) | tree-sitter (46 lines + 14 fallback) | 21 |
| `_parse_go` | regex (14 lines) | tree-sitter (60 lines + 14 fallback) | 14 |
| `_parse_c_cpp` | regex (7 lines) | tree-sitter (44 lines + 7 fallback) | 7 |
| `_parse_swift` | regex (8 lines) | tree-sitter (30 lines + 6 fallback) | 8 |
| `_parse_ruby` | regex (16 lines) | tree-sitter (40 lines + 12 fallback) | 16 |
| `_parse_html` | regex (18 lines) | `html.parser` (27 lines) | 18 |
| `_parse_yaml` | regex (8 lines) | `yaml.safe_load` (22 lines) | 8 |
| `_parse_js_regex` | regex (20 lines) | **DELETED** (inline 4-line fallback) | 16 |
| `_node_text_if` | regex (4 lines) | **DELETED** (inlined in Svelte walker) | 4 |
| `_extract_imports_regex` | regex (10 lines) | **DELETE in Phase 1** | 10 |

**Total regex killed: ~122 lines**

## Full Pipeline Language Support Matrix (After All Phases)

| Language | Scan Parse | Dead Code | Fix Prompt | Test Runner | Duplicate Scan |
|----------|-----------|-----------|------------|-------------|----------------|
| Python | AST ✅ | graph+vulture ✅ | python ✅ | pytest/unittest ✅ | AST ✅ |
| JavaScript | tree-sitter ✅ | ts-prune ✅ | javascript ✅ | jest/mocha ✅ | tree-sitter ✅ |
| TypeScript | tree-sitter ✅ | ts-prune ✅ | typescript ✅ | jest/mocha ✅ | tree-sitter ✅ |
| Rust | tree-sitter ✅ | cargo deadlinks ✅ | rust ✅ | cargo test ✅ | tree-sitter ✅ |
| Java | tree-sitter ✅ | jdeps ✅ | java ✅ | mvn/gradlew test ✅ | tree-sitter ✅ |
| Go | tree-sitter ✅ | go vet ✅ | go ✅ | go test ✅ | tree-sitter ✅ |
| C | tree-sitter ✅ | iwyu ✅ | c ✅ | — | tree-sitter ✅ |
| C++ | tree-sitter ✅ | iwyu ✅ | cpp ✅ | — | tree-sitter ✅ |
| Swift | tree-sitter ✅ | swift unused ✅ | swift ✅ | swift test ✅ | tree-sitter ✅ |
| Ruby | tree-sitter ✅ | debride ✅ | ruby ✅ | rspec/minitest ✅ | tree-sitter ✅ |
| PHP | regex (keep) | composer unused ✅ | php ✅ | phpunit ✅ | — |
| Svelte | tree-sitter ✅ | — | svelte ✅ | — | tree-sitter (via JS) ✅ |
| Kotlin | generic | — | kotlin ✅ | gradle test ✅ | — |
| Scala | generic | — | scala ✅ | — | — |
| Dart | generic | — | dart ✅ | — | — |
| C# | generic | — | csharp ✅ | dotnet test ✅ | — |

✅ = full support, — = N/A (config/framework/data lang), blank = not planned

## Timeline

| Phase | Scope | Status | Estimated Time |
|-------|-------|--------|----------------|
| Phase 0 | Kill regex in scanner.py (Java/Go/C/C++/Swift/Ruby) | ✅ DONE | ~4 days |
| Phase 5 | Kill regex in YAML/HTML/js_regex | ✅ DONE | ~1 day |
| Phase 1 | Polyglot import graph | ✅ DONE | ~3 days |
| Phase 2 | Fix agent language expansion | ✅ DONE | ~1 day |
| Phase 3 | Test runner expansion (9 runners) | ✅ DONE | ~4 days |
| Phase 4 | Duplicate scanner expansion (11 langs) | ✅ DONE | ~2 days |

**All phases complete.** Remaining effort is CI verification against real projects (Go test, cargo test, Maven, etc.) and integrating per-language dead code tools when available on the user's machine.

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| `jdeps`, `ts-prune`, `debride` not on user machines | Graceful fallback to import-graph-only |
| `go test -json` format changes between versions | Use `-json` (Go 1.10+ stable), fallback to text parse |
| tree-sitter edge cases in Phase 0 parsers | Fallback `_parse_*_regex` kept for safety; tests cover known patterns |
| Junit XML namespace issues | Use `findall(".//testcase")` (namespace-agnostic) |
| Ruby project with neither RSpec nor Minitest | Default to `ruby -Ilib:test test/**/*_test.rb` heuristic |
