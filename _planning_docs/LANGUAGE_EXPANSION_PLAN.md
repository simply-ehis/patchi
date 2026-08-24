# Patchi Language Expansion Plan — Close All Holes

**Goal:** Full-language parity for scanning, dead code detection, type checking, route detection, blast radius, fixing, and testing. Remove all regex-based source code parsing. Every language gets tree-sitter AST treatment.

---

## Phase 0: Add Missing Tree-Sitter Parsers

### New dependencies (pyproject.toml)
```toml
tree-sitter-php>=0.24
tree-sitter-c-sharp>=0.23
tree-sitter-kotlin>=1.0
tree-sitter-dart>=0.1
```

### `languages.py` changes
- Add `TREE_SITTER_LANGS`: add `PHP`, `C_SHARP`, `KOTLIN`, `DART`
- Remove the docstring lie: "Languages that use tree-sitter: Python, JavaScript, TypeScript"
- Add parser builders for all 4 new languages
- Scala not available on PyPI — keep regex until community grammar ships

### `EXTENSION_MAP` additions
- `.cs` → `C_SHARP` (already exists)
- `.kt`/`.kts` → `KOTLIN` (already exists)
- `.dart` → `DART` (already exists)
- `.php`/`.phtml` → `PHP` (already exists)

---

## Phase 1: Kill Regex Parsers in `scanner.py`

Replace all regex `_parse_*` methods with tree-sitter AST walkers.

### Priority order (impact)

| File | Method | Lines | Current | Replace With |
|------|--------|-------|---------|-------------|
| `scanner.py` | `_parse_php` | 1349-1374 | Regex | Tree-sitter PHP walker |
| `scanner.py` | `_parse_html` | 1380-1415 | html.parser | Tree-sitter HTML walker |
| `scanner.py` | `_parse_generic` | 1421-1432 | Regex | Remove — Bash/CSS/SQL get proper parsers |
| `scanner.py` | `_parse_java_regex` | 1006-1013 | Regex fallback | Delete, TS primary is sufficient |
| `scanner.py` | `_parse_go_regex` | 1060-1069 | Regex fallback | Delete |
| `scanner.py` | `_parse_c_cpp_regex` | 1140-1144 | Regex fallback | Delete |
| `scanner.py` | `_parse_swift_regex` | 1199-1206 | Regex fallback | Delete |
| `scanner.py` | `_parse_ruby_regex` | 1245-1253 | Regex fallback | Delete |
| `scanner.py` | `_parse_js_ts` regex fallback | 688-691 | Regex fallback | Delete |

### New tree-sitter walkers to write

#### `_parse_php` — tree-sitter PHP walker
Extract:
- `namespace_definition` → imports (namespace resolution)
- `use_declaration` → imports
- `function_definition` → functions
- `class_declaration` → classes
- `method_declaration` → methods
- `include_expression`/`require_expression` → file dependencies

#### `_parse_html` — tree-sitter HTML/JSX walker
Extract:
- `script` tags (delegate to JS parser)
- `link` tags → CSS dependencies
- Custom element tags → component references
- Replace stdlib `html.parser` with tree-sitter for structural accuracy

#### `_parse_bash` (split from `_parse_generic`)
Extract:
- `source`/`.` commands → imports
- `function_definition` → functions
- Variable references

#### `_parse_css` (split from `_parse_generic`)
Extract:
- `@import` → dependencies
- `@keyframes`, class definitions → symbols

#### `_parse_sql` (split from `_parse_generic`)
Extract:
- `CREATE TABLE/VIEW/PROCEDURE` → symbols
- `USE database` → dependencies

---

## Phase 2: Multi-Language Import Graph

**Problem:** `import_graph.py:153` uses `ast.parse` (Python-only). Dead code detection needs imports from ALL languages.

### Strategy

**Don't re-parse.** The scanner already extracts `ImportInfo` per file in `FileInfo.imports`. The import graph builder should consume that data directly.

### Changes to `import_graph.py`

1. **`build_graph`** — instead of calling `_extract_raw_imports` (Python ast), read `fi.imports` from already-scanned `FileInfo` objects
2. **`_resolve_to_local`** — make extension-aware:
   - Currently tries `.py` and `/__init__.py` only
   - Needs a lookup table: `{".py": ".py", ".js": [".js", ".jsx"], ".ts": [".ts", ".tsx"], ".rb": ".rb", ".rs": ".rs", ...}`
   - Use the `EXTENSION_MAP` from `languages.py` inverted
3. **`find_dead_files`** — already language-agnostic (operates on graph edges), just needs the graph populated

### Dead code detection for all languages
Once the import graph has edges for all languages:
- File-level dead code works for every language
- Symbol-level dead code (vulture) — need language-specific alternatives:
  - JS/TS: `ts-prune` or `npm-check`
  - Java: `jdepend` or built-in analysis
  - Go: `go vet` / `unused` from `honnef.co/go/tools`
  - Rust: `cargo deadlinks` or `rustc` dead_code warnings
  - PHP: `phpmd` or `phpstan`
  - Add configurable external tool runners

---

## Phase 3: Multi-Language Type Checking

**Problem:** `type_scanner.py` is TypeScript-only regex. Need AST-based checking per language.

### Architecture

Create `patchi/core/brain/type_checker/` with per-language modules:

```
type_checker/
  __init__.py       # dispatcher: TypeChecker.for_language(lang)
  base.py           # BaseTypeChecker ABC
  python.py         # Python type hints via ast
  typescript.py     # TS types via tree-sitter (replace regex)
  java.py           # Java generics/types
  go.py             # Go type system
  rust.py           # Rust type system
  csharp.py         # C# type system
  kotlin.py         # Kotlin type system
  swift.py          # Swift type system
  php.py            # PHP type hints
  dart.py           # Dart type system
```

### Per-language checks

| Language | What to Check |
|----------|---------------|
| Python | Missing type hints on public API, `Any` usage, untyped params |
| TypeScript | `any`, missing returns, unsafe assertions (replace current regex) |
| Java | Raw types, missing generics, unchecked casts |
| Go | `interface{}` usage, missing error returns, untyped constants |
| Rust | `unwrap()` usage, missing trait bounds, `Box<dyn Any>` |
| C# | `object`/`dynamic` usage, missing generics |
| Kotlin | `Any?` overuse, `!!` non-null assertions |
| Swift | Implicit unwrapped optionals, `Any` types |
| PHP | Missing type hints, mixed types |
| Dart | `dynamic` usage, missing null safety |

---

## Phase 4: Route Detection — Kill Regex in `route_graph_scanner.py` + `route_mapper.py`

### `route_graph_scanner.py` — Convert 5 regex methods to AST

| Method | Lines | Current | New Approach |
|--------|-------|---------|-------------|
| `_scan_js_routes` | 490-528 | Regex for Express/Fastify | Tree-sitter JS walker: find `call_expression` where func is `app.get/post...` |
| `_scan_java_routes` | 530-565 | Regex for Spring Boot | Tree-sitter Java walker: find `marker_annotation` with `GetMapping` etc. (already in symbol_graph) |
| `_scan_ruby_routes` | 567-612 | Regex for Rails/Sinatra | Tree-sitter Ruby walker: find `call` nodes for `get/post/resources` |
| `_scan_php_routes` | 614-648 | Regex for Laravel | Tree-sitter PHP walker: find `static_call_expression` for `Route::get` |
| `_scan_cs_routes` | 650-687 | Regex for ASP.NET | Tree-sitter C# walker: find `attribute` nodes for `HttpGet` etc. |

### `route_mapper.py` — 901 lines of regex → AST (17 frameworks)

This is the biggest single piece. Create `patchi/core/brain/route_detector/`:

```
route_detector/
  __init__.py
  base.py           # BaseRouteDetector ABC
  python.py         # FastAPI, Flask, Django (already AST in route_graph_scanner)
  javascript.py     # Express, Fastify, Next.js
  java.py           # Spring Boot
  go.py             # Gin, Echo, Fiber
  rust.py           # Actix, Axum, Rocket
  swift.py          # Vapor
  ruby.py           # Rails, Sinatra, Grape
  php.py            # Laravel
  csharp.py         # ASP.NET Core
```

Each detector uses tree-sitter for the language + framework-specific pattern matching on the AST.

---

## Phase 5: Kill Regex in `symbol_graph.py`

### `_extract_regex` (lines 1317-1352)
This is the catch-all for non-TS languages. Once Phases 0-1 are done, ALL languages have tree-sitter parsers, so this method becomes dead code. Remove it.

### `_find_references` (line 1518)
Regex `(\w+)\s*\(` fallback for call reference detection. Replace with tree-sitter cross-file reference resolution for each language that has a parser.

---

## Phase 6: Security Agent AST Upgrade

Replace regex pattern matching with AST-based analysis in security agents.

### Priority

| Agent | Current | AST Replacement |
|-------|---------|-----------------|
| `injection_agent.py` | 12+ regex patterns per lang | Tree-sitter taint tracking: data flow from user input → execution sinks |
| `security_taint.py` | Regex source/sink matching | Symbol graph + data flow analysis |
| `ssrf_agent.py` | 20+ regex patterns | AST: find all HTTP client calls, check URL sources |
| `catch_block_auditor.py` | Per-lang regex | Tree-sitter: find empty/overly-broad catch blocks |
| `env_var_validator.py` | Per-lang regex for env access | AST: find all env-access patterns per language |
| `insecure_randomness_agent.py` | Per-lang regex for RNG calls | AST: find all RNG API calls |
| `jwt_agent.py` | 25+ regex patterns | AST: find JWT lib usage, check algorithm params |
| `session_management_agent.py` | 12+ regex patterns | AST: find session config patterns |
| `auth_audit_agent.py` | 15+ regex patterns | AST + route detector: find auth on routes |
| `authz_agent.py` | 5+ regex patterns | AST: find authorization checks |
| `business_logic_agent.py` | 6+ regex patterns | AST: find mass assignment, IDOR patterns |

### Architecture

Create shared AST analysis utilities in `patchi/core/brain/ast_utils/`:

```
ast_utils/
  __init__.py
  calls.py          # Find all function calls matching a pattern
  imports.py        # Find all import statements
  decorators.py     # Find all decorators/annotations
  assignments.py    # Find variable assignments
  control_flow.py   # Track data flow through control structures
  taint.py          # Source-to-sink taint tracking
```

These are language-generic tree-sitter walking utilities. Each security agent uses these + per-language configuration (which function calls are sinks for SQLi, which are sources for SSRF, etc.)

---

## Phase 7: Fix Agent Multi-Language Support

### `_detect_language` expansion (fix_agents.py:102)
Currently maps only 5 extensions. Expand to 20+:

```python
def _detect_language(file_path: str) -> str:
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".tsx": "typescript", ".jsx": "javascript", ".php": "php",
        ".java": "java", ".cs": "csharp", ".rb": "ruby",
        ".go": "go", ".rs": "rust", ".swift": "swift",
        ".kt": "kotlin", ".kts": "kotlin", ".dart": "dart",
        ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
        ".scala": "scala",
    }.get(ext.lower(), "unknown")
```

### `TypeFixer` expansion
Currently TypeScript-only. Expand to cover all languages with type checkers (Phase 3):
- Python type hint fixer
- Java generic fixer
- Go interface{} fixer
- Rust unwrap fixer
- etc.

### `DeadCodeRemover` safety checks
Currently searches `.py`, `.json`, `.toml`, `.yml`, `.yaml` for dynamic references. Expand to search all source file types for string references to deleted files.

### `DependencyFixer` expansion
Currently handles `requirements.txt`, `package.json`, `pyproject.toml`. Add:
- `Cargo.toml` (Rust)
- `go.mod` (Go)
- `Gemfile` (Ruby)
- `composer.json` (PHP)
- `build.gradle`/`pom.xml` (Java/Kotlin)
- `Package.swift` (Swift)
- `pubspec.yaml` (Dart)

---

## Phase 8: Multi-Language Blast Radius

**Import graph** (Phase 2) feeds blast radius for all languages.
**Symbol graph** already works for all tree-sitter languages.

### Ensure parity
1. `calculate_blast_radius()` in `blast_radius.py:compute_blast_radius` — currently only searches `.py` files for string references. Change to search all source files.
2. `build_blast_radius_map()` — ensure it's called after import graph is built for all languages.
3. Add test fixtures with real multi-language projects.

---

## Phase 9: Testing Infrastructure

### Test fixtures per language
Create `tests/fixtures/languages/`:
```
tests/fixtures/languages/
  python/       # Small Flask/FastAPI project
  javascript/   # Express app
  typescript/   # Express + types
  java/         # Spring Boot app
  go/           # Gin app
  rust/         # Axum app
  ruby/         # Rails app
  php/          # Laravel app
  csharp/       # ASP.NET app
  kotlin/       # Ktor app
  swift/        # Vapor app
  dart/         # Shelf app
```

Each fixture has:
- Entry point (main/app)
- Routes
- Imports
- Functions/classes
- Some type issues
- Some dead code

### Integration tests per language

| Test | What It Validates |
|------|-------------------|
| `test_scan_{lang}.py` | Scanner finds all imports, functions, classes, routes |
| `test_import_graph_{lang}.py` | Import graph builds correctly |
| `test_dead_code_{lang}.py` | Dead files detected |
| `test_type_checker_{lang}.py` | Type issues found |
| `test_blast_radius_{lang}.py` | Blast radius correct |
| `test_routes_{lang}.py` | Routes detected and mapped |
| `test_security_{lang}.py` | Security findings for common vulns |
| `test_fix_{lang}.py` | Fix agent generates patches |

### End-to-end pipeline test
One test that runs the full pipeline (scan → detect → fix → verify) on a multi-language project and validates all outputs.

---

## Phase 10: Documentation & CI

### Language support matrix
Add `LANGUAGE_SUPPORT.md` with a table showing each language and which capabilities are supported.

### CI integration
- Add per-language test matrix in CI
- Each language fixture tested in isolation
- Combined multi-language project tested end-to-end

---

## Timeline Estimate

| Phase | Effort | Dependencies |
|-------|--------|-------------|
| 0 — TS parsers | 2 days | npm/PyPI package availability |
| 1 — Scanner regex kill | 5 days | Phase 0 |
| 2 — Multi-lang import graph | 3 days | Phase 1 |
| 3 — Type checker | 10 days | Phase 1 |
| 4 — Route detection AST | 8 days | Phase 1 |
| 5 — Symbol graph cleanup | 1 day | Phase 1 |
| 6 — Security agents AST | 15 days | Phases 1, 5 |
| 7 — Fix agents | 5 days | Phase 3 |
| 8 — Blast radius parity | 2 days | Phase 2 |
| 9 — Test fixtures | 8 days | All above |
| 10 — Docs + CI | 3 days | All above |
| **Total** | **~62 days** | |

---

## Key Architectural Decisions

1. **Never re-parse.** The scanner already produces structured `FileInfo` data. Import graph, type checker, route detector all consume scanner output — no duplicate parsing.

2. **Language-generic AST utilities.** AST walking patterns (find calls, find decorators, find imports) are shared across languages. Only language-specific node type names differ.

3. **Config-driven security patterns.** Security agents define "what's a sink for SQLi in Python vs Java" in YAML config, not hardcoded regex. The AST utility walks the tree and matches against the config.

4. **Tree-sitter primary, no fallback.** If a file can't be parsed by tree-sitter, it's a parse error finding, not a regex fallback. This ensures correctness and exposes parsing issues.

5. **Gradual roll-out.** Each phase can be implemented and tested independently. The system degrades gracefully: languages without type checkers just don't produce type findings.
