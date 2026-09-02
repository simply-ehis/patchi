# Patchi — Comprehensive Feature Expansion Plan

> **Status:** Planning Phase  
> **Target:** Language-agnostic audit, cleanup & hardening across all 11 languages (Python, JS, TS, Rust, Svelte, Java, Go, C, C++, Swift, Ruby)  
> **Principle:** Every feature must work across all languages — not be tied to a single ecosystem

---

## Table of Contents

1. [Static Analysis Engine](#1-static-analysis-engine)
2. [Dead Code & Dependency Cleanup](#2-dead-code--dependency-cleanup)
3. [Route & API Contract Validation](#3-route--api-contract-validation)
4. [Security Hardening](#4-security-hardening)
5. [Dynamic & Runtime Analysis](#5-dynamic--runtime-analysis)
6. [Testing & Coverage Intelligence](#6-testing--coverage-intelligence)
7. [Refactoring & Auto-Cleanup](#7-refactoring--auto-cleanup)
8. [Multi-Framework & Multi-Language Support](#8-multi-framework--multi-language-support)
9. [Reporting & Developer Experience](#9-reporting--developer-experience)
10. [CI/CD & Prevention](#10-cicd--prevention)
11. [Advanced / Future-Proofing](#11-advanced--future-proofing)
- [Language-Agnostic Tooling Reference](#language-agnostic-tooling-reference)
- [Implementation Roadmap](#implementation-roadmap)
- [Quick Wins](#quick-wins)

---

## 1. Static Analysis Engine

### 1.1 Type Safety & Compiler Integration

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 1.1.1 | **Strict Mode Enforcer**: Auto-detect tsconfig/jestconfig and enforce `strict: true`, `noImplicitAny`, `strictNullChecks`, `noUncheckedIndexedAccess` | ❌ Missing | Per-language config detection + JSON/YAML parser to inject strict settings; build flag injection for non-TS languages (e.g. `-Wall -Werror` for C/C++, `-race` for Go) | Custom per-language config patcher |
| 1.1.2 | **Multi-compiler Support**: TypeScript, Flow, Babel, SWC, esbuild integration | ⚠️ Partial (TS only) | Wrap each compiler's CLI as a Patchi agent; parse output into unified JSON schema | `tsc --noEmit`, `swc`, `esbuild`, `babel` as subprocess executors |
| 1.1.3 | **Incremental Type Checking**: Only re-check changed files and their dependents | ❌ Missing | Use file hash tracking (already in Patchi memory) to skip unchanged files; dependents from import graph | Patchi's existing `memory/` + import graph |
| 1.1.4 | **Type Error Categorization**: Classify errors by severity (Runtime Crash vs. Cosmetic) and blast radius | ❌ Missing | Parse compiler output; classify by error code via lookup table; cross-ref with import graph for blast radius | Custom classifier per language |
| 1.1.5 | **Auto-fix Suggestions**: Generate `--fix` patches for simple type mismatches (e.g., missing null checks) | ⚠️ Partial (TypeFixer agent exists, TS only) | Extend TypeFixer to all 11 languages; use tree-sitter AST to insert null checks, optional chaining equivalents | Patchi `TypeFixer` agent + tree-sitter |

### 1.2 Linting & Code Quality

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 1.2.1 | **Deep ESLint Integration**: Run with `@typescript-eslint/recommended-requiring-type-checking` | ⚠️ Partial (ESLint hooked, not deep) | ESLint as subprocess; parse JSON output; add TS type-checked ruleset config injection | `eslint`, `@typescript-eslint` |
| 1.2.2 | **Custom Rule Engine**: Built-in rules (no-floating-promises, no-misused-promises, await-thenable, no-implicit-any-catch, prefer-nullish-coalescing) | ❌ Missing | ESLint plugin configs; equivalent rules for other languages via Ruff (Python), clang-tidy (C/C++), golangci-lint (Go) | `ruff` (Python), `clang-tidy` (C/C++), `golangci-lint` (Go), `swiftlint` (Swift), `rubocop` (Ruby) |
| 1.2.3 | **Zero-Warnings Policy**: `--max-warnings=0` enforcement with CI gate | ❌ Missing | Pass `--max-warnings 0` to linters; aggregate pass/fail into CI gate | All linter CLIs |
| 1.2.4 | **Style Consistency**: Prettier / Biome integration with auto-format on scan | ⚠️ Partial | Run formatter post-scan; diff to report unformatted files; optional auto-format | `prettier`, `biome`, `dprint` (multi-lang), `rustfmt`, `gofmt`, `black` |

### 1.3 Architecture & Dependency Graph

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 1.3.1 | **Circular Dependency Detection**: Visual graph of import cycles | ⚠️ Partial (Patchi has import graph with some cycle detection) | Use tree-sitter import extraction across all 11 languages; run cycle detection via Tarjan's algorithm on the module graph; emit DOT/JSON for visualization | Patchi `BuildGraph` + [`multilang-depends/depends`](https://github.com/multilang-depends/depends) (8+ languages) |
| 1.3.2 | **Layer Enforcement**: Define architectural layers and block illegal imports | ❌ Missing | YAML config for layer rules; validate import edges against ruleset; block violations | Custom, inspired by `dependency-cruiser` for JS/TS; ArchUnit for Java; generalizable via import graph |
| 1.3.3 | **Import Graph Visualization**: Interactive SVG/Canvas graph of module relationships | ❌ Missing | Generate DOT/GraphML from import graph; serve via web UI or export SVG | `graphviz` + D3.js or vis-network |
| 1.3.4 | **Orphaned File Detection**: Find files with zero imports and zero exports consumed | ⚠️ Partial (Patchi has dead file detection) | Cross-ref import graph: files with `in-degree=0` and `out-degree=0` (excluding entry points) | Patchi import graph |

---

## 2. Dead Code & Dependency Cleanup

### 2.1 Dead Code Detection

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 2.1.1 | **Unused Export Scanner**: Find exported functions/classes never imported (tree-shake analysis) | ⚠️ Partial (Patchi DeadCodeRemover exists, limited scope) | Use [`sglyon/deadcode`](https://github.com/sglyon/deadcode) as orchestrator: detects language, runs best-in-class tool per language, emits unified JSON | [`sglyon/deadcode`](https://github.com/sglyon/deadcode) (Python/JS/TS/Go/Elixir), `knip` (JS/TS), `vulture` (Python), `staticcheck` (Go), `cargo-udeps` (Rust), `periphery` (Swift) |
| 2.1.2 | **Unused Variable/Import Cleanup**: Auto-remove dead imports and variables | ❌ Missing | Language-specific auto-fix commands; fallback: tree-sitter AST deletion | ESLint `--fix`, Ruff `--fix`, `golint`, `rustfix` |
| 2.1.3 | **Unreachable Code Path Detection**: Find code after return, in dead if branches, or behind always-false flags | ❌ Missing | Tree-sitter AST analysis for dead branches; compiler unreachable warnings | `clang` `-Wunreachable-code`, `golint`, `vulture`, tree-sitter custom queries |
| 2.1.4 | **Feature Flag Archaeology**: Detect boolean flags that have been hardcoded for >N releases | ❌ Missing | Git blame + grep for flag names; check if value is constant across N commits | Git blame + custom analysis ([`uber/piranha`](https://github.com/uber/piranha) for feature flag refactoring) |

### 2.2 Dependency Hygiene

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 2.2.1 | **Unused Dependency Detection**: package.json bloat detection | ⚠️ Partial (DependencyChecker exists) | Parse package manager manifests; detect deps not imported in source | `depcheck` (JS/TS), `cargo-udeps` (Rust), `go mod why`, `pip-check` |
| 2.2.2 | **Duplicate Dependency Finder**: Multiple versions of same package in lockfile | ❌ Missing | Parse lockfiles; group by package name; flag version variants | `yarn-deduplicate`, `pnpm dedupe`, `go mod why`, `cargo tree` |
| 2.2.3 | **Vulnerability Scanner**: Integrate npm audit, yarn audit, OSV database | ✅ Existing (DependencyCVEChecker) | Already exists — enhance with more data sources | Patchi `DependencyCVEChecker` + OSV API |
| 2.2.4 | **Outdated Dependency Report**: Flag packages behind by major/minor versions with changelog links | ❌ Missing | Cross-ref installed vs. latest from registries; attach changelog URL | `npm outdated`, `cargo outdated`, `go list -u`, `pip list --outdated` |
| 2.2.5 | **Supply Chain Risk**: Flag packages with suspicious metadata | ❌ Missing | Score packages on: new author, download spike, obfuscated code, known typosquatting | [`Socket.dev`](https://socket.dev) API or custom [`guacsec/guac`](https://github.com/guacsec/guac) integration |

---

## 3. Route & API Contract Validation

### 3.1 Full-Stack Route Matching

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 3.1.1 | **Frontend Route Extraction**: Parse fetch, axios, ky, trpc, graphql calls to build API call inventory | ✅ Existing (RouteMapper) | Already works — tree-sitter + regex for HTTP client calls across all 11 langs | Patchi `RouteMapper` |
| 3.1.2 | **Backend Route Extraction**: Parse framework routes to build endpoint inventory | ✅ Existing (RouteMapper) | 18+ frameworks across all 11 languages | Patchi `RouteMapper` |
| 3.1.3 | **Contract Diff Engine**: Cross-reference frontend calls ↔ backend endpoints | ⚠️ Partial (basic diff exists) | Compute diff: `set(frontend_paths) - set(backend_paths)` and vice versa; method & param matching | Custom diff engine in Patchi `RouteMapper` |
| 3.1.4 | **Missing Routes**: Frontend calls endpoint that doesn't exist (guaranteed 404) | ❌ Missing | Contract diff: frontend paths not in backend set | Patchi contract diff |
| 3.1.5 | **Orphan Endpoints**: Backend endpoint never called by frontend (dead API) | ❌ Missing | Contract diff: backend paths not in frontend set | Patchi contract diff |
| 3.1.6 | **Method Mismatch**: GET called but POST defined | ❌ Missing | Compare HTTP methods per path | Patchi contract diff |
| 3.1.7 | **Path Parameter Drift**: `/user/:id` vs `/users/:userId` | ❌ Missing | Parse path parameters; check naming consistency | Patchi contract diff |

### 3.2 Schema Validation

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 3.2.1 | **Zod / Yup / Joi Contract Sync**: Runtime validators match TypeScript types | ❌ Missing | Parse type definitions + runtime validator schemas; diff the inferred types | `ts-to-zod`, custom TypeScript compiler API analysis |
| 3.2.2 | **OpenAPI / GraphQL Schema Drift**: Compare generated schema against implementation | ❌ Missing | Diff OpenAPI spec (from routes) against implementation routes; detect missing/extra endpoints | Custom; inspired by `optiv/OpenAPI-Spec-Validator` |
| 3.2.3 | **Env Var Validation**: Scan `process.env` usage and validate against `.env.example` or schema | ❌ Missing | Grep for env var reads; cross-ref with `.env.example`; detect unvalidated usage | Custom; [`envguard`](https://github.com/nicoverbruggen/envguard) or [`dotenv-linter`](https://github.com/dotenv-linter/dotenv-linter) |

### 3.3 Navigation & Deep Link Audit

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 3.3.1 | **SPA Route Inventory**: Extract all router destinations (react-router, vue-router, next/link) | ❌ Missing | Tree-sitter parse of frontend router definitions; extract `path` + `component` pairs | Custom tree-sitter queries per framework |
| 3.3.2 | **Dead Link Detection**: Find `<Link to="/old-page">` where route no longer exists | ❌ Missing | Cross-ref link targets against SPA route inventory | Custom |
| 3.3.3 | **Deep Link Test**: Verify every route renders without crashing on direct navigation | ❌ Missing | Playwright/Cypress script that navigates to each route and checks for error state | Patchi `E2EFlowAgent` + Playwright |

---

## 4. Security Hardening

### 4.1 Static Security Analysis

*Note: Patchi already has 44+ security agents covering most SAST concerns. This section tracks gaps.*

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 4.1.1 | **SAST Engine**: Configurable rules for unsafe patterns across all languages | ✅ Existing (44+ agents) | Already covered by existing agents | Patchi security agents |
| 4.1.2 | **Unsafe `eval()` / `new Function()` detection** | ⚠️ Partial (in some agents) | Grep + tree-sitter pattern; generalize to all languages that support eval-like constructs | Semgrep rules + tree-sitter queries |
| 4.1.3 | **Path traversal detection** | ✅ Existing | InjectionAgent covers this | Patchi `InjectionAgent` |
| 4.1.4 | **SQL injection vectors** | ✅ Existing | InjectionAgent covers this | Patchi `InjectionAgent` |
| 4.1.5 | **XSS sinks detection** | ✅ Existing | `SensitiveDataAgent` + `BrowserTesterAgent` | Patchi agents |
| 4.1.6 | **Hardcoded secrets / API keys** | ✅ Existing | SecretScanner agent | Patchi `SecretScanner` |
| 4.1.7 | **Insecure randomness (Math.random() for tokens)** | ❌ Missing | Grep for weak RNG patterns; suggest crypto-secure alternatives | Custom rule in `InjectionAgent` or `TaintAnalyzer` |

### 4.2 Runtime Security

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 4.2.1 | **CSP Header Auditor**: Validate Content-Security-Policy | ✅ Existing | `RuntimeValidatorAgent` checks headers | Patchi `RuntimeValidatorAgent` |
| 4.2.2 | **CORS Misconfiguration Detection** | ✅ Existing | `CORSAuditor` agent | Patchi `CORSAuditor` |
| 4.2.3 | **Auth Bypass Detection**: Routes missing middleware checks | ⚠️ Partial | Cross-ref route metadata (auth_required flag) against middleware patterns | Patchi route mapper + `AuthZAgent` |
| 4.2.4 | **Rate Limiting Audit**: Ensure sensitive endpoints have rate limiting | ❌ Missing | Check for rate-limit middleware on auth/payment routes; grep for `rate-limit` patterns | Custom; [`rate-limiter-flexible`](https://github.com/animir/node-rate-limiter-flexible) |

### 4.3 Secret Management

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 4.3.1 | **Secret Scanner**: Detect committed .env, id_rsa, aws_credentials | ✅ Existing | `SecretScanner` agent covers this | Patchi `SecretScanner` |
| 4.3.2 | **Entropy Analysis**: Find high-entropy strings that look like tokens | ⚠️ Partial | Shannon entropy calculation on string literals; cross-ref with known secret patterns | [`truffleHog`](https://github.com/trufflesecurity/trufflehog) or [`ggshield`](https://github.com/GitGuardian/ggshield) |
| 4.3.3 | **Pre-commit Hook**: Block secrets before they reach the repo | ❌ Missing | Generate pre-commit hook config; integrate with `husky` or `pre-commit` framework | `pre-commit` (framework), `husky` + Patchi CLI |

---

## 5. Dynamic & Runtime Analysis

### 5.1 Unhandled Error Detection

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 5.1.1 | **Promise Rejection Tracker**: Instrument `unhandledRejection` and `uncaughtException` during test runs | ❌ Missing | Inject unhandled rejection handlers at app entry; aggregate during test runs; report all uncaught errors | Custom instrumentation; `process.on('unhandledRejection')` for Node, `sys.excepthook` for Python, equivalent per language |
| 5.1.2 | **Async Stack Trace Enhancement**: Use async_hooks / async-context to trace promise origins | ❌ Missing | Language-specific async context tracking libraries | `node:async_hooks` (Node), `contextvars` (Python), `tokio` tracing (Rust) |
| 5.1.3 | **Console Error Aggregation**: Collect all `console.error` / `console.warn` during CI and categorize | ❌ Missing | Wrap console methods in test runner; aggregate unique error messages | Custom test runner hook |

### 5.2 Memory & Performance Profiling

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 5.2.1 | **Memory Leak Detector**: Track heap growth across test suites | ❌ Missing | Run test suite and sample heap before/after; flag >X% growth | Chrome DevTools Protocol (CDP), `memray` (Python), `pprof` (Go), `heaptrack` (C/C++) |
| 5.2.2 | **Detached DOM Detection**: Find React/Vue components leaving DOM nodes behind | ❌ Missing | CDP heap snapshot analysis; look for detached DOM trees with JS references | Chrome DevTools Protocol via Puppeteer/Playwright |
| 5.2.3 | **Event Listener Leak Tracker**: Monitor addEventListener without matching removeEventListener | ❌ Missing | Instrument `addEventListener` / `removeEventListener` in test run; track imbalance | Custom CDP instrumentation |
| 5.2.4 | **Bundle Size Regression**: Track webpack/Vite/rollup output size per PR | ❌ Missing | Run build, capture output sizes, compare against baseline | [`relative-ci/bundle-stats`](https://github.com/relative-ci/bundle-stats) or `webpack --json` + custom tracker |
| 5.2.5 | **Startup Time Benchmark**: Measure cold start / build time and alert on regression | ❌ Missing | Script to time `npm run build` or equivalent; track in CHANGELOG-style baseline file | Custom benchmark script |

### 5.3 API Fuzzing

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 5.3.1 | **Auto-Fuzzer**: Generate malformed JSON, massive payloads, wrong Content-Types, injection strings | ❌ Missing | From OpenAPI/GraphQL schema, generate malformed inputs; fire at running server | [`WebFuzzing/EvoMaster`](https://github.com/WebFuzzing/EvoMaster) (REST/GraphQL/gRPC), [`microsoft/restler-fuzzer`](https://github.com/microsoft/restler-fuzzer), [`Endava/cats`](https://github.com/Endava/cats) |
| 5.3.2 | **Boundary Testing**: Empty arrays, null, 0, undefined, unicode, emoji, 10MB strings | ❌ Missing | Extend auto-fuzzer with boundary payload templates | Custom fuzzer payload generator |
| 5.3.3 | **Race Condition Detection**: Concurrent duplicate requests to test transaction safety | ❌ Missing | Fire N concurrent requests to same endpoint; check for duplicate records, inconsistent state | Custom; `Promise.all()` concurrent requests in test script |
| 5.3.4 | **Chaos Testing**: Randomly kill processes, drop network, fill disk during E2E runs | ❌ Missing | Integrate with chaos engineering tools; run during E2E | [`chaosblade-io/chaosblade`](https://github.com/chaosblade-io/chaosblade), [`litmuschaos/litmus`](https://github.com/litmuschaos/litmus) |

---

## 6. Testing & Coverage Intelligence

### 6.1 Test Gap Analysis

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 6.1.1 | **Coverage-Guided Prioritization**: Highlight uncovered lines in "hot" (frequently modified) files | ❌ Missing | Cross-ref git blame frequency with coverage data; highlight uncovered hot files | `git log` + coverage report (`pytest-cov`, `nyc`, `gocov`, `grcov`, `kcov`) |
| 6.1.2 | **Branch Coverage Deep Dive**: Ensure every if/else, ternary, and switch case is tested | ❌ Missing | Parse compiler/coverage tool output for branch coverage; flag uncovered branches | `pytest-cov --branch`, `nyc --branches`, `go test -coverprofile`, `grco` |
| 6.1.3 | **Mutation Testing Integration**: Run Stryker/mutators to verify tests actually catch bugs | ❌ Missing | Language-agnostic: [`agroce/universalmutator`](https://github.com/agroce/universalmutator) (regex-based, any language); language-specific: `Stryker` (JS/TS/C#/Scala), `cargo-mutants` (Rust), `mutmut` (Python), `mutant` (Ruby) | [`universalmutator`](https://github.com/agroce/universalmutator) for broad coverage; per-language tools for depth |
| 6.1.4 | **Flaky Test Detection**: Track test duration and failure correlation across runs | ❌ Missing | Log test results to SQLite; detect tests that pass/fail inconsistently; track duration variance | Patchi test history (SQLite) + custom flake analyzer |

### 6.2 Auto-Test Generation

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 6.2.1 | **Snapshot Drift Detection**: Alert when UI snapshots change unexpectedly | ❌ Missing | Run visual regression tests; diff against baseline; alert on unexpected changes | Patchi `VisualRegressionAgent` (already exists) |
| 6.2.2 | **Contract Test Generation**: Auto-generate Pact/MSW tests from API call patterns | ❌ Missing | From frontend fetch calls, generate mock server tests (MSW) or consumer-driven contract tests (Pact) | [`mswjs/msw`](https://github.com/mswjs/msw), [`pact-foundation/pact`](https://github.com/pact-foundation/pact) |
| 6.2.3 | **Type Definition → Test Scaffold**: Generate basic unit test stubs from type definitions | ⚠️ Partial (UnitTestRunner exists) | Parse function signatures → generate test skeleton with default inputs | Patchi `UnitTestRunner` (already exists) |

### 6.3 E2E Health Checks

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 6.3.1 | **Playwright / Cypress Integration**: Run smoke tests against production build | ✅ Existing | `E2EFlowAgent` already uses Playwright | Patchi `E2EFlowAgent` |
| 6.3.2 | **Visual Regression**: Pixel-diff critical user flows across branches | ✅ Existing | `VisualRegressionAgent` already does this | Patchi `VisualRegressionAgent` |
| 6.3.3 | **Accessibility Audit**: axe-core integration for WCAG compliance | ✅ Existing | `AccessibilityAgent` + `UIAccessibilityAgent` | Patchi agents |

---

## 7. Refactoring & Auto-Cleanup

### 7.1 Automated Fixes

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 7.1.1 | **Auto-fix Type Errors**: Insert missing null checks, optional chaining, type assertions where safe | ⚠️ Partial (TypeFixer, TS only) | Extend TypeFixer to all languages: tree-sitter AST transformation for null-check insertion | Patchi `TypeFixer` agent + tree-sitter per language |
| 7.1.2 | **Dead Code Removal**: Auto-delete unused imports, variables, functions, files (with backup) | ⚠️ Partial (DeadCodeRemover exists) | Already exists — extend coverage to all 11 languages | Patchi `DeadCodeRemover` |
| 7.1.3 | **Dependency Sorting**: Auto-sort package.json and imports | ❌ Missing | Run `sort-package-json`, `isort` (Python), `goimports` (Go), `rustfmt` (Rust) | `sort-package-json`, `isort`, `goimports`, `rustfmt` |
| 7.1.4 | **Modernization Codemods**: `var→const/let`, `.then()→async/await`, class→functional components, `require()→import`, callbacks→Promises | ❌ Missing | Language-specific AST codemods; JS/TS: jscodeshift; Python: bowcaster or custom lib2to3 | `jscodeshift`, `ts-migrate`, `python-modernize` |

### 7.2 Error Handling Standardization

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 7.2.1 | **Catch Block Auditor**: Find empty or `console.log(e)` catch blocks | ❌ Missing | Tree-sitter AST: find `catch` blocks with only logging or empty; flag for review | Custom tree-sitter queries per language |
| 7.2.2 | **Domain Error Class Generator**: Suggest custom error classes for repeated error patterns | ❌ Missing | Cluster similar error handling patterns; suggest domain error class names | LLM-based analysis (Patchi AI) |
| 7.2.3 | **Async Boundary Wrapper**: Auto-wrap top-level async calls with `.catch()` or `try/catch` | ❌ Missing | Detect unhandled promise/task at module level; insert error handler | Custom AST transformation |

### 7.3 Disposable & Cleanup Hygiene

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 7.3.1 | **Resource Leak Detection**: Find `setInterval`, `setTimeout`, `EventEmitter` subscriptions without cleanup | ❌ Missing | Tree-sitter pattern: `setInterval` without matching `clearInterval` in same scope; scope analysis | Custom tree-sitter queries |
| 7.3.2 | **React Effect Cleanup**: Flag `useEffect` without cleanup for subscriptions | ❌ Missing | AST pattern: `useEffect` returning non-function vs. function for subscriptions | ESLint `react-hooks/exhaustive-deps` rule |
| 7.3.3 | **File Handle Tracker**: Ensure `fs.createReadStream` and DB connections are closed | ❌ Missing | AST pattern: stream creation without `.close()` or `.destroy()` in scope | Custom tree-sitter queries |

---

## 8. Multi-Framework & Multi-Language Support

### 8.1 Frontend Frameworks

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 8.1.1 | **React**: Hooks rules, JSX key checks, useEffect dependency arrays | ⚠️ Partial (agent exists, not deep) | ESLint react-hooks plugin + tree-sitter AST for JSX key detection | `eslint-plugin-react-hooks`, custom tree-sitter |
| 8.1.2 | **Vue**: Template type checking, v-for key checks, composition API patterns | ❌ Missing | `vue-tsc` for type checking; ESLint `eslint-plugin-vue` | `vue-tsc`, `eslint-plugin-vue` |
| 8.1.3 | **Svelte**: Store subscription leaks, reactive statement analysis | ❌ Missing | Svelte compiler warnings + tree-sitter-svelte AST analysis | `svelte-check`, custom tree-sitter queries |
| 8.1.4 | **Angular**: DI container validation, template type checking | ❌ Missing | `ng lint` + `ng build` with `--configuration production` for type checking | Angular CLI |
| 8.1.5 | **Solid / Preact / Qwik**: Framework-specific optimizations | ❌ Missing | Framework-detection → apply framework-specific lint rules | Custom per-framework agents |

### 8.2 Backend & Full-Stack

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 8.2.1 | **Node.js**: Express, Fastify, NestJS, Hono, Koa route extraction | ✅ Existing | Patchi RouteMapper covers these | Patchi `RouteMapper` |
| 8.2.2 | **Python**: FastAPI, Flask, Django route and type hint analysis | ✅ Existing | Patchi RouteMapper + FrameworkDetector | Patchi |
| 8.2.3 | **Go**: Goroutine leak detection, error handling patterns | ❌ Missing | `go vet` for goroutine misuse; tree-sitter for error handling patterns (unchecked errors) | `go vet`, `golangci-lint`, custom tree-sitter |
| 8.2.4 | **Rust**: Lifetime analysis hints, `unwrap()` / `expect()` audit | ❌ Missing | `clippy` warnings for unwrap/expect; tree-sitter pattern for unsafe blocks | `cargo clippy`, custom tree-sitter |
| 8.2.5 | **GraphQL**: Schema stitching validation, resolver coverage | ❌ Missing | Compare GraphQL schema fields with resolver implementations; detect missing resolvers | [`graphql-inspector`](https://github.com/kamilkisiela/graphql-inspector), custom |

### 8.3 Build Tools

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 8.3.1 | **Vite / Webpack / Rollup / esbuild / Turbopack**: Plugin compatibility and config validation | ❌ Missing | Parse config files; validate plugin compatibility; check for known misconfigurations | Custom config validators per tool |
| 8.3.2 | **Turborepo / Nx**: Task graph validation, cache hit optimization | ❌ Missing | Parse pipeline config; validate task dependencies; suggest cache improvements | Custom analysis |
| 8.3.3 | **Docker**: Layer bloat detection, unused base image flags | ❌ Missing | `dive` for layer analysis; `docker scout` for image optimization | [`wagoodman/dive`](https://github.com/wagoodman/dive), `docker scout` |

---

## 9. Reporting & Developer Experience

### 9.1 Dashboard & Visualization

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 9.1.1 | **Health Score**: Single 0-100 score for repo health | ✅ Existing | Patchi already computes health score | Patchi `health` command |
| 9.1.2 | **Trend Graphs**: Error count, coverage, bundle size over time | ❌ Missing | Persist metrics to SQLite; Chart.js or D3.js for trend visualization | Custom dashboard (Patchi web UI) |
| 9.1.3 | **Risk Heatmap**: Color-coded file map showing bug-prone hotspots | ❌ Missing | Map file-level metrics (error count, churn, complexity) to color intensity on folder tree | D3.js treemap + Patchi metrics |
| 9.1.4 | **Tech Debt Timeline**: Estimate hours to fix each category | ❌ Missing | Category estimates based on finding count × average fix time | LLM-based estimation (Patchi AI) |

### 9.2 Actionable Output

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 9.2.1 | **PR-Ready Patches**: Generate .diff files that can be applied directly | ✅ Existing | Patchi `fix` command generates patches | Patchi `patch` model |
| 9.2.2 | **GitHub/GitLab Integration**: Post results as PR comments with line annotations | ✅ Existing | SARIF export + GitHub Code Scanning API | Patchi SARIF export |
| 9.2.3 | **SARIF Export**: Standard format for integration | ✅ Existing | Patchi `export/sarif.py` | Patchi SARIF |
| 9.2.4 | **Slack / Discord Alerts**: Notify channel when health score drops or critical bug found | ✅ Existing | Patchi notification channels (Apprise) | Patchi `notifications/` |

### 9.3 Interactive CLI

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 9.3.1 | **TUI (Terminal UI)**: Interactive file picker for selective fixes | ✅ Existing | Patchi rich terminal UI | Patchi CLI |
| 9.3.2 | **Dry-Run Mode**: Preview all changes before applying | ✅ Existing | Patchi `--dry-run` flag | Patchi CLI |
| 9.3.3 | **Undo Stack**: Roll back any auto-fix | ✅ Existing | Patchi `undo` command | Patchi CLI |
| 9.3.4 | **Watch Mode**: Re-run analysis on file save during development | ✅ Existing | Patchi `watch` command | Patchi CLI |

---

## 10. CI/CD & Prevention

### 10.1 Pipeline Integration

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 10.1.1 | **GitHub Actions**: Official action with caching | ❌ Missing | Create `patchi-action` GitHub Action; cache `.patchi/memory` | Custom GitHub Action |
| 10.1.2 | **GitLab CI**: Template `.gitlab-ci.yml` snippet | ❌ Missing | Publish Patchi CI template to GitLab CI/CD template registry | Custom CI template |
| 10.1.3 | **Pre-commit Hook**: husky / lint-staged integration for instant feedback | ❌ Missing | Generate `pre-commit` config with Patchi scan on staged files | `husky` + `lint-staged` + Patchi CLI |
| 10.1.4 | **Branch Protection Gates**: Block merge on type errors > 0, lint errors > 0, critical vulns, missing routes, coverage regression | ❌ Missing | Patchi exits non-zero on violations; configure branch protection to require passing status check | Patchi CLI exit codes + GitHub branch protection rules |

### 10.2 Baseline & Regression

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 10.2.1 | **Baseline Locking**: Snapshot current state; only fail on new issues | ❌ Missing | Store baseline finding count; diff against current | Patchi `memory/` snapshots |
| 10.2.2 | **Gradual Enforcement**: Allow teams to ratchet down error counts week by week | ❌ Missing | Baseline + percentage reduction target; fail if count exceeds target | Custom "ratchet" module |
| 10.2.3 | **Ignore Lists with Expiry**: `// patchi-ignore` comments that expire after N days | ❌ Missing | Parse inline ignore comments with expiry dates; warn on expired ignores | Custom comment parser |
| 10.2.4 | **Auto-ticket Creation**: File Jira/GitHub Issues for detected bugs with assignee suggestions | ❌ Missing | GitHub Issues API / Jira REST API; assign via CODEOWNERS or git blame | [`jira`](https://github.com/pycontribs/jira) or GitHub Issues API |

### 10.3 Team Collaboration

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 10.3.1 | **Code Owners Integration**: Route specific error categories to specific teams | ❌ Missing | Parse CODEOWNERS; map finding categories to team handles | Custom |
| 10.3.2 | **Blame Annotation**: Show who introduced each error and when | ❌ Missing | Run `git blame` on each finding line; include in report | Patchi `blame` command |
| 10.3.3 | **Knowledge Base**: Link errors to internal wiki / ADR documentation | ❌ Missing | Map finding types to URLs via configurable lookup table | Custom |
| 10.3.4 | **Gamification**: Leaderboard for "most bugs fixed this sprint" | ❌ Missing | Track fixes per developer in Patchi memory; expose via web UI | Custom |

---

## 11. Advanced / Future-Proofing

| # | Feature | Patchi Status | Lang-Agnostic Approach | Recommended Tools |
|---|---------|---------------|----------------------|-------------------|
| 11.1 | **AI-Powered Bug Prediction**: Train on commit history to predict which files will break next | ❌ Missing | Features: churn, complexity, bug density, commit message sentiment; simple regression model | [`scikit-learn`](https://github.com/scikit-learn/scikit-learn) or lightweight model |
| 11.2 | **Natural Language Query**: "Find all auth-related routes without rate limiting" | ❌ Missing | NL → search graph query; tag routes with security metadata | Patchi `search_graph` + LLM query parser |
| 11.3 | **Cross-Repo Analysis**: Detect shared library drift across microservices | ❌ Missing | Index multiple repos; compare dependency versions and API usage | Patchi cross-repo mode |
| 11.4 | **Runtime Telemetry**: Optional production error aggregation (opt-in, privacy-safe) | ❌ Missing | Lightweight agent in production that sends anonymized error fingerprints | Custom; inspired by Sentry's SDK |
| 11.5 | **SBOM Generation**: Software Bill of Materials for compliance | ❌ Missing | Use SBOM generation tools per language; unify into CycloneDX/SPDX format | [`cyclonedx/cdxgen`](https://github.com/CycloneDX/cdxgen) (multi-lang), [`anchore/syft`](https://github.com/anchore/syft) (containers + filesystems), [`microsoft/sbom-tool`](https://github.com/microsoft/sbom-tool) |
| 11.6 | **License Compliance**: Flag GPL/AGPL deps in proprietary codebases | ❌ Missing | Parse SBOM → license lookup → policy check | [`fossa-cli`](https://github.com/fossas/fossa-cli), [`licensee`](https://github.com/licensee/licensee), [`scancode-toolkit`](https://github.com/nexB/scancode-toolkit) |
| 11.7 | **Internationalization Audit**: Find hardcoded strings, missing translation keys | ❌ Missing | Tree-sitter scan for string literals in UI code; cross-ref with i18n key files; flag untranslated strings | [`i18next-scanner`](https://github.com/i18next/i18next-scanner) (JS/TS), [`better-i18n/cli`](https://github.com/better-i18n/better-i18n), custom for non-JS frameworks |
| 11.8 | **Accessibility Regression**: WCAG 2.1 AA compliance checks in CI | ✅ Existing | Patchi `AccessibilityAgent` already does this | Patchi `AccessibilityAgent` |

---

## Language-Agnostic Tooling Reference

The following orchestrator tools can wrap language-specific analyzers under a unified CLI:

### Core Orchestrators

| Tool | Type | Languages | Coverage in Patchi Plan |
|------|------|-----------|------------------------|
| [`sglyon/deadcode`](https://github.com/sglyon/deadcode) | Dead code orchestrator | Python, JS/TS, Go, Elixir (+ roadmap for more) | §2.1.1 |
| [`multilang-depends/depends`](https://github.com/multilang-depends/depends) | Dependency extraction | Java, C, C++, Python, JS/TS, Go, Ruby + more | §1.3.1 |
| [`yfedoseev/fossil-mcp`](https://github.com/yfedoseev/fossil-mcp) | Code quality (dead code, clones, scaffolding) | 15+ languages (Rust-powered) | §2.1, §2.1.3 |
| [`kucherenko/jscpd`](https://github.com/kucherenko/jscpd) | Duplicate code detection | 223+ formats, Rust v5 | §7.1 (duplication detection) |
| [`agroce/universalmutator`](https://github.com/agroce/universalmutator) | Mutation testing | Any language (regex-based) | §6.1.3 |
| [`WebFuzzing/EvoMaster`](https://github.com/WebFuzzing/EvoMaster) | API fuzzing | REST, GraphQL, gRPC (framework-agnostic) | §5.3.1 |
| [`cyclonedx/cdxgen`](https://github.com/CycloneDX/cdxgen) | SBOM generation | 20+ ecosystems | §11.5 |
| [`anchore/syft`](https://github.com/anchore/syft) | SBOM generation | Containers + filesystems, multi-ecosystem | §11.5 |

### Per-Language Tool Chain

| Language | Type Check | Linter | Dead Code | Formatter | Mutation Test | Test Coverage |
|----------|-----------|--------|-----------|-----------|---------------|---------------|
| Python | `mypy`, `pyright` | `ruff` | `vulture` | `black` | `mutmut` | `pytest-cov` |
| JavaScript | `tsc` (via `// @ts-check`) | `eslint` | `knip` | `prettier` | `stryker` | `nyc` |
| TypeScript | `tsc --noEmit` | `eslint` + `@typescript-eslint` | `knip`, `ts-prune` | `prettier` | `stryker` | `nyc` / `vitest` |
| Rust | `rustc`, `cargo check` | `clippy` | `cargo-udeps` | `rustfmt` | `cargo-mutants` | `cargo-tarpaulin` / `grcov` |
| Go | `go vet` | `golangci-lint` | `staticcheck`/`deadcode` | `gofmt` | `go-mutesting` | `go test -cover` |
| Java | `javac -Xlint` | `checkstyle`, `spotbugs` | `UCDetector` | `prettier` | `pitest` | `JaCoCo` |
| C/C++ | `clang -Wall -Wextra` | `clang-tidy`, `cppcheck` | `cppcheck` | `clang-format` | `universalmutator` | `gcov` / `lcov` |
| Swift | `swiftc` | `swiftlint` | `periphery` | `swift-format` | `muter` | `xcov` |
| Ruby | `ruby -c`, `sorbet` | `rubocop` | `unused` | `rubocop -a` | `mutant` | `simplecov` |

---

## Implementation Roadmap

### Phase 1: Quick Wins (Low Risk, High Impact)
*Estimated effort: 1-2 weeks*

| Priority | Features | Dependencies | Effort |
|----------|----------|-------------|--------|
| P0 | §9.1.2 Trend Graphs (metrics persistence to SQLite) | Patchi health score | 2-3d |
| P0 | §9.1.3 Risk Heatmap (file-level metrics → treemap) | Trend graphs | 2-3d |
| P0 | §10.2.1 Baseline Locking (snapshot + diff) | Patchi memory | 1-2d |
| P0 | §10.2.3 Ignore Lists with Expiry (inline comments) | Scanner | 2-3d |
| P0 | §10.3.2 Blame Annotation (git blame integration) | None | 1d |
| P0 | §1.1.3 Incremental Type Checking (hash-based skip) | Patchi memory | 1d |
| P1 | §2.1.4 Feature Flag Archaeology (git log analysis) | None | 2d |
| P1 | §5.1.1 Promise Rejection Tracker (test instrumentation) | None | 2-3d |
| P1 | §4.1.7 Insecure Randomness Detection (pattern rule) | TaintAnalyzer | 1d |
| P1 | §7.2.1 Catch Block Auditor (tree-sitter pattern) | Tree-sitter | 2d |

### Phase 2: Tool Integration (Medium Risk)
*Estimated effort: 3-4 weeks*

| Priority | Features | Dependencies | Effort |
|----------|----------|-------------|--------|
| P0 | §2.1.1 Dead Code Orchestrator (`sglyon/deadcode` integration) | None | 3-4d |
| P0 | §5.3.1 API Fuzzer (EvoMaster integration) | RouteMapper | 3-4d |
| P0 | §11.5 SBOM Generation (cdxgen/syft integration) | FrameworkDetector | 2-3d |
| P1 | §1.3.1 Circular Dependency Detection (full multi-lang) | Import graph | 3-4d |
| P1 | §3.1.3-7 Contract Diff Engine (full route matching) | RouteMapper | 3-4d |
| P1 | §6.1.3 Mutation Testing (universalmutator integration) | Test agents | 3-4d |
| P1 | §2.2.5 Supply Chain Risk (Socket.dev/Guac integration) | DependencyChecker | 3-4d |
| P2 | §8.3.3 Docker Layer Bloat (dive integration) | None | 2-3d |
| P2 | §8.2.3 Goroutine Leak Detection (go vet integration) | Language dispatcher | 2d |
| P2 | §8.2.4 Rust unwrap() Audit (clippy integration) | Language dispatcher | 2d |

### Phase 3: Deep Framework Analysis (Higher Risk)
*Estimated effort: 3-4 weeks*

| Priority | Features | Dependencies | Effort |
|----------|----------|-------------|--------|
| P1 | §8.1.1-5 Frontend Framework Checks (React/Vue/Svelte/Angular/Solid) | ESLint plugins, tree-sitter | 4-5d |
| P1 | §7.1.4 Modernization Codemods (jscodeshift + per-language) | TypeFixer pattern | 4-5d |
| P2 | §3.3.1-3 SPA Route Inventory + Dead Link Detection | RouteMapper | 3-4d |
| P2 | §8.3.1-2 Build Tool Config Validation (Vite/Webpack/Turborepo) | None | 3-4d |
| P2 | §7.2.2-3 Error Handling Standardization (LLM suggestions) | AI client | 3-4d |
| P2 | §7.3.1-3 Resource Leak Detection (tree-sitter patterns) | Tree-sitter | 3-4d |

### Phase 4: Runtime & Advanced (Highest Risk)
*Estimated effort: 4-6 weeks*

| Priority | Features | Dependencies | Effort |
|----------|----------|-------------|--------|
| P1 | §5.2 Memory & Performance Profiling (CDP + per-language tools) | Test framework | 4-5d |
| P2 | §5.3.3-4 Race Condition + Chaos Testing | E2E framework | 4-5d |
| P2 | §11.6 License Compliance (fossa/licensee integration) | SBOM generation | 3-4d |
| P2 | §11.7 Internationalization Audit (i18n scanners + tree-sitter) | Tree-sitter | 4-5d |
| P3 | §11.1 AI-Powered Bug Prediction (features + model) | Memory, git log | 5-6d |
| P3 | §11.2 Natural Language Query (NL → graph query) | Search graph | 4-5d |
| P3 | §11.3 Cross-Repo Analysis (multi-repo index) | None | 5-6d |
| P3 | §10.1.1-2 GitHub Actions + GitLab CI templates | None | 2-3d |
| P3 | §10.2.2 Gradual Enforcement (ratcheting) | Baseline locking | 2-3d |
| P3 | §10.2.4 Auto-ticket Creation (Jira/GitHub Issues API) | None | 3-4d |
| P3 | §10.3.1-4 Team Collaboration features | None | 3-4d |

---

## Quick Wins (Day 1-2 Items)

These can be fixed with low regression risk and high impact:

1. **Insecure randomness check** (§4.1.7): Add a tree-sitter pattern for `Math.random()` / `rand()` usage in security-sensitive contexts → suggest `crypto.randomBytes()` / `secrets` equivalent
2. **Catch block auditor** (§7.2.1): Add tree-sitter query to find empty catch blocks across all 11 languages
3. **Blame annotation** (§10.3.2): Run `git blame` on each finding line and include in report output
4. **Baseline locking** (§10.2.1): Store finding count from first scan; subsequent scans report delta
5. **Trend metrics persistence** (§9.1.2): Write scan metrics to SQLite within Patchi memory
6. **Ignore lists with expiry** (§10.2.3): Parse `// patchi-ignore: RULE_NAME YYYY-MM-DD` comments and warn on expired ones
7. **Env var validation** (§3.2.3): Grep for `process.env.*` / `os.getenv()` / `std::env::var()` and cross-ref with `.env.example`
8. **Orphaned endpoint detection** (§3.1.5): Basic diff of frontend calls vs backend routes

---

## Issues Requiring Architectural Changes

These need deeper investigation or architectural decisions:

1. **Mutation testing** (§6.1.3): `universalmutator` covers all languages but produces many invalid mutants. Need to evaluate valid mutant ratio per language and decide if per-language tools are better
2. **Memory profiling** (§5.2): Chrome DevTools Protocol works for web apps but not for CLI/backend apps. Need per-language memory profilers
3. **API fuzzing** (§5.3.1): Requires a running server. Needs to decide: start dev server automatically or fuzz against deployed instance?
4. **Cross-repo analysis** (§11.3): Requires indexing multiple repos and comparing dependency versions. Architecture for multi-repo graph traversal needed
5. **Chaos testing** (§5.3.4): Requires infrastructure (killing processes, dropping network). Needs opt-in mode and clear safety guards
6. **AI-powered bug prediction** (§11.1): Needs training data (commit history with bug labels). Cold start problem — no data for new repos
7. **Gradual enforcement ratcheting** (§10.2.2): Requires storing baseline + tracking reduction targets over time. Needs UI for team settings

---

## Feature Count Summary

| Section | Total Features | ✅ Existing | ⚠️ Partial | ❌ Missing |
|---------|---------------|------------|------------|-----------|
| 1. Static Analysis | 13 | 0 | 4 | 9 |
| 2. Dead Code & Deps | 9 | 1 | 3 | 5 |
| 3. Route & API | 10 | 2 | 2 | 6 |
| 4. Security | 10 | 6 | 3 | 1 |
| 5. Dynamic/Runtime | 11 | 0 | 0 | 11 |
| 6. Testing | 10 | 3 | 1 | 6 |
| 7. Refactoring | 9 | 0 | 2 | 7 |
| 8. Multi-Framework | 11 | 2 | 1 | 8 |
| 9. Reporting | 11 | 8 | 0 | 3 |
| 10. CI/CD | 10 | 0 | 0 | 10 |
| 11. Advanced | 8 | 1 | 0 | 7 |
| **Total** | **112** | **23** | **16** | **73** |

**Status:** 23 existing (20.5%), 16 partial (14.3%), 73 missing (65.2%)

---

## Key Decision Log

| ID | Decision | Rationale | Date |
|----|----------|-----------|------|
| D001 | All features must be language-agnostic or have per-language implementations under a unified orchestrator | Prevents ecosystem lock-in; matches user requirement | 2026-07-11 |
| D002 | `sglyon/deadcode` chosen as dead code orchestrator | Already multi-language, agent-friendly JSON output, MIT license | 2026-07-11 |
| D003 | `universalmutator` for broad mutation testing + per-language tools for depth | Covers all 11 languages immediately; per-language tools for better mutant quality | 2026-07-11 |
| D004 | `EvoMaster` for API fuzzing (REST + GraphQL + gRPC) | Most comprehensive open-source option; active development (14k+ commits) | 2026-07-11 |
| D005 | `cdxgen` + `syft` for SBOM generation | `cdxgen` covers 20+ ecosystems; `syft` covers containers and filesystems | 2026-07-11 |
| D006 | Tree-sitter as primary AST framework for cross-language code analysis | Already used in Patchi; supports 11+ target languages | 2026-07-11 |
| D007 | Phase ordering: Quick Wins (low risk) → Tool Integration (medium) → Deep Framework (higher) → Runtime/Advanced (highest) | Maximizes early value; builds foundation before deep work | 2026-07-11 |

---

*This plan is a living document. Update as features are implemented or priorities change.*
