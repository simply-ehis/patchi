# Patchi Language + Framework Expansion Plan

## Goal
Add deep tree-sitter-based AST support for Rust and Svelte (Phase 1), then Java, Go, C/C++ (Phase 2), then Swift, Ruby (Phase 3), and finally expand the framework registry and create new security domains (Phase 4).

---

## Status (verified against code, 2026-08-26)

> Verified by inspecting `patchi/core/brain/languages.py`, `framework.py`,
> `scanner.py`, `symbol_graph.py`, `route_mapper.py`.

| Phase | Scope | Status | Evidence |
|---|---|---|---|
| 1 — Rust + Svelte | Lang registration + parsers + framework detect | ✅ Done | `Lang.RUST`/`Lang.SVELTE` registered; `_parse_rust`/`_parse_svelte`, `_walk_rust`/`_walk_svelte`; Cargo.toml / Svelte detection |
| 2 — Java + Go + C/C++ | Lang registration + parsers + framework detect | ✅ Done | `Lang.JAVA`/`Lang.GO`/`Lang.C`/`Lang.CPP` registered; parsers + walkers present; Spring/Go-framework detection |
| 3 — Swift + Ruby | Lang registration + parsers + framework detect | ✅ Done | `Lang.SWIFT`/`Lang.RUBY` registered; parsers/walkers; Vapor/Rails detection |
| 4 — Framework Registry + Bun | JS/TS extras, Tauri, Bun, ext map | ✅ Mostly done | Extension map + framework detectors present; Bun/Tauri detection added |

**Net:** All four phases complete for language/framework *registration and
parsing*. The 7 new security-domain YAMLs (Phase 4) and the `domain_activator`
Rust signals should be re-confirmed against `patchi/core/security/` before
marking the domain layer 100%.

---

## Phase 1 — Rust + Svelte (immediate)

### Rust
| File | Changes |
|------|---------|
| `pyproject.toml` | Add `tree-sitter-rust` dependency |
| `patchi/core/brain/languages.py` | Add `Lang.RUST`, register tree-sitter parser, add to `TREE_SITTER_LANGS` |
| `patchi/core/brain/scanner.py` | Add `_parse_rust()` — `use` imports, `fn` functions, `struct`, `impl`, `enum`, macro invocations |
| `patchi/core/brain/symbol_graph.py` | Add `_walk_rust()` — functions, structs, traits, impl blocks, attribute macros (`#[get()]`, `#[post()]`, `#[derive()]`) |
| `patchi/core/brain/framework.py` | Add `_detect_rust()` from `Cargo.toml` — detect **Actix**, **Axum**, **Rocket**, **Tokio**, **Tauri**, **Serde**, **Clap**, **Tokio-tungstenite**, **Reqwest** |
| `patchi/core/brain/route_mapper.py` | Add Actix `#[get("/...")]`, Rocket `#[get("/...")]`, Axum `.route("/...")` extraction |
| `patchi/core/brain/domain_activator.py` | Update Rust web framework signals for `backend-api`, `desktop-app` (Tauri), `supply-chain-local-tool` |

### Svelte
| File | Changes |
|------|---------|
| `pyproject.toml` | Add `tree-sitter-svelte` dependency |
| `patchi/core/brain/languages.py` | Add `Lang.SVELTE`, register tree-sitter parser |
| `patchi/core/brain/scanner.py` | Add `_parse_svelte()` — imports (JS), components, stores, reactive declarations, script/style sections |
| `patchi/core/brain/symbol_graph.py` | Add `_walk_svelte()` — component definitions, props (`export let`), event handlers, reactive statements |
| `patchi/core/agents/ui_scanner.py` | Update to handle `.svelte` components for navigation links, event bindings, accessibility patterns |
| `patchi/core/brain/framework.py` | Already detects Svelte/SvelteKit — add `.svelte` file presence as additional signal |

---

## Phase 2 — Java + Go + C/C++

### Java
| File | Changes |
|------|---------|
| `pyproject.toml` | Add `tree-sitter-java` |
| `languages.py` | Add `Lang.JAVA`, register parser, add to `TREE_SITTER_LANGS` |
| `scanner.py` | Add `_parse_java()` — imports, classes, methods, annotations |
| `symbol_graph.py` | Add `_walk_java()` — classes, interfaces, annotations, Spring `@GetMapping`/`@PostMapping`/`@RequestMapping` |
| `framework.py` | Add `_detect_java()` from `pom.xml` / `build.gradle` — **Spring Boot**, **Quarkus**, **Micronaut** |
| `route_mapper.py` | Move Spring route extraction into core (currently agent-only) |

### Go
| File | Changes |
|------|---------|
| `pyproject.toml` | Add `tree-sitter-go` |
| `languages.py` | Add `Lang.GO`, register parser, add to `TREE_SITTER_LANGS` |
| `scanner.py` | Add `_parse_go()` — imports (`"pkg/path"`), functions, types, methods |
| `symbol_graph.py` | Add `_walk_go()` — funcs, structs, interfaces, HTTP handler signatures, Gin route patterns |
| `framework.py` | Add `_detect_go()` from `go.mod` — **Gin**, **Echo**, **Fiber**, **Chi**, **Cobra**, **urfave/cli** |
| `route_mapper.py` | Add Gin `r.GET("/...")`, Echo `e.GET("/...")`, Fiber `app.Get("/...")` |

### C/C++
| File | Changes |
|------|---------|
| `pyproject.toml` | Add `tree-sitter-c` + `tree-sitter-cpp` |
| `languages.py` | Add `Lang.C`, `Lang.CPP`, register parsers, add to `TREE_SITTER_LANGS` |
| `scanner.py` | Add parsers for `#include`, functions, classes (C++ only), macros |
| `symbol_graph.py` | Add walkers for functions, classes, templates, namespaces |
| `framework.py` | Detect CMake, Makefile, Meson; C++ web frameworks: **Crow**, **drogon**, **Pistache**, **uWebSockets** |

---

## Phase 3 — Swift + Ruby

### Swift
| File | Changes |
|------|---------|
| `pyproject.toml` | Add `tree-sitter-swift` |
| `languages.py` | Add `Lang.SWIFT`, register parser, add to `TREE_SITTER_LANGS` |
| `scanner.py` / `symbol_graph.py` | Add parsers for imports, classes, structs, functions, protocols, `@available` annotations |
| `framework.py` | Detect **Vapor**, **SwiftUI** from Package.swift |

### Ruby
| File | Changes |
|------|---------|
| `pyproject.toml` | Add `tree-sitter-ruby` |
| `languages.py` | Add `Lang.RUBY`, register parser, add to `TREE_SITTER_LANGS` |
| `scanner.py` / `symbol_graph.py` | Add parsers for `require`, `def`, `class`, `module`, `attr_*` |
| `framework.py` | Detect **Rails**, **Sinatra**, **Rack** from Gemfile |
| `route_mapper.py` | Move Rails route detection into core (currently agent-only) |

---

## Phase 4 — Framework Registry + Bun

| File | Changes |
|------|---------|
| `framework.py` | Add missing JS/TS: **Solid.js**, **Qwik**, **Preact**, **Hono**, **tRPC** |
| `framework.py` | Add **Tauri** as first-class detection for Rust apps |
| `framework.py` | Detect **Bun** via `bun.lock` / `bunfig.toml` / `"bun"` in package.json engines |
| `languages.py` | Normalize `EXTENSION_MAP` — add `.svelte`, `.rs`, `.java`, `.go`, `.c`, `.cpp`, `.h`, `.hpp`, `.swift`, `.rb` |
| `app_profile.py` | Normalize framework name casing across all files |

---

## New Security Domains

| Domain | Scope | Covers |
|--------|-------|--------|
| `native-code-safety` | C/C++/Rust | Unsafe blocks, buffer overflow patterns, use-after-free, format string vulns, null pointer deref |
| `go-concurrency` | Go | Goroutine leaks, nil channel ops, race condition patterns, `sync.Mutex` misuse |
| `jvm-hardening` | Java/JVM | Deserialization vectors, actuator exposure, reflection abuse, verbose stack traces in production |
| `mobile-native` | Swift/Kotlin | URL scheme hijacking, insecure Keychain/Keystore, entitlement mismanagement, debug builds in prod |
| `ruby-rails` | Ruby on Rails | Mass assignment, SQL injection in ActiveRecord, unsafe `params.permit`, `eval`/`send` reflection |
| `svelte-ssr` | SvelteKit | Server-side data leakage in `+page.server.js`, CSRF in form actions, server `load` function exposure |
| `cargo-supply-chain` | Rust crates | Crate CVEs (via OSV), typo-squatting patterns in Cargo.toml, malicious dependency heuristics |

Total: 23 existing + 7 new = **30 domains**

---

## Web/Hosted De-prioritization

- **Close/shut down**: Web dashboard (`p web`), hosted service backend (`patchi/web/`), FastAPI/uvicorn server
- **Keep working**: Visual test agents that need Playwright/Chromium — they open a browser window directly
- **Mark as "later"**: Route/web code that serves a UI server — add `[DEPRECATED]` marker, skip in imports

---

## File Change Summary

| Module | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|--------|---------|---------|---------|---------|
| `pyproject.toml` | +rust, +svelte | +java, +go, +c, +cpp | +swift, +ruby | — |
| `languages.py` | +RUST, +SVELTE | +JAVA, +GO, +C, +CPP | +SWIFT, +RUBY | extension map |
| `scanner.py` | rust + svelte parsers | java + go + c/cpp parsers | swift + ruby parsers | — |
| `symbol_graph.py` | rust + svelte walkers | java + go + c/cpp walkers | swift + ruby walkers | — |
| `framework.py` | Cargo.toml, .svelte | pom.xml, go.mod | Package.swift, Gemfile | Solid, Qwik, Tauri, Bun |
| `route_mapper.py` | Actix/Axum/Rocket | Spring, Gin/Echo/Fiber | Rails | — |
| `domain_activator.py` | Rust signals | — | — | — |
| `app_profile.py` | — | — | — | Name normalization |
| New domain YAMLs | +7 YAMLs | — | — | — |
| `ui_scanner.py` | Svelte component analysis | — | — | — |
