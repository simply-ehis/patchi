# Patchi — Exploration/Mapping Agent
### Technical Spec
Draft v0.1

---

## 1. Purpose

The foundation every other testing agent reads from and writes to. Its job: maintain a **living, incremental, symbol-level graph** of the target app — what exists, what depends on what, and what changed — so that:

- The **flow agent** discovers new routes/journeys automatically instead of needing hand-written scripts.
- The **load/stress agent** scopes runs to affected endpoints instead of blind full-app tests.
- The **fix-verification agent** can compute blast radius without rebuilding a graph from scratch each time.
- Any agent can ask "what does X affect?" or "what does X depend on?" in milliseconds, not minutes.

Without this agent, every other agent re-derives "what matters here" per run — which is the exact bottleneck that breaks down at VS Code scale. This agent exists to make that cost paid once, incrementally, not repeatedly.

---

## 2. Two Data Sources: Static + Dynamic

Neither alone is sufficient. Static parsing tells you what *could* execute; dynamic crawling tells you what *actually* executes and how it behaves.

### 2.1 Static extraction
Parse the codebase without running it.

| Signal | How | Feeds |
|---|---|---|
| Import/module graph | Language-specific AST parse (ts-morph for TS/JS, `ast` module for Python, `go/packages` for Go) | Symbol-level dependency graph |
| Route definitions | Framework-aware extraction (Express routes, Next.js file-based routes, FastAPI decorators, etc.) | Flow agent's route list |
| Component tree | Framework-aware for frontend (React/Vue component imports and prop flow) | Flow agent's journey candidates |
| API schema | OpenAPI/GraphQL SDL if present, else inferred from route handlers | Contract/API agent |
| Exported symbols per file | AST-level, function/class/const granularity, not file-level | The core graph node unit |

Static extraction runs fast, has no side effects, and is safe to run on every commit. It's the backbone of the graph.

### 2.2 Dynamic crawling
Actually run the app and observe it — needed because static parsing misses runtime-only relationships (dynamic imports, feature-flag-gated routes, client-side routing that isn't file-based, actual click-reachable UI states).

- **Headless browser crawl** (Playwright) — starting from entry routes, follow every clickable/navigable element, record the resulting URL/state graph. Depth-limited and deduplicated (don't re-crawl identical page states reached via different paths).
- **API traffic capture** — during the crawl, record every network call made, mapping frontend actions to backend endpoints actually hit (not just theoretically routable).
- **Runtime call graph sampling** — in standalone/hosted mode, lightweight instrumentation (OpenTelemetry spans) captures which functions actually get invoked in production, layered onto the static graph as a "confirmed live" weight, distinct from "theoretically reachable."

Dynamic crawling is expensive — it doesn't run on every commit. It runs on a schedule (nightly) and whenever static analysis detects large structural changes (new routes, new top-level components).

---

## 3. Graph Schema

Nodes are **symbols**, not files. Two edge types.

```yaml
node:
  id: "src/auth/session.ts::validateSession"
  type: "function"              # function | class | route | component | config-key | endpoint
  file: "src/auth/session.ts"
  exported: true
  test_coverage: 0.62           # from existing coverage reports
  runtime_confirmed: true       # seen invoked via dynamic crawl/tracing, vs. theoretical only
  criticality: "high"           # tagged: auth | payment | data-write | logging | ui-only
  last_changed_commit: "a1b2c3d"

edge:
  from: "src/routes/login.ts::POST /login"
  to: "src/auth/session.ts::validateSession"
  edge_type: "calls"             # calls | imports | renders | depends-on-config | http-calls
  confirmed_by: ["static", "dynamic"]   # which extraction method(s) found this edge
```

**Why symbol-level, not file-level:** a one-word change in a key file might touch one exported constant used in three places, not the whole file's forty exports. File-level graphs force over-broad blast radius; symbol-level graphs make "what does this specific change affect" precise, which is what the blast-radius model from the earlier plan actually needs to be useful rather than just conservative-and-noisy.

**Why two confirmation sources:** an edge that's only static (theoretically reachable, never observed live) is a different risk profile than one confirmed by both static and dynamic — the former might be dead code or gated behind a flag nobody's tested; the latter is proven-live and should weight higher in blast-radius scoring.

---

## 4. Incremental Update — the part that makes this scale

Full re-crawl/re-parse on every commit is what makes testing infrastructure slow and eventually gets disabled by frustrated teams. This has to work like a language server or a build system's dependency cache, not like a fresh LLM context read every time.

**Update trigger:** a diff (commit, PR, or file-save in watch mode).

**Update procedure:**
1. Diff the changed files against the last-indexed commit.
2. For each changed file, re-run static extraction **only on that file** — get its new symbol list and edges.
3. Diff old vs. new symbol/edge sets for that file: added, removed, modified symbols.
4. Patch the graph: add new nodes/edges, remove deleted ones, mark modified nodes' `last_changed_commit`.
5. Do **not** re-run dynamic crawling on every commit — dynamic confirmation data persists until the next scheduled crawl; a code change doesn't invalidate previously-observed runtime behavior of *unrelated* parts of the graph.
6. If the diff touches route definitions, component entry points, or config schemas (structural signals), flag for an **out-of-band dynamic re-crawl** rather than waiting for the nightly schedule — this keeps the flow agent's route list from going stale after a real structural change without re-crawling on every trivial commit.

This is the same incrementality model as `tsc --incremental`, Bazel's dependency-aware rebuilds, or Nx's affected-graph computation — proven patterns, not something novel to invent from scratch.

**Storage:** the graph is a persistent artifact, not recomputed in memory per request. A local embedded graph store (SQLite with an edge table, or a lightweight graph DB like Kùzu for larger repos) checked into `.patchi/graph/` or held in the standalone service's data volume — versioned alongside the commit it was computed from, so any agent's blast-radius query is reproducible against a known graph state.

---

## 5. Query Interface (what other agents actually call)

Keep this small and composable — every other agent's needs reduce to a handful of graph traversals.

```
GET /graph/affected?symbol=<id>&direction=downstream&depth=<n>
  → all symbols transitively depending on <id>, weighted by test_coverage, runtime_confirmed, criticality

GET /graph/affected?symbol=<id>&direction=upstream
  → what <id> itself depends on (root-cause diagnosis path)

GET /graph/routes?changed_since=<commit>
  → routes/flows touched by a given diff — feeds the flow agent's targeted run list

GET /graph/diff?from=<commit>&to=<commit>
  → damage-graph vs repair-graph comparison (Section 7 of the master plan)

GET /graph/coverage-gaps?criticality=high
  → high-criticality nodes with low test_coverage or runtime_confirmed=false — prioritization feed for the fix-verification agent
```

Every downstream agent (flow, load, contract, fix-verification) consumes this API instead of independently parsing the codebase — that's the actual leverage point: one shared, incrementally-maintained source of truth instead of ten agents each re-deriving their own partial picture.

---

## 6. Recommended Stack

| Concern | Choice | Why |
|---|---|---|
| Static AST parsing (JS/TS) | ts-morph / typescript compiler API | Full symbol resolution, not just regex/text matching |
| Static AST parsing (Python) | `ast` + `jedi` for cross-file resolution | Same reasoning |
| Multi-language fallback | Tree-sitter | Broad language coverage when a dedicated parser isn't worth building yet |
| Dynamic crawling | Playwright | Already in your stack; headless, scriptable, good state-dedup support |
| Runtime tracing | OpenTelemetry | Already needed for hosted-mode monitoring — reuse the same instrumentation instead of a second system |
| Graph storage (small/embedded) | SQLite w/ edge table | Zero-infra, fits the CLI/embedded deployment mode |
| Graph storage (large repos, standalone/hosted) | Kùzu (embedded graph DB) or Neo4j Community | Real graph traversal performance at VS-Code scale |

---

## 7. Build Milestones

1. Static single-language extractor (start with TS/JS, your likely primary stack) producing symbol nodes + import/call edges.
2. Graph storage + incremental update on file diff (steps 1–5 of Section 4) — prove the patch-not-rebuild model works before adding dynamic data.
3. Query API (Section 5) wired to the flow agent as first consumer — validates the schema is actually useful, not just theoretically complete.
4. Playwright dynamic crawl layered in, populating `runtime_confirmed` and route discovery.
5. OpenTelemetry runtime-confirmed weighting in hosted mode.
6. Multi-language support via Tree-sitter fallback once the single-language path is proven.

---

*This spec is a child document of the Patchi Master Plan — it implements the shared graph referenced in that plan's blast-radius model (Section 7) and underlies the testing-agent restructure discussed for scaling to large repos.*
