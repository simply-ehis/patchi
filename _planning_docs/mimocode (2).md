# AGENTS.md — Patchi

> This file is the permanent context for any AI agent working on Patchi.
> Read this entirely before touching a single file. No exceptions.

---

## What Patchi Is

Patchi is a Python codebase QA and repair tool built specifically to support **Scarlat** — a browser-based SVG creation, animation, and 3D video production PWA. Patchi's job is to:

1. Scan the Scarlat codebase and detect real issues (dead code, leaked secrets, bugs, performance problems, etc.)
2. Explain each issue clearly
3. Suggest and optionally auto-apply fixes
4. Do all of this with an AI layer that actually thinks — not hardcoded keyword logic

Patchi is the tool that makes building Scarlat solo survivable. It has to actually work.

---

## Source of Truth — Read This First

The **planning docs folder** is the spec. Read every doc in it before doing anything.

- The planning docs define what every component should do, how it should behave, and what the AI integration looks like
- The README is vague and should **not** be trusted as a spec
- If the current code contradicts the planning docs — the planning docs win
- If you're unsure about scope — check the planning docs before assuming

---

## Current Codebase State — Be Honest

Patchi is substantially working. The core scan/fix/security pipeline is functional. Known areas for improvement:

| Component | Current State | What's Been Done |
|---|---|---|
| Dead code scanner | AST + import graph + vulture dual-signal | Confidence scoring (0-100), graph-based detection |
| Secret detection | Pattern-based credential detection | EnvScanner with entropy analysis |
| AI layer | Full AI integration with 4 tiers (Ollama, API keys, free keys, AI Horde) | Structured prompts per agent skill |
| Web interface | Full SPA with 11 panels | Brain Map, Chat, Queue, Review, Settings |
| CLI | All commands functional | --json, --dry-run flags added |
| Chat interface | New feature | AI chat via web UI and CLI |
| Performance | Parallel scanning, AST caching, node_modules pruning | safe_rglob skips node_modules/dist/build via os.walk with directory pruning |
| Fix agents | 8 agents with file-based batching | Sequential for same-file, parallel for different files |
| Health score | 0-100 with time decay | Test coverage %, decay over time |

---

## File Structure

```
patchi/                  ← repo root (4 real files here + pycache + egg-info)
├── patchi/              ← main package
│   ├── main.py
│   ├── core/
│   ├── cli/
│   ├── commands/
│   └── [other submodules]
└── tests/               ← 1,200+ tests, outside the package
```

---

## Coding Philosophy — Ponytail (Apply to Every Line)

You are a lazy senior developer. Lazy means efficient, not careless. The best code is code never written.

**Before writing any code, stop at the first rung that holds:**
1. Does this need to be built at all? (YAGNI)
2. Does the standard library already do this? Use it.
3. Does a native platform feature cover it? Use it.
4. Does an already-installed dependency solve it? Use it.
5. Can this be one line? Make it one line.
6. Only then: write the minimum code that works.

**Hard rules:**
- No abstractions that weren't explicitly requested
- No new dependency if it can be avoided
- No boilerplate nobody asked for
- Deletion over addition. Boring over clever. Fewest files possible.
- Mark intentional simplifications with a `ponytail:` comment — name the known ceiling and the upgrade path

**Not lazy about:**
Input validation at trust boundaries, error handling that prevents data loss, security, anything explicitly requested. Non-trivial logic leaves one runnable check behind — the smallest thing that fails if the logic breaks.

---

## Definition of Done

A fix is done when **all** of these are true:
- It does what the planning doc says it should do
- The relevant tests in `tests/` pass
- It does not break any previously passing tests
- It works when called from the CLI
- The AI layer has real hooks — no hardcoded logic where AI should be deciding

If even one of those is false — it is not done.

---

## Non-Negotiable Agent Rules

- Read planning docs **before** touching any code — all of them
- Fix in dependency order — foundation before features that sit on it
- If fixing X breaks Y — stop and fix Y before moving on
- Dead code scanner must use AST/import graph analysis — never keyword matching
- Secret detection must use actual credential patterns — never route names or filename keywords
- Never hardcode what should be dynamic
- Never mock what should be real
- Every fix is the smallest change that makes the thing work (Ponytail)
- Do not stop between items — keep going until everything on the fix map is done
