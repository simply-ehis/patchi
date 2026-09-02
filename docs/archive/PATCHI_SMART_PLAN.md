# Patchi Smart Plan — Understander-First Brain

**Vision:** Stop being a 60-agent scanner bus with optional AI. Become an understander that earns agent execution: `FileCorpus → Brain + Body tags → Understander (12 core files) → Enriched Context → Gated agents → Tool-reading LLM for fix/validate/attack`. One LLM call in the hot path, 3 scoped file reads max.

---

## 1. Where we are (audited)

- `patchi/core/brain/brain.py:440-501` builds `context_data` from heuristics, sends `file_infos[:50]` in insertion order to `patchi/core/brain/contract.py:269` — not importance. `patchi/core/brain/reasoning.py:179` is `re.findall` bag-of-words. `patchi/core/fix/base.py:229` sees `line±5` with no callers.
- `patchi/core/brain/council.py:270` picks personas by keyword, `patchi/core/brain/personas/base.py:255` fallback `confidence 0.4`. Context is `layers level≤2` dump `personas/base.py:144-159`.
- `patchi/core/security/red_team_engine.py:174-202` has 7 tools (`fuzz_params`, `sql_payload`, `http_request`, `browser_action`, `code_scan`, `jwt_tool`) with static YAML payloads `patchi/core/security/attack_scenarios/sqli.yaml:22`. Real `aiohttp` + real `Playwright` (`red_team_engine.py:127`) but no `sqlmap`/`nuclei`/`zap`.
- `patchi/core/security/confidence_gate.py:71` `ai_weight 0.3`, `patchi/core/security/ai_validator.py:128` heuristic filter saves tokens, but validator never reads beyond `fline±30` (`ai_validator.py:364`).

---

## 2. Target Architecture

```
Scan
 ├─ FileCorpus + import_graph + blast_radius + layered_brain
 ├─ Body tags → .patchi/memory/body_tags.json {role,system,layer,criticality,fan_in,score,is_hub,is_route_file}
 ├─ Understander.core_files(16) ranked score=fan_in*10+dep*3+criticality bonus
 ├─ enriched_context (1 LLM call, PATCHI_OFFLINE-safe, now core-aware)
 ├─ active_domains = understander.refine(domains)  # drops false hubs
 └─ Scanners gated: only domains with high/medium core files run → 182→~40 on Flask

Fix/Validate/Attack/Test: shared read_file(path, start, end, reason) tool 500 lines / 3 calls / validated path ≤2MB not in .patchi lockfiles
```

Body roles (`patchi/core/brain/body_tags.py:14`) `brain/muscle/bone/blood/skin/nerve` derived deterministically — no hand-written `BODY.md`.

---

## 3. Slices (small, reversible, verified each)

### Slice 1 — DONE
`patchi/core/brain/enriched_context.py` + `patchi/core/brain/brain.py:458` — 1 LLM call/scan, offline fallback. Verified `0 bare except` in prod, `pytest 73` passed.

### Slice 2 — DONE
`patchi/core/brain/body_tags.py` + `patchi/core/brain/understander.py` + `patchi/core/brain/brain.py:446` (Body tags) + `patchi/core/brain/contract.py:269` (`core_files(20)`). Replaces `file_infos[:50]` insertion-order. Verified `75 tags`, top `languages.py fan_in 34 score 519`, `0 bare except`.

### Slice 3 — Real Pentest (user request) — Shannon Option 2 (chosen: no vendoring, AGPL-clean adapter)

**Goal:** Keep YAML as knowledge base, execution calls real tools with AI choice. Shannon added as *external tool* via `npx` — not vendored source — to avoid AGPL contamination of Patchi Freemium (`pyproject.toml:6`).

- New `patchi/core/security/pentest/base.py` — `PentestTool {name, is_available()->shutil.which, run(target,safe_mode)->{success, evidence, findings[]}}`
- Adapters: `nuclei_adapter`, `sqlmap_adapter`, `dalfox_adapter`, `ffuf_adapter`, `zap_adapter` — each `shutil.which` + `docker` fallback + parse JSONL → `make_tool_finding()` (`patchi/core/security/tool_adapters.py:94`) with `tool_confidence` for `confidence_gate.py:51`.
- **Shannon adapter (Option 2):** `patchi/core/security/pentest/shannon_adapter.py` — `class ShannonTool(PentestTool): name="shannon"` — `is_available()` checks `npx --version && docker info`, `run(target_url, repo_root, workspace)` shells `npx @keygraph/shannon@latest start -u {target_url} -r {repo_root} --workspace {root/.patchi/shannon/<uuid>} --json` (ephemeral container, repo read-only, `PATCHI_OFFLINE` respected). Parses `workspace/**/*.sarif` (SARIF 2.1.0) + `report.json` → `make_tool_finding` with `cwe, tool_confidence, evidence {screenshot, poc}`; mutative warnings from `shannon/docs/safety.md` surfaced via `safe_mode=True` default. Fail-open if `npx/docker` missing — falls back to YAML.
- `patchi/core/security/pentest/registry.py` + `patchi/core/security/pentest/ai_pentester.py` — ReAct loop: `SYSTEM="You are Patchi Red Team Lead. routes:{5} core:{understander} domains:{active} tools:{schemas} pick ONE tool/call per turn, 5 max"` — AI chooses `nuclei` for CVE surface, `shannon` for full authenticated chain, `sqlmap` for singled-out endpoint.
- Wire `patchi/core/security/red_team_engine.py:189` `AttackExecutor.execute_step` → `if use_real_tools and registry.has(tool): registry.run()` else YAML fallback (fail-open like `patchi/core/security/tool_verify.py:116`).
- Expose `p red-team --with-real-tools` (existing YAML+local tools) and `p red-team --with-shannon --target https://staging.example.com` + `patchi/core/ai/tools/registry.py:234` `attack_simulate(use_real_tools, use_shannon)` + `Council` tool `red_team`. Docs note: needs running staging with disposable data, BYOK (`docs/ai-providers.md`), `1-1.5h`, `PATCHI_OFFLINE` disables all.

Why Option 2: No `git submodule add https://github.com/KeygraphHQ/shannon.git` (300MB history, AGPL `LICENSE`), no Python deps — `npx` pulls worker image from Docker Hub on demand. Keeps Patchi license clean while reusing Shannon's reconcile→exploit→discard (`no exploit, no report`).

Verify: `nuclei -u http://127.0.0.1:1612 -t cves -jsonl` mocked via `mock_resp` (`tests/test_ai_client.py:68`); Shannon mocked via `sarif` fixture `benchmark/photoview-*.sarif`.

### Slice 4 — Tool-Reading LLM + Reasoning
- New `tools/read_file` (`patchi/core/ai/tools/registry.py:86` + `patchi/core/ai/tools/realize.py`) — 500 lines / 3 calls, path validated (`root / path is_file + suffix in SOURCE_EXTENSIONS + ≤2MB`).
- Wire to `AIValidator._read_file` (`security/ai_validator.py:308`), `fix/base._read_file` (`fix/base.py:36`), `personas _call_ai_with_persona`, `TEST_GENERATE`.
- Replace `patchi/core/brain/reasoning.py:179` with `understander.retrieve(question)` TF-IDF over `layer.summary + body_tags` + optional `ask_brain` LLM synthesis if `ai_weight>0`. Keep `call_ai_structured` JSON.

### Slice 5 — Fix/Test with Real Context
- `patchi/core/fix/base.py:229` `_build_fix_prompt` injects `blast_radius_map.get(path).all_dependents[:3]` contents + `understander.function_at(path, line)` instead of `±5`.
- `patchi/core/testing/unit_test_agent.py:129` — add `generate_tests(target_files: understander.untested_core())` using `Skill.TEST_GENERATE` (`patchi/core/ai/prompts.py:250`) + `existing_tests_section` nearest `tests/test_*.py`.

### Slice 6 — Gating + Speed
- `patchi/core/brain/brain.py:440` prune `scan_vulnerabilities(domains=active_refined)`; `confidence_gate.py:367` `min_agents_for_defend` now respects `tool_confidence` from DAST.

---

## 4. Guardrails

- Tokens fixed: `enriched_context.py:26` `MAX_CHARS 6000`, attack 5 tool calls max, validator cache `24h` (`ai_validator.py:203`).
- Offline: every new LLM path checks `PATCHI_OFFLINE` (`client.py:103` / `fix/base.py:23`) and returns heuristic `confidence 0.3 true-positive` (`ai_validator.py:452`).
- Path validation: `root / path is_file + suffix in SOURCE_EXTENSIONS + ≤2MB` (`import_graph.py:26`).
- No free-form `rglob **/*.env` — only `ToolRegistry` enumerated tools.

## 5. Not Building

- Free-form shell tool, full codebase `cat` by LLM, per-finding LLM (N calls) — cost death.

---

*Last updated: 2026-09-02 | Slices 1-6 landed (L1-L4 + pentest + understander + gating) | Gate: pytest 73 pass, scan patchi/core/brain 75 files 18s, 0 bare except | Next: tag v0.7.2*
