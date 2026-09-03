# Live Testing + Playwright + App Runner — Reformed Plan

> Source: user spec 8 points + refined p check domain + tester logging → brain verification.
> Status: approved to execute. Single docs/planning folder, archive on done, ROADMAP from remainder.

---

## 0. Side Agent Family — preflight before app run

**Purpose:** run the app and catch formatting/build/install errors before testing. Can run standalone `p check` or hand-in-hand `p test --with-check`.

**Agents `core/agents/side/*` Group.SIDE timeout 30-120:**

* `InstallAgent` — `package.json→npm ci, requirements.txt→pip install -r, pyproject.toml→pip install -e ., Cargo.toml→cargo build, go.mod→go mod download, Gemfile→bundle install` → log `.patchi/launcher/install.log` `Finding install_failed HIGH` on non-zero.
* `BuildAgent` — `npm run build / tsc --noEmit / cargo check / go vet / mvn test-compile` → `Finding build_failed HIGH` `msg: stdout[:500]`.
* `FormatAgent` — `ruff check / eslint --max-warnings 0 / prettier --check` → `Finding format_error LOW`.

Each `shutil.which` fail-open. Results `scan_results["SideInstall"]` → `p check` aborts if `HIGH` unless `--force`.

---

## 1. App Launcher — `core/testing/app_launcher.py`

**Single service, used by Playwright + attack.**

* `detect()` `FrameworkDetector brain/framework.py:318 + project_reader tech_stack entry_points` → table `fastapi:uvicorn app:app --port {port}` `flask:flask run --port {port}` `express: npm run dev` `next: npm run dev -p {port}` `go: go run .` `django: python manage.py runserver {port}`.
* `ensure_running(root, config, extra) → base_url` — if `find_server _browser.py:54` finds `1612/3000` return; else `install` if missing `node_modules/.venv` → `start` `Popen(start_cmd, cwd=root, env PORT/HOST=127.0.0.1 + .env)` → poll `GET /health|/ 200 2s×30 httpx` → store `proc, port, log .patchi/launcher/app.log` → return `http://127.0.0.1:{port}`.
* `stop()` `atexit + finally` `terminate→kill 5s` `port free check`.

---

## 2. Playwright + Attack start app before work

`BrowserTestAgent:58`, `UIButtonAgent:57`, `red_team_engine:127`, `dast_agent` all receive `extra base_url` from launcher — no `socket.create_connection` probe-only `_browser.py:54`. `page.goto(wait_until=load/body visible + 700→1500ms settle _browser.py:124)` + `screenshot_manager.save_screenshot`.

---

## 3. Tester Family — different tasks, personas, stress

**`p test --browser --e2e --visual --stress --personas=bad` `test_cmd:run_test` → `AgentInput extra {base_url, personas}`:**

* `ButtonAgent` clicks + `LayoutAgent` `ui_accessibility` + `NavigationAgent` `spa_route_inventory createBrowserRouter` + `E2EFlowAgent` critical flows `contract`
* `StressAgent` `core/testing/stress_orchestrator` `concurrent 10-100 spike/soak 30s httpx rps/p50/p95`
* `PersonaBadUserAgent` `core/brain/personas/bad_user.py` 3 personas: `breaker (fuzz InputFuzzer injection)`, `impatient (rapid nav)`, `malicious (auth bypass jwt_tool)` → `call_ai Skill.TEST_GENERATE` with persona `get_system_prompt_additions() personas/base.py:104`
* Launcher provides `base_url`, `p scan` is `SCANNER/SECURITY` only — `Group.TEST` removed from `scan_cmd coord`.

---

## 4. Shown in `p web` + video recordings

`live_v2/video_recorder.py + screenshot_manager` `playwright video: recordVideo dir .patchi/evidence/browser` `web/routes/live_testing.py` streams `evidence_dir` `page.screenshot full_page` `Panel heatmap`.

---

## 5. Ads Agent — visual videos/screenshots

`core/testing/ads_agent.py: Group.TEST` `viewport 1440/768/375` `screenshots + 5s video` `page.goto` `waits networkidle 1500ms _browser.py:124` → `marketing gallery` `.patchi/evidence/ads/` `story + pricing hero` for `imagegen-frontend-web`.

---

## 6. Testing = AI + personas + specific agents + optional stress

`Council test_engineer` persona picks `Button/Layout/E2E` set via `domain_activator active_domains + understander.core_files MAX_CHARS 6000 enriched_context`, stress `parallel 6 realize.py:412`.

---

## 7. Out of `p scan`

`scan_cmd: security_scan` → `AgentGroup.SCANNER/SECURITY` only; `red_team_engine pentest/shannon/nuclei` only via `p test --attack` / `p red-team --with-...` `tools/registry:234 attack_simulate`.

---

## 8. `p check` fix/signals to brain — thorough audit, domain-only

**Domain fix gate:** `check` only fixes in its lane `type/deps/build/format/install` (`TypeFixer` for `mypy/tsc --noEmit missing_type`, `SupplyChainAgent` `unpinned_dependency`), never `security` findings. Else asks brain: `ask_brain "dep bump for {dep}@{ver}?" reasoning.py ask(ask_ai=True)` with `enriched_context top_risks` → returns `suggested actions` `brain.json`.

**Tester logging → brain verification:**

* Every `Group.TEST` `UIButtonAgent:50, BrowserTestAgent:52, NavigationAgent, StressAgent, BadUserAgent, AdsAgent` writes `trace_log brain/trace_log.py` + `result.data {pages_tested, issues, console_errors[10], http_5xx[10], screenshots[5], errors[]}` `ui_button_agent:149 suite` — `error_pages, console_errors, page_errors` captured via `open_page PageSession status/console_errors/page_errors _browser.py:90` even on `page.goto networkidle 15s` failure `ui_button_agent:83`.
* `Live probe` `browser_test_agent:185 _live_probe` logs `nav_failures console_errors screenshots .patchi/artifacts/browser` — not trusted until verified.
* **Verification:** `scan_cmd` after `p test` merges `test_agents merge_results` → `brain/verify.py:32` checks `code snippet` exists in `FileCorpus`, `line` matches `FileInfo`, `route` in `RouteMapper` — only then `memory.save_scan_result("UI")` + `brain.json:errors report.errors brain.py:312` appended. No verification → not added as `Finding`.

---

## Files

`cli/commands/check_cmd.py` (new `p check --fix --json`) `core/agents/side/install_agent.py, build_agent.py, format_agent.py` `core/testing/app_launcher.py` `core/brain/personas/bad_user.py` `core/testing/ads_agent.py` `cli/registry p check/test` `core/brain/verify.py` `install.sh playwright install` `docs/planning/live-testing-playwright-app-runner-plan.md` (this file)

## Phases

* **P1 2d:** Side `install/build/format` + `app_launcher ensure/stop` + move `TEST` out of `scan`.
* **P2 2d:** Audit `12` `py_compile + p test --browser` against `p web 1612` self-test `5 pages`.
* **P3 2d:** AI operator `call_ai` loop + `p test --generate` `.patchi/tests/browser/` + `doctor` binary check.
