<!--
PURPOSE: Contract for CLI ↔ Web UI parity. The web is a "fancy CLI wrapper":
         every screen maps to a command, and p web serves the project the
         terminal is standing in — same resolution, same refusal.
OWNS:     The mapping table below; the 1:1 resolution rule.
READ-WHEN: Adding/changing any web action or CLI command; touching
           web_cmd project resolution.
KEY-FILES: patchi/cli/commands/web_cmd.py, patchi/web/routes/dashboard_v2.py,
           patchi/cli/registry.py
INVARIANTS:
  - `p web` resolves its root with the SAME find_project_root() as all other
    commands (nearest .patchi at/above cwd). No child-dir guessing.
  - Refusal without a project matches require_project_root()'s message.
  - A web action that duplicates a command must call the same underlying
    code path (CLI handler or shared core), never a divergent reimplementation.
GOTCHAS: scan_cmd.run reports via rich console and returns None — read results
         from memory after calling it.
UPDATED: 2026-08-25
-->

# CLI ↔ Web Parity

| Web surface | CLI equivalent | Shared code path |
|---|---|---|
| `p web` project selection | `p <any>` root walk-up | ✅ same `find_project_root()` |
| Header switcher → `/api/tenant/switch` | `p web --project <path>` (restart) | runtime swap vs restart — both validated against `.patchi` |
| Overview ▸ Scan button (WS `start_scan`) | `p scan` | ✅ calls `scan_cmd.run()` directly |
| Attacks tab ▸ Launch Red Team | `p scan --red-team` / tool `red_team` | tool layer (`tools/realize.py`) |
| Live Tests tab | `p test ...` / tool `run_tests` | tool layer |
| Findings page | `p status` / findings memory | shared memory (`core/memory.py`) |
| Review ▸ Apply-all-safe | risk-gated apply | ✅ RiskGate + PatchApplier (same as fix pipeline) |
| Hosted ▸ Compliance report | `p hosted` data | `core/hosted/*` modules |
| Council deliberation | council engine | ✅ `core/brain/council.py` |

Rules for new features:
1. Build the capability in `core/` first.
2. Expose it as a CLI command (registry entry).
3. Wrap it in the web via that command's handler or the tool layer — never a third implementation.
