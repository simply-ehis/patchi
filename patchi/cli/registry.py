"""
Command registry â€” the single source of truth Â§3 Command Unification promises.

Every `p <command>` in the system is declared here and nowhere else. The
incremental migration is complete: the legacy argparse blocks and the elif
dispatch ladder in main.py are gone, and TestCLIRegistryLinking in
tests/test_regression_audit.py proves parser â†” registry exact equality at
every nesting level â€” no command can ever live on a hidden ladder again.

Command shapes used:

- Kwarg handlers (the default): Arg specs map to handler parameters
  (scan, fix, report, audit, undo, reason, trend, learn, ...).
- Subcommand trees: Command.subcommands for `p <cmd> <sub>` (queue, patch,
  key, agents, model, memory, restrict, settings, access, ai, charter, ...).
- Self-routing Namespace handlers (framework namespace_handler=True): the
  handler receives the whole parsed Namespace and routes on the subcommand
  dests itself. Used by notify, hosted (deepest tree: hosted token revoke
  <id>), test, security, and cross-repo â€” all dispatch on parsed values a
  static Arg->kwarg mapping can't express (e.g. `p test generate` routes to a
  different function than `p test unit`).

Every handler's ACTUAL signature was checked against these entries before
registering â€” several didn't match the parser's attribute name at first pass
(scan's --file stores under `file`, handler wants `file_path`; queue's mode
positional was `mode_name`, handler wants `mode_str`; patch's id args were
`id`, handlers want `patch_id`; key's remove/test were `name`, handlers want
`nickname`). All are fixed below, not assumed â€” and TestCLIRegistryLinking now
guards the whole set mechanically.
"""

from __future__ import annotations

from patchi.cli.framework import Arg, Command
from patchi.core.constants import RestrictionType as _RestrictionType

COMMANDS: list[Command] = [
    Command(
        "init",
        "Initialize Patchi in the current project",
        "patchi.cli.commands.init:run",
        args=(
            Arg("--no-logo", dest="no_logo", action="store_true", help="Skip logo draw (for CI)"),
        ),
    ),
    Command(
        "ready",
        "Ship readiness check — is my code ready to ship?",
        "patchi.cli.commands.ready_cmd:run",
        args=(
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
            Arg("--quick", dest="quick", action="store_true", help="Fast check (subset of agents)"),
            Arg("--ci", dest="ci", action="store_true", help="CI-friendly output (exit 1 on failure)"),
        ),
    ),
    Command(
        "quick",
        "Fast readiness check — minimal agents for quick verification",
        "patchi.cli.commands.quick_cmd:run",
        args=(
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
        ),
    ),
    Command(
        "status",
        "Show Brain health, mode, queue state, and key status",
        "patchi.cli.commands.status_cmd:run",
        args=(
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
            Arg("--deep", dest="deep", action="store_true", help="Show detailed health breakdown (was p health)"),
            Arg("--validate", dest="validate", action="store_true", help="Run system validation checks (was p doctor)"),
            Arg("--verbose", dest="verbose", action="store_true", help="Show detailed output"),
        ),
    ),
    Command(
        "doctor",
        "System health check — stale commands, dependencies, config",
        "patchi.cli.commands.doctor_cmd:run",
        args=(
            Arg("--verbose", dest="verbose", action="store_true", help="Show detailed output"),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
            Arg("--fix", dest="fix", action="store_true", help="Auto-update stale command references in scripts/"),
        ),
    ),
    Command(
        "watch",
        "Auto-scan on file saves",
        "patchi.cli.commands.watch_cmd:run",
        args=(
            Arg("area", nargs="?", help="Watch specific area only"),
            Arg("--dry-run", action="store_true", help="Preview auto-fixes without applying them"),
            Arg("--preview", action="store_true", help="Show detailed before/after of proposed fixes"),
            Arg("--auto-fix", action="store_true", help="Enable proactive fixing on file saves (overrides config)"),
        ),
    ),
    Command(
        "scan",
        "Scan the project (full or targeted)",
        "patchi.cli.commands.scan_cmd:run",
        args=(
            Arg("area", nargs="?", help="Targeted area â€” plain language or path"),
            Arg("--force", action="store_true", help="Re-scan even if brain is fresh"),
            Arg(
                "--offline",
                dest="offline",
                action="store_true",
                help="Skip all AI calls â€” static analysis only, zero token cost",
            ),
            Arg(
                "--dry-run",
                dest="dry_run",
                action="store_true",
                help="Preview what would be scanned without parsing",
            ),
            Arg(
                "--quiet",
                dest="quiet",
                action="store_true",
                help="Suppress non-essential output",
            ),
            Arg(
                "--deep",
                action="store_true",
                help="Include LLM analysis of changed files (uses AI tokens)",
            ),
            Arg("--file", dest="file_path", type=str, help="Deep analysis of a specific file"),
            Arg("--contract", action="store_true", help="Review and confirm app contract flows"),
            Arg(
                "--all-flows",
                dest="all_flows",
                action="store_true",
                help="Show all flows including low-confidence (used with --contract)",
            ),
            Arg(
                "--json",
                dest="json_output",
                action="store_true",
                help="Output scan results as JSON (machine-readable)",
            ),
            Arg(
                "--no-side",
                dest="side",
                action="store_false",
                default=True,
                help="Skip side file scanners (faster, source-only scan). Default: on",
            ),
            Arg(
                "--pipeline",
                action="store_true",
                help="Enable defense pipeline: ConfidenceGate + DefenseLayer auto-fix",
            ),
            Arg("--daemon", action="store_true", help="Start background scan scheduler daemon"),
            Arg(
                "--governor",
                action="store_true",
                help="Run Governor v2 pipeline: scan â†’ graph â†’ test â†’ fix â†’ reverify â†’ select",
            ),
            Arg(
                "--with-attackers",
                dest="with_attackers",
                action="store_true",
                help="Run adversarial attacker hypotheses against the assurance graph",
            ),
            Arg(
                "--with-campaigns",
                dest="with_campaigns",
                action="store_true",
                help="Run state transition and data flow abuse campaigns",
            ),
            Arg(
                "--with-fuzz",
                dest="with_fuzz",
                action="store_true",
                help="Generate fuzz inputs for discovered endpoints",
            ),
            Arg(
                "--red-team",
                dest="red_team",
                action="store_true",
                help="Run Red Team Engine: live attack simulation + auto-fix generation",
            ),
            Arg(
                "--dast",
                action="store_true",
                help="Run DAST scanner: Playwright-based dynamic security testing with screenshots",
            ),
            Arg(
                "--changed",
                action="store_true",
                help="On-demand mode: only activate domains relevant to git-diff changed files",
            ),
            Arg(
                "--since",
                dest="since",
                default=None,
                help="Only report findings in files changed since git ref (e.g. HEAD~3, main)",
            ),
            Arg(
                "--fail-on",
                dest="fail_on",
                default=None,
                choices=("critical", "high", "medium"),
                help="Exit 1 when findings at/above this severity exist (CI gate). Default: always exit 0",
            ),
            Arg(
                "--changed-commits",
                dest="changed_commits",
                type=int,
                default=1,
                help="Number of commits to diff (default: 1)",
            ),
            Arg(
                "--with-license",
                dest="with_license",
                action="store_true",
                help="Include license compliance findings (heavy/noisy). Use p scan --with-license for full supply-chain license audit",
            ),
            Arg(
                "--with-extended",
                dest="with_extended",
                action="store_true",
                help="Include extended noise (duplicates, hygiene). Main scan stays focused; use for deep audit",
            ),
            Arg("--quiet", dest="quiet", global_flag=True),
        ),
    ),
    Command(
        "cockpit",
        "Live session dashboard â€” health, drift, fix list, blast radius",
        "patchi.cli.commands.cockpit_cmd:run",
        args=(
            Arg("--area", dest="area", default=None, help="Scope the fix list to this area/path"),
            Arg(
                "--interval",
                dest="interval",
                type=float,
                default=15.0,
                help="Seconds between full health/drift/fix refreshes",
            ),
            Arg(
                "--poll",
                dest="poll",
                type=float,
                default=1.0,
                help="Seconds between file-change polls",
            ),
            Arg(
                "--once",
                dest="once",
                action="store_true",
                help="Render one frame and exit (CI / smoke test)",
            ),
            Arg(
                "--scan-secrets",
                dest="scan_secrets",
                action="store_true",
                help="Run a full secrets sweep at startup",
            ),
        ),
    ),
    Command(
        "queue",
        "View and control the task queue",
        "patchi.cli.commands.queue_cmd:run_show",  # used when no subcommand given
        subcommands=(
            Command("pause", "Pause queue execution", "patchi.cli.commands.queue_cmd:run_pause"),
            Command("resume", "Resume queue", "patchi.cli.commands.queue_cmd:run_resume"),
            Command(
                "skip", "Skip the current active task", "patchi.cli.commands.queue_cmd:run_skip"
            ),
    # `p mode` merged into `p settings` — use `p settings set mode <name>`
            Command(
                "mode",
                "Set queue mode",
                "patchi.cli.commands.queue_cmd:run_set_mode",
                args=(Arg("mode_str", choices=("single", "multi", "off")),),
            ),
        ),
    ),
    Command(
        "patch",
        "Manage individual patches",
        "patchi.cli.commands.patch_cmd:run_list",  # used when no subcommand given
        subcommands=(
            Command(
                "list",
                "List all patches",
                "patchi.cli.commands.patch_cmd:run_list",
                args=(
                    Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
                ),
            ),
            Command(
                "show",
                "Show diff for a patch",
                "patchi.cli.commands.patch_cmd:run_show",
                args=(
                    Arg("patch_id"),
                    Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
                ),
            ),
            Command(
                "apply",
                "Apply a pending patch",
                "patchi.cli.commands.patch_cmd:run_apply",
                args=(Arg("patch_id"),),
            ),
            Command(
                "reject",
                "Reject a patch",
                "patchi.cli.commands.patch_cmd:run_reject",
                args=(Arg("patch_id"),),
            ),
            # Canonical home for the undo family (top-level names kept as compat)
            Command(
                "undo",
                "Undo last applied fix or specific patch",
                "patchi.cli.commands.undo_cmd:run_undo",
                args=(Arg("patch_id", nargs="?", help="Specific patch ID"),),
            ),
            Command(
                "redo",
                "Redo last undone fix or specific patch",
                "patchi.cli.commands.undo_cmd:run_redo",
                args=(Arg("patch_id", nargs="?", help="Specific patch ID"),),
            ),
            Command(
                "rollback",
                "Roll back to a specific patch",
                "patchi.cli.commands.undo_cmd:run_rollback",
                args=(Arg("patch_id"),),
            ),
        ),
    ),
    Command(
        "key",
        "Manage API keys",
        "patchi.cli.commands.key_cmd:run_add",  # no subcommand -> interactive add, matches original
        subcommands=(
            Command("add", "Add an API key (interactive)", "patchi.cli.commands.key_cmd:run_add"),
            Command("list", "List all keys with status", "patchi.cli.commands.key_cmd:run_list"),
            Command(
                "remove",
                "Remove a key by nickname",
                "patchi.cli.commands.key_cmd:run_remove",
                args=(Arg("nickname"),),
            ),
            Command(
                "test",
                "Test a key connection",
                "patchi.cli.commands.key_cmd:run_test",
                args=(Arg("nickname", nargs="?", help="Key nickname (omit for all)"),),
            ),
        ),
    ),
    # `p ignore` merged into `p memory` — use `p memory ignore`
    # â”€â”€ Batch 3: 22 more commands. Every handler signature checked directly
    # against the real code, not assumed from the parser's attribute names --
    # 7 more drift fixes found this batch (running total: 11 across the whole
    # migration): undo/redo/rollback's `id`->`patch_id`, explain's `type`->
    # `finding_type`, blast's `all`->`show_all`. â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    Command(
        "fix",
        "Fix issues in the project",
        "patchi.cli.commands.fix_cmd:run",
        args=(
            Arg("area", nargs="?", help="Targeted area"),
            Arg(
                "--dry-run",
                dest="dry_run",
                action="store_true",
                help="Preview fixes without applying",
            ),
            Arg(
                "--preview",
                dest="preview",
                action="store_true",
                help="Show before/after code diffs for each proposed fix",
            ),
            Arg(
                "--safe-all",
                dest="safe_all",
                action="store_true",
                help="Apply every non-blocked patch (AUTO + review), not just AUTO — test-only edits still queue",
            ),
        ),
    ),
    Command(
        "fix-review",
        "Review and decide on proposed patches",
        "patchi.cli.commands.fix_review_cmd:run",
        args=(
            Arg("--patch", dest="patch_id", help="Review a specific patch by ID"),
        ),
    ),
    Command("review", "Review pending changes", "patchi.cli.commands.review_cmd:run"),
    Command(
        "undo",
        "Undo last applied fix or specific patch (compat â€” prefer p patch undo)",
        "patchi.cli.commands.undo_cmd:run_undo",
        args=(Arg("patch_id", nargs="?", help="Specific patch ID"),),
    ),
    Command(
        "redo",
        "Redo last undone fix or specific patch (compat â€” prefer p patch redo)",
        "patchi.cli.commands.undo_cmd:run_redo",
        args=(Arg("patch_id", nargs="?", help="Specific patch ID"),),
    ),
    Command(
        "rollback",
        "Roll back to a specific patch (compat â€” prefer p patch rollback)",
        "patchi.cli.commands.undo_cmd:run_rollback",
        args=(Arg("patch_id"),),
    ),
    Command(
        "why",
        "Explain why a file matters",
        "patchi.cli.commands.reason_cmd:run_why",
        args=(Arg("path", help="File path to explain"),),
    ),
    Command(
        "impact",
        "Show change-impact / blast radius for changed files",
        "patchi.cli.commands.reason_cmd:run_impact",
        aliases=("blast",),
        args=(
            Arg("files", nargs="*", help="One or more changed file paths"),
            Arg(
                "--all",
                dest="show_all",
                action="store_true",
                help="Show blast radius for all files (absorbed from p blast)",
            ),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
        ),
    ),
    Command(
        "auto",
        "Propose/apply safe fixes for changed files",
        "patchi.cli.commands.auto_cmd:run",
        args=(
            Arg("files", nargs="+", help="One or more changed file paths"),
            Arg("--apply", action="store_true", help="Apply safe fixes automatically"),
            Arg("--unsafe", action="store_true", help="Also apply non-safe fixes (with --apply)"),
            Arg(
                "--reject",
                dest="reject",
                default=None,
                help="Record that you reject a fix type (Phase 5 learning), then exit",
            ),
        ),
    ),
    # verify currently has zero CLI-exposed args in the original (no_scan/claim
    # exist on the handler but nothing ever set them) -- replicated faithfully
    # as-is, not "fixed" into a new feature that wasn't there before.
    Command(
        "verify",
        "Independently re-run tests+scan and report truth (not self-report)",
        "patchi.cli.commands.verify_cmd:run",
        args=(
            Arg(
                "--no-scan",
                dest="no_scan",
                action="store_true",
                help="Only re-run tests, skip scan",
            ),
            Arg(
                "--claim",
                dest="claim",
                default=None,
                help="Assert a claim (e.g. 'tests pass') against actual truth",
            ),
        ),
    ),
    # `p mode` merged into `p settings` - use `p settings set mode <name>`
    Command(
        "chat",
        "Interactive AI chat with Patchi",
        "patchi.cli.commands.chat_cmd:run",
        args=(
            Arg("message", nargs="?", help="Single message (non-interactive)"),
            Arg("--stream", action="store_true", help="Show real-time tool execution progress"),
            Arg("--explain-all", action="store_true", dest="explain_all", help="Show full security knowledge base"),
        ),
    ),
    Command(
        "dev",
        "Developer utilities, testing docs, and diagnostics",
        "patchi.cli.commands.dev_cmd:run",
        args=(
            Arg(
                "action",
                nargs="?",
                default=None,
                help="Dev action: check | test | security | playwright | docs | hook (--strict)",
            ),
            # dev has its own --verbose, separate from the global one
            Arg("--verbose", dest="verbose", action="store_true", help="Show detailed output"),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON (for check)"),
            Arg("--strict", dest="strict", action="store_true", help="Fail commits on violations (hook)"),
            Arg("--auto-fix", dest="auto_fix", action="store_true", help="Auto-fix charter violations on commit (hook)"),
            Arg("--fast", dest="fast", action="store_true", help="Fast mode: run only core tests (~18s) for quick iteration"),
        ),
    ),
    Command(
        "deps",
        "Supply chain security scan",
        "patchi.cli.commands.deps_cmd:run",
        args=(
            Arg("--sbom", action="store_true", help="Generate SBOM"),
            Arg("--licenses", action="store_true", help="Check license compliance"),
            Arg("--outdated", action="store_true", help="Check for outdated packages"),
            Arg("--cve", action="store_true", help="Check for known CVEs"),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
        ),
    ),
    # `p blast` was merged into `p impact` (--all + alias). One blast-radius
    # implementation, one command.
        # `p brain` merged into `p agents list --brain` — use `p agents list --brain`
    Command(
        "trend",
        "Health and quality trend over time",
        "patchi.cli.commands.trend_cmd:run",
        args=(
            Arg(
                "metric",
                nargs="?",
                choices=("security", "tests"),
                help="Specific metric (default: overall health)",
            ),
            Arg(
                "--last",
                dest="last_n",
                type=int,
                default=20,
                help="Number of recent entries to show",
            ),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
        ),
    ),
    Command(
        "heatmap",
        "Risk heatmap — bug-prone hotspots (score = findings×10 + churn×2 + size/10)",
        "patchi.cli.commands.heatmap_cmd:run",
        args=(Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),),
    ),
    Command(
        "blame",
        "Show git blame for a file",
        "patchi.cli.commands.blame_cmd:run",
        args=(
            Arg("file_path", help="File path to blame"),
            Arg("line", nargs="?", type=int, help="Specific line number"),
        ),
    ),
    Command(
        "log",
        "Show git changelog",
        "patchi.cli.commands.log_cmd:run",
        args=(Arg("--since", default="HEAD~10", help="Git ref or date (default: HEAD~10)"),),
    ),
    Command(
        "update",
        "Check for and apply updates",
        "patchi.cli.commands.update_cmd:run",
        args=(
            Arg("--check", action="store_true", help="Check only, no install"),
            Arg("--force", action="store_true", help="Force reinstall current version"),
            Arg("--auto", action="store_true", help="Auto-install without prompting (for CI)"),
        ),
    ),
    Command(
        "learn",
        "Learn project conventions and patterns",
        "patchi.cli.commands.learn_cmd:run",
        args=(
            Arg("--force", action="store_true", help="Relearn even if conventions already stored"),
            Arg("sub", nargs="?", choices=("patterns",), help="Show fix patterns"),
        ),
    ),
    # â”€â”€ Batch 4: agents, model, memory, plan, restrict. â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # `restrict` needed the new `fixed_kwargs` framework feature -- add/
    # scan-only/sensitive all call the SAME run_add(path, rtype, reason) with
    # a different hardcoded RestrictionType per subcommand, not something
    # derivable from parsed args alone. 8th drift fix this migration: run_add's
    # second param is `rtype`, not `restriction_type`.
    Command(
        "agents",
        "Inspect and manage agents",
        "patchi.cli.commands.agents_cmd:run_list",  # no subcommand -> list, matches original
        subcommands=(
            Command(
                "list",
                "List agent groups or agents in a group",
                "patchi.cli.commands.agents_cmd:run_list",
                args=(Arg("group_name", nargs="?"),),
            ),
            Command(
                "status",
                "Show currently active agents",
                "patchi.cli.commands.agents_cmd:run_status",
            ),
            Command(
                "reset",
                "Reset circuit breaker for an agent (LIMIT-04)",
                "patchi.cli.commands.agents_cmd:run_reset",
                args=(Arg("agent_name", nargs="?", help="Agent name to reset (omit for all)"),),
            ),
        ),
    ),
    Command(
        "model",
        "Manage local Ollama model",
        "patchi.cli.commands.model_cmd:run_status",  # no subcommand -> status, matches original
        subcommands=(
            Command(
                "set",
                "Set local model",
                "patchi.cli.commands.model_cmd:run_set",
                args=(Arg("model_name"),),
            ),
            Command(
                "list", "List available local models", "patchi.cli.commands.model_cmd:run_list"
            ),
            Command(
                "status", "Show model connection health", "patchi.cli.commands.model_cmd:run_status"
            ),
        ),
    ),
    Command(
        "memory",
        "View and manage Patchi's memory",
        "patchi.cli.commands.memory_cmd:run_show_all",  # no subcommand -> show_all, matches original
        subcommands=(
            Command(
                "show",
                "Show memory for a category",
                "patchi.cli.commands.memory_cmd:run_show",
                args=(Arg("category_str"),),
            ),
            Command(
                "delete",
                "Clear memory (category or all)",
                "patchi.cli.commands.memory_cmd:run_delete",
                args=(Arg("category_str", help="Category name or 'all'"),),
            ),
        ),
    ),
    Command(
        "plan",
        "Plan changes before making them",
        "patchi.cli.commands.plan_cmd:run",
        args=(
            Arg("area", nargs="?", help="Targeted area â€” plain language or path"),
            Arg(
                "--format",
                dest="include_format",
                action="store_true",
                help="Include formatting-only changes",
            ),
            Arg(
                "--missing-import",
                dest="include_missing_import",
                action="store_true",
                help="Include missing-import fixes",
            ),
            Arg("--json", dest="json_output", action="store_true"),
            Arg("--html", dest="html", default=None, help="Write a self-contained HTML report"),
        ),
    ),
    Command(
        "restrict",
        "Manage file restrictions",
        "patchi.cli.commands.restrict_cmd:run_list",  # no subcommand -> list, matches original
        subcommands=(
            Command(
                "add",
                "Add path as no-touch zone",
                "patchi.cli.commands.restrict_cmd:run_add",
                args=(Arg("path"), Arg("--reason", dest="reason", default="")),
                fixed_kwargs={"rtype": _RestrictionType.NO_TOUCH},
            ),
            Command(
                "scan-only",
                "Mark path as scan-only",
                "patchi.cli.commands.restrict_cmd:run_add",
                args=(Arg("path"), Arg("--reason", dest="reason", default="")),
                fixed_kwargs={"rtype": _RestrictionType.SCAN_ONLY},
            ),
            Command(
                "sensitive",
                "Mark path as sensitive",
                "patchi.cli.commands.restrict_cmd:run_add",
                args=(Arg("path"), Arg("--reason", dest="reason", default="")),
                fixed_kwargs={"rtype": _RestrictionType.SENSITIVE},
            ),
            Command("list", "List all restrictions", "patchi.cli.commands.restrict_cmd:run_list"),
            Command(
                "remove",
                "Remove a restriction",
                "patchi.cli.commands.restrict_cmd:run_remove",
                args=(Arg("path"),),
            ),
            Command(
                "disable",
                "Temporarily disable a restriction",
                "patchi.cli.commands.restrict_cmd:run_disable",
                args=(Arg("path"),),
            ),
            Command(
                "enable",
                "Re-enable a restriction",
                "patchi.cli.commands.restrict_cmd:run_enable",
                args=(Arg("path"),),
            ),
        ),
    ),
    # â”€â”€ Batch 5: Legacy ladder commands migrated last â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    Command(
        "check",
        "Preflight install/build/format — side agents before app run (also --fix domain: type/deps)",
        "patchi.cli.commands.check_cmd:run",
        args=(
            Arg("--fix", action="store_true", help="Auto-fix domain issues (type/deps/build)"),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
        ),
    ),
    Command(
        "link",
        "Link frontend + backend for separate repos (auto discovery + tag confirm)",
        "patchi.cli.commands.link_cmd:run",
        args=(
            Arg("action", nargs="?", choices=("status", "add", "confirm", "remove", "list"), help="status|add|confirm|remove"),
            Arg("--frontend", dest="frontend", default=None, help="Frontend repo path (for add)"),
            Arg("--backend", dest="backend", default=None, help="Backend repo path (for add)"),
            Arg("--frontend-url", dest="frontend_url", default=None, help="Frontend URL"),
            Arg("--backend-url", dest="backend_url", default=None, help="Backend URL"),
        ),
    ),
    Command(
        "report",
        "Generate a structured analysis report",
        "patchi.cli.commands.report_cmd:run",
        args=(
            Arg("report_cmd", nargs="?", choices=("export", "weekly"), help="export | weekly"),
            Arg("--format", dest="fmt", default="markdown", help="Output format (markdown | json)"),
        ),
    ),
    Command(
        "assure",
        "Assurance campaigns â€” prove properties, record evidence",
        "patchi.cli.commands.assure_cmd:run",
        args=(
            Arg("--json", dest="json_output", action="store_true", help="JSON output"),
            Arg("--reset", action="store_true", help="Discard all recorded claims/evidence"),
            Arg(
                "--run-attackers",
                dest="run_attackers",
                action="store_true",
                help="Run adversarial attacker hypotheses against the assurance graph",
            ),
            Arg(
                "--run-campaigns",
                dest="run_campaigns",
                action="store_true",
                help="Run state transition + data flow abuse campaigns",
            ),
            Arg(
                "--run-all",
                dest="run_all",
                action="store_true",
                help="Run attackers + campaigns + fuzz in sequence",
            ),
            Arg(
                "--chain-report",
                dest="chain_report",
                action="store_true",
                help="Show chain-sourced assurance claims with remediation",
            ),
        ),
    ),
    Command(
        "audit",
        "Full project audit + Plan-vs-Built drift",
        "patchi.cli.commands.audit_cmd:run",
        args=(
            Arg("--quick", action="store_true", help="Quick audit (skip deep scan)"),
            Arg("--json", dest="json_output", action="store_true", help="JSON output"),
            Arg("--plan", action="store_true", help="Snapshot current state as the agreed Plan"),
            Arg(
                "--plan-file",
                dest="plan_file",
                type=str,
                help="Audit built state against a plan file",
            ),
            Arg("--intent", type=str, help="Intent description (with --plan)"),
            Arg("--no-scan", dest="no_scan", action="store_true", help="Skip scan during audit"),
            Arg("--html", type=str, help="Write self-contained HTML report"),
        ),
    ),
    Command(
        "settings",
        "View or modify configuration",
        "patchi.cli.commands.settings_cmd:run_show",  # no subcommand -> show
        subcommands=(
            Command(
                "show", "Show current configuration", "patchi.cli.commands.settings_cmd:run_show"
            ),
            Command(
                "set",
                "Set a configuration value",
                "patchi.cli.commands.settings_cmd:run_set",
                args=(Arg("key"), Arg("value")),
            ),
            Command(
                "mode",
                "View or set operating mode (confirm/auto/autopilot)",
                "patchi.cli.commands.mode_cmd:run",
                args=(
                    Arg("mode_str", nargs="?", choices=("confirm", "auto", "autopilot"), help="New mode"),
                ),
            ),
        ),
    ),
    Command(
        "access",
        "Manage dev access tokens",
        "patchi.cli.commands.access_cmd:run_list",  # no subcommand -> list
        subcommands=(
            Command(
                "add",
                "Add a token",
                "patchi.cli.commands.access_cmd:run_add",
                args=(Arg("name"), Arg("--env-var", dest="env_var")),
            ),
            Command("list", "List all tokens", "patchi.cli.commands.access_cmd:run_list"),
            Command(
                "remove",
                "Remove a token",
                "patchi.cli.commands.access_cmd:run_remove",
                args=(Arg("name"),),
            ),
        ),
    ),
    Command(
        "web",
        "Launch the unified Patchi web UI (dashboard, council, red team, tests, hosted)",
        "patchi.cli.commands.web_cmd:run",
        args=(
            Arg("--host", help="Bind address", default="127.0.0.1"),
            Arg("--port", help="Port to listen on", default=1612, type=int),
            Arg(
                "--open",
                help="Open the browser after start",
                action="store_true",
                dest="open_browser",
            ),
            Arg(
                "--project",
                help="Path to the project to view (default: nearest .patchi up from cwd)",
                default=None,
            ),
        ),
    ),
    Command(
        "ai",
        "AI configuration and status",
        "patchi.cli.commands.ai_cmd:run_status",  # no subcommand -> status
        subcommands=(
            Command(
                "status",
                "Show all configured AI keys and status",
                "patchi.cli.commands.ai_cmd:run_status",
            ),
            Command(
                "test",
                "Send test prompt to active AI provider",
                "patchi.cli.commands.ai_cmd:run_test",
            ),
            Command("add", "Add a new API key interactively", "patchi.cli.commands.ai_cmd:run_add"),
            Command(
                "remove",
                "Remove an API key by name",
                "patchi.cli.commands.ai_cmd:run_remove",
                args=(Arg("name"),),
            ),
            Command(
                "profiles",
                "List configured AI provider profiles (E-12 S-2)",
                "patchi.cli.commands.ai_cmd:run_profiles",
            ),
        ),
    ),
    Command(
        "charter",
        "Manage project charter and rules",
        "patchi.cli.commands.charter_cmd:run_show",
        namespace_handler=True,
        subcommands=(
            Command("show", "Show current charter", "patchi.cli.commands.charter_cmd:run_show", namespace_handler=True),
            Command(
                "set",
                "Set charter from a file",
                "patchi.cli.commands.charter_cmd:run_set",
                namespace_handler=True,
                args=(
                    Arg("text"),
                    Arg(
                        "--ai",
                        dest="use_ai",
                        action="store_true",
                        help="Use AI to generate charter",
                    ),
                ),
            ),
            Command(
                "check",
                "Check code against charter",
                "patchi.cli.commands.charter_cmd:run_check",
                namespace_handler=True,
                args=(Arg("--rebuild", action="store_true", help="Rebuild charter index"),),
            ),
            Command(
                "hooks",
                "Manage git hooks",
                "patchi.cli.commands.charter_cmd:run_hooks",
                namespace_handler=True,
                args=(Arg("--install", action="store_true", help="Install git hooks"),),
            ),
        ),
    ),
    Command(
        "chains",
        "Show exploit chains and intent gaps from last scan",
        "patchi.cli.commands.chains_cmd:run",
        args=(
            Arg("--min-score", type=float, default=0, help="Filter chains by minimum score"),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
            Arg("--fix", action="store_true", help="Apply auto-fixable remediations via RiskGate"),
            Arg("--analyze", action="store_true", help="Analyze findings from memory (like old p chain)"),
            Arg("--min-severity", dest="min_severity", default="medium", help="Minimum severity for --analyze mode"),
        ),
    ),
    Command(
        "findings",
        "View and manage security findings",
        "patchi.cli.commands.findings_cmd:run",
        namespace_handler=True,
        args=(
            Arg("--summary", action="store_true", help="Per-agent before/after counts"),
            Arg("--save-baseline", action="store_true", help="Snapshot current counts as baseline"),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
        ),
    ),
    Command(
        "rules",
        "View and validate security rule packs",
        "patchi.cli.commands.rules_cmd:run",
        namespace_handler=True,
        args=(
            Arg("--validate", action="store_true", help="Validate all rule packs"),
            Arg(
                "--which", type=str, default=None, help="Map a finding control id to its rule pack"
            ),
        ),
    ),
    # â”€â”€ Batch 6: the last commands off the legacy ladder. â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # notify / hosted / test / security / cross-repo use the self-routing
    # Namespace-handler shape (framework namespace_handler=True): the handler
    # receives the whole parsed Namespace and routes on the subcommand dests
    # itself, so the subcommand tree below is parsing/help sugar only. `help`
    # is a plain kwarg command backed by help_cmd.py. With these six, main.py
    # has zero elif-dispatch left â€” the registry IS the router.
    Command(
        "notify",
        "Configure notifications",
        "patchi.cli.commands.notify_cmd:run_notify",
        namespace_handler=True,
        subcommands=(
            Command("list", "List channels"),
            Command(
                "add",
                "Add a notification channel",
                args=(
                    Arg(
                        "channel_type", choices=("email", "slack", "discord", "webhook", "telegram")
                    ),
                ),
            ),
            Command("remove", "Remove a channel", args=(Arg("channel_name"),)),
            Command(
                "test",
                "Send test alert to all or one channel",
                args=(Arg("channel_name", nargs="?"),),
            ),
            Command("ack", "Acknowledge a CRITICAL/HIGH alert", args=(Arg("alert_id"),)),
            Command("flush", "Force-flush the digest queue now"),
            Command("pending", "Show unacknowledged escalation alerts"),
        ),
    ),
    Command(
        "hosted",
        "Hosted mode â€” monitor live apps(experimental)",
        "patchi.cli.commands.hosted_cmd:run",
        namespace_handler=True,
        subcommands=(
            Command("init", "Set up hosted mode (interactive)"),
            Command("worker", "Start the background worker"),
            Command(
                "daemon",
                "Start worker with auto-restart + health checks",
                args=(
                    Arg(
                        "--guard",
                        action="store_true",
                        help="Also run anomaly detection in daemon mode",
                    ),
                ),
            ),
            Command("stop", "Stop a running daemon"),
            Command("guard", "Start live guard monitoring"),
            Command(
                "status",
                "Show connection status",
                args=(Arg("--json", action="store_true", help="Output as JSON"),),
            ),
            Command("logs", "Stream hosted logs in real time"),
            Command(
                "token",
                "Manage admin tokens",
                subcommands=(
                    Command("add", "Generate new admin token"),
                    Command("list", "List active tokens"),
                    Command("revoke", "Revoke a token", args=(Arg("id"),)),
                ),
            ),
            Command("block", "Block an IP address", args=(Arg("ip"),)),
            Command("unblock", "Unblock an IP address", args=(Arg("ip"),)),
            Command("disconnect", "Disconnect from hosted mode"),
        ),
    ),
    Command(
        "test",
        "Run tests, generate suites, view history",
        "patchi.cli.commands.test_cmd:run_test",
        namespace_handler=True,
        args=(
            Arg(
                "type",
                nargs="?",
                help="Test type, agent name, or generate/report/config subcommand",
            ),
            Arg("area", nargs="?", help="Test scope area, or config action for 'config'"),
            Arg("config_key", nargs="?", help="Config key to set"),
            Arg("config_value", nargs="?", help="New value for config key"),
            Arg("--last", type=int, default=20, help="Number of recent runs to show"),
            Arg(
                "--attack",
                action="store_true",
                help="Run Metasploit auxiliary/scanner probes against localhost (requires msfrpcd)",
            ),
        ),
    ),
    # `p security` merged into `p scan` — use `p scan --deep` or `p scan <area>`
    Command(
        "command",
        "List all commands with tags and arguments",
        "patchi.cli.commands.help_cmd:run",
        namespace_handler=True,
        args=(
            Arg("--all", action="store_true", help="Show all commands with arguments and subcommands"),
            Arg("--json", action="store_true", help="Output as JSON"),
            Arg("--write-md", action="store_true", help="Write command_list.md"),
        ),
    ),
    Command(
        "help",
        "Show command help",
        "patchi.cli.commands.help_cmd:run",
        namespace_handler=True,
        args=(Arg("group", nargs="?", help="Command group"),),
    ),
        # `p smart` merged into `p chat` — use `p chat --stream` for the same functionality
    Command(
        "cross-repo",
        "Cross-repository dependency intelligence",
        "patchi.cli.commands.cross_repo_cmd:run",
        namespace_handler=True,
        args=(
            Arg(
                "action",
                nargs="?",
                default="scan",
                choices=("scan", "health", "fix"),
                help="Action: scan (default), health, fix",
            ),
            Arg("--target", type=str, help="Target project path for fix action"),
        ),
    ),
    Command(
        "goal",
        "Autonomous mode: loop the agent pipeline until the health score hits the target",
        "patchi.cli.commands.goal_cmd:run",
        args=(
            Arg("--max-loops", type=int, default=5, help="Maximum pipeline iterations (default 5)"),
            Arg(
                "--target", type=int, default=100, help="Health score target to reach (default 100)"
            ),
            Arg(
                "--dry-run",
                action="store_true",
                help="Produce + verify patches but never apply them",
            ),
        ),
    ),
    Command(
        "cleanup",
        "Clean stale .patchi/ artifacts (JUnit, caches, logs, DBs)",
        "patchi.cli.commands.cleanup_cmd:cleanup",
        args=(
            Arg("--apply", action="store_true", help="Actually delete files (default is dry-run)"),
            Arg("--all", action="store_true", help="Also remove evidence/screenshots"),
            Arg("--older-than", dest="older_than", default=None, help="Only remove files older than this (e.g. 7d, 24h, 30m)"),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON for CI integration"),
        ),
    ),
    Command(
        "agent-stats",
        "Agent profiling stats and learning state",
        "patchi.cli.commands.agent_stats_cmd:run",
        args=(
            Arg("agent_name", nargs="?", default=None, help="Show details for a specific agent"),
            Arg("--profile", dest="show_profile", action="store_true", help="Show only profiler stats"),
            Arg("--learning", dest="show_learning", action="store_true", help="Show only learning state"),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
        ),
    ),
    Command(
        "vr",
        "Visual regression baseline management",
        "patchi.cli.commands.vr_cmd:run",
        args=(
            Arg(
                "action",
                nargs="?",
                default="list",
                choices=("capture", "baseline", "compare", "diff", "reset", "list", "ls"),
                help="baseline=capture, compare=diff, reset=delete, list=show",
            ),
            Arg("--json", dest="json_output", action="store_true", help="Output as JSON"),
        ),
    ),
    Command(
        "plugins",
        "Manage analyzer plugins (list, run, info)",
        "patchi.cli.commands.plugins_cmd:cmd_plugins",
        namespace_handler=True,
        args=(
            Arg("args", nargs="*", help="Plugin subcommand and arguments"),
        ),
    ),
    Command(
        "commands",
        "Show command families and subcommands",
        "patchi.cli.commands.commands_cmd:run",
        args=(
            Arg("--flat", action="store_true", help="Alphabetical list of all commands"),
            Arg("--search", dest="search", type=str, help="Search commands by name/description"),
        ),
    ),
]
