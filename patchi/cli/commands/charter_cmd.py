"""
CLI command for the project Charter — guard rails.

Subcommands:
    p charter show              Show current charter
    p charter set "<text>"      Set charter from natural language
    p charter check             Check code against charter
    p charter hooks --install   Manage git hooks
"""

from __future__ import annotations

import json
import sys


def _get_root():
    from patchi.core.config import require_project_root
    return require_project_root()


def run_show(args) -> None:
    """Show the current charter."""
    root = _get_root()
    from patchi.core.security.charter import load_charter

    charter = load_charter(root)
    json_output = getattr(args, "json_output", False)

    if not charter.text and not charter.rules:
        print("No charter set. Use: p charter set \"<rules>\"")
        return

    if json_output:
        print(json.dumps(charter.to_dict(), indent=2))
    else:
        print("=== Project Charter ===")
        if charter.text:
            print(f"\n{charter.text}\n")
        print(f"Rules ({len(charter.rules)}):")
        for r in charter.rules:
            status = "✓" if r.enabled else "✗"
            print(f"  {status} [{r.type.value:10s}] {r.id}: {r.description}")


def run_set(args) -> None:
    """Set charter from natural language text."""
    text = getattr(args, "text", None)
    if not text:
        print("Usage: p charter set \"<natural language rules>\"", file=sys.stderr)
        sys.exit(1)

    root = _get_root()
    from patchi.core.security.charter import (
        Charter,
        parse_nl_to_rules,
        save_charter,
    )

    rules = parse_nl_to_rules(text)
    charter = Charter(text=text, rules=rules)
    path = save_charter(charter, root)
    print(f"Charter saved to {path}")
    print(f"Parsed {len(rules)} rule(s):")
    for r in rules:
        print(f"  [{r.type.value:10s}] {r.id}: {r.description}")


def run_check(args) -> None:
    """Check codebase against the charter."""
    root = _get_root()
    from patchi.core.security.charter import (
        check_all_violations,
        load_charter,
    )

    charter = load_charter(root)
    if not charter.rules:
        print("No charter set. Nothing to check.")
        return

    # Try to get import edges from the brain
    import_edges: list[tuple[str, str]] = []
    try:
        graph_path = root / ".patchi" / "memory" / "import_graph.json"
        if graph_path.exists():
            data = json.loads(graph_path.read_text(encoding="utf-8"))
            edges = data.get("edges", [])
            for e in edges:
                if isinstance(e, dict):
                    import_edges.append((e.get("source", ""), e.get("target", "")))
                elif isinstance(e, (list, tuple)) and len(e) >= 2:
                    import_edges.append((str(e[0]), str(e[1])))
    except Exception:
        pass

    violations = check_all_violations(charter, import_edges=import_edges)

    json_output = getattr(args, "json_output", False)
    if json_output:
        print(json.dumps([v.to_dict() for v in violations], indent=2))
    else:
        if not violations:
            print("✓ No charter violations found.")
        else:
            print(f"✗ {len(violations)} charter violation(s):")
            for v in violations:
                loc = f" in {v.file_path}" if v.file_path else ""
                print(f"  [{v.severity}] {v.rule_id}: {v.message}{loc}")
                if v.suggestion:
                    print(f"    → {v.suggestion}")

    sys.exit(1 if violations else 0)


def run_hooks(args) -> None:
    """Manage charter-related git hooks."""
    install = getattr(args, "install", False)

    if not install:
        print("Usage: p charter hooks --install")
        return

    root = _get_root()
    hooks_dir = root / ".git" / "hooks"
    if not hooks_dir.exists():
        print("Not a git repository. Run 'git init' first.", file=sys.stderr)
        sys.exit(1)

    hook_path = hooks_dir / "charter-check"
    hook_body = """#!/bin/sh
# Patchi Charter check hook — runs after pre-commit
# Checks staged files against the project charter

PATCHI_DIR="$(git rev-parse --show-toplevel)"

# Only check .py, .ts, .js, .go, .java, .rs files
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(py|ts|js|go|java|rs)$')

if [ -z "$STAGED" ]; then
    exit 0
fi

cd "$PATCHI_DIR" && python -m patchi.cli.main charter check 2>/dev/null
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo ""
    echo "⚠  Charter violations detected. Fix before committing."
    echo "   Run 'p charter check' for details."
    echo "   Bypass with: git commit --no-verify"
fi
exit 0
"""
    hook_path.write_text(hook_body, encoding="utf-8")
    # Make executable on Unix
    import stat
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Charter check hook installed at {hook_path}")
    print("It will run after pre-commit on every commit.")


# Backward compat entry point
def run(args) -> None:
    """Dispatch to the appropriate subcommand."""
    if hasattr(args, "action"):
        action = args.action
    elif isinstance(args, list) and args:
        action = args[0]
    else:
        action = "show"

    dispatch = {
        "show": run_show,
        "set": run_set,
        "check": run_check,
        "hooks": run_hooks,
    }

    handler = dispatch.get(action)
    if handler:
        handler(args)
    else:
        print(f"Unknown action: {action}. Use: show, set, check, hooks", file=sys.stderr)
        sys.exit(1)
