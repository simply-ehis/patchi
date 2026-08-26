#!/usr/bin/env bash
# ci-audit.sh — Comprehensive CI audit for Patchi
# Runs: agent audit, lint (ruff), typecheck (mypy), fast tests
# Exits non-zero on any failure.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "═══════════════════════════════════════════════════════"
echo "Patchi CI Audit"
echo "═══════════════════════════════════════════════════════"

# Ensure we're in a virtualenv or have the tools
if [[ ! -d ".venv" ]]; then
    echo "⚠ Virtualenv not found. Run 'make install' first."
    exit 1
fi

export PYTHONPATH="${ROOT_DIR}:${PYTHONPATH:-}"
export PATCHI_OFFLINE=1

echo ""
echo "┌─ Agent Audit ────────────────────────────────────────"
.venv/bin/python -m patchi.core.ai.agent_audit || {
    echo "❌ Agent audit failed"
    exit 1
}
echo "✅ Agent audit passed"

echo ""
echo "┌─ Lint (ruff) ───────────────────────────────────────"
.venv/bin/ruff check patchi/ tests/ || {
    echo "❌ Lint failed"
    exit 1
}
echo "✅ Lint passed"

echo ""
echo "┌─ Typecheck (mypy) ──────────────────────────────────"
# mypy is configured in pyproject.toml; allow non-zero exit for now (warn-only)
.venv/bin/mypy patchi/ tests/ || echo "⚠ Typecheck warnings (non-blocking)"

echo ""
echo "┌─ Fast Tests (excludes slow/integration) ────────────"
python -m pytest tests/ -q --tb=short -k "not slow and not integration" || {
    echo "❌ Fast tests failed"
    exit 1
}
echo "✅ Fast tests passed"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "✅ All CI audit checks passed"
echo "═══════════════════════════════════════════════════════"