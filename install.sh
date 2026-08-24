#!/usr/bin/env bash
# Patchi installer for Linux/macOS
set -e

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   PATCHI v0.6.0 — Install               ║"
echo "  ║   26 Security Agents · Hosted Guard      ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Check Python version
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        version=$("$cmd" -c "import sys; print(sys.version_info[:2] >= (3, 11))")
        if [ "$version" = "True" ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "  Error: Python 3.11+ required. Install from https://python.org"
    exit 1
fi

echo "  Using $($PYTHON --version)"

# Create virtual environment (WIRE-09)
VENV_DIR="$PWD/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "  Creating virtual environment..."
    $PYTHON -m venv "$VENV_DIR"
fi
PYTHON="$VENV_DIR/bin/python"

# Install in editable mode
$PYTHON -m pip install -e ".[dev]" --quiet

# Create alias
SHELL_RC=""
if [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

if [ -n "$SHELL_RC" ]; then
    if ! grep -q "alias p='patchi'" "$SHELL_RC" 2>/dev/null; then
        echo "alias p='patchi'  # added by patchi install" >> "$SHELL_RC"
        echo "  Alias added to $SHELL_RC — run 'source $SHELL_RC' or restart terminal"
    fi
fi

echo ""
echo "  Done! Run 'p init' in your project directory to start."
