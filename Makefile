.PHONY: venv install dev install-web clean lint typecheck test audit smoke pipeline manifest

SHELL := /bin/bash
PYTHON := python3

venv:
	$(PYTHON) -m venv .venv
	@echo "  -> Run 'source .venv/bin/activate' to activate"

install: venv
	.venv/bin/pip install -e ".[dev]" --quiet
	@echo "  -> Installed patchi in editable mode"
	@echo "  -> Run 'p init' in your project directory"

install-web: install
	.venv/bin/pip install -e ".[web]" --quiet
	@echo "  -> Web dependencies installed"

dev: install
	.venv/bin/pip install pytest ruff --quiet
	@echo "  -> Dev tooling ready"

clean:
	rm -rf .venv/ build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .ruff_cache/ __pycache__/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "  -> Cleaned"

lint:
	.venv/bin/ruff check patchi/ tests/

typecheck:
	@echo "  -> Run mypy or pyright when configured"

test:
	.venv/bin/python -m pytest tests/ -q --tb=short

audit:
	./scripts/ci-audit.sh

smoke:
	PATCHI_OFFLINE=1 .venv/bin/python tools/smoke_sweep.py

pipeline:
	PATCHI_OFFLINE=1 .venv/bin/python tools/smoke_sweep.py --pipeline

manifest:
	PATCHI_OFFLINE=1 .venv/bin/python tools/smoke_sweep.py --check-manifest

manifest-update:
	PATCHI_OFFLINE=1 .venv/bin/python tools/smoke_sweep.py --update-manifest
