# Contributing to Patchi

Thanks for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
git clone https://github.com/yourusername/patchi.git
cd patchi
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests (1,200+ passing)
python -m pytest tests/ -q -x --ignore=tests/test_security_agents.py --ignore=tests/test_security_agents_deep.py

# Quick smoke test
python -m pytest tests/ -q --ignore=tests/test_new_features.py

# Specific test file
python -m pytest tests/test_contract.py -q
python -m pytest tests/test_web.py -q

# With coverage
python -m pytest tests/ --cov=patchi -q
```

## Code Style

- **PEP 8** with 100 char line length (enforced by ruff)
- Type hints on all public functions
- Google-style docstrings on modules and public APIs
- 4-space indentation, no tabs
- Imports: stdlib → third-party → local

```bash
ruff check patchi/ tests/    # lint
ruff format patchi/ tests/   # format
```

## Architecture

```
patchi/
├── cli/commands/     ← One file per CLI command
├── core/agents/      ← 20 scanner agents + coordinators
├── core/brain/       ← Brain scan pipeline modules
├── core/fix/         ← 8 fix agents and risk gate
├── core/security/    ← 54 security agents (lazy-loaded)
├── core/hosted/      ← Hosted mode components
├── web/              ← Archived (preserved at .patchi/web_archive/)
└── tests/            ← 1,200+ tests across the suite
```

### Adding a New Scanner Agent

1. Create `patchi/core/agents/my_scanner.py`
2. Inherit from `BaseAgent`, implement `_run()`
3. Add `@register` decorator
4. Set `group = AgentGroup.SCANNER`
5. Add `_should_skip_file()` with the standard `_SKIP_DIRS` check
6. Add test in `tests/test_scanners.py`
7. Import in `patchi/core/agents/scanners.py`

### Adding a New CLI Command

1. Create `patchi/cli/commands/my_cmd.py` with `def run(...)` 
2. Add lazy loader in `patchi/cli/main.py`
3. Add subparser in `_build_parser()`
4. Add dispatch in `main()`
5. Add test in `tests/`

### Adding a New Fix Agent

1. Create in `patchi/core/fix/fix_agents.py` (or split if >200 lines)
2. Inherit from `BaseAgent`, implement `_run()`
3. Add `@register` decorator, set `group = AgentGroup.FIX`
4. Add corresponding `Skill` and prompts in `patchi/core/ai/prompts.py`
5. Add test in `tests/test_fix_agents.py`

## Design Principles

- **Ponytail principle:** Lazy senior developer. Efficient, not careless.
- **YAGNI:** Does this need to be built at all?
- **Standard library first:** Use stdlib before adding dependencies.
- **Fewest files possible:** Deletion over addition.
- **Not lazy about:** Security, error handling, input validation.

## Pull Request Process

1. Create a feature branch from `main`
2. Make changes following the design philosophy
3. Add or update tests — every non-trivial change needs at least one test
4. Run `python -m pytest tests/ -q` — all tests must pass
5. Run `ruff check patchi/ tests/` — no new warnings
6. Submit the PR with a clear description of what changed and why

## Reporting Issues

When reporting a bug, please include:
- Python version (`python --version`)
- Patchi version (`p --version`)
- OS and terminal
- Steps to reproduce
- Expected vs actual behavior
- Full error traceback

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
