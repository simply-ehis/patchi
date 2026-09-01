# Contributing to Patchi

Thanks for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
git clone <repo-url>
cd Patchi_COMPLETE
pip install -e ".[dev]"

# With web UI support
pip install -e ".[web]"
```

**Requires Python 3.11+**

## Pre-commit Hook

```bash
p dev hook                # Install pre-commit hook
p dev hook --strict       # Install with strict mode (blocks on errors)
```

The hook runs `p dev check` on every commit:
1. Ruff lint check
2. Pytest (60+ stable tests)
3. Security scan (changed files)

## Running Tests

```bash
# Full gate (same as pre-commit hook)
p dev check

# Fast mode (8 core tests, ~18s)
p dev check --fast

# All tests directly
python -m pytest tests/ -q --timeout=30

# Specific test file
python -m pytest tests/test_contract.py -q
python -m pytest tests/test_web.py -q

# With coverage
python -m pytest tests/ --cov=patchi -q
```

## Code Style

- **PEP 8** with E501/E402/E741 ignored (enforced by ruff)
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
├── cli/
│   ├── main.py         # Root parser, lazy imports
│   ├── framework.py    # Command registration framework
│   ├── registry.py     # All 50 registered commands
│   └── commands/       # One file per command (48 files)
├── core/
│   ├── brain/          # AST scanning, import graph, languages
│   ├── agents/         # Agent framework + coordinator
│   ├── security/       # 54 security agents (lazy-loaded)
│   ├── ai/             # Unified AI client (14 providers)
│   ├── fix/            # Fix agents + risk gate
│   ├── testing/        # Playwright browser testing
│   ├── config.py       # Project configuration
│   ├── memory.py       # Atomic persistent memory
│   ├── queue.py        # File-locked task queue
│   └── health.py       # Health scoring (0-100)
├── web/
│   ├── app.py          # FastAPI application
│   ├── routes/         # Page routes (Jinja2 templates)
│   ├── api/            # REST API endpoints
│   ├── templates/      # Jinja2 HTML templates
│   └── static/         # CSS, JS, brain map assets
└── tests/              # 1,377 tests across 82 files
```

### Adding a New Security Agent

1. Create `patchi/core/security/my_agent.py`
2. Inherit from `BaseAgent`, implement `_run()`
3. Add `@register` decorator
4. Set `group = AgentGroup.SECURITY`
5. Add `_should_skip_file()` with the standard `_SKIP_DIRS` check
6. Add test in `tests/test_new_agents.py`
7. Register in `patchi/core/security/security_agents.py`

### Adding a New CLI Command

1. Create `patchi/cli/commands/my_cmd.py` with `def run(...)`
2. Add to `COMMANDS` list in `patchi/cli/registry.py`
3. Add test in `tests/`
4. Update `p doctor` stale list if replacing an old command

### Adding a New Fix Agent

1. Create in `patchi/core/fix/fix_agents.py` (or split if >200 lines)
2. Inherit from `BaseAgent`, implement `_run()`
3. Add `@register` decorator, set `group = AgentGroup.FIX`
4. Add corresponding `Skill` and prompts in `patchi/core/ai/prompts.py`
5. Add test in `tests/test_fix_agents.py`

### Adding a New Web Page

1. Create route in `patchi/web/routes/my_page.py`
2. Create template in `patchi/web/templates/my_page.html`
3. Register router in `patchi/web/app.py`
4. Add navigation link in `patchi/web/templates/base.html`

## Design Principles

- **Ponytail principle:** Lazy senior developer. Efficient, not careless.
- **YAGNI:** Does this need to be built at all?
- **Standard library first:** Use stdlib before adding dependencies.
- **Fewest files possible:** Deletion over addition.
- **Not lazy about:** Security, error handling, input validation.
- **1:1 CLI ↔ Web:** Every screen maps to a command.

## Pull Request Process

1. Create a feature branch from `main`
2. Make changes following the design philosophy
3. Add or update tests — every non-trivial change needs at least one test
4. Run `p dev check` — all 3 gates must pass
5. Submit the PR with a clear description of what changed and why

The CI pipeline runs:
- **test** — ruff + mypy + pytest (Python 3.11, 3.12 matrix)
- **dev-check** — Full `p dev check` gate
- **security-scan** — Security agents on fixtures
- **audit** — Full audit gate

## Reporting Issues

When reporting a bug, please include:
- Python version (`python --version`)
- Patchi version (`p --version`)
- OS and terminal
- Steps to reproduce
- Expected vs actual behavior
- Full error traceback

## License

By contributing, you agree that your contributions will be licensed under the Patchi Freemium license.

- **Free:** Personal use, education, teams <3 users
- **Enterprise:** Contact **idemudiaehis6@gmail.com**
