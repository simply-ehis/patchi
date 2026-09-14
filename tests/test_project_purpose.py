"""Manifest-first project classification (Part 7 §2 + acceptance)."""

import tempfile
from pathlib import Path

from patchi.core.brain.brain import _classify_by_dependencies, _manifest_dep_names
from patchi.core.brain.project_reader import read_project_insight


def _proj(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


def test_requirements_txt_deps_visible():
    root = _proj({"requirements.txt": "discord.py==2.3.2\naiohttp==3.9.0\n"})
    insight = read_project_insight(root)
    assert "discord.py" in insight.dependencies


def test_discord_bot_from_manifest_no_ai():
    root = _proj(
        {
            "requirements.txt": "discord.py==2.3.2\n",
            "bot.py": "import discord\nclient = discord.Client()\n",
        }
    )
    deps = _manifest_dep_names(root)
    cats = _classify_by_dependencies(deps)
    assert cats and cats[0] == "Discord bot"


def test_fastapi_sqlalchemy_shape():
    cats = _classify_by_dependencies({"fastapi", "sqlalchemy"})
    assert cats == ["web API", "data-driven"]


def test_thin_signals_stay_unclear():
    assert _classify_by_dependencies(set()) == []
    assert _classify_by_dependencies({"pytest"}) == []


def test_framework_names_feed_classification():
    # Extension packages resolve via FrameworkDetector (boundary-aware);
    # the classifier consumes exact names from either source.
    assert "web API" in _classify_by_dependencies({"flask"})
    assert _classify_by_dependencies({"deflasker-utils"}) == []
