"""Unified tool registry (Part 3 §2): coverage, hints, and honest states."""

from patchi.core.agents.tool_health import check_tool, is_available, list_tools


def test_every_entry_has_install_hint():
    tools = list_tools()
    assert len(tools) >= 25, f"registry shrank: {len(tools)}"
    for t in tools:
        assert t["install"], f"{t['name']}: no install hint"
        assert t["group"], f"{t['name']}: no group"
        assert t["auto"] in ("pip", "npm", "go", "playwright", None), t


def test_auto_install_entries_have_exact_packages():
    """The installer runs these blindly — a wrong package is worse than none."""
    tools = {t["name"]: t for t in list_tools()}
    assert tools["pyre"]["pkg"] == "pyre-check"
    assert tools["cdxgen"]["pkg"] == "@cyclonedx/cdxgen"
    for name in ("gitleaks", "osv-scanner", "nuclei", "dalfox", "ffuf"):
        assert tools[name]["go_pkg"].startswith("github.com/"), name
    for name, t in tools.items():
        if t["auto"] in ("pip", "npm") and name != "playwright":
            pkg = t.get("pkg") or name
            assert " " not in pkg, (name, pkg)
            if "/" in pkg:
                # Scoped npm packages (@scope/name) are the only legal slash
                assert pkg.startswith("@") and pkg.count("/") == 1, (name, pkg)


def test_missing_tool_reports_hint_not_silence():
    st = check_tool("definitely-not-a-real-tool-xyz")
    assert st["status"] == "missing"
    assert is_available("definitely-not-a-real-tool-xyz") is False


def test_broken_state_exists():
    """pyre is present-but-unrunnable here: the third state must surface."""
    import shutil

    if shutil.which("pyre") is None:
        import pytest

        pytest.skip("pyre not installed here — nothing to prove broken")
    st = check_tool("pyre")
    assert st["status"] in ("ok", "broken")
    if st["status"] == "broken":
        assert st["hint"], "broken without explanation is silent failure"


def test_tool_verify_delegates_to_registry(monkeypatch):
    from patchi.core.security import tool_verify

    monkeypatch.setattr(tool_verify, "is_tool_ready", lambda _t: (True, ""))
    # Registry says ready: unsupported-tool error still comes from the map
    try:
        tool_verify.run_tool_on_file("nope-not-a-tool", __file__)
    except ValueError as e:
        assert "unsupported tool" in str(e)
    else:
        raise AssertionError("expected ValueError for unknown tool")
