"""LLMSecurityAgent verdict policy (Part 7)."""

import tempfile
from pathlib import Path

from patchi.core.agents.base import AgentInput, Severity
from patchi.core.security.llm_security_agent import LLMSecurityAgent


def _run(rel: str, content: str):
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return LLMSecurityAgent().run(
        AgentInput(root=root, scope=[], brain={}, config={}, extra={})
    )


def _types(res):
    return [(f.type, f.severity) for f in res.findings]


def test_exec_llm_output_critical():
    res = _run("src/a.py", "out = llm.generate(p)\nexec(response[0])\n")
    assert ("insecure_llm_output", Severity.CRITICAL) in _types(res)


def test_bare_response_word_silent():
    res = _run("src/a.py", "response = get_status()\nprint(response)\n")
    assert not [f for f in res.findings if f.type == "insecure_llm_output"]


def test_fstring_prompt_medium_not_high():
    res = _run("src/a.py", 'system_prompt = f"You are helpful {mode}"\n')
    assert ("prompt_injection", Severity.MEDIUM) in _types(res)
    assert ("prompt_injection", Severity.HIGH) not in _types(res)


def test_hub_load_medium_pickle_high():
    res = _run(
        "src/a.py",
        'from transformers import AutoModel\nm = AutoModel.from_pretrained("bert-base")\n',
    )
    assert ("untrusted_model_source", Severity.MEDIUM) in _types(res)
    res = _run("src/a.py", 'import pickle\ndata = pickle.load(open("m.pt", "rb"))\n')
    assert ("unsafe_deserialization", Severity.HIGH) in _types(res)


def test_agency_with_gate_silent_without_gate_high():
    res = _run("src/a.py", 'agent.run("delete all")\n')
    assert ("excessive_agency", Severity.HIGH) in _types(res)
    assert not [f for f in res.findings if f.severity == Severity.CRITICAL]
    res = _run(
        "src/a.py",
        "if confirm(action):\n    agent.run(\"delete all\")\n",
    )
    assert not [f for f in res.findings if f.type == "excessive_agency"]


def test_shell_without_input_demoted():
    res = _run("src/a.js", "exec(cmd, {shell: true})\n")
    assert ("tool_shell_injection", Severity.MEDIUM) in _types(res)
    res = _run("src/a.js", "exec(user_input, {shell: true})\n")
    assert ("tool_shell_injection", Severity.HIGH) in _types(res)
