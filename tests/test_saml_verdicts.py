"""SamlSSOAgent verdict policy (Part 7)."""

import tempfile
from pathlib import Path

from patchi.core.agents.base import AgentInput, Severity
from patchi.core.security.saml_sso_agent import SamlSSOAgent


def _run(rel: str, content: str):
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return SamlSSOAgent().run(
        AgentInput(root=root, scope=[], brain={}, config={}, extra={})
    )


def _types(res):
    return [(f.type, f.severity) for f in res.findings]


def test_entity_id_not_xxe():
    res = _run("src/sp.py", 'from onelogin.saml2.auth import OneLogin_Saml2_Auth\nentity_id = "my-sp"\n')
    assert not [f for f in res.findings if "XXE" in f.type or "XXE" in f.title]


def test_resolve_entities_critical():
    res = _run(
        "src/sp.py",
        "from lxml import etree\nparser = etree.XMLParser(resolve_entities=True)\n",
    )
    assert ("SAML-01: XML External Entity (XXE) vulnerability", Severity.CRITICAL) in [
        (f.title, f.severity) for f in res.findings
    ] or any("XXE" in f.title and f.severity == Severity.CRITICAL for f in res.findings)


def test_clone_node_demoted():
    res = _run("src/sp.py", "from lxml import etree\nnode.cloneNode(True)\n")
    xsw = [f for f in res.findings if "Wrapping" in f.title]
    assert xsw and all(f.severity == Severity.MEDIUM for f in xsw)


def test_library_delegated_sig_validation_silent():
    # pysaml2 validates by default; no custom XML handling => no verdict.
    res = _run(
        "src/sp.py",
        "from onelogin.saml2.auth import OneLogin_Saml2_Auth\nauth = OneLogin_Saml2_Auth(req)\n",
    )
    assert not [f for f in res.findings if "SAML-04" in f.title]


def test_custom_xml_without_validation_flagged():
    res = _run(
        "src/sp.py",
        "from lxml import etree\nresp = etree.fromstring(SAMLResponse)\n",
    )
    assert any("SAML-04" in f.title for f in res.findings)


def test_sha1_without_digest_context_silent():
    res = _run("src/sp.py", "# sha1 was considered, see ticket-123\nx = 1\n")
    assert not [f for f in res.findings if "SAML-03" in f.title]


def test_digest_method_sha1_flagged():
    res = _run("src/sp.py", 'digest = "http://www.w3.org/2000/09/xmldsig#sha1"\n')
    assert any("SAML-03" in f.title and f.severity == Severity.HIGH for f in res.findings)
