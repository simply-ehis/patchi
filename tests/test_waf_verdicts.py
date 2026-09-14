"""CloudWAFDetector verdict policy (Part 7)."""

import tempfile
from pathlib import Path

from patchi.core.agents.base import AgentInput, Severity
from patchi.core.security.cloud_waf_detector import CloudWAFDetector


def _run(files: dict[str, str]):
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return CloudWAFDetector().run(
        AgentInput(root=root, scope=[], brain={}, config={}, extra={})
    )


def _types(res):
    return [(f.type, f.severity) for f in res.findings]


def test_alb_without_waf_flagged_once():
    res = _run({"main.tf": 'resource "aws_alb" "x" {\n  name = "x"\n}\n'})
    assert ("missing_waf", Severity.HIGH) in _types(res)


def test_attached_waf_silences_missing():
    res = _run(
        {
            "alb.tf": 'resource "aws_alb" "x" {\n  name = "x"\n}\n',
            "waf.tf": 'resource "aws_wafv2_web_acl_association" "x" {\n  resource_arn = "y"\n}\n',
        }
    )
    assert not [f for f in res.findings if f.type == "missing_waf"]


def test_geo_restriction_present_is_info_not_missing():
    res = _run(
        {"waf.tf": 'resource "aws_wafv2_web_acl" "x" {\n  rule {\n    action {\n      block {}\n    }\n    statement {\n      geo_match_statement {\n        country_codes = ["US"]\n      }\n    }\n  }\n}\n'}
    )
    assert ("waf_geo_ip_restriction", Severity.INFO) in _types(res)
    assert not [f for f in res.findings if f.type == "no_ip_restriction_admin"]


def test_test_payloads_are_info():
    res = _run({"tests/test_waf.py": "payload = '?a=1&b=2&c=3'\n"})
    assert ("waf_bypass", Severity.INFO) in _types(res)
    assert ("waf_bypass", Severity.MEDIUM) not in _types(res)
    assert ("waf_bypass", Severity.LOW) not in _types(res)


def test_rate_limit_weakness_once_per_project():
    res = _run(
        {
            "a.tf": 'resource "aws_wafv2_web_acl" "x" {\n  name = "x"\n}\n',
            "b.tf": 'resource "aws_wafv2_web_acl" "y" {\n  name = "y"\n}\n',
        }
    )
    assert sum(1 for f in res.findings if "rate" in f.type) <= 1
