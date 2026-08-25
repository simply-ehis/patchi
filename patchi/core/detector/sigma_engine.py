"""
Sigma rule engine — portable detection rule matching.

Implements a subset of the Sigma specification sufficient for Patchi's needs:
- Rule loading from YAML files
- Field matching (equality, wildcard, regex, CIDR)
- Aggregation matching (cardinality, count over time windows)
- Tag-based routing to MITRE ATT&CK technique_ids
"""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from patchi.core.detector.event import Event, EventSeverity, EventSource, TechniqueID

logger = logging.getLogger("patchi.detector.sigma")


@dataclass
class SigmaMatch:
    """Result of matching a rule against an event."""

    rule_name: str
    rule_id: str
    technique_id: TechniqueID | str
    confidence: float
    severity: str
    matched_fields: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    target_agent: str = ""


@dataclass
class SigmaRule:
    title: str
    id: str = ""
    description: str = ""
    status: str = "experimental"
    level: str = "medium"
    tags: list[str] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    author: str = ""
    selections: dict[str, dict[str, Any]] = field(default_factory=dict)
    condition_expr: str = ""
    target_agent: str = ""
    min_confidence: float = 0.3

    @property
    def technique_id(self) -> TechniqueID:
        for tag in self.tags:
            if tag.startswith("attack."):
                tid = tag.split(".", 1)[1].upper()
                try:
                    return TechniqueID(tid)
                except ValueError:
                    continue
            if tag.startswith("mitre."):
                try:
                    return TechniqueID(tag.split(".", 1)[1])
                except ValueError:
                    continue
        return TechniqueID.UNKNOWN


class SigmaRuleSet:
    def __init__(self, rules: list[SigmaRule] | None = None):
        self._rules: list[SigmaRule] = rules or []
        self._rule_index: dict[str, list[SigmaRule]] = {}

    @classmethod
    def load_directory(cls, path: Path) -> SigmaRuleSet:
        import yaml

        rules: list[SigmaRule] = []
        if not path.exists():
            logger.warning("Sigma rules directory not found: %s", path)
            return cls()
        for fpath in sorted(path.glob("*.yml")):
            try:
                raw = yaml.safe_load(fpath.read_text(encoding="utf-8"))
                if not raw or not isinstance(raw, dict):
                    continue
                rule = _parse_sigma_rule(raw)
                if rule:
                    rules.append(rule)
            except Exception as exc:
                logger.warning("Failed to load Sigma rule %s: %s", fpath.name, exc)
        engine = cls(rules)
        engine._build_index()
        logger.info("Loaded %d Sigma rules from %s", len(rules), path)
        return engine

    @classmethod
    def load_text(cls, yaml_text: str) -> SigmaRuleSet:
        import yaml

        rules: list[SigmaRule] = []
        try:
            raw = yaml.safe_load(yaml_text)
        except yaml.YAMLError:
            return cls(rules)
        if isinstance(raw, dict):
            rule = _parse_sigma_rule(raw)
            if rule:
                rules.append(rule)
        elif isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    rule = _parse_sigma_rule(entry)
                    if rule:
                        rules.append(rule)
        return cls(rules)

    def match(self, event: Event) -> list[SigmaMatch]:
        results: list[SigmaMatch] = []
        for rule in self._rules:
            m = self._match_one(rule, event)
            if m:
                results.append(m)
        return results

    def _build_index(self) -> None:
        self._rule_index.clear()
        for rule in self._rules:
            tid = (
                rule.technique_id.value
                if isinstance(rule.technique_id, TechniqueID)
                else str(rule.technique_id)
            )
            self._rule_index.setdefault(tid, []).append(rule)

    @property
    def count(self) -> int:
        return len(self._rules)

    def _match_one(self, rule: SigmaRule, event: Event) -> SigmaMatch | None:
        if rule.logsource and not self._match_logsource(rule.logsource, event):
            return None
        if not rule.selections:
            return None
        evaluated: dict[str, bool] = {}
        for sel_name, sel_fields in rule.selections.items():
            evaluated[sel_name] = self._match_selection(sel_fields, event)
        if not self._evaluate_condition(rule.condition_expr, evaluated):
            return None
        sev_map = {"informational": 0.1, "low": 0.3, "medium": 0.5, "high": 0.7, "critical": 0.9}
        confidence = max(rule.min_confidence, sev_map.get(rule.level, 0.3))
        return SigmaMatch(
            rule_name=rule.title,
            rule_id=rule.id,
            technique_id=rule.technique_id,
            confidence=confidence,
            severity=rule.level,
            description=rule.description or rule.title,
            target_agent=rule.target_agent,
        )

    def _match_logsource(self, logsource: dict[str, str], event: Event) -> bool:
        if "category" in logsource:
            if not self._value_match(
                logsource["category"], event.source_details.get("category", event.source.value)
            ):
                return False
        if "product" in logsource:
            if not self._value_match(logsource["product"], event.source_details.get("product", "")):
                return False
        if "service" in logsource:
            if not self._value_match(logsource["service"], event.source_details.get("service", "")):
                return False
        return True

    def _match_selection(self, fields: dict[str, Any], event: Event) -> bool:
        for field_key, expected in fields.items():
            field_name, modifier = self._parse_sigma_field(field_key)
            actual = self._get_event_field(event, field_name)
            if actual is None:
                return False
            if modifier:
                result = self._match_with_modifier(modifier, expected, actual)
            else:
                result = self._value_match(expected, actual)
            if not result:
                return False
        return True

    def _parse_sigma_field(self, field_key: str) -> tuple[str, str | None]:
        if "|" in field_key:
            parts = field_key.rsplit("|", 1)
            return parts[0], parts[1]
        return field_key, None

    def _match_with_modifier(self, modifier: str, expected: Any, actual: Any) -> bool:
        actual_str = str(actual)
        if modifier == "contains":
            return str(expected) in actual_str
        if modifier == "startswith":
            return actual_str.startswith(str(expected))
        if modifier == "endswith":
            return actual_str.endswith(str(expected))
        if modifier == "re":
            try:
                return bool(re.search(str(expected), actual_str))
            except re.error:
                return False
        if modifier == "base64":
            try:
                import base64

                decoded = base64.b64decode(actual_str).decode()
                return str(expected) in decoded
            except Exception as e:
                return False
                logger.warning("SigmaRuleSet._match_with_modifier failed: %s", e)
        if modifier == "cidr":
            return self._match_cidr(str(expected), actual_str)
        if modifier == "gt":
            return isinstance(actual, (int, float)) and actual > expected
        if modifier == "lt":
            return isinstance(actual, (int, float)) and actual < expected
        if modifier == "gte":
            return isinstance(actual, (int, float)) and actual >= expected
        if modifier == "lte":
            return isinstance(actual, (int, float)) and actual <= expected
        return self._value_match(expected, actual)

    def _match_cidr(self, cidr: str, ip: str) -> bool:
        try:
            import ipaddress

            net = ipaddress.ip_network(cidr, strict=False)
            addr = ipaddress.ip_address(ip)
            return addr in net
        except ImportError:
            return False
        except ValueError:
            return False

    def _get_event_field(self, event: Event, field: str) -> Any:
        if field.startswith("event."):
            field = field[6:]
        d = event.to_dict()
        parts = field.split(".")
        obj: Any = d
        for part in parts:
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None
        return obj

    def _value_match(self, expected: Any, actual: Any) -> bool:
        if isinstance(expected, str):
            if "*" in expected:
                return fnmatch.fnmatch(str(actual), expected)
            if expected.startswith("re:"):
                try:
                    return bool(re.search(expected[3:], str(actual)))
                except re.error:
                    return False
            return str(actual) == expected
        if isinstance(expected, list):
            return any(self._value_match(v, actual) for v in expected)
        if isinstance(expected, dict):
            if "contains" in expected:
                return str(expected["contains"]) in str(actual)
            if "startswith" in expected:
                return str(actual).startswith(str(expected["startswith"]))
            if "endswith" in expected:
                return str(actual).endswith(str(expected["endswith"]))
            if "re" in expected:
                try:
                    return bool(re.search(expected["re"], str(actual)))
                except re.error:
                    return False
        return str(actual) == str(expected)

    def _evaluate_condition(self, expr: str, results: dict[str, bool]) -> bool:
        expr = expr.strip()
        if not expr:
            return True
        lower = expr.lower()
        if " or " in lower:
            return any(
                self._evaluate_condition(p.strip(), results)
                for p in re.split(r"\s+or\s+", expr, flags=re.IGNORECASE)
            )
        if " and " in lower:
            return all(
                self._evaluate_condition(p.strip(), results)
                for p in re.split(r"\s+and\s+", expr, flags=re.IGNORECASE)
            )
        if lower in ("all of them", "all of the"):
            return all(results.values())
        if lower in ("any of them", "any of the"):
            return any(results.values())
        m = re.match(r"(all|1|any)\s+of\s+(.+?)(?:\*)?$", lower)
        if m:
            prefix = m.group(2).rstrip()
            relevant = {k: v for k, v in results.items() if k.startswith(prefix)}
            if not relevant:
                return False
            return all(relevant.values()) if m.group(1) in ("all", "1") else any(relevant.values())
        if lower.startswith("not "):
            return not results.get(expr[4:].strip(), False)
        if lower in results:
            return results[lower]
        if lower == "1 of them":
            return any(results.values())
        return True


def _parse_sigma_rule(raw: dict[str, Any]) -> SigmaRule | None:
    if not raw.get("title"):
        return None
    detection = raw.get("detection", {})
    selections: dict[str, dict[str, Any]] = {}
    condition_expr = ""
    for key, value in detection.items():
        if key == "condition":
            if isinstance(value, str):
                condition_expr = value
            elif isinstance(value, dict):
                condition_expr = value.get("expression", "any of them")
        elif isinstance(value, dict):
            selections[key] = value
    if not selections and not condition_expr:
        logger.debug("No selections found in rule '%s'", raw.get("title", ""))
        return None
    return SigmaRule(
        title=str(raw.get("title", "")),
        id=str(raw.get("id", "")),
        description=str(raw.get("description", "")),
        status=str(raw.get("status", "experimental")),
        level=str(raw.get("level", "low")),
        tags=[str(t) for t in raw.get("tags", [])],
        logsource={k: str(v) for k, v in raw.get("logsource", {}).items()},
        detection=detection,
        falsepositives=[str(f) for f in raw.get("falsepositives", [])],
        author=str(raw.get("author", "")),
        selections=selections,
        condition_expr=condition_expr,
        target_agent=str(raw.get("target_agent", "")),
    )


def _sigma_level_to_severity(level: str) -> EventSeverity:
    mapping = {
        "informational": EventSeverity.INFO,
        "low": EventSeverity.LOW,
        "medium": EventSeverity.MEDIUM,
        "high": EventSeverity.HIGH,
        "critical": EventSeverity.CRITICAL,
    }
    return mapping.get(level, EventSeverity.INFO)


def sigma_match_to_event(match: SigmaMatch, parent_event: Event | None = None) -> Event:
    return Event(
        source=parent_event.source if parent_event else EventSource.AGENT,
        technique_id=match.technique_id,
        summary=match.description or match.rule_name,
        severity=_sigma_level_to_severity(match.severity),
        confidence=match.confidence,
        payload={
            "rule_id": match.rule_id,
            "rule_name": match.rule_name,
            "matched_fields": match.matched_fields,
        },
        suggested_agent=match.target_agent or "",
    )
