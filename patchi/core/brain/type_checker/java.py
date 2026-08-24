"""Java type checker — uses tree-sitter."""

from __future__ import annotations

from typing import Any

from ..languages import Lang, get_parser
from .base import BaseTypeChecker, _node_text, make_finding


import logging
_log = logging.getLogger("patchi.brain.java")

class JavaTypeChecker(BaseTypeChecker):
    language = "java"

    def check(self, source: str, file_path: str) -> list[dict]:
        findings: list[dict] = []
        parser = get_parser(Lang.JAVA)
        if parser is None:
            return findings
        try:
            tree = parser.parse(source.encode("utf-8"))
            self._walk(tree.root_node, source, file_path, findings)
        except Exception as e:
            _log.warning("JavaTypeChecker.check failed: %s", e)
        return findings

    def _walk(self, node: Any, source: str, file_path: str, findings: list[dict]) -> None:
        ntype = node.type
        if ntype == "method_declaration":
            line = node.start_point[0] + 1
            name_node = self._child_by_type(node, "identifier")
            name = _node_text(source, name_node) if name_node else ""
            return_type_node = self._child_by_type(node, "type_identifier") or self._child_by_type(node, "generic_type")
            if return_type_node and _node_text(source, return_type_node) == "Object":
                findings.append(make_finding(
                    finding_type="explicit_object",
                    file=file_path, line=line,
                    title="Method returns 'Object'",
                    description=f"Method '{name}' returns raw 'Object' type — consider generics",
                    evidence=f"{name}: Object",
                    severity="medium",
                ))
            params = self._child_by_type(node, "formal_parameters")
            if params:
                for child in params.children:
                    if child.type == "formal_parameter":
                        ptype = self._child_by_type(child, "type_identifier") or self._child_by_type(child, "generic_type")
                        if ptype and _node_text(source, ptype) == "Object":
                            findings.append(make_finding(
                                finding_type="explicit_object",
                                file=file_path, line=line,
                                title="Parameter typed as 'Object'",
                                description=f"Parameter in '{name}' is raw 'Object' type",
                                severity="medium",
                            ))
        for child in node.children:
            self._walk(child, source, file_path, findings)

    def _child_by_type(self, node: Any, ntype: str) -> Any | None:
        for child in node.children:
            if child.type == ntype:
                return child
        return None
