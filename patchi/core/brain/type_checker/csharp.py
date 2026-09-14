"""C# type checker — uses tree-sitter."""

from __future__ import annotations

import logging
from typing import Any

from ..languages import Lang, get_parser
from .base import BaseTypeChecker, _node_text, make_finding

_log = logging.getLogger("patchi.brain.csharp")


class CSharpTypeChecker(BaseTypeChecker):
    language = "c_sharp"

    def check(self, source: str, file_path: str) -> list[dict]:
        findings: list[dict] = []
        parser = get_parser(Lang.C_SHARP)
        if parser is None:
            return findings
        try:
            tree = parser.parse(source.encode("utf-8"))
            self._walk(tree.root_node, source, file_path, findings)
        except Exception as e:
            _log.warning("CSharpTypeChecker.check failed: %s", e)
        return findings

    def _walk(self, node: Any, source: str, file_path: str, findings: list[dict]) -> None:
        ntype = node.type
        if ntype == "method_declaration":
            line = node.start_point[0] + 1
            name = (
                _node_text(source, self._child_by_type(node, "identifier"))
                if self._child_by_type(node, "identifier")
                else ""
            )
            return_type = self._child_by_type(node, "predefined_type") or self._child_by_type(node, "identifier")
            if return_type and _node_text(source, return_type) in ("object", "dynamic"):
                findings.append(
                    make_finding(
                        finding_type="untyped_return",
                        file=file_path,
                        line=line,
                        title=f"Method returns '{_node_text(source, return_type)}'",
                        description=f"Method '{name}' returns untyped '{_node_text(source, return_type)}' — consider a"
                        f" specific type",
                        severity="medium",
                    )
                )
        for child in node.children:
            self._walk(child, source, file_path, findings)

    def _child_by_type(self, node: Any, ntype: str) -> Any | None:
        for child in node.children:
            if child.type == ntype:
                return child
        return None
