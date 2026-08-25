"""Rust type checker — uses tree-sitter."""

from __future__ import annotations

import logging
from typing import Any

from ..languages import Lang, get_parser
from .base import BaseTypeChecker, _node_text, make_finding

_log = logging.getLogger("patchi.brain.rust")


class RustTypeChecker(BaseTypeChecker):
    language = "rust"

    def check(self, source: str, file_path: str) -> list[dict]:
        findings: list[dict] = []
        parser = get_parser(Lang.RUST)
        if parser is None:
            return findings
        try:
            tree = parser.parse(source.encode("utf-8"))
            self._walk(tree.root_node, source, file_path, findings)
        except Exception as e:
            _log.warning("RustTypeChecker.check failed: %s", e)
        return findings

    def _walk(self, node: Any, source: str, file_path: str, findings: list[dict]) -> None:
        ntype = node.type
        if ntype == "function_item":
            line = node.start_point[0] + 1
            name = (
                _node_text(source, self._child_by_type(node, "identifier"))
                if self._child_by_type(node, "identifier")
                else ""
            )
            return_type = self._child_by_type(node, "return_type")
            if return_type:
                for child in return_type.children:
                    if child.type == "type_identifier" and _node_text(source, child) == "Box":
                        inner = self._child_by_type(child, "type_arguments")
                        if inner and _node_text(source, inner).find("dyn") >= 0:
                            findings.append(
                                make_finding(
                                    finding_type="trait_object",
                                    file=file_path,
                                    line=line,
                                    title="Returns Box<dyn Trait> — consider generics",
                                    description=f"Function '{name}' returns Box<dyn ...> — consider `impl Trait` or generics",
                                    evidence=f"{name}: Box<dyn ...>",
                                    severity="low",
                                )
                            )
            # Check for unwrap() calls
            for child in node.children:
                self._walk(child, source, file_path, findings)
        elif ntype == "call_expression":
            line = node.start_point[0] + 1
            fn_name = _node_text(source, node).split("(")[0].strip()
            if fn_name == "unwrap" or fn_name.endswith(".unwrap"):
                findings.append(
                    make_finding(
                        finding_type="unwrap_call",
                        file=file_path,
                        line=line,
                        title="Unwrap call — may panic",
                        description="Call to .unwrap() may panic on None/Err — handle with match or ?",
                        evidence=fn_name,
                        severity="medium",
                    )
                )
        else:
            for child in node.children:
                self._walk(child, source, file_path, findings)

    def _child_by_type(self, node: Any, ntype: str) -> Any | None:
        for child in node.children:
            if child.type == ntype:
                return child
        return None
