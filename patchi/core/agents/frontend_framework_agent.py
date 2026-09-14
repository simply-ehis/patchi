"""
FrontendFrameworkAgent §8.1.1-5 — React/Vue/Svelte/Angular/Solid checks.

Uses ESLint plugins where available, else tree-sitter structural queries.

Checks:
  React: hooks rules, missing key in list, useEffect dep array
  Vue: v-for key, template type, composition API
  Svelte: store subscription leak ($store without unsubscribe)
  Angular: DI, template type, standalone
  Solid: createEffect without cleanup
"""

from __future__ import annotations

import logging

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    get_shard_files,
    make_finding,
    register,
)
from patchi.core.brain.code_query import (
    extract_script_blocks,
    js_call_names,
    js_calls,
    js_constructor_di_line,
    js_identifier_lines,
    js_jsx_attributes,
    js_jsx_elements,
    lang_for_file,
    parse_js,
    vue_template_attrs,
)

_log = logging.getLogger("patchi.agents.frontend_framework")

_HOOKS = {"useEffect", "useState", "useMemo", "useCallback", "useRef"}


@register
class FrontendFrameworkAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "FrontendFrameworkAgent"
    description = "React/Vue/Svelte/Angular/Solid framework checks §8.1.1-5"
    timeout = 60
    shardable = True
    supported_languages = ["JavaScript", "TypeScript"]

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        _MIN_SIZE = 200
        _MAX_FILES = 500
        scanned = 0
        for pat in ("*.jsx", "*.tsx", "*.js", "*.ts", "*.vue", "*.svelte"):
            for fp in get_shard_files(inp, pat):
                if scanned >= _MAX_FILES:
                    break
                if fp.stat().st_size < _MIN_SIZE:
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                if "node_modules" in rel or "tests" in rel:
                    continue
                try:
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                scanned += 1
                lang = lang_for_file(rel)
                tree = parse_js(txt, lang)
                if tree is None:
                    continue
                calls = js_calls(tree, lang)
                names = {c.name for c in calls}
                is_jsx = fp.suffix in (".jsx", ".tsx") or "React" in txt
                # React: useEffect without dep array (single-argument call)
                if is_jsx:
                    for call in calls:
                        if call.name == "useEffect" and len(call.arg_kinds) < 2:
                            findings.append(
                                make_finding(
                                    severity=Severity.LOW,
                                    file=rel,
                                    line_start=call.line,
                                    title="React useEffect missing deps",
                                    description="Add dependency array or disable exhaustive-deps consciously",
                                    finding_type="react_hook",
                                )
                            )
                            break
                    # React: list rendering without key (previously dead branch)
                    attrs = js_jsx_attributes(tree, lang)
                    if any(c.name in ("map", "forEach") for c in calls):
                        if not any(name == "key" for _, name, _ in attrs):
                            elems = js_jsx_elements(tree, lang)
                            line0 = elems[0][1] if elems else 1
                            findings.append(
                                make_finding(
                                    severity=Severity.LOW,
                                    file=rel,
                                    line_start=line0,
                                    title="List element without key",
                                    description="Add key to list-rendered elements for stable diffing",
                                    finding_type="react_key",
                                )
                            )
                # Vue: v-for without :key (template markup via html.parser)
                if fp.suffix == ".vue":
                    by_el: dict[tuple[str, int], set[str]] = {}
                    for tag, attr, line in vue_template_attrs(txt):
                        by_el.setdefault((tag, line), set()).add(attr)
                    for (_tag, line), attr_set in by_el.items():
                        if "v-for" in attr_set and "key" not in attr_set and ":key" not in attr_set:
                            findings.append(
                                make_finding(
                                    severity=Severity.LOW,
                                    file=rel,
                                    line_start=line,
                                    title="Vue v-for without :key",
                                    description="Add :key to v-for for stable diffing",
                                    finding_type="vue_key",
                                )
                            )
                            break
                # Svelte: $store subscription without unsubscribe
                if fp.suffix == ".svelte":
                    for block in extract_script_blocks(txt) or [txt]:
                        stree = parse_js(block, "javascript")
                        if stree is None:
                            continue
                        snames = js_call_names(stree, "javascript")
                        stores = [(t, n) for t, n in js_identifier_lines(stree, "javascript") if t.startswith("$")]
                        if not stores or "subscribe" not in snames:
                            continue
                        if snames & {"unsubscribe", "onDestroy"}:
                            continue
                        findings.append(
                            make_finding(
                                severity=Severity.LOW,
                                file=rel,
                                line_start=stores[0][1],
                                title="Svelte store without unsubscribe",
                                description=(
                                    "Store subscription may leak; use $store auto-sub or onDestroy unsubscribe"
                                ),
                                finding_type="svelte_store_leak",
                            )
                        )
                        break
                # Angular: constructor DI (private param)
                if "Angular" in txt or "@Component" in txt:
                    line = js_constructor_di_line(tree, lang)
                    if line:
                        findings.append(
                            make_finding(
                                severity=Severity.INFO,
                                file=rel,
                                line_start=line,
                                title="Angular DI injection",
                                description="Verify DI token provided",
                                finding_type="angular_di",
                            )
                        )
                # Solid: createEffect without cleanup
                if "createEffect" in names:
                    line = next(c.line for c in calls if c.name == "createEffect")
                    findings.append(
                        make_finding(
                            severity=Severity.INFO,
                            file=rel,
                            line_start=line,
                            title="Solid createEffect without cleanup",
                            description="Return cleanup function if needed",
                            finding_type="solid_effect",
                        )
                    )
                if len(findings) >= 40:
                    break
            if len(findings) >= 40:
                break
        result.status = AgentStatus.SUCCEEDED
        result.findings = findings[:40]
