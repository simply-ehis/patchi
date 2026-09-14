"""
I18nAgent §11.7 — Internationalization Audit.

Finds hardcoded strings in UI code, missing translation keys, untranslated strings
via tree-sitter scan for string literals in JSX/TSX/Vue/Svelte.
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
    js_calls,
    js_jsx_texts,
    lang_for_file,
    parse_js,
    vue_template_texts,
)

_log = logging.getLogger("patchi.agents.i18n")


def _looks_hardcoded(text: str) -> bool:
    words = text.split()
    return len(text) > 10 and 2 <= len(words) <= 5 and text[0].isupper()


def _has_i18n(tree, lang: str, raw: str) -> bool:
    for call in js_calls(tree, lang):
        if call.name == "useTranslation":
            return True
        if call.full.startswith("i18n."):
            return True
        if call.name == "t" and call.arg_kinds[:1] == ["string"]:
            return True
    markers = ("useTranslation", "i18n", "$t(", "t('", 't("')
    return any(m in raw for m in markers)


@register
class I18nAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "I18nAgent"
    description = "i18n audit §11.7 — hardcoded strings vs translation keys"
    timeout = 60
    shardable = True
    supported_languages = None

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        for pat in ("*.jsx", "*.tsx", "*.vue", "*.svelte"):
            for fp in get_shard_files(inp, pat):
                rel = fp.relative_to(inp.root).as_posix()
                if "node_modules" in rel:
                    continue
                try:
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if fp.suffix in (".vue", ".svelte"):
                    texts = vue_template_texts(txt)
                    markers = ("useTranslation", "i18n", "$t(", "t('", 't("')
                    has_i18n = any(m in txt for m in markers)
                else:
                    lang = lang_for_file(rel)
                    tree = parse_js(txt, lang)
                    if tree is None:
                        continue
                    texts = js_jsx_texts(tree, lang)
                    has_i18n = _has_i18n(tree, lang, txt)
                if has_i18n:
                    continue
                for s, line in texts:
                    if _looks_hardcoded(s):
                        findings.append(
                            make_finding(
                                severity=Severity.LOW,
                                file=rel,
                                line_start=line,
                                title=f"Hardcoded UI string '{s[:30]}' without i18n",
                                description="Use t('key') / $t() / i18n key; check i18next-scanner",
                                finding_type="i18n_hardcoded",
                            )
                        )
                        break
                if len(findings) >= 20:
                    break
            if len(findings) >= 20:
                break
        result.status = AgentStatus.SUCCEEDED
        result.findings = findings[:20]
