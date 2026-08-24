"""DocClaimAgent — LLM-powered documentation claim miner.

Reads all project documentation files (README, docs/, .md, .txt, .rst, .adoc),
extracts structured verifiable claims via LLM, and hands them to the Brain
for structural cross-referencing against the actual codebase.

Usage (via Brain.scan):
    agent = DocClaimAgent()
    result = agent.run(AgentInput(root=root, config=config, ...))
    claims = result.data["claims"]  # list[Claim]

Fallback (--offline mode):
    from patchi.core.brain.doc_validator import validate_project_docs
    result = validate_project_docs(...)  # regex-based heuristic
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    register,
)

# Doc file discovery patterns — covers every common project doc format
_DOC_PATTERNS = [
    "README*",
    "CONTRIBUTING*",
    "CHANGELOG*",
    "CHANGES*",
    "HISTORY*",
    "SECURITY*",
    "CODE_OF_CONDUCT*",
    "SUPPORT*",
    "AUTHORS*",
    "MAINTAINERS*",
    "GOVERNANCE*",
    "ROADMAP*",
    "VISION*",
    "GOALS*",
    "MILESTONES*",
    "LICENSE*",
    "COPYING*",
    "NOTICE*",
    "*.md",
    "*.MD",
    "*.txt",
    "*.TXT",
    "*.rst",
    "*.RST",
    "*.adoc",
    "*.ADOC",
    "*.asciidoc",
    "*.mdown",
    "docs/**/*",
    "documentation/**/*",
    "wiki/**/*",
    "man/**/*",
]

_EXCLUDED_DIRS = DEFAULT_IGNORE_DIRS | {"files 6", ".vscode", ".idea"}

_CLAIM_EXTRACTION_PROMPT = """\
You are reading a documentation file from a software project.
Extract every concrete, verifiable claim about the project into a JSON array.

A claim is a statement that CAN be checked against source code — something that is either true or false based on what the code actually does.

INCLUDE claims about:
- Features the project supports ("supports JWT", "handles file uploads")
- CLI commands and flags ("`p scan --deep` runs deep scan")
- API endpoints and methods ("POST /api/v1/users")
- Configuration keys and options ("`debug: true` enables debug mode")
- Supported formats, platforms, protocols ("exports to CSV", "runs on Linux/macOS")
- Dependencies and integrations ("uses Redis for caching", "integrates with Slack")
- Architecture patterns ("uses MVC architecture", "plugin-based")
- Security measures ("audit logging", "rate limiting")
- Test capabilities ("supports browser tests via Playwright")

EXCLUDE:
- Opinions, intros, thank-yous ("we love contributors", "built with care")
- License text, copyright notices
- Contribution guidelines, setup instructions for contributors
- Hypotheticals, future plans ("we plan to add", "coming soon")
- Generic meta-commentary about the project
- Things that are self-evident from reading ("this is a README file")

Output ONLY a JSON array of objects with this structure:
[
  {{
    "claim": "The exact sentence from the doc",
    "category": "feature|cli_command|api_endpoint|config_key|dependency|architecture|format_support|security|test_capability",
    "evidence_hints": [
      "route: POST /api/v1/users",
      "function: verify_jwt_token",
      "class: JwtMiddleware",
      "cli: p scan --deep",
      "import: redis",
      "file_match: config/**/*.yaml",
      "config_key: debug",
      "package: pytest",
      "symbol: JWT_SECRET"
    ]
  }}
]

If there are zero verifiable claims, output: []
Do NOT output anything else — no explanations, no markdown.
"""


import logging
_log = logging.getLogger("patchi.agents.doc_claim_agent")

@dataclass
class Claim:
    """A single verifiable claim extracted from documentation."""

    text: str
    source_file: str
    category: str  # feature, cli_command, api_endpoint, config_key, dependency, architecture, format_support, security, test_capability
    evidence_hints: list[str]  # hints for the brain to verify structurally
    verified: bool = False  # set by the brain after cross-referencing
    evidence: list[str] = field(default_factory=list)  # actual verification evidence


@register
class DocClaimAgent(BaseAgent):
    """LLM-powered documentation claim miner.

    Discovers all project documentation files, sends each to the LLM
    with a structured extraction prompt, and returns structured claims
    with evidence hints for the brain to verify against the codebase.

    Falls back gracefully: if LLM is unavailable, returns empty claims
    and the caller should fall back to doc_validator heuristic.
    """

    group = AgentGroup.SCANNER
    name = "DocClaimAgent"
    timeout = 120  # LLM calls can take time

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        import os

        if os.environ.get("PATCHI_OFFLINE"):
            logger.info("Offline mode — DocClaimAgent skipped")
            result.data["claims"] = []
            result.data["doc_files_found"] = []
            result.data["offline"] = True
            return

        doc_files = self._discover_docs(inp.root)
        if not doc_files:
            logger.info("No documentation files found")
            result.data["claims"] = []
            result.data["doc_files_found"] = []
            return

        result.data["doc_files_found"] = [str(p) for p in doc_files]

        all_claims: list[dict] = []
        ai_config = inp.config.get("ai", {})
        has_ai = bool(ai_config.get("keys") or ai_config.get("local_model_name"))

        if not has_ai:
            logger.info("No AI configured — DocClaimAgent returns no claims (fallback to heuristic)")
            result.data["claims"] = []
            result.data["ai_unavailable"] = True
            return

        max_workers = min(len(doc_files), 4)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_doc = {}
            for doc_path in doc_files:
                try:
                    text = doc_path.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    logger.warning(f"Cannot read {doc_path}: {e}")
                    continue

                if len(text.strip()) < 20:
                    continue

                future = executor.submit(self._extract_claims, text, doc_path, result, inp.config, ai_config)
                future_to_doc[future] = doc_path

            for future in as_completed(future_to_doc):
                doc_path = future_to_doc[future]
                try:
                    claims = future.result()
                except Exception as e:
                    logger.warning(f"Claim extraction failed for {doc_path.name}: {e}")
                    result.errors.append(f"{doc_path.name}: {e}")
                    continue

                for c in claims:
                    c["source_file"] = str(doc_path.relative_to(inp.root))
                    all_claims.append(c)

                result.ai_calls_made += 1

        result.data["claims"] = all_claims
        result.data["total_claims"] = len(all_claims)
        logger.info(f"DocClaimAgent: {len(all_claims)} claims from {len(doc_files)} files")

    def _discover_docs(self, root: Path) -> list[Path]:
        """Discover all documentation files in the project tree."""
        found: list[Path] = []
        seen: set[Path] = set()

        for pattern in _DOC_PATTERNS:
            for path in root.glob(pattern):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                # Skip excluded dirs
                rel = resolved.relative_to(root).as_posix()
                parts = rel.replace("\\", "/").split("/")
                if any(p in _EXCLUDED_DIRS for p in parts):
                    continue
                # Skip binary/irrelevant files by extension check
                if resolved.suffix.lower() not in (
                    ".md", ".txt", ".rst", ".adoc", ".asciidoc", ".mdown",
                    ".mdx",
                ) and resolved.name not in (
                    "README", "CONTRIBUTING", "CHANGELOG", "CHANGES", "HISTORY",
                    "SECURITY", "CODE_OF_CONDUCT", "LICENSE", "COPYING", "NOTICE",
                    "SUPPORT", "AUTHORS", "MAINTAINERS", "GOVERNANCE", "ROADMAP",
                    "VISION", "GOALS", "MILESTONES",
                ):
                    # Skip non-text files matched by docs/**/* (binary, images, etc.)
                    if resolved.suffix in (".png", ".jpg", ".gif", ".svg", ".ico", ".pdf",
                                            ".zip", ".gz", ".tar", ".bin", ".exe", ".dll",
                                            ".so", ".dylib", ".pyc", ".woff", ".woff2",
                                            ".ttf", ".eot"):
                        continue
                seen.add(resolved)
                found.append(resolved)

        found.sort(key=lambda p: p.as_posix())
        return found

    def _extract_claims(
        self,
        text: str,
        doc_path: Path,
        result: AgentResult,
        config: dict,
        ai_config: dict,
    ) -> list[dict]:
        """Send a single doc file to the LLM and parse the claim JSON."""
        from patchi.core.ai.client import call_ai

        # Truncate very large doc files to avoid token blowout
        text = text[:15000]

        prompt = _CLAIM_EXTRACTION_PROMPT + "\n\n--- DOCUMENT ---\n" + text
        system_prompt = "You are a documentation analyser. Output only valid JSON."

        max_retries = 2
        for attempt in range(max_retries):
            try:
                response = call_ai(
                    config=config,
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                    max_tokens=4096,
                    temperature=0.1,
                )
            except Exception as e:
                logger.warning(f"LLM extraction failed for {doc_path.name} (attempt {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    continue
                result.errors.append(f"{doc_path.name}: LLM error — {e}")
                return []

            if not response:
                if attempt < max_retries - 1:
                    continue
                return []

            claims = self._parse_claims(response, doc_path)
            if not claims and attempt < max_retries - 1:
                logger.debug(f"Empty claims for {doc_path.name}, retrying...")
                continue

            return claims

        return []

    def _parse_claims(self, response: str, doc_path: Path) -> list[dict]:
        """Parse the LLM response into a list of claim dicts."""
        text = response.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) >= 2:
                lines = lines[1:] if lines[0].startswith("```") else lines
                if lines and lines[-1].strip().startswith("```"):
                    lines = lines[:-1]
                text = "\n".join(lines).strip()

        # Try to extract JSON array if embedded in other text
        start = text.find("[")
        end = text.rfind("]")
        if start >= 0 and end > start:
            text = text[start : end + 1]

        try:
            claims = json.loads(text)
            if not isinstance(claims, list):
                logger.warning(f"LLM returned non-array for {doc_path.name}")
                return []
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse LLM claims from {doc_path.name}: {e}")
            return []

        # Validate structure
        valid = []
        for c in claims:
            if isinstance(c, dict) and "claim" in c and "category" in c:
                if not isinstance(c.get("evidence_hints"), list):
                    c["evidence_hints"] = []
                valid.append(c)

        return valid


# ── Brain integration helper ──────────────────────────────────────────────


def verify_claims_against_code(
    claims: list[dict],
    file_infos: list,
    routes: list,
    symbol_graph=None,
    import_graph=None,
    config: dict | None = None,
) -> list[dict]:
    """Cross-reference each claim's evidence_hints against the codebase.

    Returns the claims list with verified=True/False and evidence populated.
    """
    if not claims:
        return claims

    # Build lookup sets from scan results
    route_set: set[str] = set()
    for r in routes:
        if hasattr(r, "method"):
            route_set.add(r.method.upper() + " " + r.path)
            route_set.add((r.method.upper() + " " + r.path).lower())
            route_set.add(r.path.lower())
        elif isinstance(r, dict):
            method = r.get("method", "GET")
            path = r.get("path", "/")
            route_set.add(method.upper() + " " + path)
            route_set.add((method.upper() + " " + path).lower())
            route_set.add(path.lower())

    file_paths: set[str] = set()
    file_names: set[str] = set()
    func_names: set[str] = set()
    class_names: set[str] = set()
    import_names: set[str] = set()
    symbols: set[str] = set()

    for fi in file_infos:
        if hasattr(fi, "path"):
            rel = fi.path
        elif isinstance(fi, dict):
            rel = fi.get("path", "")
        else:
            continue
        file_paths.add(rel.lower())
        file_names.add(Path(rel).stem.lower())
        funcs = fi.functions if hasattr(fi, "functions") else fi.get("functions", [])
        classes = fi.classes if hasattr(fi, "classes") else fi.get("classes", [])
        imports = fi.imports if hasattr(fi, "imports") else fi.get("imports", [])
        if funcs:
            func_names.update(f.name.lower() if hasattr(f, "name") else f.get("name", "").lower() for f in funcs)
        if classes:
            class_names.update(c.name.lower() if hasattr(c, "name") else c.get("name", "").lower() for c in classes)
        if imports:
            import_names.update(
                i.source.lower() if hasattr(i, "source") else i.get("source", "").lower() for i in imports
            )

    if symbol_graph:
        try:
            for sym in symbol_graph.get_all_symbols():
                symbols.add(sym.name.lower())
                symbols.add(sym.qualified_name.lower())
        except Exception as e:
            _log.warning("verify_claims_against_code failed: %s", e)

    cli_flags: set[str] = set()
    if config:
        cli_parser = config.get("_cli_parser")
        if cli_parser:
            for action in cli_parser._actions:
                for opt in action.option_strings:
                    cli_flags.add(opt.lower())

    # Build import graph node set for dependency verification
    ig_nodes: set[str] = set()
    if import_graph:
        try:
            if hasattr(import_graph, "graph") and hasattr(import_graph.graph, "nodes"):
                ig_nodes = set(import_graph.graph.nodes())
            elif hasattr(import_graph, "nodes"):
                ig_nodes = set(import_graph.nodes())
        except Exception as e:
            _log.warning("verify_claims_against_code failed: %s", e)

    for claim in claims:
        hints = claim.get("evidence_hints", [])
        evidence: list[str] = []

        for hint in hints:
            hint_lower = hint.lower()

            # Route check
            if hint_lower.startswith("route:"):
                target = hint_lower.replace("route:", "").strip()
                if target in route_set:
                    evidence.append(f"matched_route:{hint}")

            # Function/class/symbol check
            elif hint_lower.startswith("function:"):
                target = hint_lower.replace("function:", "").strip()
                if target in func_names:
                    evidence.append(f"matched_function:{hint}")

            elif hint_lower.startswith("class:"):
                target = hint_lower.replace("class:", "").strip()
                if target in class_names:
                    evidence.append(f"matched_class:{hint}")

            elif hint_lower.startswith("symbol:"):
                target = hint_lower.replace("symbol:", "").strip()
                if target in symbols:
                    evidence.append(f"matched_symbol:{hint}")

            # CLI flag check
            elif hint_lower.startswith("cli:"):
                target = hint_lower.replace("cli:", "").strip()
                if target in cli_flags:
                    evidence.append(f"matched_cli:{hint}")

            # Import/package check (now also uses import_graph)
            elif hint_lower.startswith("import:"):
                target = hint_lower.replace("import:", "").strip()
                if target in import_names:
                    evidence.append(f"matched_import:{hint}")
                elif ig_nodes:
                    for node in ig_nodes:
                        if target in node.lower():
                            evidence.append(f"matched_import_graph:{hint}")
                            break

            elif hint_lower.startswith("package:"):
                target = hint_lower.replace("package:", "").strip()
                if target in import_names or target in file_names:
                    evidence.append(f"matched_package:{hint}")
                elif ig_nodes:
                    for node in ig_nodes:
                        if target in node.lower():
                            evidence.append(f"matched_import_graph:{hint}")
                            break

            # Config key check
            elif hint_lower.startswith("config_key:"):
                target = hint_lower.replace("config_key:", "").strip()
                if config and target in str(config).lower():
                    evidence.append(f"matched_config:{hint}")

            # File match check
            elif hint_lower.startswith("file_match:"):
                target = hint_lower.replace("file_match:", "").strip()
                if any(target in fp for fp in file_paths):
                    evidence.append(f"matched_file:{hint}")
                elif ig_nodes:
                    for node in ig_nodes:
                        if target in node.lower():
                            evidence.append(f"matched_file_via_import_graph:{hint}")
                            break

            # Dependency verification via import graph
            elif hint_lower.startswith("dependency:"):
                target = hint_lower.replace("dependency:", "").strip()
                if ig_nodes:
                    for node in ig_nodes:
                        if target in node.lower():
                            evidence.append(f"matched_import_graph_dep:{hint}")
                            break
                if target in import_names:
                    evidence.append(f"matched_import:{hint}")

            # General keyword search (fallback)
            else:
                if hint_lower in func_names or hint_lower in class_names or hint_lower in symbols:
                    evidence.append(f"matched_symbol:{hint}")
                elif ig_nodes:
                    for node in ig_nodes:
                        if hint_lower in node.lower():
                            evidence.append(f"matched_import_graph:{hint}")
                            break

        claim["verified"] = len(evidence) > 0
        claim["evidence"] = evidence

    return claims
