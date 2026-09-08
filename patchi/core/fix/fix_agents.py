"""
All 8 fix agents for Patchi.

Fix agents use AI to generate surgical patches for findings from scanner agents.
Each fix agent:
  1. Receives a Finding + the current file content
  2. Calls AI with a structured system prompt + skill-specific user prompt
  3. Parses the AI response into a Patch with FileChange(s)
  4. Computes risk_score and confidence
  5. Returns the Patch (never applies it — applier does that)

AI call budget: fix agents make 1 AI call per finding. No loops, no re-asks.
If the AI response can't be parsed into a clean diff, the finding is tagged
'fix_failed' and returned to the user with the raw AI explanation.

Agents:
  1. CodeFixer        — bug fixes, missing error handling, null checks
  2. SecurityFixer    — patches confirmed vulnerabilities
  3. DeadCodeRemover  — proposes deletion of confirmed dead files/functions
  4. DependencyFixer  — version bumps, lockfile fixes, Dependabot setup
  5. EnvFixer         — .env.example generation, secret removal from source
  6. TypeFixer        — TypeScript type errors, unsafe casts (TS only)
  7. RefactorAgent    — extracts duplicated logic to shared functions
  8. UnitTestRunner   — generates test skeletons for uncovered functions

Fix agents are registered in the same registry as scanner agents.
The coordinator runs them sequentially (not in parallel — spec is explicit).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from patchi.core.agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    register,
)
from patchi.core.ai.client import call_ai
from patchi.core.ai.prompts import (
    Skill,
    build_prompt,
    get_system_prompt,
)
from patchi.core.fix.base import compute_blast_radius
from patchi.core.fix.patch import (
    FileChange,
    Patch,
    PatchState,
    PatchType,
    compute_confidence,
    compute_risk_score,
)

_log = logging.getLogger("patchi.fix.fix_agents")

# ── Shared helpers ─────────────────────────────────────────────────────────────


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _extract_code_block(text: str) -> str:
    """Extract the first ```...``` block from an AI response."""
    m = re.search(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    return m.group(1) if m else text.strip()


def _try_apply_partial(ai_response: str, original: str) -> str | None:
    """
    If AI returned partial lines (e.g., '42: fixed_code'), apply them to the original.
    Returns the full file with changes applied, or None if not a partial response.
    """
    lines = original.splitlines()
    partial_pattern = re.compile(r"^(\d+):\s*(.*)$")
    changes = {}
    for line in ai_response.splitlines():
        line = line.strip()
        m = partial_pattern.match(line)
        if m:
            line_num = int(m.group(1))
            new_code = m.group(2)
            if 1 <= line_num <= len(lines):
                changes[line_num - 1] = new_code

    if not changes:
        return None

    for idx, new_code in changes.items():
        lines[idx] = new_code
    return "\n".join(lines)


def _detect_language(file_path: str, project_root: str | None = None) -> str:
    """Detect language from file extension for prompt formatting."""
    ext = Path(file_path).suffix.lower()
    # .h files are ambiguous (C vs C++). Default to "c", but if project has .cpp files, assume C++
    if ext == ".h" and project_root:
        root = Path(project_root)
        if root.exists():
            cpp_files = (
                list(root.rglob("*.cpp")) + list(root.rglob("*.cxx")) + list(root.rglob("*.cc"))
            )
            if cpp_files:
                return "cpp"
    return {
        ".py": "python",
        ".pyw": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mts": "typescript",
        ".rs": "rust",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".cs": "csharp",
        ".dart": "dart",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".cc": "cpp",
        ".hpp": "cpp",
        ".php": "php",
        ".php3": "php",
        ".php4": "php",
        ".php5": "php",
        ".phtml": "php",
        ".svelte": "svelte",
        ".sh": "bash",
        ".bash": "bash",
        ".zsh": "bash",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".html": "html",
        ".htm": "html",
        ".css": "css",
        ".sql": "sql",
        ".md": "markdown",
        ".dockerfile": "dockerfile",
    }.get(ext, "")


def _make_patch(
    agent_name: str,
    patch_type: PatchType,
    changes: list[FileChange],
    description: str,
    ai_explanation: str,
    finding_id: str = "",
    blast_radius: int = 0,
    agent_certainty: float = 0.9,
    has_test_coverage: bool = True,
    scanner_agent: str = "",
    source_finding: dict | None = None,
) -> Patch:
    risk = compute_risk_score(changes, blast_radius)
    conf = compute_confidence(changes, agent_certainty, has_test_coverage=has_test_coverage)
    return Patch(
        agent=agent_name,
        patch_type=patch_type,
        finding_id=finding_id,
        changes=changes,
        description=description,
        ai_explanation=ai_explanation,
        risk_score=risk,
        confidence=conf,
        blast_radius=blast_radius,
        state=PatchState.PROPOSED,
        scanner_agent=scanner_agent,
        source_finding=source_finding or {},
        verify_retries=2,
    )


def _ai_fix(
    config: dict,
    skill: Skill,
    file_path: str,
    file_content: str,
    finding: dict,
    blast_radius: int = 0,
    root=None,
    framework: str = "",
) -> str | None:
    """
    Call AI with structured system prompt + skill-specific prompt.
    Returns the corrected file content, or None if AI unavailable/failed.
    Handles both full-file and partial-line responses.
    """
    lang = _detect_language(file_path)
    system = get_system_prompt(skill)

    fw = framework or finding.get("framework", "")

    from patchi.core.debug import debug_context_from_finding

    dbg = debug_context_from_finding(finding, root or Path.cwd())

    ctx: dict = {
        "debug_context": (json.dumps(dbg, indent=2) if dbg else ""),
        "file_path": file_path,
        "file_content": file_content[:8000],
        "finding_message": finding.get("message", ""),
        "finding_line": finding.get("line", 0),
        "suggestion": finding.get("suggestion", ""),
        "code_snippet": finding.get("code_snippet", ""),
        "cwe": finding.get("cwe", ""),
        "blast_radius": str(blast_radius),
        "language": lang,
        "framework": fw,
        "pattern_type": finding.get("pattern_type", ""),
        "issue_type": finding.get("type", ""),
    }

    user_prompt = build_prompt(skill, ctx)

    # Log AI call for audit trail (WIRE-04)
    try:
        from patchi.core.security.governance import patchi_action_log

        r = root or Path.cwd()
        patchi_action_log(
            r,
            "ai_call",
            file_path,
            agent=skill.value if hasattr(skill, "value") else "fix_agent",
            detail=finding.get("type", ""),
        )
    except Exception as e:
        _log.warning("Failed to write AI-call audit log entry for %s: %s", file_path, e)

    response = call_ai(config, system, user_prompt)
    if not response:
        return None

    proposed = _extract_code_block(response)
    if not proposed.strip() or proposed.strip() == file_content.strip():
        return None

    # Check if AI returned partial lines (e.g., "42: fixed_code")
    # Apply partial changes to the original file
    partial = _try_apply_partial(proposed, file_content)
    if partial is not None:
        return partial

    return proposed


# CodeFixer, SecurityFixer, and DeadCodeRemover live in their own files
# (code_fixer.py, security_fixer.py, dead_code_remover.py) imported via fix/__init__.py.
# They are registered there with @register.


# ── 4. DependencyFixer ────────────────────────────────────────────────────────


@register
class DependencyFixer(BaseAgent):
    """
    Version bumps for vulnerable dependencies.
    Reads the OSV result and proposes the patched version.
    """

    name = "DependencyFixer"
    group = AgentGroup.FIX
    domain = AgentDomain.CODE_QUALITY
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        vuln_findings = [
            f for f in inp.extra.get("findings", []) if f.get("type") == "vulnerable_dependency"
        ]

        patches: list[Patch] = []

        for finding in vuln_findings[:10]:
            pkg_name = self._extract_package_name(finding.get("message", ""))
            if not pkg_name:
                continue

            for dep_file in [
                "requirements.txt",
                "package.json",
                "pyproject.toml",
                "Cargo.toml",
                "go.mod",
                "Gemfile",
                "composer.json",
                "pom.xml",
                "build.gradle",
                "build.gradle.kts",
                "pubspec.yaml",
                "Package.swift",
                "Package.resolved",
            ]:
                dep_path = inp.root / dep_file
                if not dep_path.exists():
                    continue

                original = _read_file(dep_path)
                if not original:
                    continue

                system = get_system_prompt(Skill.DEPENDENCY_FIX)
                user_prompt = build_prompt(
                    Skill.DEPENDENCY_FIX,
                    {
                        "package_name": pkg_name,
                        "finding_message": finding.get("message", ""),
                        "cwe": finding.get("cwe", finding.get("detail", "")),
                        "package_file": dep_file,
                        "package_file_content": original[:3000],
                    },
                )

                # Log AI call for audit trail (WIRE-04)
                try:
                    from patchi.core.security.governance import patchi_action_log

                    patchi_action_log(
                        inp.root, "ai_call", dep_file, agent="DependencyFixer", detail=pkg_name
                    )
                except Exception as e:
                    _log.warning("Failed to write AI-call audit log entry for %s: %s", dep_file, e)

                response = call_ai(inp.config, system, user_prompt)
                if not response:
                    continue

                proposed = _extract_code_block(response)
                if proposed == original or not proposed.strip():
                    continue

                change = FileChange(path=dep_file, original=original, proposed=proposed)
                if not change.diff.strip():
                    break  # AI made no change, skip this file

                blast_radius = compute_blast_radius(dep_file, inp.root)

                patch = _make_patch(
                    agent_name=self.name,
                    patch_type=PatchType.DEPENDENCY,
                    changes=[change],
                    description=f"Update vulnerable dependency: {pkg_name}",
                    ai_explanation=finding.get("detail", finding.get("message", "")),
                    finding_id=finding.get("type", ""),
                    blast_radius=blast_radius,
                )
                patches.append(patch)
                result.data.setdefault("patches", []).append(patch.to_dict())
                break

        result.data["patch_count"] = len(patches)
        result.ai_calls_made = len(patches)

    def _extract_package_name(self, message: str) -> str:
        m = re.match(r"^([\w\-\.\/]+)\s", message)
        return m.group(1) if m else ""


# ── 5. EnvFixer ───────────────────────────────────────────────────────────────


@register
class EnvFixer(BaseAgent):
    """
    Fixes environment variable issues:
    - Removes hardcoded secrets from source and replaces with os.environ / process.env
    - Generates .env.example from .env variable names
    - Adds missing .gitignore entries
    """

    name = "EnvFixer"
    group = AgentGroup.FIX
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        secret_findings = [
            f for f in inp.extra.get("findings", []) if f.get("type") == "hardcoded_secret"
        ]

        patches: list[Patch] = []

        for finding in secret_findings[:10]:
            fpath = finding.get("file", "")
            path = inp.root / fpath
            original = _read_file(path)
            if not original:
                continue

            framework = finding.get("framework", "")
            proposed = _ai_fix(
                inp.config,
                Skill.ENV_FIX,
                fpath,
                original,
                finding,
                root=inp.root,
                framework=framework,
            )
            if not proposed:
                continue

            change = FileChange(path=fpath, original=original, proposed=proposed)
            if not change.diff.strip():
                continue

            blast_radius = compute_blast_radius(fpath, inp.root)

            patch = _make_patch(
                agent_name=self.name,
                patch_type=PatchType.ENV_FIX,
                changes=[change],
                description=f"Replace hardcoded secret in {fpath}",
                ai_explanation="Moved secret to environment variable reference.",
                finding_id=finding.get("type", ""),
                blast_radius=blast_radius,
                agent_certainty=0.9,
            )
            patches.append(patch)
            result.data.setdefault("patches", []).append(patch.to_dict())

        # Also generate .env.example if not present
        self._generate_env_example(inp, result)

        result.data["patch_count"] = len(patches)
        result.ai_calls_made = len(patches)

    def _generate_env_example(self, inp: AgentInput, result: AgentResult) -> None:
        env_example = inp.root / ".env.example"
        if env_example.exists():
            return

        env_vars = inp.extra.get("env_vars", [])
        if not env_vars:
            return

        content = "# Environment variables required by this application\n"
        content += "# Copy to .env and fill in the values\n\n"
        for var in env_vars:
            content += f"{var}=\n"

        change = FileChange(path=".env.example", original="", proposed=content)
        patch = _make_patch(
            agent_name=self.name,
            patch_type=PatchType.ENV_FIX,
            changes=[change],
            description="Generate .env.example from discovered env variables",
            ai_explanation="Created .env.example so contributors know which variables are required.",
            agent_certainty=1.0,
        )
        result.data.setdefault("patches", []).append(patch.to_dict())


# ── 6. TypeFixer ──────────────────────────────────────────────────────────────

# Multi-language type-issue finding types produced by the type checker
# (patchi.core.brain.type_checker). TypeFixer now handles every language the
# checker supports, not just TypeScript.
TYPE_ISSUE_TYPES = frozenset(
    {
        "any_type",
        "dynamic_type",
        "empty_interface",
        "explicit_any",
        "explicit_object",
        "missing_param_type",
        "missing_return_type",
        "missing_type",
        "missing_prop_types",
        "non_null_assertion",
        "trait_object",
        "ts_ignore",
        "unsafe_cast",
        "untyped_return",
        "unwrap_call",
    }
)


@register
class TypeFixer(BaseAgent):
    """Multi-language type fixer: explicit any, unsafe casts, missing return types, etc.

    Handles type-issue findings from every language the type checker supports
    (TypeScript, Python, Go, Java, Kotlin, C#, Dart, PHP, Swift, Rust). The AI
    prompt receives the file's language so the corrected code is idiomatic.
    """

    name = "TypeFixer"
    group = AgentGroup.FIX
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # TypeFixer handles any type-issue finding. The type scanner does not
        # always tag fix_agent, so accept both tagged and untagged type issues.
        type_findings = [
            f
            for f in inp.extra.get("findings", [])
            if f.get("type") in TYPE_ISSUE_TYPES
            and (f.get("fix_agent") == self.name or f.get("fix_agent") in (None, ""))
        ]

        patches: list[Patch] = []

        for finding in type_findings[:10]:
            fpath = finding.get("file", "")
            path = inp.root / fpath
            original = _read_file(path)
            if not original:
                continue

            framework = finding.get("framework", "")
            proposed = _ai_fix(
                inp.config,
                Skill.TYPE_FIX,
                fpath,
                original,
                finding,
                root=inp.root,
                framework=framework,
            )
            if not proposed:
                continue

            change = FileChange(path=fpath, original=original, proposed=proposed)
            if not change.diff.strip():
                continue

            blast_radius = compute_blast_radius(fpath, inp.root)

            patch = _make_patch(
                agent_name=self.name,
                patch_type=PatchType.TYPE_FIX,
                changes=[change],
                description=f"Type fix ({finding.get('type', '')}): {fpath}",
                ai_explanation="Fixed type issue using the project's type system.",
                finding_id=finding.get("type", ""),
                blast_radius=blast_radius,
            )
            patches.append(patch)
            result.data.setdefault("patches", []).append(patch.to_dict())

        result.data["patch_count"] = len(patches)
        result.ai_calls_made = len(patches)


# ── 7. RefactorAgent ──────────────────────────────────────────────────────────


@register
class RefactorAgent(BaseAgent):
    """
    Extracts duplicated logic into shared functions.
    Only runs after DuplicateScanner confirms high similarity (>= 85%).
    """

    name = "RefactorAgent"
    group = AgentGroup.FIX
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        dup_findings = [
            f
            for f in inp.extra.get("findings", [])
            if f.get("type") == "duplicate_function" and f.get("fix_agent") == self.name
        ]

        patches: list[Patch] = []

        for finding in dup_findings[:5]:
            file1 = finding.get("file", "")
            file2 = finding.get("similar_to", "").split(":")[0] if finding.get("similar_to") else ""

            if not file1 or not file2:
                continue

            orig1 = _read_file(inp.root / file1)
            orig2 = _read_file(inp.root / file2)
            if not orig1 or not orig2:
                continue

            score = finding.get("similarity_score", 0)

            system = get_system_prompt(Skill.REFACTOR)
            user_prompt = build_prompt(
                Skill.REFACTOR,
                {
                    "file1_path": file1,
                    "file1_content": orig1[:2000],
                    "file2_path": file2,
                    "file2_content": orig2[:2000],
                    "similarity_score": str(score),
                    "language": _detect_language(file1),
                },
            )

            # Log AI call for audit trail (WIRE-04)
            try:
                from patchi.core.security.governance import patchi_action_log

                patchi_action_log(inp.root, "ai_call", f"{file1}, {file2}", agent="RefactorAgent")
            except Exception as e:
                _log.warning(
                    "Failed to write AI-call audit log entry for %s, %s: %s", file1, file2, e
                )

            response = call_ai(inp.config, system, user_prompt, max_tokens=3000)
            if not response:
                continue

            blocks = re.findall(
                r"(?://|#)?\s*FILE:\s*([^\n]+)\n```(?:\w+)?\n(.*?)```",
                response,
                re.DOTALL,
            )
            if not blocks:
                blocks = re.findall(
                    r"FILE:\s*([^\n]+)\n```(?:\w+)?\n(.*?)```",
                    response,
                    re.DOTALL,
                )
            if len(blocks) < 2:
                continue

            changes: list[FileChange] = []
            for fname, proposed_code in blocks:
                fname = fname.strip()
                if fname == file1:
                    changes.append(FileChange(path=file1, original=orig1, proposed=proposed_code))
                elif fname == file2:
                    changes.append(FileChange(path=file2, original=orig2, proposed=proposed_code))

            if not changes:
                continue

            br1 = compute_blast_radius(file1, inp.root)
            br2 = compute_blast_radius(file2, inp.root)
            blast_radius = max(br1, br2)

            patch = _make_patch(
                agent_name=self.name,
                patch_type=PatchType.REFACTOR,
                changes=changes,
                description=f"Extract shared logic from {file1} and {file2}",
                ai_explanation=f"Functions are {int(score * 100)}% similar. Extracted to shared utility.",
                finding_id=finding.get("type", ""),
                blast_radius=blast_radius,
                agent_certainty=0.8,
                has_test_coverage=False,
            )
            patches.append(patch)
            result.data.setdefault("patches", []).append(patch.to_dict())

        result.data["patch_count"] = len(patches)
        result.ai_calls_made = len(patches)


# ── 8. UnitTestRunner ─────────────────────────────────────────────────────────


@register
class UnitTestRunner(BaseAgent):
    """
    Generates test skeletons for uncovered source files.
    Writes to tests/ directory. Never modifies source files.
    """

    name = "UnitTestRunner"
    group = AgentGroup.FIX
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        uncovered_findings = [
            f
            for f in inp.extra.get("findings", [])
            if f.get("type") == "uncovered_file" and f.get("fix_agent") == self.name
        ]

        patches: list[Patch] = []

        for finding in uncovered_findings[:5]:
            source_path = finding.get("file", "")
            path = inp.root / source_path
            original = _read_file(path)
            if not original:
                continue

            lang = _detect_language(source_path)
            test_path = self._test_path(source_path, lang)

            if (inp.root / test_path).exists():
                continue

            system = get_system_prompt(Skill.TEST_GENERATE)
            user_prompt = build_prompt(
                Skill.TEST_GENERATE,
                {
                    "file_path": source_path,
                    "file_content": original[:3000],
                    "existing_tests_section": "Write tests for all exported functions.",
                    "language": lang,
                },
            )

            # Log AI call for audit trail (WIRE-04)
            try:
                from patchi.core.security.governance import patchi_action_log

                patchi_action_log(inp.root, "ai_call", source_path, agent="UnitTestRunner")
            except Exception as e:
                _log.warning("Failed to write AI-call audit log entry for %s: %s", source_path, e)

            response = call_ai(inp.config, system, user_prompt)
            if not response:
                continue

            proposed = _extract_code_block(response)
            if not proposed.strip():
                continue

            change = FileChange(path=test_path, original="", proposed=proposed)

            blast_radius = compute_blast_radius(source_path, inp.root)

            patch = _make_patch(
                agent_name=self.name,
                patch_type=PatchType.TEST_ADD,
                changes=[change],
                description=f"Add tests for {source_path}",
                ai_explanation="Generated unit test skeleton covering exported functions.",
                finding_id=finding.get("type", ""),
                blast_radius=blast_radius,
                agent_certainty=0.85,
            )
            patches.append(patch)
            result.data.setdefault("patches", []).append(patch.to_dict())

        result.data["patch_count"] = len(patches)
        result.ai_calls_made = len(patches)

    def _test_path(self, source_path: str, lang: str) -> str:
        from pathlib import PurePosixPath

        p = PurePosixPath(source_path)
        stem = p.stem
        parent = str(p.parent)
        if lang == "python":
            test_name = f"test_{stem}.py"
        else:
            ext = p.suffix
            test_name = f"{stem}.test{ext}"
        # Mirror source directory structure under tests/
        if parent and parent != ".":
            return f"tests/{parent}/{test_name}"
        return f"tests/{test_name}"
