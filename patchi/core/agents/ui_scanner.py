"""
UIScanner — JSX/TSX components, props, navigation links.

Scans frontend files including:
- React/Vue/Svelte components (jsx, tsx, vue, svelte)
- Template files (html, hbs, ejs, etc.)
- CSS/SCSS files
- Static assets and asset references
- Navigation structures
- Accessibility issues

Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import re
from pathlib import Path

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    get_shard_files,
    make_finding,
    register,
)


@register
class UIScanner(BaseAgent):
    """Scanner for UI/frontend files."""

    group = AgentGroup.SCANNER
    name = "UIScanner"
    description = "Frontend components, templates, static files"
    shardable = True
    supported_languages = ["JavaScript", "TypeScript"]

    def _mkf(self, *args, **kwargs) -> Finding:
        """Backwards-compatible finding helper for UIScanner."""
        if args and isinstance(args[0], Severity):
            severity = args[0]
            file = args[1] if len(args) > 1 else ""
            line = args[2] if len(args) > 2 else 0
            title = args[3] if len(args) > 3 else ""
            message = args[4] if len(args) > 4 else ""
            evidence = args[5] if len(args) > 5 else ""
            finding_type = kwargs.pop("finding_type", None) or title.lower().replace(
                " ", "_"
            ).replace(":", "").replace("'", "").replace("-", "_")
            return make_finding(
                self.name,
                finding_type,
                severity,
                file,
                message,
                line=line,
                evidence=evidence,
                **kwargs,
            )
        return make_finding(*args, **kwargs)

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan UI files for components and structure."""
        findings = []
        component_tree: dict = {}
        navigation_map: list[dict[str, str]] = []
        ui_files = 0

        ui_patterns = [
            "*.jsx",
            "*.tsx",
            "*.vue",
            "*.svelte",
            "*.html",
            "*.htm",
            "*.hbs",
            "*.handlebars",
            "*.ejs",
            "*.pug",
            "*.jade",
            "*.css",
            "*.scss",
            "*.sass",
            "*.less",
            "*.styl",
            "*.svg",
            "*.json",  # JSON might contain UI configs
        ]

        for pattern in ui_patterns:
            for file_path in get_shard_files(inp, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        ui_files += 1
                        try:
                            content = file_path.read_text(encoding="utf-8")
                        except Exception as e:
                            findings.append(
                                self._mkf(
                                    Severity.LOW,
                                    rel_path,
                                    0,
                                    "UI file read error",
                                    f"Could not read UI file {file_path.name}: {str(e)}",
                                    str(e),
                                )
                            )
                            continue
                        findings.extend(
                            self._scan_ui_file(
                                file_path, rel_path, content, component_tree, navigation_map
                            )
                        )

        for finding in findings:
            result.add_finding(finding)

        result.data["component_tree"] = component_tree
        result.data["navigation_map"] = navigation_map
        result.data["component_types"] = ["react", "vue", "svelte", "html", "css", "template"]
        result.data["needs_ai"] = False
        result.files_scanned = ui_files

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        # Skip ignored directories (node_modules, .venv, etc.)
        from pathlib import PurePosixPath

        if any(p in DEFAULT_IGNORE_DIRS for p in PurePosixPath(file_path).parts):
            return True

        # Check restrictions
        restrictions = inp.config.get("restrictions", [])
        for r in restrictions:
            if r.get("enabled", True):
                path = r["path"]
                if file_path.startswith(path) or PurePosixPath(file_path).match(path):
                    if r["type"] == "NO_TOUCH":
                        return True
                    elif r["type"] == "SCAN_ONLY" and self.__class__.__name__ == "FixAgent":
                        return True
        return False

    def _scan_ui_file(
        self,
        file_path: Path,
        rel_path: str,
        content: str,
        component_tree: dict,
        navigation_map: list[dict[str, str]],
    ) -> list[Finding]:
        """Scan a UI file."""
        findings = []

        # Determine file type and scan accordingly
        if file_path.suffix.lower() in [".jsx", ".tsx"]:
            findings.extend(
                self._scan_jsx_tsx(file_path, rel_path, content, component_tree, navigation_map)
            )
        elif file_path.suffix.lower() in [".vue"]:
            findings.extend(
                self._scan_vue(file_path, rel_path, content, component_tree, navigation_map)
            )
        elif file_path.suffix.lower() in [".svelte"]:
            findings.extend(
                self._scan_svelte(file_path, rel_path, content, component_tree, navigation_map)
            )
        elif file_path.suffix.lower() in [".html", ".htm"]:
            findings.extend(
                self._scan_html(file_path, rel_path, content, component_tree, navigation_map)
            )
        elif file_path.suffix.lower() in [".css", ".scss", ".sass", ".less"]:
            findings.extend(
                self._scan_css(file_path, rel_path, content, component_tree, navigation_map)
            )
        elif file_path.suffix.lower() in [".hbs", ".handlebars", ".ejs", ".pug", ".jade"]:
            findings.extend(
                self._scan_template(file_path, rel_path, content, component_tree, navigation_map)
            )

        findings.append(
            self._mkf(
                self.name,
                "ui_file",
                Severity.INFO,
                rel_path,
                f"Found UI file: {file_path.name}",
                line=0,
                evidence=f"Type: {file_path.suffix}, Size: {len(content)} chars",
            )
        )

        return findings

    def _scan_jsx_tsx(
        self,
        file_path: Path,
        rel_path: str,
        content: str,
        component_tree: dict,
        navigation_map: list[dict[str, str]],
    ) -> list[Finding]:
        """Scan JSX/TSX files for components and issues."""
        findings = []

        # Look for React components and prop types
        component_pattern = (
            r"(?:class|function)\s+(\w+)(?=\s*\(|\s*\(.*?\))|const\s+(\w+)\s*=\s*(?:\(\)|[^=]*=>)"
        )
        comp_matches = list(re.finditer(component_pattern, content))
        props_interface_pattern = r"interface\s+(\w+)\s*\{"
        prop_type_names = {m.group(1) for m in re.finditer(props_interface_pattern, content)}

        for match in comp_matches:
            comp_name = match.group(1) or match.group(2)
            line_start = content[: match.start()].count("\n") + 1
            component_entry = {
                "name": comp_name,
                "path": rel_path,
                "has_prop_types": False,
            }

            # Detect if props are typed within the component signature
            comp_region = content[match.start() : match.end() + 200]
            if re.search(r"\bprops\s*:\s*\w+", comp_region):
                component_entry["has_prop_types"] = True
            elif any(name in comp_region for name in prop_type_names):
                component_entry["has_prop_types"] = True

            if not component_entry["has_prop_types"] and re.search(
                r"\bfunction\s+" + re.escape(comp_name) + r"\s*\(\s*props\s*\)", content
            ):
                findings.append(
                    self._mkf(
                        self.name,
                        "missing_prop_types",
                        Severity.MEDIUM,
                        rel_path,
                        f"Component {comp_name} is missing prop type definitions",
                        line=line_start,
                        evidence=match.group(0),
                    )
                )

            component_tree[rel_path] = component_entry
            findings.append(
                self._mkf(
                    self.name,
                    "react_component",
                    Severity.INFO,
                    rel_path,
                    f"Found React component definition: {comp_name}",
                    line=line_start,
                    evidence=match.group(0),
                )
            )

        # Look for JSX elements that might indicate navigation
        link_patterns = [
            (r'<a\s+[^>]*href\s*=\s*["\'](?P<to>[^"\']+)["\']', "anchor_link"),
            (
                r'<(?:Link|NavLink|RouterLink)\b[^>]*to\s*=\s*["\'](?P<to>[^"\']+)["\']',
                "router_link",
            ),
        ]
        for pattern, _finding_type in link_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_start = content[: match.start()].count("\n") + 1
                to_value = match.group("to")
                navigation_map.append({"from": rel_path, "to": to_value})
                findings.append(
                    self._mkf(
                        self.name,
                        "navigation_element",
                        Severity.INFO,
                        rel_path,
                        f"Found navigation element to {to_value}",
                        line=line_start,
                        evidence=match.group(0)[:100],
                    )
                )

        # Look for accessibility issues
        accessibility_issues = [
            (r'<img[^>]+?alt\s*=\s*["\']["\'][^>]*>', "Image without alt text"),
            (
                r'<input[^>]+?type\s*=\s*["\']submit["\'][^>]*>',
                "Submit button without accessible label",
            ),
            (r"<button[^>]*>(\s*|<(?!span|img))</button>", "Empty button"),
        ]

        for pattern, issue_desc in accessibility_issues:
            for match in re.finditer(pattern, content):
                line_start = content[: match.start()].count("\n") + 1
                findings.append(
                    self._mkf(
                        self.name,
                        "accessibility_issue",
                        Severity.MEDIUM,
                        rel_path,
                        issue_desc,
                        line=line_start,
                        evidence=match.group(0),
                    )
                )

        return findings

    def _scan_vue(
        self,
        file_path: Path,
        rel_path: str,
        content: str,
        component_tree: dict,
        navigation_map: list[dict[str, str]],
    ) -> list[Finding]:
        """Scan Vue files for components and structure."""
        findings = []

        # Look for Vue component definitions
        comp_pattern = r'name:\s*["\']([^"\']+)["\']'
        matches = re.finditer(comp_pattern, content)

        for match in matches:
            comp_name = match.group(1)
            line_start = content[: match.start()].count("\n") + 1
            findings.append(
                self._mkf(
                    severity=Severity.INFO,
                    file=rel_path,
                    line_start=line_start,
                    title=f"Vue Component: {comp_name}",
                    description="Found Vue component definition",
                    evidence=match.group(0),
                )
            )

        # Look for router-link or nuxt-link
        router_patterns = [r"<router-link\b", r"<nuxt-link\b"]
        for pattern in router_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_start = content[: match.start()].count("\n") + 1
                findings.append(
                    self._mkf(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=line_start,
                        title="Vue Router Link",
                        description="Found Vue router link",
                        evidence=match.group(0),
                    )
                )

        return findings

    def _scan_svelte(
        self,
        file_path: Path,
        rel_path: str,
        content: str,
        component_tree: dict,
        navigation_map: list[dict[str, str]],
    ) -> list[Finding]:
        """Scan Svelte files for components."""
        findings = []

        # Look for Svelte component patterns
        # Svelte components are usually just functions or default exports
        comp_patterns = [
            r"export\s+let\s+",  # Svelte props
            r"<script[^>]*>.*?</script>",  # Script tags
            r"<style[^>]*>.*?</style>",  # Style tags
        ]

        for i, pattern in enumerate(comp_patterns):
            matches = re.finditer(pattern, content, re.DOTALL)
            for match in matches:
                line_start = content[: match.start()].count("\n") + 1
                desc = ["Svelte prop", "Svelte script", "Svelte style"][i]
                findings.append(
                    self._mkf(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=line_start,
                        title=f"Svelte {desc}",
                        description=f"Found {desc}",
                        evidence=match.group(0)[:100],
                    )
                )

        return findings

    def _scan_html(
        self,
        file_path: Path,
        rel_path: str,
        content: str,
        component_tree: dict,
        navigation_map: list[dict[str, str]],
    ) -> list[Finding]:
        """Scan HTML files for structure and issues."""
        findings = []

        # Look for common HTML patterns
        patterns = [
            (r"<title[^>]*>.*?</title>", "HTML Title"),
            (r"<form[^>]*>", "HTML Form"),
            (r"<input[^>]*>", "HTML Input"),
            (r"<button[^>]*>", "HTML Button"),
            (r"<nav[^>]*>", "Navigation"),
            (r"<header[^>]*>", "Header"),
            (r"<footer[^>]*>", "Footer"),
        ]

        for pattern, title in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_start = content[: match.start()].count("\n") + 1
                findings.append(
                    self._mkf(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=line_start,
                        title=title,
                        description=f"Found {title.lower()}",
                        evidence=match.group(0)[:100],
                    )
                )

        # Accessibility checks
        accessibility_checks = [
            (r"<img[^>]*>", "Images - check for alt attributes"),
            (r"<table[^>]*>", "Tables - check for proper headings"),
            (r"<label[^>]*>", "Labels - check for associated inputs"),
        ]

        for pattern, desc in accessibility_checks:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_start = content[: match.start()].count("\n") + 1
                findings.append(
                    self._mkf(
                        severity=Severity.LOW,
                        file=rel_path,
                        line_start=line_start,
                        title="Accessibility Check",
                        description=desc,
                        evidence=match.group(0)[:100],
                    )
                )

        return findings

    def _scan_css(
        self,
        file_path: Path,
        rel_path: str,
        content: str,
        component_tree: dict,
        navigation_map: list[dict[str, str]],
    ) -> list[Finding]:
        """Scan CSS files for patterns."""
        findings = []

        # Look for common CSS patterns
        patterns = [
            (r"\.([\w-]+)\s*\{", "CSS Class"),
            (r"#([\w-]+)\s*\{", "CSS ID"),
            (r"@media\s+", "Media Query"),
            (r"@import\s+", "Import Statement"),
            (r'url\([\'"]?[\w\/\.\-]+\.\w+[\'"]?\)', "Resource URL"),
        ]

        for pattern, title in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_start = content[: match.start()].count("\n") + 1
                findings.append(
                    self._mkf(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=line_start,
                        title=title,
                        description=f"Found {title.lower()}",
                        evidence=match.group(0),
                    )
                )

        return findings

    def _scan_template(
        self,
        file_path: Path,
        rel_path: str,
        content: str,
        component_tree: dict,
        navigation_map: list[dict[str, str]],
    ) -> list[Finding]:
        """Scan template files (Handlebars, EJS, etc.)."""
        findings = []

        # Look for template-specific patterns
        if file_path.suffix.lower() in [".hbs", ".handlebars"]:
            patterns = [
                (r"\{\{[#/]\s*(\w+)", "Handlebars Helper"),
                (r"\{\{!\s*.*?\s*\}\}", "Handlebars Comment"),
            ]
        elif file_path.suffix.lower() in [".ejs"]:
            patterns = [
                (r"<%\s*=?", "EJS Tag"),
                (r"<%-?\s*.*?\s*%>", "EJS Expression"),
            ]
        elif file_path.suffix.lower() in [".pug", ".jade"]:
            # Pug is indentation-based, harder to scan with regex
            findings.append(
                self._mkf(
                    severity=Severity.INFO,
                    file=rel_path,
                    line_start=0,
                    title="Pug/Jade Template",
                    description="Found Pug/Jade template file",
                    evidence=f"Lines: {len(content.splitlines())}",
                )
            )
            return findings
        else:
            # Generic template patterns
            patterns = [
                (r"\{\{.*?\}\}", "Template Variable"),
                (r"<%.*?%>", "Server-side Template"),
            ]

        for pattern, title in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_start = content[: match.start()].count("\n") + 1
                findings.append(
                    self._mkf(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=line_start,
                        title=title,
                        description=f"Found {title.lower()}",
                        evidence=match.group(0),
                    )
                )

        return findings
