"""
Plugin registry with auto-discovery for Patchi.

Automatically discovers and registers analyzers from:
  1. patchi/core/plugins/analyzers/ (built-in)
  2. ~/.patchi/plugins/ (user plugins)
  3. .patchi/plugins/ (project plugins)

Usage:
    from patchi.core.plugins.registry import get_registry

    registry = get_registry()
    results = registry.run_all(context)

    # Or run specific analyzer
    result = registry.run("secret-scanner", context)
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
import time
from pathlib import Path

from patchi.core.plugins.analyzer import (
    Analyzer,
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    Severity,
)

_log = logging.getLogger("patchi.plugins")


class PluginRegistry:
    """Registry for discovering and running analyzers.

    Features:
    - Auto-discovery from plugin directories
    - Lazy loading (only import when needed)
    - Priority-based execution order
    - Timeout enforcement
    - Error isolation (one plugin can't crash others)
    """

    def __init__(self) -> None:
        self._analyzers: dict[str, Analyzer] = {}
        self._loaded: bool = False
        self._load_time_ms: int = 0

    def discover(self, extra_dirs: list[Path] | None = None) -> list[str]:
        """Discover and register all analyzers.

        Returns list of errors (empty = success).
        """
        if self._loaded:
            return []

        t0 = time.monotonic()
        errors: list[str] = []

        # Plugin search paths
        search_paths = [
            Path(__file__).parent / "analyzers",  # built-in
            Path.home() / ".patchi" / "plugins",  # user
            Path.cwd() / ".patchi" / "plugins",  # project
        ]
        if extra_dirs:
            search_paths.extend(extra_dirs)

        for plugin_dir in search_paths:
            if not plugin_dir.exists():
                continue

            _log.debug("Discovering plugins in %s", plugin_dir)

            # Walk all Python files in the plugin directory
            for py_file in plugin_dir.glob("**/*.py"):
                if py_file.name.startswith("_"):
                    continue

                try:
                    self._load_plugin_file(py_file, plugin_dir)
                except Exception as e:
                    errors.append(f"{py_file}: {type(e).__name__}: {e}")
                    _log.debug("Failed to load plugin %s: %s", py_file, e)

        # Also discover from AGENT_PACKAGES (existing agents)
        try:
            self._discover_from_agent_packages()
        except Exception as e:
            errors.append(f"Agent package discovery: {type(e).__name__}: {e}")

        self._loaded = True
        self._load_time_ms = int((time.monotonic() - t0) * 1000)

        _log.info(
            "Plugin discovery complete: %d analyzers in %dms",
            len(self._analyzers),
            self._load_time_ms,
        )

        return errors

    def _load_plugin_file(self, py_file: Path, base_dir: Path) -> None:
        """Load a single plugin file and register any Analyzer subclasses."""
        # Compute module name relative to base_dir
        rel = py_file.relative_to(base_dir)
        module_name = f"patchi.plugins.{rel.stem}"

        # Skip if already loaded
        if module_name in sys.modules:
            return

        # Load the module
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        if not spec or not spec.loader:
            return

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        # Find and register any Analyzer subclasses
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, Analyzer)
                and attr is not Analyzer
            ):
                self.register_analyzer(attr())

    def _discover_from_agent_packages(self) -> None:
        """Discover analyzers from existing agent packages.

        This wraps existing BaseAgent subclasses as analyzers for backwards
        compatibility.
        """
        try:
            from patchi.core.agents.base import (
                _REGISTRY,
                discover_agent_modules,
            )

            # Discover all agents first
            discover_agent_modules()

            # Wrap each agent as an analyzer
            for name, agent_cls in _REGISTRY.items():
                if name not in self._analyzers:
                    wrapper = AgentAnalyzerWrapper(agent_cls)
                    self._analyzers[name] = wrapper

        except ImportError:
            pass

    def register_analyzer(self, analyzer: Analyzer) -> None:
        """Register an analyzer instance."""
        if analyzer.name in self._analyzers:
            _log.warning(
                "Analyzer '%s' already registered, overriding",
                analyzer.name,
            )
        self._analyzers[analyzer.name] = analyzer
        _log.debug("Registered analyzer: %s v%s", analyzer.name, analyzer.version)

    def get(self, name: str) -> Analyzer | None:
        """Get an analyzer by name."""
        if not self._loaded:
            self.discover()
        return self._analyzers.get(name)

    def list_analyzers(self, enabled_only: bool = True) -> list[Analyzer]:
        """List all registered analyzers."""
        if not self._loaded:
            self.discover()

        analyzers = list(self._analyzers.values())
        if enabled_only:
            analyzers = [a for a in analyzers if a.enabled]

        return sorted(analyzers, key=lambda a: (a.priority, a.name))

    def run(self, name: str, context: AnalyzerContext) -> AnalyzerResult:
        """Run a specific analyzer by name."""
        analyzer = self.get(name)
        if not analyzer:
            return AnalyzerResult(
                errors=[f"Analyzer '{name}' not found"],
            )

        return self._run_with_timeout(analyzer, context)

    def run_all(
        self,
        context: AnalyzerContext,
        analyzers: list[str] | None = None,
    ) -> dict[str, AnalyzerResult]:
        """Run all (or specified) analyzers and return results.

        Args:
            context: The analysis context
            analyzers: Optional list of analyzer names to run (None = all)

        Returns:
            Dict mapping analyzer name to its result
        """
        if not self._loaded:
            self.discover()

        to_run = self.list_analyzers(enabled_only=True)
        if analyzers:
            to_run = [a for a in to_run if a.name in analyzers]

        results: dict[str, AnalyzerResult] = {}
        for analyzer in to_run:
            try:
                results[analyzer.name] = self._run_with_timeout(analyzer, context)
            except Exception as e:
                results[analyzer.name] = AnalyzerResult(
                    errors=[f"{type(e).__name__}: {e}"],
                )
                _log.debug("Analyzer %s failed: %s", analyzer.name, e)

        return results

    def _run_with_timeout(
        self,
        analyzer: Analyzer,
        context: AnalyzerContext,
    ) -> AnalyzerResult:
        """Run an analyzer with timeout enforcement."""
        import concurrent.futures

        t0 = time.monotonic()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(analyzer.analyze, context)
                result = future.result(timeout=analyzer.timeout)
                result.duration_ms = int((time.monotonic() - t0) * 1000)

                # Set analyzer name on all findings for stable IDs
                for finding in result.findings:
                    finding.extra["_analyzer"] = analyzer.name

                return result

        except concurrent.futures.TimeoutError:
            return AnalyzerResult(
                errors=[f"Analyzer '{analyzer.name}' timed out after {analyzer.timeout}s"],
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        except Exception as e:
            return AnalyzerResult(
                errors=[f"{type(e).__name__}: {e}"],
                duration_ms=int((time.monotonic() - t0) * 1000),
            )


class AgentAnalyzerWrapper(Analyzer):
    """Wraps an existing BaseAgent as an Analyzer for backwards compatibility."""

    def __init__(self, agent_cls: type) -> None:
        self._agent_cls = agent_cls
        self.name = getattr(agent_cls, "name", "unknown")
        self.version = "0.0.0"
        self.description = f"Legacy agent wrapper for {self.name}"
        self.priority = 200  # Run after native analyzers
        self.timeout = getattr(agent_cls, "timeout", 60)

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        """Wrap agent execution as analyzer."""
        from patchi.core.agents.base import AgentInput

        # Convert AnalyzerContext to AgentInput
        agent_input = AgentInput(
            root=context.root,
            scope=context.scope,
            brain={},
            config=context.config,
            extra=context.extra,
        )

        # Run the agent
        agent = self._agent_cls()
        result = agent.run(agent_input)

        # Convert AgentResult to AnalyzerResult
        findings = []
        for f in result.findings:
            findings.append(Finding(
                file=f.file,
                line=f.line,
                type=f.type,
                severity=Severity(f.severity.value),
                message=f.message,
                detail=f.detail,
                code_snippet=f.code_snippet,
                suggestion=f.suggestion,
                cwe=f.cwe,
                extra={"_legacy_agent": True},
            ))

        return AnalyzerResult(
            findings=findings,
            metrics=result.data,
            errors=result.errors,
            duration_ms=result.duration_ms,
            files_analyzed=len(context.files),
        )


# ── Singleton ─────────────────────────────────────────────────────────────────

_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    """Get or create the global plugin registry."""
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry


def list_plugins() -> list[dict]:
    """List all registered plugins with their metadata."""
    registry = get_registry()
    return [a.describe() for a in registry.list_analyzers()]
