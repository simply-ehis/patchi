"""
Plugin system for Patchi.

Provides a formal contract for analyzers, tools, and agents that can be
added without touching core code. New plugins are discovered automatically
from the plugins directory.

Usage:
    # To add a new analyzer, create a file in patchi/core/plugins/analyzers/
    # and define a class that inherits from Analyzer:

    from patchi.core.plugins.analyzer import Analyzer, AnalyzerResult

    class MyAnalyzer(Analyzer):
        name = "my-analyzer"
        version = "1.0.0"
        description = "Does something useful"

        def analyze(self, context) -> AnalyzerResult:
            # Your analysis logic here
            return AnalyzerResult(findings=[...])

    # That's it! The plugin is automatically discovered and registered.
"""

from patchi.core.plugins.analyzer import (
    Analyzer,
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    Severity,
)
from patchi.core.plugins.registry import (
    PluginRegistry,
    get_registry,
    list_plugins,
)

__all__ = [
    "Analyzer",
    "AnalyzerContext",
    "AnalyzerResult",
    "Finding",
    "Severity",
    "PluginRegistry",
    "get_registry",
    "list_plugins",
]
