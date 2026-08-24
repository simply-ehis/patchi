"""
Fix module for Patchi.

This module contains all the fix agents that generate patches for issues
found by the scanner agents.
"""

# Re-export all fix agents for backward compatibility
from .code_fixer import CodeFixer
from .dead_code_remover import DeadCodeRemover
from .security_fixer import SecurityFixer

__all__ = [
    "CodeFixer",
    "SecurityFixer",
    "DeadCodeRemover",
]
