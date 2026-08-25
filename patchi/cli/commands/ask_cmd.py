"""
CLI command for the Reasoning Engine.

Usage:
    p ask "what changed?"
    p ask "what does auth do?"
    p ask "what imports secrets?"
    p ask "security hotspots"
"""

from __future__ import annotations

import json
import sys


def run(args) -> None:
    """Entry point for ``p ask``."""
    # Handle args — could be namespace or list
    if hasattr(args, "question"):
        question = args.question
        json_output = getattr(args, "json_output", False)
    elif isinstance(args, list) and args:
        # Filter out flags
        non_flags = [a for a in args if not a.startswith("--")]
        question = " ".join(non_flags) if non_flags else ""
        json_output = "--json" in args
    else:
        print("Usage: p ask \"<question>\"", file=sys.stderr)
        sys.exit(1)

    if not question:
        print("Usage: p ask \"<question>\"", file=sys.stderr)
        sys.exit(1)

    from patchi.core.config import require_project_root
    root = require_project_root()

    from patchi.core.security.reasoning import answer_question

    result = answer_question(question, root)

    if json_output:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.answer)
