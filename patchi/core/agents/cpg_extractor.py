"""
Code Property Graph (CPG) extractor for Patchi's GNN-based bug detection system.
"""

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CPGExtractor:
    """
    Code Property Graph (CPG) extractor.

    This class extracts and standardizes Code Property Graphs from source code
    across multiple programming languages. A CPG combines AST, CFG, and DDG
    to provide a comprehensive structural representation of code.
    """

    def __init__(self):
        self.supported_languages = [
            "python",
            "c",
            "cpp",
            "java",
            "javascript",
            "typescript",
            "go",
            "rust",
        ]
        self.parsers = {}

    def extract_graph(self, file_path: str, project_root: Any) -> Dict[str, Any]:
        """
        Extract Code Property Graph from source file.

        Args:
            file_path: Path to the source file
            project_root: Root directory of the project

        Returns:
            Dictionary containing the CPG data
        """
        try:
            # Determine file language
            file_ext = Path(file_path).suffix.lower()
            language = self._detect_language(file_ext)

            if not language:
                logger.warning(f"Unsupported file extension: {file_ext}")
                return self._create_empty_graph()

            # Extract graph based on language
            graph = self._extract_graph_for_language(
                file_path, language, project_root
            )

            # Standardize graph format
            standardized_graph = self._standardize_graph(graph)

            return standardized_graph

        except Exception as e:
            logger.error(f"Error extracting CPG: {e}")
            return self._create_empty_graph()

    def _detect_language(self, file_ext: str) -> Optional[str]:
        """Detect programming language based on file extension."""
        extension_map = {
            ".py": "python",
            ".pyw": "python",
            ".pyx": "python",
            ".java": "java",
            ".c": "c",
            ".h": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".hpp": "cpp",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".html": "html",
            ".xml": "xml",
        }

        return extension_map.get(file_ext)

    def _extract_graph_for_language(
        self, file_path: str, language: str, project_root: Any
    ) -> Dict[str, Any]:
        """Extract graph for specific language."""
        # Simplified implementation - in practice, this would use
        # Joern, Tree-sitter, or other language-specific parsers

        try:
            # Read file content
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Extract basic structure based on language
            if language == "python":
                return self._extract_python_graph(content, file_path)
            elif language in ("c", "cpp"):
                return self._extract_c_cpp_graph(content, file_path)
            elif language == "java":
                return self._extract_java_graph(content, file_path)
            elif language in ("javascript", "typescript"):
                return self._extract_js_ts_graph(content, file_path)
            else:
                return self._extract_generic_graph(content, file_path)

        except Exception as e:
            logger.error(f"Error extracting graph for {language}: {e}")
            return self._create_empty_graph()

    def _extract_python_graph(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract Python-specific graph structure."""
        # Simulate Python AST extraction
        lines = content.split("\n")
        nodes = []
        edges = []

        for i, line in enumerate(lines):
            # Create node for each line (simplified)
            node_id = i
            node_type = self._get_python_node_type(line)
            node_info = {
                "id": node_id,
                "type": node_type,
                "line": i + 1,
                "code": line.strip(),
                "function": self._extract_python_function(line, nodes),
            }
            nodes.append(node_info)

        # Create simple edges (parent-child relationships)
        for i, node in enumerate(nodes):
            if i > 0:
                edges.append([i - 1, i, "contains"])

        return {
            "nodes": nodes,
            "edges": edges,
            "language": "python",
            "file_path": file_path,
        }

    def _extract_c_cpp_graph(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract C/C++-specific graph structure."""
        # Similar to Python but with C-specific constructs
        return self._extract_generic_graph(content, file_path)

    def _extract_java_graph(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract Java-specific graph structure."""
        return self._extract_generic_graph(content, file_path)

    def _extract_js_ts_graph(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract JavaScript/TypeScript-specific graph structure."""
        return self._extract_generic_graph(content, file_path)

    def _extract_generic_graph(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract generic graph structure."""
        lines = content.split("\n")
        nodes = []
        edges = []

        for i, line in enumerate(lines):
            node_id = i
            node_type = self._get_generic_node_type(line)
            node_info = {
                "id": node_id,
                "type": node_type,
                "line": i + 1,
                "code": line.strip(),
                "function": self._extract_function_from_line(line),
            }
            nodes.append(node_info)

        # Create edges
        for i, node in enumerate(nodes):
            if i > 0:
                edges.append([i - 1, i, "contains"])

        return {
            "nodes": nodes,
            "edges": edges,
            "language": "generic",
            "file_path": file_path,
        }

    def _get_python_node_type(self, line: str) -> str:
        """Get Python AST node type for a line."""
        line = line.strip()
        if not line:
            return "empty"
        elif line.startswith("#"):
            return "comment"
        elif line.startswith("def "):
            return "function_definition"
        elif line.startswith("class "):
            return "class_definition"
        elif line.startswith("import "):
            return "import"
        elif line.startswith("from "):
            return "from_import"
        elif "=" in line and not line.startswith("#"):
            return "assignment"
        elif line.startswith("if "):
            return "if_statement"
        elif line.startswith("for "):
            return "for_loop"
        elif line.startswith("while "):
            return "while_loop"
        elif line.startswith("try "):
            return "try_block"
        elif line.startswith("except "):
            return "except_block"
        else:
            return "statement"

    def _get_generic_node_type(self, line: str) -> str:
        """Get generic node type for a line."""
        line = line.strip()
        if not line:
            return "empty"
        elif line.startswith("#"):
            return "comment"
        elif "function" in line.lower() and "def" in line:
            return "function_definition"
        elif "class" in line.lower():
            return "class_definition"
        elif "import" in line.lower():
            return "import"
        elif "if" in line.lower() and line.startswith("if"):
            return "if_statement"
        elif "for" in line.lower() and line.startswith("for"):
            return "for_loop"
        elif "while" in line.lower() and line.startswith("while"):
            return "while_loop"
        elif "=" in line and not line.startswith("#"):
            return "assignment"
        else:
            return "statement"

    def _extract_python_function(self, line: str, nodes: List[Dict[str, Any]]) -> str:
        """Extract Python function name from line."""
        if line.startswith("def "):
            return line[4:].split("(")[0].strip()
        return ""

    def _extract_function_from_line(self, line: str) -> str:
        """Extract function name from line."""
        line = line.strip()
        if line.startswith("def "):
            return line[4:].split("(")[0].strip()
        elif line.startswith("class "):
            return line[6:].strip()
        elif "function" in line:
            return "anonymous"
        return ""

    def _standardize_graph(self, graph: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize graph format for GNN input."""
        # Ensure consistent structure
        standardized = {
            "nodes": graph.get("nodes", []),
            "edges": graph.get("edges", []),
            "language": graph.get("language", "unknown"),
            "file_path": graph.get("file_path", ""),
            "metadata": {
                "created_at": time.time(),
                "version": "1.0",
                "format": "cpg_v1",
            },
        }

        # Add derived features for GNN
        standardized["features"] = self._compute_node_features(
            standardized["nodes"]
        )

        return standardized

    def _compute_node_features(self, nodes: List[Dict[str, Any]]) -> List[List[float]]:
        """Compute features for each node."""
        features = []
        for node in nodes:
            # Simple feature vector based on node type and content
            node_type = node.get("type", "")
            code = node.get("code", "")

            # Type one-hot encoding
            type_one_hot = [0.0] * len(self.supported_languages)
            if node_type in self.supported_languages:
                idx = self.supported_languages.index(node_type)
                type_one_hot[idx] = 1.0

            # Code length feature
            code_length = min(len(code), 100) / 100.0

            # Complexity heuristic (simplified)
            complexity = self._estimate_complexity(code)

            # Combine features
            node_features = type_one_hot + [code_length, complexity]
            features.append(node_features)

        return features

    def _estimate_complexity(self, code: str) -> float:
        """Estimate complexity of code snippet."""
        complexity = 0.0

        # Count control structures
        if "if" in code.lower():
            complexity += 0.2
        if "for" in code.lower():
            complexity += 0.2
        if "while" in code.lower():
            complexity += 0.2
        if "try" in code.lower():
            complexity += 0.1
        if "except" in code.lower():
            complexity += 0.1

        # Count function calls
        complexity += min(code.count("."), 5) * 0.1

        # Normalize to [0, 1]
        return min(complexity, 1.0)

    def _create_empty_graph(self) -> Dict[str, Any]:
        """Create an empty graph structure."""
        return {
            "nodes": [],
            "edges": [],
            "language": "unknown",
            "file_path": "",
            "features": [],
        }
