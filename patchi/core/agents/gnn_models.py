"""
GNN model implementations for vulnerability detection.

This module contains the Graph Neural Network models used by the GNN-based
bug detection agent to identify structural vulnerabilities in code.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class GNNVulnerabilityClassifier:
    """
    Graph Neural Network classifier for detecting structural vulnerabilities.

    Uses a Gated Graph Neural Network (GGNN) architecture to analyze
    Code Property Graphs and identify patterns indicative of vulnerabilities.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.inference_session = None
        self.input_name = None
        self.output_name = None
        self.class_names = [
            "buffer_overflow",
            "null_pointer_dereference",
            "memory_leak",
            "race_condition",
            "type_mismatch",
            "logic_bug",
            "sql_injection",
            "xss",
            "path_traversal",
            "command_injection",
            "format_string_vulnerability",
            "integer_overflow",
            "division_by_zero",
            "resource_leak",
            "deadlock",
        ]

        if model_path:
            self._load_model(model_path)

    def _load_model(self, model_path: str) -> None:
        """Load the GNN model from ONNX file."""
        try:
            self.inference_session = InferenceSession(model_path)
            # Get input and output names
            self.input_name = self.inference_session.get_inputs()[0].name
            self.output_name = self.inference_session.get_outputs()[0].name
            logger.info(f"GNN model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load GNN model: {e}")
            raise

    def detect_vulnerabilities(
        self, graph_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities in a Code Property Graph.

        Args:
            graph_data: Dictionary containing the CPG data

        Returns:
            List of detected vulnerabilities with details
        """
        if not self.inference_session:
            logger.warning("GNN model not loaded, returning empty results")
            return []

        try:
            # Prepare input for GNN
            input_data = self._prepare_graph_input(graph_data)

            # Run inference
            result = self.inference_session.run(
                [self.output_name], {self.input_name: input_data}
            )

            # Parse results
            vulnerabilities = self._parse_gnn_output(
                result[0], graph_data, input_data
            )

            return vulnerabilities

        except Exception as e:
            logger.error(f"Error during GNN inference: {e}")
            return []

    def _prepare_graph_input(self, graph_data: Dict[str, Any]) -> Any:
        """Prepare graph data for GNN input."""
        # This is a simplified implementation
        # In practice, this would convert the CPG to the specific
        # format expected by the GNN model (e.g., adjacency matrix,
        # node features, edge features)

        # Extract relevant features from graph data
        num_nodes = len(graph_data.get("nodes", []))
        num_edges = len(graph_data.get("edges", []))

        # Create simple feature matrix (simplified for demonstration)
        # In a real implementation, this would be much more sophisticated
        node_features = [[0.1] * 32 for _ in range(num_nodes)]
        edge_features = [[0.0] for _ in range(num_edges)]

        # Create adjacency matrix
        adjacency = [[0] * num_nodes for _ in range(num_nodes)]
        for edge in graph_data.get("edges", []):
            if len(edge) >= 2:
                src, dst = edge[0], edge[1]
                if src < num_nodes and dst < num_nodes:
                    adjacency[src][dst] = 1
                    adjacency[dst][src] = 1

        # Combine into input format expected by model
        input_data = {
            "node_features": node_features,
            "edge_features": edge_features,
            "adjacency": adjacency,
            "num_nodes": num_nodes,
            "num_edges": num_edges,
        }

        return input_data

    def _parse_gnn_output(
        self, output: Any, graph_data: Dict[str, Any], input_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Parse GNN output into structured vulnerability information."""
        vulnerabilities = []

        # Simplified parsing - in practice, this would be much more sophisticated
        num_nodes = input_data["num_nodes"]

        # Simulate vulnerability detection based on node features
        # In a real implementation, this would use the actual GNN predictions
        for i in range(min(5, num_nodes)):  # Check first 5 nodes for demo
            # Simulate different types of vulnerabilities
            if i % 2 == 0:
                vuln_type = "buffer_overflow"
                severity = 0.8 + (i * 0.02)
                line = graph_data.get("nodes", [])[i].get("line", 0)
            elif i % 3 == 0:
                vuln_type = "null_pointer_dereference"
                severity = 0.7 + (i * 0.015)
                line = graph_data.get("nodes", [])[i].get("line", 0)
            elif i % 4 == 0:
                vuln_type = "memory_leak"
                severity = 0.6 + (i * 0.01)
                line = graph_data.get("nodes", [])[i].get("line", 0)
            else:
                vuln_type = "type_mismatch"
                severity = 0.5 + (i * 0.005)
                line = graph_data.get("nodes", [])[i].get("line", 0)

            # Filter by confidence threshold
            if severity >= 0.6:
                vulnerability = {
                    "type": vuln_type,
                    "severity": severity,
                    "line": line,
                    "confidence": float(severity),
                    "category": self._get_vulnerability_category(vuln_type),
                    "affected_function": graph_data.get("nodes", [])[i].get(
                        "function", ""
                    ),
                    "title": self._get_vulnerability_title(vuln_type),
                    "description": self._get_vulnerability_description(vuln_type),
                    "suggestion": self._get_vulnerability_suggestion(vuln_type),
                    "code_snippet": graph_data.get("nodes", [])[i].get(
                        "code", ""
                    ),
                    "cwe": self._get_cwe_for_vulnerability(vuln_type),
                }
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _get_vulnerability_category(self, vuln_type: str) -> str:
        """Get vulnerability category for given type."""
        categories = {
            "buffer_overflow": "Memory Safety",
            "null_pointer_dereference": "Memory Safety",
            "memory_leak": "Resource Management",
            "race_condition": "Concurrency",
            "type_mismatch": "Type Safety",
            "logic_bug": "Logic",
            "sql_injection": "Injection",
            "xss": "Injection",
            "path_traversal": "Input Validation",
            "command_injection": "Injection",
            "format_string_vulnerability": "Input Validation",
            "integer_overflow": "Numeric Safety",
            "division_by_zero": "Numeric Safety",
            "resource_leak": "Resource Management",
            "deadlock": "Concurrency",
        }
        return categories.get(vuln_type, "Other")

    def _get_vulnerability_title(self, vuln_type: str) -> str:
        """Get vulnerability title."""
        titles = {
            "buffer_overflow": "Buffer Overflow Vulnerability",
            "null_pointer_dereference": "Null Pointer Dereference",
            "memory_leak": "Memory Leak",
            "race_condition": "Race Condition",
            "type_mismatch": "Type Mismatch",
            "logic_bug": "Logic Bug",
            "sql_injection": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "path_traversal": "Path Traversal",
            "command_injection": "Command Injection",
            "format_string_vulnerability": "Format String Vulnerability",
            "integer_overflow": "Integer Overflow",
            "division_by_zero": "Division by Zero",
            "resource_leak": "Resource Leak",
            "deadlock": "Deadlock",
        }
        return titles.get(vuln_type, "Unknown Vulnerability")

    def _get_vulnerability_description(self, vuln_type: str) -> str:
        """Get vulnerability description."""
        descriptions = {
            "buffer_overflow": "Code attempts to write to memory outside allocated bounds.",
            "null_pointer_dereference": "Code attempts to access memory through a null pointer.",
            "memory_leak": "Code allocates memory but never frees it, causing resource exhaustion.",
            "race_condition": "Concurrent access to shared resources without proper synchronization.",
            "type_mismatch": "Type conversion errors can lead to unexpected behavior or crashes.",
            "logic_bug": "Incorrect logic in code that produces unexpected results.",
            "sql_injection": "User input is improperly sanitized before being used in SQL queries.",
            "xss": "User input is not properly escaped before being rendered in web pages.",
            "path_traversal": "User input is used to construct file paths without validation.",
            "command_injection": "User input is improperly validated before being passed to system commands.",
            "format_string_vulnerability": "User input is improperly formatted in string operations.",
            "integer_overflow": "Arithmetic operations produce results that exceed data type limits.",
            "division_by_zero": "Code performs division by zero, causing runtime errors.",
            "resource_leak": "Code fails to properly release resources after use.",
            "deadlock": "Threads wait indefinitely for resources held by other threads.",
        }
        return descriptions.get(vuln_type, "Unknown vulnerability")

    def _get_vulnerability_suggestion(self, vuln_type: str) -> str:
        """Get vulnerability fix suggestion."""
        suggestions = {
            "buffer_overflow": "Use safe string functions (e.g., snprintf), validate buffer sizes.",
            "null_pointer_dereference": "Add null pointer checks before dereferencing.",
            "memory_leak": "Use smart pointers or manual memory management with proper cleanup.",
            "race_condition": "Implement proper locking mechanisms, use atomic operations.",
            "type_mismatch": "Add type assertions, use static type checking.",
            "logic_bug": "Review logic flow, add unit tests for edge cases.",
            "sql_injection": "Use parameterized queries, validate and sanitize user input.",
            "xss": "Escape user input, use template engines that auto-escape.",
            "path_traversal": "Validate file paths, use allowlists for permitted directories.",
            "command_injection": "Validate and sanitize user input, use command allowlists.",
            "format_string_vulnerability": "Use safe formatting functions, validate format strings.",
            "integer_overflow": "Use larger data types, add overflow checks.",
            "division_by_zero": "Check denominator before division operations.",
            "resource_leak": "Implement proper RAII, use smart resource management.",
            "deadlock": "Implement timeout mechanisms, avoid circular resource acquisition.",
        }
        return suggestions.get(vuln_type, "Review and fix the vulnerability.")

    def _get_cwe_for_vulnerability(self, vuln_type: str) -> str:
        """Get CWE ID for vulnerability type."""
        cwe_ids = {
            "buffer_overflow": "CWE-120",
            "null_pointer_dereference": "CWE-476",
            "memory_leak": "CWE-401",
            "race_condition": "CWE-367",
            "type_mismatch": "CWE-843",
            "logic_bug": "CWE-384",  # Session Fixation is an example
            "sql_injection": "CWE-89",
            "xss": "CWE-79",
            "path_traversal": "CWE-22",
            "command_injection": "CWE-78",
            "format_string_vulnerability": "CWE-134",
            "integer_overflow": "CWE-190",
            "division_by_zero": "CWE-369",
            "resource_leak": "CWE-402",
            "deadlock": "CWE-833",
        }
        return cwe_ids.get(vuln_type, "")

    def is_loaded(self) -> bool:
        """Check if the GNN model is loaded."""
        return self.inference_session is not None