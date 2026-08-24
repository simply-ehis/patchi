"""
Graph normalizer for standardizing Code Property Graphs across languages.
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class GraphNormalizer:
    """
    Normalizes Code Property Graphs from different language parsers
    into a unified format suitable for GNN inference.
    """

    NODE_TYPES = {
        "function_definition",
        "class_definition",
        "assignment",
        "if_statement",
        "for_loop",
        "while_loop",
        "try_block",
        "except_block",
        "return_statement",
        "import",
        "from_import",
        "comment",
        "empty",
        "statement",
        "expression",
        "call",
        "identifier",
        "literal",
        "operator",
    }

    EDGE_TYPES = {
        "contains",
        "calls",
        "reads",
        "writes",
        "depends_on",
        "controls",
        "returns",
        "throws",
    }

    def normalize(self, graph: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a graph to the standard CPG format.

        Args:
            graph: Raw graph from CPG extractor

        Returns:
            Normalized graph dictionary
        """
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        normalized_nodes = [self._normalize_node(n) for n in nodes]
        normalized_edges = [self._normalize_edge(e) for e in edges]

        # Remove empty nodes and re-index edges
        id_map = {}
        filtered_nodes = []
        for i, node in enumerate(normalized_nodes):
            if node.get("type") != "empty":
                old_id = node.get("id", i)
                new_id = len(filtered_nodes)
                id_map[old_id] = new_id
                node["id"] = new_id
                filtered_nodes.append(node)

        reindexed_edges = []
        for edge in normalized_edges:
            src = id_map.get(edge[0])
            dst = id_map.get(edge[1])
            if src is not None and dst is not None:
                reindexed_edges.append([src, dst, edge[2]])

        return {
            "nodes": filtered_nodes,
            "edges": reindexed_edges,
            "language": graph.get("language", "unknown"),
            "file_path": graph.get("file_path", ""),
            "metadata": graph.get("metadata", {}),
            "features": graph.get("features", []),
        }

    def _normalize_node(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single node."""
        node_type = node.get("type", "statement")
        if node_type not in self.NODE_TYPES:
            node_type = "statement"

        return {
            "id": node.get("id", 0),
            "type": node_type,
            "line": node.get("line", 0),
            "code": node.get("code", ""),
            "function": node.get("function", ""),
        }

    def _normalize_edge(self, edge: Any) -> List[Any]:
        """Normalize a single edge."""
        if not isinstance(edge, list) or len(edge) < 3:
            return [0, 0, "contains"]

        edge_type = edge[2]
        if edge_type not in self.EDGE_TYPES:
            edge_type = "contains"

        return [edge[0], edge[1], edge_type]

    def merge_graphs(self, graphs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge multiple normalized graphs into a single graph.

        Useful for analyzing relationships across multiple files.
        """
        all_nodes = []
        all_edges = []
        node_offset = 0

        for graph in graphs:
            for node in graph.get("nodes", []):
                new_node = node.copy()
                new_node["id"] = node.get("id", 0) + node_offset
                all_nodes.append(new_node)

            for edge in graph.get("edges", []):
                new_edge = [
                    edge[0] + node_offset,
                    edge[1] + node_offset,
                    edge[2],
                ]
                all_edges.append(new_edge)

            node_offset += len(graph.get("nodes", []))

        return {
            "nodes": all_nodes,
            "edges": all_edges,
            "language": "multi",
            "file_path": "",
            "metadata": {"merged_from": len(graphs)},
            "features": [],
        }