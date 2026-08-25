"""
Tests for the CPG extractor and graph normalizer.
"""

from patchi.core.agents.cpg_extractor import CPGExtractor
from patchi.core.agents.graph_normalizer import GraphNormalizer


class TestCPGExtractor:
    """Tests for CPGExtractor."""

    def test_extract_graph(self, tmp_path):
        """Test extraction from a file."""
        extractor = CPGExtractor()
        test_file = tmp_path / "test.py"
        test_file.write_text("""
def hello_world():
    print("Hello, World!")
    return True

class MyClass:
    def __init__(self):
        self.value = 42

    def method(self):
        if self.value > 0:
            return self.value
        return 0
""")
        graph = extractor.extract_graph(str(test_file), tmp_path)
        assert graph is not None
        assert "nodes" in graph
        assert "edges" in graph
        assert len(graph["nodes"]) > 0

    def test_extract_empty_file(self, tmp_path):
        """Test extraction from empty file."""
        extractor = CPGExtractor()
        test_file = tmp_path / "empty.py"
        test_file.write_text("")
        graph = extractor.extract_graph(str(test_file), tmp_path)
        assert graph is not None
        assert "nodes" in graph
        # Empty files produce a single "empty" placeholder node
        assert len(graph["nodes"]) <= 1
        if graph["nodes"]:
            assert graph["nodes"][0]["type"] == "empty"

    def test_extract_with_syntax_error(self, tmp_path):
        """Test extraction handles syntax errors gracefully."""
        extractor = CPGExtractor()
        test_file = tmp_path / "broken.py"
        test_file.write_text("def broken(:\n    print('missing paren')")
        graph = extractor.extract_graph(str(test_file), tmp_path)
        assert graph is not None
        assert "nodes" in graph

    def test_extract_javascript(self, tmp_path):
        """Test extraction from JavaScript file."""
        extractor = CPGExtractor()
        test_file = tmp_path / "test.js"
        test_file.write_text("""
function greet(name) {
    console.log("Hello " + name);
    return true;
}

class Person {
    constructor(name) {
        this.name = name;
    }
}
""")
        graph = extractor.extract_graph(str(test_file), tmp_path)
        assert graph is not None
        assert "nodes" in graph
        assert len(graph["nodes"]) > 0

    def test_unsupported_extension(self, tmp_path):
        """Test extraction from unsupported file type."""
        extractor = CPGExtractor()
        test_file = tmp_path / "test.xyz"
        test_file.write_text("not a real language")
        graph = extractor.extract_graph(str(test_file), tmp_path)
        assert graph is not None
        assert "nodes" in graph


class TestGraphNormalizer:
    """Tests for GraphNormalizer."""

    def test_init(self):
        """Test GraphNormalizer initialization."""
        normalizer = GraphNormalizer()
        assert normalizer is not None
        assert hasattr(normalizer, "normalize")

    def test_normalize_empty_graph(self):
        """Test normalization of empty graph."""
        normalizer = GraphNormalizer()
        graph = {"nodes": [], "edges": [], "language": "python"}
        result = normalizer.normalize(graph)
        assert result is not None
        assert "nodes" in result
        assert "edges" in result
        assert len(result["nodes"]) == 0

    def test_normalize_with_nodes(self):
        """Test normalization with nodes."""
        normalizer = GraphNormalizer()
        graph = {
            "nodes": [
                {"id": 0, "type": "function_definition", "code": "def foo(): pass"},
                {"id": 1, "type": "call", "code": "foo()"},
            ],
            "edges": [[0, 1, "calls"]],
            "language": "python",
        }
        result = normalizer.normalize(graph)
        assert len(result["nodes"]) == 2
        assert len(result["edges"]) == 1
        assert result["edges"][0][2] == "calls"

    def test_normalize_unknown_node_type(self):
        """Test normalization handles unknown node types."""
        normalizer = GraphNormalizer()
        graph = {
            "nodes": [{"id": 0, "type": "unknown_type", "code": "test"}],
            "edges": [],
            "language": "python",
        }
        result = normalizer.normalize(graph)
        assert len(result["nodes"]) == 1
        # Unknown types should be normalized to "statement"
        assert result["nodes"][0]["type"] == "statement"

    def test_normalize_unknown_edge_type(self):
        """Test normalization handles unknown edge types."""
        normalizer = GraphNormalizer()
        graph = {
            "nodes": [
                {"id": 0, "type": "function_definition", "code": "def foo(): pass"},
                {"id": 1, "type": "call", "code": "foo()"},
            ],
            "edges": [[0, 1, "unknown_edge"]],
            "language": "python",
        }
        result = normalizer.normalize(graph)
        assert len(result["edges"]) == 1
        # Unknown edges should be normalized to "contains"
        assert result["edges"][0][2] == "contains"

    def test_merge_graphs(self):
        """Test merging multiple graphs."""
        normalizer = GraphNormalizer()
        graph1 = {
            "nodes": [{"id": 0, "type": "function_definition", "code": "def foo(): pass"}],
            "edges": [],
            "language": "python",
        }
        graph2 = {
            "nodes": [{"id": 0, "type": "function_definition", "code": "def bar(): pass"}],
            "edges": [],
            "language": "python",
        }
        result = normalizer.merge_graphs([graph1, graph2])
        assert len(result["nodes"]) == 2
        # IDs should be re-indexed
        assert result["nodes"][0]["id"] == 0
        assert result["nodes"][1]["id"] == 1
