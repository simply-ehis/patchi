"""
Tests for the GNN vulnerability classifier.
"""

from patchi.core.agents.vulnerability_classifier import (
    VulnerabilityClassifier,
    VULNERABILITY_TYPES,
)


class TestVulnerabilityClassifier:
    """Tests for VulnerabilityClassifier."""

    def test_classify_nodes_empty_graph(self):
        """Test classification of empty graph."""
        classifier = VulnerabilityClassifier()
        graph = {"nodes": [], "edges": []}
        findings = classifier.classify_nodes(graph)
        assert findings == []

    def test_classify_safe_code(self):
        """Test classification of safe code."""
        classifier = VulnerabilityClassifier()
        graph = {
            "nodes": [
                {"id": 0, "type": "function_definition", "code": "def safe_function(): pass"},
                {"id": 1, "type": "return_statement", "code": "return True"},
            ],
            "edges": [[0, 1, "contains"]],
        }
        findings = classifier.classify_nodes(graph)
        # Safe code should produce no findings
        assert len(findings) == 0

    def test_classify_sql_injection(self):
        """Test detection of SQL injection vulnerability."""
        classifier = VulnerabilityClassifier()
        graph = {
            "nodes": [
                {"id": 0, "type": "call", "code": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)'},
            ],
            "edges": [],
        }
        findings = classifier.classify_nodes(graph)
        assert len(findings) > 0
        assert findings[0]["type"] == "sql_injection"
        assert findings[0]["severity"] == "high"

    def test_classify_command_injection(self):
        """Test detection of command injection vulnerability."""
        classifier = VulnerabilityClassifier()
        graph = {
            "nodes": [
                {"id": 0, "type": "call", "code": 'os.system("ls " + user_input)'},
            ],
            "edges": [],
        }
        findings = classifier.classify_nodes(graph)
        assert len(findings) > 0
        assert findings[0]["type"] == "command_injection"
        assert findings[0]["severity"] == "critical"

    def test_classify_xss(self):
        """Test detection of XSS vulnerability."""
        classifier = VulnerabilityClassifier()
        graph = {
            "nodes": [
                {"id": 0, "type": "call", "code": "request.args.get('name')"},
            ],
            "edges": [],
        }
        findings = classifier.classify_nodes(graph)
        assert len(findings) > 0
        assert findings[0]["type"] == "xss"

    def test_classify_hardcoded_secret(self):
        """Test detection of hardcoded secret."""
        classifier = VulnerabilityClassifier()
        graph = {
            "nodes": [
                {"id": 0, "type": "assignment", "code": 'api_key = "sk_1234567890abcdef"'},
            ],
            "edges": [],
        }
        findings = classifier.classify_nodes(graph)
        assert len(findings) > 0
        assert findings[0]["type"] == "information_disclosure"

    def test_rank_findings(self):
        """Test ranking of findings."""
        classifier = VulnerabilityClassifier()
        findings = [
            {"severity": "low", "confidence": 0.3},
            {"severity": "critical", "confidence": 0.9},
            {"severity": "high", "confidence": 0.7},
        ]
        ranked = classifier.rank_findings(findings)
        assert ranked[0]["severity"] == "critical"
        assert ranked[1]["severity"] == "high"
        assert ranked[2]["severity"] == "low"

    def test_vulnerability_types_defined(self):
        """Test that vulnerability types are defined."""
        assert len(VULNERABILITY_TYPES) > 0
        assert "sql_injection" in VULNERABILITY_TYPES
        assert "command_injection" in VULNERABILITY_TYPES


class TestGNNIntegration:
    """Integration tests for GNN components."""

    def test_cpg_to_classifier_pipeline(self, tmp_path):
        """Test full pipeline from CPG extraction to classification."""
        from patchi.core.agents.cpg_extractor import CPGExtractor

        extractor = CPGExtractor()
        classifier = VulnerabilityClassifier()

        test_file = tmp_path / "vuln.py"
        test_file.write_text("""
def vulnerable_function(user_input):
    cursor.execute("SELECT * FROM users WHERE name='" + user_input + "'")
    return cursor.fetchall()
""")
        graph = extractor.extract_graph(str(test_file), tmp_path)
        findings = classifier.classify_nodes(graph)

        # Should detect SQL injection
        assert len(findings) > 0
        assert any(f["type"] == "sql_injection" for f in findings)

    def test_security_agents_registered(self):
        """Test that PysaAgent and CodeqlAgent are registered."""
        # Importing security_agents triggers the eager registration pass;
        # without it the SECURITY group is empty in isolation (it only filled
        # up in the full suite via unrelated import side-effects).
        import patchi.core.security.security_agents  # noqa: F401

        from patchi.core.agents.base import list_agents, AgentGroup

        agents = list_agents(AgentGroup.SECURITY)
        agent_names = [a.name for a in agents]
        assert "PysaAgent" in agent_names
        assert "CodeqlAgent" in agent_names