# GNN-Based Bug Detection Implementation Plan

## Overview
This plan outlines the implementation of a Graph Neural Network (GNN) based bug detection system for Patchi. The GNN will operate as a two-stage hybrid framework that complements the existing static analysis and AI-powered fix generation pipeline.

## Technical Approach

### Graph-Based Analysis
- **Code Property Graphs (CPGs)**: Structural representations combining AST, CFG, and DDG
- **Language-Agnostic Parsing**: Uses Joern/Tree-sitter for cross-language analysis
- **Lightweight GNN Models**: 15M parameter models running in <5ms per function
- **Vulnerability Classification**: Detects buffer overflows, null pointer dereferences, race conditions, memory leaks, and logic bugs

### Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Source Code   │    │ Code Property   │    │ GNN Classifier  │
│                 │    │     Graph      │    │   (VulGraB/    │
│   (Multiple     │───▶│   (CPG)         │───▶│  DevGNN/GGNN) │
│   Languages)    │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Static         │    │  Graph          │    │  Bug           │
│  Analysis       │    │  Extraction     │    │  Detection     │
│  (Existing)     │    │  (Joern/TS)     │    │  (Structural)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Implementation Phases

### Phase 1: Core GNN Detector (Days 1-5)

#### 1.1 Create GNN Agent Infrastructure
**Files to create:**
- `patchi/core/agents/gnn_detector.py` - Main GNN agent class
- `patchi/core/agents/gnn_models.py` - GNN model implementations
- `patchi/core/agents/gnn_utils.py` - Utility functions for graph processing

**Key Features:**
- Inherits from `BaseAgent`
- ONNX Runtime integration for model inference
- Configurable model loading and inference
- Error handling and retry logic

#### 1.2 Graph Processing Pipeline
**Files to create:**
- `patchi/core/agents/cpg_extractor.py` - Code Property Graph extraction
- `patchi/core/agents/graph_normalizer.py` - Graph standardization across languages
- `patchi/core/agents/vulnerability_classifier.py` - GNN-based vulnerability detection

**Language Support:**
- C/C++ (via Joern)
- Java (via Tree-sitter)
- Python (via Tree-sitter)
- JavaScript/TypeScript (via Tree-sitter)
- Go (via Tree-sitter)
- Rust (via Tree-sitter)

#### 1.3 Integration with Existing Pipeline
**Updates needed:**
- `patchi/core/agents/base.py` - Register GNN detector in agent registry
- `patchi/core/agents/__init__.py` - Export GNN agent
- `patchi/core/agents/agent_registry.py` - Add GNN to agent groups

### Phase 2: Orchestrator Integration (Days 6-12)

#### 2.1 Agent Group Management
**Files to update:**
- `patchi/core/agents/base.py` - Create `AgentGroup.GNN_DETECTION`
- `patchi/core/agents/agent_registry.py` - Register GNN detector

#### 2.2 Pipeline Flow Integration
**Implementation details:**
- GNN detector runs as a separate phase in the scan pipeline
- Results are merged with existing static analysis findings
- GNN findings are routed to appropriate fix agents based on vulnerability type
- Optional parallel execution with other detectors for performance

### Phase 3: Testing & Validation (Days 13-20)

#### 3.1 Test Suite Creation
**Files to create:**
- `tests/test_gnn_detector.py` - Unit tests for GNN inference
- `tests/test_cpg_extractor.py` - Tests for graph extraction
- `tests/test_gnn_integration.py` - Integration tests

#### 3.2 Validation Framework
**Implementation:**
- Create test fixtures for various bug patterns
- Benchmark against existing static analysis tools
- Measure performance characteristics (latency, memory, accuracy)

### Phase 4: Architecture Enhancements (Days 21-28)

#### 4.1 Memory Management
**Features:**
- Graph caching for repeated analyses
- Incremental graph updates for modified files
- Efficient serialization/deserialization
- Resource usage monitoring and limits

#### 4.2 Configuration & Deployment
**Implementation:**
- YAML/JSON configuration files for model settings
- Command-line options for language selection
- Performance tuning parameters
- Docker/container support

## Technical Implementation Details

### GNN Model Integration

```python
# patchi/core/agents/gnn_detector.py
class GNNBugDetector(BaseAgent):
    name = "GNNBugDetector"
    group = AgentGroup.GNN_DETECTION
    timeout = 30
    
    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Process files through GNN pipeline
        for file_path in self._get_files_to_analyze(inp):
            cpg = self._extract_code_property_graph(file_path)
            vulnerabilities = self._detect_vulnerabilities(cpg)
            
            for vuln in vulnerabilities:
                finding = make_finding(
                    agent=self.name,
                    finding_type=vuln.type,
                    severity=self._map_severity(vuln.severity),
                    file=file_path,
                    line=vuln.line,
                    message=vuln.title,
                    detail=vuln.description,
                    fix_agent=self._determine_fix_agent(vuln),
                    cwe=vuln.cwe
                )
                result.add_finding(finding)
```

### Performance Considerations

#### Graph Extraction Optimization
- Incremental analysis for modified files
- Parallel processing for multiple files
- Efficient graph serialization

#### Inference Optimization
- Model quantization for edge deployment
- Batch processing for better throughput
- Hardware acceleration (CPU/GPU)

## Expected Benefits

### Quality Improvements
- **Lower false positives**: Structural analysis reduces noise
- **Earlier detection**: Catches bugs static analysis misses
- **Cross-language consistency**: Unified approach across languages

### Performance
- **Fast inference**: <5ms per function
- **Low memory**: <100MB RAM
- **Scalable**: Handles large codebases efficiently

### Integration
- **Non-invasive**: Works alongside existing tools
- **Extensible**: Easy to add new vulnerability types
- **Configurable**: Can tune sensitivity/performance tradeoff

## Testing Strategy

### Unit Tests
- Graph extraction correctness
- GNN inference validation
- Vulnerability classification accuracy

### Integration Tests
- End-to-end pipeline testing
- Cross-language compatibility
- Performance under load

### Regression Tests
- Comparison with existing tools
- Stability over time
- Resource usage monitoring

## Risk Mitigation

### Technical Risks
1. **Model compatibility**: Use ONNX Runtime for model-agnostic inference
2. **Graph parsing complexity**: Implement robust error handling and fallback mechanisms
3. **Performance bottlenecks**: Optimize with caching and parallel processing

### Operational Risks
1. **Resource usage**: Implement resource monitoring and limits
2. **Deployment complexity**: Provide comprehensive documentation and examples
3. **Testing coverage**: Create extensive test coverage for all components

## Project Timeline

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| Phase 1 | Days 1-5 | GNN agent core, graph extraction |
| Phase 2 | Days 6-12 | Integration with pipeline |
| Phase 3 | Days 13-20 | Test suite and validation |
| Phase 4 | Days 21-28 | Architecture enhancements |

## Success Metrics

1. **Detection Accuracy**: >90% detection rate for common vulnerability patterns
2. **Performance**: <10ms per 1KLOC
3. **Resource Usage**: <100MB RAM for full analysis
4. **Integration**: Seamlessly works with existing Patchi pipeline
5. **User Adoption**: Easy configuration and deployment

## Next Steps

1. **Initialize repository**: Create new branch and set up version control
2. **Create skeleton code**: Implement basic class structures and interfaces
3. **Develop core components**: Build GNN agent, graph extraction, and classification
4. **Implement tests**: Create comprehensive test suite
5. **Integrate**: Connect with existing Patchi pipeline
6. **Validate**: Benchmark and optimize

## Files Created/TBD

### New Files (to be created)
- `patchi/core/agents/gnn_detector.py`
- `patchi/core/agents/gnn_models.py`
- `patchi/core/agents/cpg_extractor.py`
- `patchi/core/agents/graph_normalizer.py`
- `patchi/core/agents/vulnerability_classifier.py`
- `tests/test_gnn_detector.py`
- `tests/test_cpg_extractor.py`
- `tests/test_gnn_integration.py`
- `docs/gnn_implementation.md` (implementation guide)

### Modified Files (to be updated)
- `patchi/core/agents/base.py`
- `patchi/core/agents/agent_registry.py`
- `patchi/core/agents/__init__.py`

## Conclusion

This GNN-based bug detection system will significantly enhance Patchi's ability to detect structural vulnerabilities across multiple programming languages. By operating on Code Property Graphs rather than raw text, the GNN approach provides deeper semantic understanding and reduces false positives compared to traditional static analysis tools.

The implementation follows an incremental approach, starting with core GNN capabilities and progressively integrating with the existing Patchi ecosystem. This ensures stability while delivering immediate value through improved bug detection.

The project is positioned to deliver a robust, high-performance bug detection solution that complements and extends Patchi's existing capabilities.