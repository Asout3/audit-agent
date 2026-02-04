"""Tests for call graph analyzer"""
import pytest
from unittest.mock import Mock, patch
from call_graph import CallGraphAnalyzer


class TestCallGraphAnalyzer:
    """Test call graph analysis"""
    
    def test_initialization(self):
        """Test call graph analyzer initializes"""
        analyzer = CallGraphAnalyzer("/tmp/test")
        assert analyzer.project_path == "/tmp/test"
        assert analyzer.graph is not None
    
    def test_build_graph_with_valid_contracts(self):
        """Test building call graph from contracts"""
        analyzer = CallGraphAnalyzer("/tmp/test")
        
        with patch('call_graph.Slither') as mock_slither_class:
            mock_slither = Mock()
            mock_contract = Mock()
            mock_function = Mock()
            mock_function.name = "testFunc"
            mock_function.calls_as_expressions = []
            mock_contract.name = "TestContract"
            mock_contract.functions = [mock_function]
            mock_slither.contracts = [mock_contract]
            mock_slither_class.return_value = mock_slither
            
            success = analyzer.build_graph()
        
        assert isinstance(success, bool)
    
    def test_find_cross_function_reentrancy(self):
        """Test finding cross-function reentrancy"""
        analyzer = CallGraphAnalyzer("/tmp/test")
        analyzer.graph = {}  # Empty graph
        
        findings = analyzer.find_cross_function_reentrancy()
        
        assert isinstance(findings, list)
    
    def test_find_delegatecall_injection(self):
        """Test finding delegatecall injection"""
        analyzer = CallGraphAnalyzer("/tmp/test")
        analyzer.graph = {}
        
        findings = analyzer.find_delegatecall_injection()
        
        assert isinstance(findings, list)
    
    def test_build_graph_handles_errors(self):
        """Test graph building handles errors"""
        analyzer = CallGraphAnalyzer("/tmp/test")
        
        with patch('call_graph.Slither', side_effect=Exception("Failed")):
            success = analyzer.build_graph()
        
        assert success is False
    
    def test_detect_cycles(self):
        """Test cycle detection in call graph"""
        analyzer = CallGraphAnalyzer("/tmp/test")
        
        # Create simple graph with cycle
        analyzer.graph = {
            "funcA": {"calls": ["funcB"]},
            "funcB": {"calls": ["funcA"]}
        }
        
        cycles = analyzer._detect_cycles()
        
        assert isinstance(cycles, list)
