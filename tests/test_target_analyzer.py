"""Tests for target analyzer"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path


class TestTargetAnalyzer:
    """Test target analyzer functionality"""
    
    def test_analyzer_initialization_with_valid_path(self, temp_contract_dir):
        """Test analyzer initializes with valid contract path"""
        from target_analyzer import TargetAnalyzer
        
        analyzer = TargetAnalyzer(str(temp_contract_dir))
        assert analyzer.project_path == Path(temp_contract_dir)
    
    def test_analyzer_initialization_with_invalid_path(self):
        """Test analyzer handles invalid path"""
        from target_analyzer import TargetAnalyzer
        
        with pytest.raises(Exception):
            TargetAnalyzer("/nonexistent/path")
    
    def test_detect_solidity_version(self, temp_contract_dir):
        """Test Solidity version detection from pragma"""
        from target_analyzer import TargetAnalyzer
        
        analyzer = TargetAnalyzer(str(temp_contract_dir))
        version = analyzer._detect_solidity_version()
        
        assert version is not None
        assert isinstance(version, str)
    
    def test_get_functions_extracts_functions(self, temp_contract_dir):
        """Test function extraction from contracts"""
        from target_analyzer import TargetAnalyzer
        
        with patch('target_analyzer.Slither') as mock_slither_class:
            mock_slither = Mock()
            mock_contract = Mock()
            mock_function = Mock()
            mock_function.name = "withdraw"
            mock_function.visibility = "public"
            mock_function.view = False
            mock_function.pure = False
            mock_function.modifiers = []
            mock_function.source_mapping = {"filename": "Test.sol", "lines": [10, 11, 12]}
            mock_contract.name = "TestContract"
            mock_contract.functions = [mock_function]
            mock_slither.contracts = [mock_contract]
            mock_slither_class.return_value = mock_slither
            
            analyzer = TargetAnalyzer(str(temp_contract_dir))
            functions = analyzer.get_functions()
        
        assert isinstance(functions, list)
    
    def test_get_detectors_runs_slither(self, temp_contract_dir):
        """Test getting Slither detector results"""
        from target_analyzer import TargetAnalyzer
        
        with patch('target_analyzer.Slither') as mock_slither_class:
            mock_slither = Mock()
            mock_slither.detectors_results = [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "description": "Test finding",
                    "elements": [{"source_mapping": {"filename": "Test.sol", "lines": [10]}}]
                }
            ]
            mock_slither_class.return_value = mock_slither
            
            analyzer = TargetAnalyzer(str(temp_contract_dir))
            detectors = analyzer.get_detectors()
        
        assert isinstance(detectors, list)
    
    def test_risk_scoring(self, temp_contract_dir):
        """Test risk scoring for functions"""
        from target_analyzer import TargetAnalyzer
        
        analyzer = TargetAnalyzer(str(temp_contract_dir))
        
        # Test function with high risk indicators
        high_risk_func = {
            "function": "withdraw",
            "visibility": "external",
            "code": "function withdraw() external { delegatecall(...); }",
            "modifiers": []
        }
        
        score = analyzer._calculate_risk_score(high_risk_func)
        assert score > 0
    
    def test_slither_error_handling(self):
        """Test analyzer handles Slither errors gracefully"""
        from target_analyzer import TargetAnalyzer
        
        with patch('target_analyzer.Slither', side_effect=Exception("Slither failed")):
            with pytest.raises(Exception):
                analyzer = TargetAnalyzer("/tmp/test")
