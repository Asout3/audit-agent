"""Tests for pattern matcher"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from pattern_matcher import PatternMatcher


class TestPatternMatcher:
    """Test pattern matcher functionality"""
    
    @pytest.fixture
    def matcher(self):
        return PatternMatcher()
    
    @pytest.fixture
    def mock_analyzer(self):
        """Mock target analyzer"""
        analyzer = Mock()
        analyzer.get_detectors.return_value = [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "description": "Reentrancy vulnerability",
                "instances": [
                    {
                        "source_mapping": {
                            "filename": "Vulnerable.sol",
                            "lines": [10]
                        }
                    }
                ]
            }
        ]
        analyzer.get_functions.return_value = [
            {
                "contract": "TestContract",
                "function": "withdraw",
                "signature": "withdraw()",
                "code": "function withdraw() public { msg.sender.call{value: 100}(\"\"); }",
                "modifiers": []
            }
        ]
        analyzer.project_path = "/tmp/test"
        return analyzer
    
    def test_matcher_initialization(self, matcher):
        """Test matcher initializes with DB and LLM"""
        assert matcher.db is not None
        assert matcher.llm is not None
    
    def test_analyze_with_slither_findings(self, matcher, mock_analyzer):
        """Test analysis includes Slither findings"""
        with patch.object(matcher.db, 'load_all_vectors'):
            with patch.object(matcher.db, 'search_similar', return_value=[]):
                findings = matcher.analyze(mock_analyzer)
        
        # Should have Slither finding
        slither_findings = [f for f in findings if f.get("source") == "Slither"]
        assert len(slither_findings) > 0
        assert any("SLITHER" in f["type"] for f in slither_findings)
    
    def test_analyze_with_static_analysis(self, matcher, mock_analyzer):
        """Test analysis includes static analysis findings"""
        with patch.object(matcher.db, 'load_all_vectors'):
            with patch.object(matcher.db, 'search_similar', return_value=[]):
                findings = matcher.analyze(mock_analyzer)
        
        # Should have static analysis findings
        static_findings = [f for f in findings if f.get("source") == "StaticAnalyzer"]
        assert len(static_findings) > 0
    
    def test_analyze_with_semantic_matching(self, matcher, mock_analyzer, sample_patterns):
        """Test analysis includes semantic matching"""
        with patch.object(matcher.db, 'load_all_vectors'):
            with patch.object(matcher.db, 'search_similar', return_value=sample_patterns):
                with patch.object(matcher.llm, 'generate_hypothesis', return_value=[
                    {
                        "vulnerability_type": "Reentrancy",
                        "hypothesis": "Test hypothesis",
                        "confidence": "High",
                        "attack_vector": "Test vector"
                    }
                ]):
                    findings = matcher.analyze(mock_analyzer)
        
        # Should have LLM-generated findings
        llm_findings = [f for f in findings if f.get("source") == "LLM"]
        assert len(llm_findings) > 0
    
    def test_deduplicate_findings(self, matcher):
        """Test deduplication of similar findings"""
        findings = [
            {
                "type": "REENTRANCY",
                "file": "Test.sol",
                "description": "Reentrancy in withdraw",
                "score": 85
            },
            {
                "type": "REENTRANCY",
                "file": "Test.sol",
                "description": "Reentrancy in withdraw",
                "score": 80
            },
            {
                "type": "ACCESS_CONTROL",
                "file": "Test.sol",
                "description": "Missing access control",
                "score": 70
            }
        ]
        
        deduplicated = matcher._deduplicate(findings)
        
        # Should keep higher scoring duplicate
        assert len(deduplicated) == 2
        reentrancy_findings = [f for f in deduplicated if f["type"] == "REENTRANCY"]
        assert len(reentrancy_findings) == 1
        assert reentrancy_findings[0]["score"] == 85
    
    def test_score_findings(self, matcher):
        """Test scoring algorithm"""
        finding = {
            "severity": "critical",
            "confidence": "high",
            "score": 90
        }
        
        final_score = matcher._calculate_final_score(finding)
        
        assert final_score > 80
        assert isinstance(final_score, (int, float))
    
    def test_sniper_mode_filters_low_confidence(self, matcher, mock_analyzer):
        """Test sniper mode filters low confidence findings"""
        with patch.object(matcher.db, 'load_all_vectors'):
            with patch.object(matcher.db, 'search_similar', return_value=[]):
                findings = matcher.analyze(mock_analyzer, sniper=True)
        
        # In sniper mode, should only have high confidence findings
        for finding in findings:
            assert finding.get("confidence", "").lower() in ["high", ""]
    
    def test_analyze_handles_empty_detectors(self, matcher):
        """Test analyze handles analyzer with no findings"""
        empty_analyzer = Mock()
        empty_analyzer.get_detectors.return_value = []
        empty_analyzer.get_functions.return_value = []
        empty_analyzer.project_path = "/tmp/test"
        
        with patch.object(matcher.db, 'load_all_vectors'):
            findings = matcher.analyze(empty_analyzer)
        
        assert isinstance(findings, list)
    
    def test_analyze_handles_llm_failure(self, matcher, mock_analyzer):
        """Test analyze continues when LLM fails"""
        with patch.object(matcher.db, 'load_all_vectors'):
            with patch.object(matcher.db, 'search_similar', return_value=[{"similarity": 0.9}]):
                with patch.object(matcher.llm, 'generate_hypothesis', side_effect=Exception("LLM failed")):
                    findings = matcher.analyze(mock_analyzer)
        
        # Should still have other findings (Slither, static)
        assert len(findings) > 0
    
    def test_display_formats_findings(self, matcher):
        """Test display formats findings correctly"""
        findings = [
            {
                "type": "REENTRANCY",
                "severity": "critical",
                "file": "Test.sol",
                "description": "Reentrancy vulnerability",
                "score": 95,
                "confidence": "high"
            }
        ]
        
        # Should not raise exception
        try:
            matcher.display(findings)
            success = True
        except Exception:
            success = False
        
        assert success is True
    
    def test_findings_sorted_by_score(self, matcher, mock_analyzer):
        """Test findings are sorted by score"""
        with patch.object(matcher.db, 'load_all_vectors'):
            with patch.object(matcher.db, 'search_similar', return_value=[]):
                findings = matcher.analyze(mock_analyzer)
        
        if len(findings) > 1:
            scores = [f.get("score", 0) for f in findings]
            # Check if sorted in descending order
            assert scores == sorted(scores, reverse=True)
