"""Tests for LLM client"""
import pytest
import json
from unittest.mock import Mock, patch
from llm_client import LLMClient, ExtractionResult, HypothesisResult


class TestLLMClient:
    """Test LLM client functionality"""
    
    def test_initialization_without_api_key(self):
        """Test initialization fails gracefully without API key"""
        with patch('llm_client.Config.GROQ_API_KEY', None):
            client = LLMClient()
            assert client.client is None
    
    def test_initialization_with_api_key(self, mock_groq_client):
        """Test successful initialization with API key"""
        with patch('llm_client.Groq', return_value=mock_groq_client):
            client = LLMClient()
            assert client.client is not None
    
    def test_strict_parse_valid_json(self, mock_llm_client):
        """Test parsing valid JSON response"""
        valid_json = json.dumps({
            "vuln_class": "Reentrancy",
            "assumed_invariant": "Balance updated before external call",
            "break_condition": "External call before state update",
            "preconditions": ["payable function"],
            "code_indicators": ["call.value"],
            "severity_score": "High"
        })
        
        result = mock_llm_client._strict_parse(valid_json)
        
        assert isinstance(result, ExtractionResult)
        assert result.vuln_class == "Reentrancy"
        assert result.severity_score == "High"
    
    def test_strict_parse_json_in_markdown(self, mock_llm_client):
        """Test parsing JSON wrapped in markdown code blocks"""
        markdown_json = """```json
        {
            "vuln_class": "AccessControl",
            "assumed_invariant": "Only owner can call",
            "break_condition": "Missing modifier",
            "preconditions": [],
            "code_indicators": ["onlyOwner"],
            "severity_score": "Critical"
        }
        ```"""
        
        result = mock_llm_client._strict_parse(markdown_json)
        
        assert result.vuln_class == "AccessControl"
        assert result.severity_score == "Critical"
    
    def test_strict_parse_invalid_json(self, mock_llm_client):
        """Test parsing invalid JSON raises error"""
        invalid_json = "This is not JSON at all"
        
        with pytest.raises(ValueError):
            mock_llm_client._strict_parse(invalid_json)
    
    def test_strict_parse_missing_fields(self, mock_llm_client):
        """Test parsing JSON with missing fields uses defaults"""
        partial_json = json.dumps({
            "vuln_class": "LogicError"
        })
        
        result = mock_llm_client._strict_parse(partial_json)
        
        assert result.vuln_class == "LogicError"
        assert result.assumed_invariant == "Unknown"
        assert result.break_condition == "Unknown"
    
    def test_extract_invariant_success(self, mock_llm_client, sample_finding):
        """Test successful invariant extraction"""
        result = mock_llm_client.extract_invariant(
            sample_finding["content"],
            sample_finding["title"]
        )
        
        assert isinstance(result, ExtractionResult)
        assert result.vuln_class == "Reentrancy"
    
    def test_extract_invariant_with_retry(self, mock_llm_client):
        """Test extraction with retry logic on failure"""
        # First call fails, second succeeds
        mock_llm_client.client.chat.completions.create.side_effect = [
            Exception("API Error"),
            Mock(choices=[Mock(message=Mock(content='{"vuln_class": "Test", "assumed_invariant": "Test", "break_condition": "Test", "preconditions": [], "code_indicators": [], "severity_score": "Medium"}'))])
        ]
        
        result = mock_llm_client.extract_invariant("test content", "test title")
        
        # Should fall back to emergency extraction
        assert isinstance(result, ExtractionResult)
    
    def test_emergency_extraction_fallback(self, mock_llm_client):
        """Test emergency extraction creates valid result"""
        result = mock_llm_client._emergency_extraction("content", "Test Title")
        
        assert isinstance(result, ExtractionResult)
        assert result.vuln_class == "LogicError"
        assert "Test Title" in result.assumed_invariant
    
    def test_generate_hypothesis_empty_patterns(self, mock_llm_client):
        """Test hypothesis generation with no patterns"""
        result = mock_llm_client.generate_hypothesis("code", [], "testFunc")
        
        assert result == []
    
    def test_generate_hypothesis_success(self, mock_llm_client, sample_patterns):
        """Test successful hypothesis generation"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = json.dumps([{
            "hypothesis": "Reentrancy vulnerability",
            "attack_vector": "Call external contract",
            "confidence": "High",
            "invariant_assumed": "Balance updated first",
            "location": "line 10",
            "remediation": "Use checks-effects-interactions",
            "vulnerability_type": "Reentrancy"
        }])
        mock_llm_client.client.chat.completions.create.return_value = mock_response
        
        result = mock_llm_client.generate_hypothesis(
            "function withdraw() { }",
            sample_patterns,
            "withdraw"
        )
        
        assert isinstance(result, list)
        assert len(result) > 0
    
    def test_generate_hypothesis_with_dict_response(self, mock_llm_client, sample_patterns):
        """Test hypothesis generation with dict containing findings key"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = json.dumps({
            "findings": [{
                "hypothesis": "Test hypothesis",
                "attack_vector": "Test vector",
                "confidence": "High",
                "invariant_assumed": "Test invariant",
                "location": "test location",
                "remediation": "Test fix",
                "vulnerability_type": "Test"
            }]
        })
        mock_llm_client.client.chat.completions.create.return_value = mock_response
        
        result = mock_llm_client.generate_hypothesis("code", sample_patterns, "func")
        
        assert isinstance(result, list)
        assert len(result) == 1
    
    def test_batch_extract_success(self, mock_llm_client, sample_finding):
        """Test batch extraction of invariants"""
        findings = [sample_finding, sample_finding]
        
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = json.dumps({
            "extractions": [
                {
                    "vuln_class": "Reentrancy",
                    "assumed_invariant": "Test 1",
                    "break_condition": "Break 1",
                    "preconditions": [],
                    "code_indicators": [],
                    "severity_score": "High"
                },
                {
                    "vuln_class": "AccessControl",
                    "assumed_invariant": "Test 2",
                    "break_condition": "Break 2",
                    "preconditions": [],
                    "code_indicators": [],
                    "severity_score": "Critical"
                }
            ]
        })
        mock_llm_client.client.chat.completions.create.return_value = mock_response
        
        results = mock_llm_client.batch_extract(findings, batch_size=2)
        
        assert len(results) == 2
        assert all(isinstance(r["extraction"], ExtractionResult) for r in results)
    
    def test_batch_extract_fallback_on_error(self, mock_llm_client, sample_finding):
        """Test batch extraction falls back to individual on error"""
        findings = [sample_finding]
        
        # First call fails, triggering individual extraction
        mock_llm_client.client.chat.completions.create.side_effect = [
            Exception("Batch failed"),
            Mock(choices=[Mock(message=Mock(content='{"vuln_class": "Test", "assumed_invariant": "Test", "break_condition": "Test", "preconditions": [], "code_indicators": [], "severity_score": "Medium"}'))])
        ]
        
        results = mock_llm_client.batch_extract(findings, batch_size=5)
        
        assert len(results) == 1
    
    def test_call_with_retry_rate_limit(self, mock_llm_client):
        """Test retry logic handles rate limiting"""
        mock_llm_client.client.chat.completions.create.side_effect = [
            Exception("Rate limit exceeded 429"),
            Mock(choices=[Mock(message=Mock(content="success"))])
        ]
        
        with patch('time.sleep'):  # Speed up test
            response = mock_llm_client._call_with_retry(
                [{"role": "user", "content": "test"}],
                max_retries=3
            )
        
        assert response is not None
    
    def test_call_with_retry_max_retries_exceeded(self, mock_llm_client):
        """Test retry logic fails after max retries"""
        mock_llm_client.client.chat.completions.create.side_effect = Exception("Persistent error")
        
        with pytest.raises(Exception):
            with patch('time.sleep'):
                mock_llm_client._call_with_retry(
                    [{"role": "user", "content": "test"}],
                    max_retries=2
                )
    
    def test_validate_connection_success(self, mock_llm_client):
        """Test connection validation succeeds"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "connected"
        mock_llm_client.client.chat.completions.create.return_value = mock_response
        
        assert mock_llm_client.validate() is True
    
    def test_validate_connection_failure(self, mock_llm_client):
        """Test connection validation handles failures"""
        mock_llm_client.client.chat.completions.create.side_effect = Exception("Connection failed")
        
        assert mock_llm_client.validate() is False
