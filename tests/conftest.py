"""Pytest fixtures for Deep Audit Agent tests"""
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llm_client import LLMClient, ExtractionResult, HypothesisResult
from local_db import LocalDB
from config import Config


@pytest.fixture
def mock_groq_client():
    """Mock Groq API client"""
    mock_client = Mock()
    mock_response = Mock()
    mock_response.choices = [Mock()]
    mock_response.choices[0].message.content = '{"vuln_class": "Reentrancy", "assumed_invariant": "Test invariant", "break_condition": "Test break", "preconditions": [], "code_indicators": [], "severity_score": "High"}'
    mock_client.chat.completions.create.return_value = mock_response
    return mock_client


@pytest.fixture
def mock_llm_client(mock_groq_client):
    """Mock LLM client with working API"""
    client = LLMClient()
    client.client = mock_groq_client
    return client


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    temp_dir = tempfile.mkdtemp()
    original_db_path = Config.DB_PATH
    Config.DB_PATH = Path(temp_dir) / "test_patterns.db"
    
    db = LocalDB()
    
    yield db
    
    # Cleanup
    db.conn.close()
    Config.DB_PATH = original_db_path
    shutil.rmtree(temp_dir)


@pytest.fixture
def sample_finding():
    """Sample vulnerability finding"""
    return {
        "title": "Reentrancy in withdraw function",
        "content": "The withdraw function is vulnerable to reentrancy attacks because it calls an external contract before updating the balance.",
        "source_link": "https://example.com/finding",
        "finders_count": 5,
        "quality_score": 0.9
    }


@pytest.fixture
def sample_extraction():
    """Sample extraction result"""
    return ExtractionResult(
        vuln_class="Reentrancy",
        assumed_invariant="Balance is updated before external calls",
        break_condition="External call made before balance update",
        preconditions=["contract has payable function", "external call to untrusted contract"],
        code_indicators=["call.value", "transfer", "send"],
        severity_score="High"
    )


@pytest.fixture
def sample_contract_code():
    """Sample Solidity contract with vulnerability"""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    
    contract Vulnerable {
        mapping(address => uint256) public balances;
        
        function withdraw() external {
            uint256 amount = balances[msg.sender];
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] = 0; // Vulnerability: balance updated after call
        }
        
        function deposit() external payable {
            balances[msg.sender] += msg.value;
        }
    }
    """


@pytest.fixture
def temp_contract_dir(sample_contract_code):
    """Create a temporary directory with a sample contract"""
    temp_dir = tempfile.mkdtemp()
    contract_file = Path(temp_dir) / "Vulnerable.sol"
    contract_file.write_text(sample_contract_code)
    
    yield Path(temp_dir)
    
    shutil.rmtree(temp_dir)


@pytest.fixture
def sample_patterns():
    """Sample vulnerability patterns for testing"""
    return [
        {
            "id": "pattern1",
            "invariant": "State must be updated before external calls",
            "break_condition": "External call made with stale state",
            "vuln_class": "Reentrancy",
            "similarity": 0.85,
            "severity": "High"
        },
        {
            "id": "pattern2",
            "invariant": "Access control must be checked",
            "break_condition": "Missing access control modifier",
            "vuln_class": "AccessControl",
            "similarity": 0.72,
            "severity": "Critical"
        }
    ]


@pytest.fixture
def sample_slither_detectors():
    """Sample Slither detector results"""
    return [
        {
            "check": "reentrancy-eth",
            "impact": "High",
            "confidence": "High",
            "description": "Reentrancy in withdraw function",
            "elements": [{"source_mapping": {"filename": "Vulnerable.sol"}}]
        },
        {
            "check": "unprotected-selfdestruct",
            "impact": "High",
            "confidence": "High",
            "description": "Unprotected selfdestruct call",
            "elements": [{"source_mapping": {"filename": "Vulnerable.sol"}}]
        }
    ]


@pytest.fixture(autouse=True)
def reset_logging():
    """Reset logging between tests"""
    import logging
    logging.getLogger().handlers.clear()
    yield


@pytest.fixture
def mock_sentence_transformer():
    """Mock sentence transformer model"""
    import numpy as np
    
    mock_model = Mock()
    # Return consistent embeddings for testing
    mock_model.encode.return_value = np.random.rand(384).astype(np.float32)
    return mock_model
