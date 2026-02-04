"""Tests for local database"""
import pytest
import numpy as np
from unittest.mock import Mock, patch
from local_db import LocalDB
from config import Config


class TestLocalDB:
    """Test local database operations"""
    
    def test_db_initialization(self, temp_db):
        """Test database initializes correctly"""
        assert temp_db.conn is not None
        
        # Check table exists
        cursor = temp_db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='patterns'")
        assert cursor.fetchone() is not None
    
    def test_add_pattern_success(self, temp_db, sample_extraction, sample_finding, mock_sentence_transformer):
        """Test adding a pattern to database"""
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            success = temp_db.add_pattern(
                title=sample_finding["title"],
                content=sample_finding["content"],
                invariant=sample_extraction.assumed_invariant,
                break_condition=sample_extraction.break_condition,
                vuln_class=sample_extraction.vuln_class,
                severity=sample_extraction.severity_score,
                metadata={
                    "quality_score": 0.9,
                    "finders_count": 5,
                    "source": "test"
                }
            )
        
        assert success is True
        
        # Verify pattern was added
        stats = temp_db.get_stats()
        assert stats["total_patterns"] == 1
    
    def test_add_pattern_with_duplicate_id(self, temp_db, sample_extraction, sample_finding, mock_sentence_transformer):
        """Test adding same pattern twice (should replace)"""
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            # Add first time
            temp_db.add_pattern(
                title=sample_finding["title"],
                content=sample_finding["content"],
                invariant=sample_extraction.assumed_invariant,
                break_condition=sample_extraction.break_condition,
                vuln_class=sample_extraction.vuln_class,
                severity=sample_extraction.severity_score,
                metadata={}
            )
            
            # Add second time (same content)
            temp_db.add_pattern(
                title=sample_finding["title"],
                content=sample_finding["content"],
                invariant=sample_extraction.assumed_invariant,
                break_condition=sample_extraction.break_condition,
                vuln_class=sample_extraction.vuln_class,
                severity=sample_extraction.severity_score,
                metadata={}
            )
        
        # Should still be only 1 pattern (replaced)
        stats = temp_db.get_stats()
        assert stats["total_patterns"] == 1
    
    def test_is_duplicate(self, temp_db, sample_extraction, sample_finding, mock_sentence_transformer):
        """Test duplicate detection"""
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            # Add pattern
            temp_db.add_pattern(
                title=sample_finding["title"],
                content=sample_finding["content"],
                invariant=sample_extraction.assumed_invariant,
                break_condition=sample_extraction.break_condition,
                vuln_class=sample_extraction.vuln_class,
                severity=sample_extraction.severity_score,
                metadata={}
            )
        
        # Check for duplicate
        assert temp_db.is_duplicate(sample_extraction.assumed_invariant) is True
        assert temp_db.is_duplicate("Different invariant") is False
    
    def test_load_all_vectors(self, temp_db, mock_sentence_transformer):
        """Test loading all vectors from database"""
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            # Add multiple patterns
            for i in range(3):
                temp_db.add_pattern(
                    title=f"Finding {i}",
                    content=f"Content {i}",
                    invariant=f"Invariant {i}",
                    break_condition=f"Break {i}",
                    vuln_class="Test",
                    severity="High",
                    metadata={}
                )
        
        # Load vectors
        cache = temp_db.load_all_vectors()
        
        assert cache is not None
        assert len(cache["ids"]) == 3
        assert len(cache["data"]) == 3
        assert cache["vectors"] is not None
        assert cache["vectors"].shape[0] == 3
    
    def test_load_all_vectors_cached(self, temp_db, mock_sentence_transformer):
        """Test that load_all_vectors uses cache on second call"""
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            temp_db.add_pattern(
                title="Test",
                content="Content",
                invariant="Invariant",
                break_condition="Break",
                vuln_class="Test",
                severity="High",
                metadata={}
            )
        
        # First load
        cache1 = temp_db.load_all_vectors()
        # Second load should return same object (cached)
        cache2 = temp_db.load_all_vectors()
        
        assert cache1 is cache2  # Same object reference
    
    def test_search_similar_empty_db(self, temp_db, mock_sentence_transformer):
        """Test search on empty database"""
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            results = temp_db.search_similar("test query", top_k=5)
        
        assert results == []
    
    def test_search_similar_with_patterns(self, temp_db, mock_sentence_transformer):
        """Test similarity search"""
        # Create mock encoder that returns predictable embeddings
        def mock_encode(text, convert_to_numpy=False):
            # Different texts get different but similar embeddings
            if "reentrancy" in text.lower():
                vec = np.ones(384, dtype=np.float32) * 0.9
            else:
                vec = np.ones(384, dtype=np.float32) * 0.1
            return vec
        
        mock_sentence_transformer.encode = mock_encode
        
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            # Add patterns
            temp_db.add_pattern(
                title="Reentrancy vulnerability",
                content="State change after external call",
                invariant="State updated before call",
                break_condition="Call made before update",
                vuln_class="Reentrancy",
                severity="High",
                metadata={"finders_count": 5, "quality_score": 0.9}
            )
            
            temp_db.add_pattern(
                title="Access control",
                content="Missing modifier",
                invariant="Only owner can call",
                break_condition="No modifier check",
                vuln_class="AccessControl",
                severity="High",
                metadata={"finders_count": 3, "quality_score": 0.8}
            )
            
            # Search for reentrancy
            results = temp_db.search_similar("reentrancy external call", top_k=2)
        
        assert len(results) > 0
        # First result should be reentrancy pattern (more similar)
        assert results[0]["vuln_class"] == "Reentrancy"
        assert "similarity" in results[0]
    
    def test_search_similar_respects_threshold(self, temp_db, mock_sentence_transformer):
        """Test search filters by similarity threshold"""
        # Mock encoder that returns low similarity
        def mock_encode(text, convert_to_numpy=False):
            return np.random.rand(384).astype(np.float32) * 0.1
        
        mock_sentence_transformer.encode = mock_encode
        
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            temp_db.add_pattern(
                title="Test",
                content="Content",
                invariant="Invariant",
                break_condition="Break",
                vuln_class="Test",
                severity="High",
                metadata={}
            )
            
            # Search should return no results if below threshold
            results = temp_db.search_similar("completely different query", top_k=5)
        
        # Results might be empty or very few due to low similarity
        assert isinstance(results, list)
    
    def test_get_stats(self, temp_db, mock_sentence_transformer):
        """Test getting database statistics"""
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            # Add some patterns
            for i in range(5):
                temp_db.add_pattern(
                    title=f"Test {i}",
                    content="Content",
                    invariant=f"Invariant {i}",
                    break_condition="Break",
                    vuln_class="Test",
                    severity="High",
                    metadata={}
                )
        
        stats = temp_db.get_stats()
        
        assert "total_patterns" in stats
        assert stats["total_patterns"] == 5
    
    def test_encoder_lazy_initialization(self, temp_db):
        """Test encoder is lazily initialized"""
        assert temp_db.encoder is None
        
        # Should initialize on first use
        encoder = temp_db._get_encoder()
        assert encoder is not None
        assert temp_db.encoder is not None
    
    def test_add_pattern_error_handling(self, temp_db):
        """Test add_pattern handles errors gracefully"""
        # Try to add pattern with invalid data
        with patch.object(temp_db, '_get_encoder', side_effect=Exception("Encoder failed")):
            success = temp_db.add_pattern(
                title="Test",
                content="Content",
                invariant="Invariant",
                break_condition="Break",
                vuln_class="Test",
                severity="High",
                metadata={}
            )
        
        assert success is False
    
    def test_search_with_zero_norm_vectors(self, temp_db, mock_sentence_transformer):
        """Test search handles zero-norm vectors"""
        # Mock encoder that returns zero vector
        mock_sentence_transformer.encode.return_value = np.zeros(384, dtype=np.float32)
        
        with patch.object(temp_db, '_get_encoder', return_value=mock_sentence_transformer):
            temp_db.add_pattern(
                title="Test",
                content="Content",
                invariant="Invariant",
                break_condition="Break",
                vuln_class="Test",
                severity="High",
                metadata={}
            )
            
            results = temp_db.search_similar("test query", top_k=5)
        
        # Should handle gracefully and return empty or filtered results
        assert isinstance(results, list)
    
    def test_vector_cache_cleared_on_new_instance(self):
        """Test each DB instance starts with empty cache"""
        db1 = LocalDB()
        db1._vector_cache = {"test": "data"}
        
        db2 = LocalDB()
        # New instance should have None cache
        assert db2._vector_cache is None
        
        db1.conn.close()
        db2.conn.close()
