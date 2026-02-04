"""Smart caching system for Deep Audit Agent"""
import pickle
import hashlib
import json
from pathlib import Path
from typing import Any, Optional, Dict
from datetime import datetime, timedelta
from config import Config
from logger import get_logger
from exceptions import CacheError

logger = get_logger()


class CacheManager:
    """Intelligent caching for embeddings, Slither results, and LLM responses"""
    
    def __init__(self, cache_dir: Path = None):
        self.cache_dir = cache_dir or Config.DATA_DIR / "cache"
        self.cache_dir.mkdir(exist_ok=True)
        
        self.embedding_cache_file = self.cache_dir / "embedding_cache.pkl"
        self.slither_cache_dir = self.cache_dir / "slither"
        self.llm_cache_dir = self.cache_dir / "llm"
        
        self.slither_cache_dir.mkdir(exist_ok=True)
        self.llm_cache_dir.mkdir(exist_ok=True)
        
        self.max_cache_size = 100 * 1024 * 1024  # 100MB
        self._stats = {
            "hits": 0,
            "misses": 0,
            "embedding_loaded": False
        }
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            **self._stats,
            "cache_size": self._get_total_cache_size(),
            "embedding_cached": self.embedding_cache_file.exists()
        }
    
    def _get_total_cache_size(self) -> int:
        """Calculate total cache size in bytes"""
        total = 0
        for path in self.cache_dir.rglob("*"):
            if path.is_file():
                total += path.stat().st_size
        return total
    
    def _compute_hash(self, data: Any) -> str:
        """Compute hash for cache key"""
        if isinstance(data, str):
            content = data.encode()
        elif isinstance(data, dict):
            content = json.dumps(data, sort_keys=True).encode()
        elif isinstance(data, Path):
            # Hash file content + mtime
            if data.exists():
                content = data.read_bytes() + str(data.stat().st_mtime).encode()
            else:
                content = str(data).encode()
        else:
            content = str(data).encode()
        
        return hashlib.sha256(content).hexdigest()
    
    def save_embedding_cache(self, vectors: Dict[str, Any]) -> bool:
        """Save embedding vectors to cache"""
        try:
            start = datetime.now()
            with open(self.embedding_cache_file, 'wb') as f:
                pickle.dump(vectors, f, protocol=pickle.HIGHEST_PROTOCOL)
            duration = (datetime.now() - start).total_seconds()
            logger.log_db_operation("save_embedding_cache", len(vectors.get("ids", [])), duration)
            logger.info(f"Saved embedding cache: {len(vectors.get('ids', []))} vectors")
            return True
        except Exception as e:
            logger.error(f"Failed to save embedding cache: {e}")
            return False
    
    def load_embedding_cache(self) -> Optional[Dict[str, Any]]:
        """Load embedding vectors from cache"""
        if not self.embedding_cache_file.exists():
            self._stats["misses"] += 1
            return None
        
        try:
            start = datetime.now()
            with open(self.embedding_cache_file, 'rb') as f:
                vectors = pickle.load(f)
            duration = (datetime.now() - start).total_seconds()
            
            self._stats["hits"] += 1
            self._stats["embedding_loaded"] = True
            logger.log_db_operation("load_embedding_cache", len(vectors.get("ids", [])), duration)
            logger.info(f"Loaded embedding cache: {len(vectors.get('ids', []))} vectors ({duration:.2f}s)")
            return vectors
        except Exception as e:
            logger.error(f"Failed to load embedding cache: {e}")
            self._stats["misses"] += 1
            return None
    
    def save_slither_result(self, contract_path: Path, result: Dict) -> bool:
        """Save Slither analysis result"""
        try:
            cache_key = self._compute_hash(contract_path)
            cache_file = self.slither_cache_dir / f"{cache_key}.json"
            
            cached_data = {
                "timestamp": datetime.now().isoformat(),
                "file_path": str(contract_path),
                "file_mtime": contract_path.stat().st_mtime,
                "result": result
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cached_data, f, indent=2)
            
            logger.debug(f"Cached Slither result: {contract_path.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to save Slither cache: {e}")
            return False
    
    def load_slither_result(self, contract_path: Path, max_age_hours: int = 24) -> Optional[Dict]:
        """Load cached Slither analysis result"""
        try:
            cache_key = self._compute_hash(contract_path)
            cache_file = self.slither_cache_dir / f"{cache_key}.json"
            
            if not cache_file.exists():
                self._stats["misses"] += 1
                return None
            
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            
            # Validate cache freshness
            cached_time = datetime.fromisoformat(cached_data["timestamp"])
            if datetime.now() - cached_time > timedelta(hours=max_age_hours):
                logger.debug(f"Slither cache expired: {contract_path.name}")
                self._stats["misses"] += 1
                return None
            
            # Validate file hasn't changed
            if contract_path.stat().st_mtime != cached_data["file_mtime"]:
                logger.debug(f"Slither cache invalidated (file modified): {contract_path.name}")
                self._stats["misses"] += 1
                return None
            
            self._stats["hits"] += 1
            logger.debug(f"Slither cache hit: {contract_path.name}")
            return cached_data["result"]
        except Exception as e:
            logger.error(f"Failed to load Slither cache: {e}")
            self._stats["misses"] += 1
            return None
    
    def save_llm_response(self, prompt_hash: str, response: Any, ttl_hours: int = 168) -> bool:
        """Save LLM response with TTL (default 7 days)"""
        try:
            cache_file = self.llm_cache_dir / f"{prompt_hash}.json"
            
            cached_data = {
                "timestamp": datetime.now().isoformat(),
                "ttl_hours": ttl_hours,
                "response": response
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cached_data, f, indent=2)
            
            logger.debug(f"Cached LLM response: {prompt_hash[:12]}")
            return True
        except Exception as e:
            logger.error(f"Failed to save LLM cache: {e}")
            return False
    
    def load_llm_response(self, prompt_hash: str) -> Optional[Any]:
        """Load cached LLM response"""
        try:
            cache_file = self.llm_cache_dir / f"{prompt_hash}.json"
            
            if not cache_file.exists():
                self._stats["misses"] += 1
                return None
            
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            
            # Check TTL
            cached_time = datetime.fromisoformat(cached_data["timestamp"])
            ttl = timedelta(hours=cached_data.get("ttl_hours", 168))
            
            if datetime.now() - cached_time > ttl:
                logger.debug(f"LLM cache expired: {prompt_hash[:12]}")
                cache_file.unlink()
                self._stats["misses"] += 1
                return None
            
            self._stats["hits"] += 1
            logger.debug(f"LLM cache hit: {prompt_hash[:12]}")
            return cached_data["response"]
        except Exception as e:
            logger.error(f"Failed to load LLM cache: {e}")
            self._stats["misses"] += 1
            return None
    
    def clear_cache(self, cache_type: str = "all") -> bool:
        """Clear cache by type"""
        try:
            if cache_type in ["all", "embedding"]:
                if self.embedding_cache_file.exists():
                    self.embedding_cache_file.unlink()
                    logger.info("Cleared embedding cache")
            
            if cache_type in ["all", "slither"]:
                for file in self.slither_cache_dir.glob("*.json"):
                    file.unlink()
                logger.info("Cleared Slither cache")
            
            if cache_type in ["all", "llm"]:
                for file in self.llm_cache_dir.glob("*.json"):
                    file.unlink()
                logger.info("Cleared LLM cache")
            
            self._stats = {"hits": 0, "misses": 0, "embedding_loaded": False}
            return True
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            return False
    
    def enforce_size_limit(self) -> bool:
        """Remove oldest cache entries if size exceeds limit"""
        try:
            total_size = self._get_total_cache_size()
            
            if total_size <= self.max_cache_size:
                return True
            
            logger.info(f"Cache size ({total_size / 1024 / 1024:.1f}MB) exceeds limit, cleaning...")
            
            # Get all cache files sorted by access time
            cache_files = []
            for path in self.cache_dir.rglob("*"):
                if path.is_file():
                    cache_files.append((path, path.stat().st_atime))
            
            cache_files.sort(key=lambda x: x[1])  # Oldest first
            
            # Remove oldest files until under limit
            for path, _ in cache_files:
                if self._get_total_cache_size() <= self.max_cache_size * 0.8:  # 80% threshold
                    break
                path.unlink()
                logger.debug(f"Removed old cache file: {path.name}")
            
            logger.info(f"Cache cleaned to {self._get_total_cache_size() / 1024 / 1024:.1f}MB")
            return True
        except Exception as e:
            logger.error(f"Failed to enforce cache size limit: {e}")
            return False


# Global cache manager instance
_cache_manager = None


def get_cache_manager() -> CacheManager:
    """Get the global cache manager instance"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager
