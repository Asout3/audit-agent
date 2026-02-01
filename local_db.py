import sqlite3
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Optional
from config import Config
from collections import defaultdict

class LocalDB:
    def __init__(self):
        self.conn = sqlite3.connect(str(Config.DB_PATH))
        self.encoder = None  # Lazy load
        self._vector_cache = None
        self._arch_index = defaultdict(list)  # Architecture index
        
    def _get_encoder(self):
        """Lazy load encoder"""
        if self.encoder is None:
            print("[+] Loading embedding model (first time)...")
            self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
        return self.encoder
        
    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                id TEXT PRIMARY KEY,
                vuln_class TEXT,
                invariant TEXT,
                break_condition TEXT,
                preconditions TEXT,
                code_indicators TEXT,
                embedding BLOB,
                severity TEXT,
                quality_score REAL,
                finders_count INTEGER,
                raw_title TEXT,
                source_link TEXT,
                protocol_category TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_class ON patterns(vuln_class)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_finders ON patterns(finders_count)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON patterns(protocol_category)")
        self.conn.commit()
        
    def add_pattern(self, finding_id: str, pattern: dict, severity: str, 
                    quality_score: float = 0, finders_count: int = 1, 
                    title: str = "", source_link: str = "", protocol_cat: str = ""):
        """Add pattern with deduplication check"""
        try:
            # Check for near-duplicates first
            if self._is_duplicate(pattern):
                return False
                
            text = f"{pattern.get('assumed_invariant', '')} {pattern.get('break_condition', '')}"
            embedding = self._get_encoder().encode(text, convert_to_numpy=True)
            emb_bytes = embedding.astype(np.float32).tobytes()
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO patterns 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id,
                pattern.get("vuln_class", "Unknown"),
                pattern.get("assumed_invariant", ""),
                pattern.get("break_condition", ""),
                json.dumps(pattern.get("preconditions", [])),
                json.dumps(pattern.get("code_indicators", [])),
                emb_bytes,
                severity,
                quality_score,
                finders_count,
                title,
                source_link,
                protocol_cat
            ))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"  [!] DB insert error: {e}")
            return False
    
    def _is_duplicate(self, pattern: dict, threshold: float = 0.92) -> bool:
        """Check if similar pattern already exists"""
        try:
            existing = self.search_similar(
                pattern.get('assumed_invariant', '') + ' ' + pattern.get('break_condition', ''),
                top_k=1,
                min_score=threshold
            )
            return len(existing) > 0
        except:
            return False
        
    def load_all_vectors(self):
        """Cache all vectors in RAM for fast search"""
        if self._vector_cache is not None:
            return self._vector_cache
            
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, invariant, break_condition, code_indicators, 
                   embedding, severity, finders_count, quality_score, protocol_category, preconditions
            FROM patterns
        """)
        
        self._vector_cache = {
            "ids": [],
            "vectors": [],
            "data": []
        }
        
        rows = cursor.fetchall()
        for row in rows:
            if row[4]:  # embedding exists
                try:
                    vec = np.frombuffer(row[4], dtype=np.float32)
                    self._vector_cache["ids"].append(row[0])
                    self._vector_cache["vectors"].append(vec)
                    self._vector_cache["data"].append({
                        "id": row[0],
                        "invariant": row[1],
                        "break_condition": row[2],
                        "indicators": json.loads(row[3]) if row[3] else [],
                        "severity": row[4] if len(row) > 4 else "Medium",
                        "finders_count": row[5] if len(row) > 5 else 1,
                        "quality_score": row[6] if len(row) > 6 else 0,
                        "protocol_category": row[7] if len(row) > 7 else "",
                        "preconditions": json.loads(row[8]) if len(row) > 8 and row[8] else []
                    })
                except Exception as e:
                    continue
        
        if self._vector_cache["vectors"]:
            self._vector_cache["vectors"] = np.array(self._vector_cache["vectors"])
            print(f"[+] Loaded {len(self._vector_cache['vectors'])} unique patterns into memory")
        else:
            print("[!] Warning: No vectors in database")
        
        return self._vector_cache
        
    def search_similar(self, query: str, top_k: int = 5, min_score: float = None, 
                       vuln_class: str = None, protocol_hint: str = None) -> List[Dict]:
        """Semantic search with filtering"""
        if min_score is None:
            min_score = Config.SIMILARITY_THRESHOLD
            
        cache = self.load_all_vectors()
        if not cache or len(cache["vectors"]) == 0:
            return []
        
        # Encode query
        q_vec = self._get_encoder().encode(query, convert_to_numpy=True).astype(np.float32)
        vectors = cache["vectors"]
        
        # Cosine similarity
        q_norm = np.linalg.norm(q_vec)
        v_norms = np.linalg.norm(vectors, axis=1)
        
        # Avoid division by zero
        valid = v_norms > 0
        similarities = np.zeros(len(vectors))
        similarities[valid] = np.dot(vectors[valid], q_vec) / (v_norms[valid] * q_norm)
        
        # Get top matches
        indices = np.argsort(similarities)[-top_k*2:][::-1]  # Get more candidates for filtering
        
        results = []
        for idx in indices:
            score = float(similarities[idx])
            if score < min_score:
                continue
                
            data = cache["data"][idx]
            
            # Filter by vulnerability class if specified
            if vuln_class and vuln_class.lower() not in data.get("vuln_class", "").lower():
                continue
            
            results.append({
                **data,
                "similarity": score,
                "rank_boost": self._calculate_rank_boost(data, score, protocol_hint)
            })
        
        # Sort by rank boost then similarity
        results.sort(key=lambda x: (x["rank_boost"], x["similarity"]), reverse=True)
        return results[:top_k]
    
    def _calculate_rank_boost(self, data: dict, similarity: float, protocol_hint: str) -> float:
        """Boost rare, high-quality findings"""
        boost = similarity
        
        # Boost low-finder-count (rare) bugs
        finders = data.get("finders_count", 1)
        if finders <= 2:
            boost += 0.15
        elif finders <= 5:
            boost += 0.08
        
        # Boost high quality
        quality = data.get("quality_score", 0)
        boost += (quality / 5) * 0.1
        
        # Boost protocol match
        if protocol_hint and protocol_hint.lower() in data.get("protocol_category", "").lower():
            boost += 0.12
            
        return boost
    
    def get_stats(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*), AVG(finders_count), AVG(quality_score) FROM patterns")
        total, avg_finders, avg_quality = cursor.fetchone()
        
        cursor.execute("SELECT vuln_class, COUNT(*) FROM patterns GROUP BY vuln_class ORDER BY COUNT(*) DESC")
        classes = cursor.fetchall()
        
        return total, avg_finders, avg_quality, classes
    
    def get_patterns_by_class(self, vuln_class: str, limit: int = 20):
        """Get all patterns of a specific class"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, invariant, break_condition, severity, finders_count 
            FROM patterns 
            WHERE vuln_class LIKE ?
            ORDER BY quality_score DESC, finders_count ASC
            LIMIT ?
        """, (f"%{vuln_class}%", limit))
        return cursor.fetchall()
    
    def close(self):
        self.conn.close()