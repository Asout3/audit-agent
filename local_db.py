import sqlite3
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Optional, Any
from config import Config
from collections import defaultdict
import logging

class LocalDB:
    """SQLite-based vector database for vulnerability patterns"""
    
    def __init__(self):
        self.conn = sqlite3.connect(str(Config.DB_PATH))
        self._init_db()
        self.encoder = None
        self._vector_cache = None
        
    def _get_encoder(self):
        if self.encoder is None:
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
                confidence_score REAL DEFAULT 0.5,
                protocol_tags TEXT,
                source_quality TEXT DEFAULT 'community',
                exploit_complexity TEXT DEFAULT 'medium',
                financial_impact TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_class ON patterns(vuln_class)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_confidence ON patterns(confidence_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_complexity ON patterns(exploit_complexity)")
        self.conn.commit()
        
    def add_pattern(self, title: str, content: str, invariant: str, break_condition: str, 
                    vuln_class: str, severity: str, metadata: Dict):
        try:
            text = f"{invariant} {break_condition}"
            embedding = self._get_encoder().encode(text, convert_to_numpy=True)
            emb_bytes = embedding.astype(np.float32).tobytes()

            import hashlib
            pattern_id = hashlib.md5(text.encode()).hexdigest()

            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO patterns
                (id, vuln_class, invariant, break_condition, preconditions, code_indicators,
                 embedding, severity, quality_score, finders_count, raw_title, source_link)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern_id,
                vuln_class,
                invariant,
                break_condition,
                json.dumps([]),
                json.dumps([]),
                emb_bytes,
                severity,
                metadata.get("quality_score", 0),
                metadata.get("finders_count", 1),
                title,
                metadata.get("source", "")
            ))
            self.conn.commit()
            return True
        except Exception as e:
            logging.error(f"DB error: {e}")
            return False

    def is_duplicate(self, invariant: str) -> bool:
        cursor = self.conn.cursor()
        cursor.execute("SELECT 1 FROM patterns WHERE invariant = ? LIMIT 1", (invariant,))
        return cursor.fetchone() is not None
        
    def load_all_vectors(self):
        if self._vector_cache is not None:
            return self._vector_cache
            
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, invariant, break_condition, embedding, severity, finders_count, quality_score
            FROM patterns
        """)
        
        self._vector_cache = {"ids": [], "vectors": [], "data": []}
        
        for row in cursor.fetchall():
            if row[3]:
                vec = np.frombuffer(row[3], dtype=np.float32)
                self._vector_cache["ids"].append(row[0])
                self._vector_cache["vectors"].append(vec)
                self._vector_cache["data"].append({
                    "id": row[0],
                    "invariant": row[1],
                    "break_condition": row[2],
                    "severity": row[4],
                    "finders_count": row[5],
                    "quality_score": row[6]
                })
        
        if self._vector_cache["vectors"]:
            self._vector_cache["vectors"] = np.array(self._vector_cache["vectors"])
        else:
            self._vector_cache["vectors"] = None
        return self._vector_cache
        
    def search_similar(self, query: str, top_k: int = 5) -> List[Dict]:
        cache = self.load_all_vectors()
        if not cache or cache["vectors"] is None or len(cache["vectors"]) == 0:
            return []
        
        q_vec = self._get_encoder().encode(query, convert_to_numpy=True).astype(np.float32)
        vectors = cache["vectors"]
        
        # Cosine similarity
        q_norm = np.linalg.norm(q_vec)
        v_norms = np.linalg.norm(vectors, axis=1)
        
        valid = (v_norms > 0) & (q_norm > 0)
        if not np.any(valid):
            return []
            
        similarities = np.zeros(len(vectors))
        similarities[valid] = np.dot(vectors[valid], q_vec) / (v_norms[valid] * q_norm)
        
        indices = np.argsort(similarities)[-top_k:][::-1]
        
        results = []
        for idx in indices:
            score = float(similarities[idx])
            if score < Config.SIMILARITY_THRESHOLD:
                continue
            data = cache["data"][idx]
            results.append({**data, "similarity": score})
        return results

    def get_stats(self) -> Dict:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM patterns")
        total = cursor.fetchone()[0]
        return {"total_patterns": total}
