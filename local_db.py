import sqlite3
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from config import Config

class LocalDB:
    def __init__(self):
        self.conn = sqlite3.connect(Config.DB_PATH)
        # Load model once (slow first time, fast after)
        print("[+] Loading embedding model...")
        self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
        self._init_db()
        self._vector_cache = {}  # Cache vectors in memory for speed
        
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
                raw_title TEXT
            )
        """)
        
        # Create index for fast lookup
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_class ON patterns(vuln_class)")
        self.conn.commit()
        
    def add_pattern(self, finding_id: str, pattern: dict, severity: str, title: str):
        """Store with embedding"""
        text = f"{pattern.get('assumed_invariant', '')} {pattern.get('break_condition', '')}"
        embedding = self.encoder.encode(text, convert_to_numpy=True)
        emb_bytes = embedding.astype(np.float32).tobytes()
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO patterns 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding_id,
            pattern.get("vuln_class", "Unknown"),
            pattern.get("assumed_invariant", ""),
            pattern.get("break_condition", ""),
            json.dumps(pattern.get("preconditions", [])),
            json.dumps(pattern.get("code_indicators", [])),
            emb_bytes,
            severity,
            title
        ))
        self.conn.commit()
        
    def load_all_vectors(self):
        """Preload all vectors into memory for fast similarity search"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, invariant, break_condition, code_indicators, embedding, severity FROM patterns")
        
        self._vector_cache = {
            "ids": [],
            "vectors": [],
            "data": []
        }
        
        for row in cursor.fetchall():
            if row[4]:
                vec = np.frombuffer(row[4], dtype=np.float32)
                self._vector_cache["ids"].append(row[0])
                self._vector_cache["vectors"].append(vec)
                self._vector_cache["data"].append({
                    "id": row[0],
                    "invariant": row[1],
                    "break_condition": row[2],
                    "indicators": json.loads(row[3]) if row[3] else [],
                    "severity": row[4]
                })
        
        if self._vector_cache["vectors"]:
            self._vector_cache["vectors"] = np.array(self._vector_cache["vectors"])
            
    def search_similar(self, query: str, top_k: int = 5):
        """Fast vector similarity"""
        if not self._vector_cache.get("vectors") is not None or len(self._vector_cache["vectors"]) == 0:
            self.load_all_vectors()
            
        if len(self._vector_cache["vectors"]) == 0:
            return []
            
        # Encode query
        q_vec = self.encoder.encode(query, convert_to_numpy=True).astype(np.float32)
        
        # Batch cosine similarity
        vectors = self._vector_cache["vectors"]
        norms = np.linalg.norm(vectors, axis=1) * np.linalg.norm(q_vec)
        similarities = np.dot(vectors, q_vec) / norms
        
        # Get top k
        top_indices = np.argsort(similarities)[-top_k:][::-1]
        
        results = []
        for idx in top_indices:
            if similarities[idx] > 0.65:  # Slightly lower threshold for recall
                results.append({
                    **self._vector_cache["data"][idx],
                    "similarity": float(similarities[idx])
                })
        return results
    
    def get_stats(self):
        """Show database statistics"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*), vuln_class FROM patterns GROUP BY vuln_class")
        stats = cursor.fetchall()
        total = sum(s[0] for s in stats)
        return total, stats