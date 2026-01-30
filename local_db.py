import sqlite3
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from config import Config

class LocalDB:
    def __init__(self):
        self.conn = sqlite3.connect(Config.DB_PATH)
        print("[+] Loading embedding model (this takes 30s first time)...")
        self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
        self._init_db()
        self._vector_cache = None
        
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
                source_link TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_class ON patterns(vuln_class)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_finders ON patterns(finders_count)")
        self.conn.commit()
        
    def add_pattern(self, finding_id: str, pattern: dict, severity: str, 
                    quality_score: float = 0, finders_count: int = 1, 
                    title: str = "", source_link: str = ""):
        text = f"{pattern.get('assumed_invariant', '')} {pattern.get('break_condition', '')}"
        embedding = self.encoder.encode(text, convert_to_numpy=True)
        emb_bytes = embedding.astype(np.float32).tobytes()
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO patterns 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            source_link
        ))
        self.conn.commit()
        
    def load_all_vectors(self):
        """Cache all vectors in RAM for fast search"""
        if self._vector_cache is not None:
            return
            
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, invariant, break_condition, code_indicators, 
                   embedding, severity, finders_count, quality_score 
            FROM patterns
        """)
        
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
                    "severity": row[4],
                    "finders_count": row[5],
                    "quality_score": row[6]
                })
        
        if self._vector_cache["vectors"]:
            self._vector_cache["vectors"] = np.array(self._vector_cache["vectors"])
            print(f"[+] Loaded {len(self._vector_cache['vectors'])} patterns into memory")
        
    def search_similar(self, query: str, top_k: int = 5):
        self.load_all_vectors()
        if not self._vector_cache or len(self._vector_cache["vectors"]) == 0:
            return []
            
        q_vec = self.encoder.encode(query, convert_to_numpy=True).astype(np.float32)
        vectors = self._vector_cache["vectors"]
        
        # Cosine similarity
        norms = np.linalg.norm(vectors, axis=1) * np.linalg.norm(q_vec)
        similarities = np.dot(vectors, q_vec) / norms
        
        indices = np.argsort(similarities)[-top_k:][::-1]
        
        results = []
        for idx in indices:
            if similarities[idx] > Config.SIMILARITY_THRESHOLD:
                results.append({
                    **self._vector_cache["data"][idx],
                    "similarity": float(similarities[idx])
                })
        return results
    
    def get_stats(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*), AVG(finders_count) FROM patterns")
        total, avg_finders = cursor.fetchone()
        
        cursor.execute("SELECT vuln_class, COUNT(*) FROM patterns GROUP BY vuln_class ORDER BY COUNT(*) DESC")
        classes = cursor.fetchall()
        
        return total, avg_finders, classes