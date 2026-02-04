import requests
import time
import json
import logging
from typing import List, Dict, Optional
from config import Config

class SoloditFetcher:
    """Robust fetcher for Solodit findings with rate-limit and quality filtering"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "X-Cyfrin-API-Key": Config.SOLODIT_API_KEY,
            "Content-Type": "application/json"
        })
        self.last_request_time = 0
        
    def validate_api(self) -> bool:
        if not Config.SOLODIT_API_KEY:
            return False
        try:
            self._respect_rate_limit()
            resp = self.session.post(
                f"{Config.SOLODIT_BASE_URL}/findings",
                json={"page": 1, "pageSize": 1},
                timeout=10
            )
            return resp.status_code == 200
        except Exception:
            return False
        
    def _respect_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < Config.SOLODIT_RATE_LIMIT_DELAY:
            time.sleep(Config.SOLODIT_RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()
        
    def fetch_findings(self, protocol_type: Optional[str] = None, 
                      severity: Optional[List[str]] = None, 
                      limit: int = 500) -> List[Dict]:
        
        findings = []
        page = 1
        consecutive_errors = 0
        
        print(f"[+] Fetching up to {limit} high-quality findings from Solodit...")
        
        while len(findings) < limit:
            self._respect_rate_limit()
            
            filters = {}
            if severity:
                valid_impacts = ["HIGH", "MEDIUM", "LOW", "GAS"]
                filtered = [s.upper() for s in severity if s.upper() in valid_impacts]
                if filtered:
                    filters["impact"] = filtered
                    
            if protocol_type:
                filters["protocolCategory"] = [{"value": protocol_type}]
                
            payload = {
                "page": page,
                "pageSize": Config.BATCH_SIZE,
                "filters": filters
            }
                
            try:
                resp = self.session.post(
                    f"{Config.SOLODIT_BASE_URL}/findings", 
                    json=payload,
                    timeout=30
                )
                
                if resp.status_code == 429:
                    time.sleep(60)
                    continue
                
                if resp.status_code != 200:
                    consecutive_errors += 1
                    if consecutive_errors > 3: break
                    time.sleep(5)
                    continue
                
                consecutive_errors = 0
                data = resp.json()
                batch = data.get("findings", [])
                
                if not batch: break
                
                for f in batch:
                    finders = f.get("finders_count", 999)
                    quality = f.get("quality_score", 3)
                    
                    if finders <= Config.MAX_DUPLICATES or quality >= 4:
                        findings.append({
                            "id": f.get("id"),
                            "title": f.get("title"),
                            "content": f.get("content", f.get("summary", "")),
                            "severity": f.get("impact"),
                            "protocol": f.get("protocol_name"),
                            "finders_count": finders,
                            "quality_score": quality,
                            "source_link": f.get("source_link")
                        })
                    if len(findings) >= limit: break
                
                metadata = data.get("metadata", {})
                if page >= metadata.get("totalPages", page): break
                page += 1
                            
            except Exception as e:
                logging.error(f"Solodit fetch error: {e}")
                time.sleep(5)
                
        # Final ranking by quality and rarity
        findings.sort(key=lambda x: (x.get('quality_score', 0), -(x.get('finders_count', 999))), reverse=True)
        print(f"[✓] Successfully retrieved {len(findings)} patterns")
        return findings
