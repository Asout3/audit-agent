import requests
import time
import json
from typing import List, Dict, Optional
from config import Config

class SoloditFetcher:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "X-Cyfrin-API-Key": Config.SOLODIT_API_KEY,
            "Content-Type": "application/json"
        })
        self.last_request_time = 0
        self.cache = self._load_checkpoint()
        
    def _load_checkpoint(self) -> dict:
        if Config.CHECKPOINT_PATH.exists():
            with open(Config.CHECKPOINT_PATH) as f:
                return json.load(f)
        return {"findings": [], "page": 1, "complete": False}
    
    def _save_checkpoint(self, findings: list, page: int):
        with open(Config.CHECKPOINT_PATH, 'w') as f:
            json.dump({
                "findings": findings, 
                "page": page,
                "complete": False
            }, f)
    
    def validate_api(self) -> bool:
        try:
            self._respect_rate_limit()
            resp = self.session.post(
                f"{Config.SOLODIT_BASE_URL}/findings",
                json={"page": 1, "pageSize": 1},
                timeout=10
            )
            if resp.status_code == 401:
                print("[✗] Invalid Solodit API Key")
                return False
            if resp.status_code == 200:
                print("[✓] Solodit API connected")
                return True
            print(f"[✗] Solodit API error: {resp.status_code} - {resp.text[:100]}")
            return False
        except Exception as e:
            print(f"[✗] Cannot reach Solodit: {e}")
            return False
        
    def _respect_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < Config.SOLODIT_RATE_LIMIT_DELAY:
            time.sleep(Config.SOLODIT_RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()
        
    def fetch_findings(self, protocol_type: Optional[str] = None, severity: Optional[List[str]] = None, 
                      max_duplicates: int = Config.MAX_DUPLICATES, limit: int = 500) -> List[Dict]:
        
        findings = []
        page = self.cache.get("page", 1)
        
        if self.cache.get("complete") and len(self.cache["findings"]) >= limit:
            print(f"[+] Using cached {len(self.cache['findings'])} findings")
            return self.cache["findings"][:limit]
            
        if self.cache.get("findings"):
            findings = self.cache["findings"]
            print(f"[+] Resuming from page {page}: {len(findings)} findings already collected")
        
        print(f"[+] Fetching {limit} findings from Solodit...")
        
        while len(findings) < limit:
            self._respect_rate_limit()
            
            # Build filters according to API spec
            filters = {}
            if severity:
                filters["impact"] = severity  # ["HIGH", "MEDIUM", etc]
            if protocol_type:
                filters["protocolCategory"] = [{"value": protocol_type}]
                
            payload = {
                "page": page,
                "pageSize": min(100, limit - len(findings)),  # Max 100 per request
                "filters": filters
            }
                
            try:
                resp = self.session.post(
                    f"{Config.SOLODIT_BASE_URL}/findings", 
                    json=payload,
                    timeout=30
                )
                
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get('Retry-After', 60))
                    print(f"  [!] Rate limited, waiting {retry_after}s...")
                    time.sleep(retry_after)
                    continue
                    
                if resp.status_code != 200:
                    print(f"  [!] API error {resp.status_code}: {resp.text[:200]}")
                    time.sleep(5)
                    continue
                    
                data = resp.json()
                batch = data.get("findings", [])
                
                if not batch:
                    break
                    
                # Filter by duplicate count (from general_score or finders_count)
                for f in batch:
                    # Use quality_score or general_score as proxy for rarity
                    # Or use finders_count (lower = less duplicates)
                    finders = f.get("finders_count", 1)
                    if finders <= max_duplicates:
                        findings.append(f)
                        if len(findings) >= limit:
                            break
                
                # Check pagination
                metadata = data.get("metadata", {})
                total_pages = metadata.get("totalPages", page)
                
                if page >= total_pages:
                    break
                    
                page += 1
                print(f"  Progress: {len(findings)}/{limit} (page {page}/{total_pages})")
                
                # Save checkpoint every page
                if len(findings) % 50 == 0:
                    self._save_checkpoint(findings, page)
                            
            except Exception as e:
                print(f"  [!] Network error: {e}, saving checkpoint...")
                self._save_checkpoint(findings, page)
                time.sleep(10)
                
        # Mark complete
        with open(Config.CHECKPOINT_PATH, 'w') as f:
            json.dump({"findings": findings, "page": page, "complete": True}, f)
            
        print(f"[✓] Fetched {len(findings)} high-quality findings")
        return findings