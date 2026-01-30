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
                data = resp.json()
                print(f"[✓] Solodit API connected ({data.get('metadata', {}).get('totalResults', 0)} total findings available)")
                return True
            print(f"[✗] Solodit error {resp.status_code}: {resp.text[:100]}")
            return False
        except Exception as e:
            print(f"[✗] Cannot reach Solodit: {e}")
            return False
        
    def _respect_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < Config.SOLODIT_RATE_LIMIT_DELAY:
            time.sleep(Config.SOLODIT_RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()
        
    def fetch_findings(self, protocol_type: Optional[str] = None, 
                      severity: Optional[List[str]] = None, 
                      limit: int = 300) -> List[Dict]:
        
        findings = []
        page = 1
        consecutive_errors = 0
        
        print(f"[+] Fetching up to {limit} findings from Solodit...")
        
        while len(findings) < limit:
            self._respect_rate_limit()
            
            filters = {}
            if severity:
                filters["impact"] = [s.upper() for s in severity]
            if protocol_type:
                filters["protocolCategory"] = [{"value": protocol_type}]
                
            payload = {
                "page": page,
                "pageSize": min(Config.BATCH_SIZE, limit - len(findings)),
                "filters": filters
            }
                
            try:
                resp = self.session.post(
                    f"{Config.SOLODIT_BASE_URL}/findings", 
                    json=payload,
                    timeout=30
                )
                
                if resp.status_code == 429:
                    reset_time = int(resp.headers.get('X-RateLimit-Reset', 60))
                    print(f"  [!] Rate limited, waiting {max(reset_time, 60)}s...")
                    time.sleep(max(reset_time, 60))
                    continue
                
                if resp.status_code == 400:
                    print(f"  [!] Bad request: {resp.text[:200]}")
                    print(f"      Payload: {json.dumps(payload)[:200]}")
                    break
                    
                if resp.status_code != 200:
                    consecutive_errors += 1
                    if consecutive_errors > 3:
                        print(f"  [!] Too many errors, stopping")
                        break
                    print(f"  [!] API error {resp.status_code}, retry...")
                    time.sleep(5)
                    continue
                
                consecutive_errors = 0
                data = resp.json()
                batch = data.get("findings", [])
                
                if not batch:
                    break
                
                # Filter by rarity (finder count)
                for f in batch:
                    finders = f.get("finders_count", 999)
                    if finders <= Config.MAX_DUPLICATES:
                        findings.append({
                            "id": f.get("id"),
                            "title": f.get("title"),
                            "content": f.get("content", f.get("summary", "")),
                            "severity": f.get("impact"),
                            "protocol": f.get("protocol_name"),
                            "finders_count": finders,
                            "quality_score": f.get("quality_score", 0),
                            "source_link": f.get("source_link")
                        })
                    if len(findings) >= limit:
                        break
                
                metadata = data.get("metadata", {})
                total_pages = metadata.get("totalPages", page)
                
                if page >= total_pages:
                    break
                    
                rate_limit = data.get("rateLimit", {})
                remaining = rate_limit.get("remaining", 20)
                
                if remaining < 3:
                    print(f"  [!] Rate limit low ({remaining}), pausing 60s...")
                    time.sleep(60)
                    
                page += 1
                print(f"  Progress: {len(findings)}/{limit} (page {page}/{total_pages}, {len(batch)} this batch)")
                            
            except Exception as e:
                print(f"  [!] Error: {e}")
                time.sleep(5)
                
        print(f"[✓] Fetched {len(findings) high-quality findings")
        return findings