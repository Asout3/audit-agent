import requests
import time
import json
from typing import List, Dict, Optional
from config import Config

class SoloditFetcher:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {Config.SOLODIT_API_KEY}",
            "Content-Type": "application/json"
        })
        self.last_request_time = 0
        self.cache = self._load_checkpoint()
        
    def _load_checkpoint(self) -> dict:
        """Resume from crash"""
        if Config.CHECKPOINT_PATH.exists():
            with open(Config.CHECKPOINT_PATH) as f:
                return json.load(f)
        return {"findings": [], "offset": 0, "complete": False}
    
    def _save_checkpoint(self, findings: list, offset: int):
        """Save progress"""
        with open(Config.CHECKPOINT_PATH, 'w') as f:
            json.dump({
                "findings": findings, 
                "offset": offset,
                "complete": False
            }, f)
    
    def validate_api(self) -> bool:
        """Test API before long fetch"""
        try:
            self._respect_rate_limit()
            resp = self.session.get(f"{Config.SOLODIT_BASE_URL}/findings", params={"limit": 1}, timeout=10)
            if resp.status_code == 401:
                print("[✗] Invalid Solodit API Key")
                return False
            if resp.status_code == 200:
                print("[✓] Solodit API connected")
                return True
            print(f"[✗] Solodit API error: {resp.status_code}")
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
        
        # Check if we have cached complete fetch
        if self.cache.get("complete") and len(self.cache["findings"]) >= limit:
            print(f"[+] Using cached {len(self.cache['findings'])} findings")
            return self.cache["findings"][:limit]
            
        # Resume from checkpoint
        findings = self.cache.get("findings", [])
        offset = self.cache.get("offset", 0)
        
        if findings:
            print(f"[+] Resuming from checkpoint: {len(findings)} findings already collected")
        
        print(f"[+] Fetching {limit} findings from Solodit (rate limited: 20/min)...")
        
        while len(findings) < limit:
            self._respect_rate_limit()
            
            params = {
                "limit": min(Config.BATCH_SIZE, limit - len(findings)),
                "offset": offset
            }
            if severity:
                params["severity"] = ",".join(severity)
            if protocol_type:
                params["protocol_type"] = protocol_type
                
            try:
                resp = self.session.get(f"{Config.SOLODIT_BASE_URL}/findings", params=params, timeout=30)
                
                if resp.status_code == 429:
                    print("  [!] Rate limited, backing off 60s...")
                    time.sleep(60)
                    continue
                if resp.status_code != 200:
                    print(f"  [!] API error {resp.status_code}, retrying...")
                    time.sleep(5)
                    continue
                    
                data = resp.json()
                batch = data.get("data", [])
                
                if not batch:
                    break
                    
                for f in batch:
                    dupe_count = f.get("duplicate_count", 999)
                    if dupe_count <= max_duplicates:
                        findings.append(f)
                        if len(findings) >= limit:
                            break
                
                offset += len(batch)
                print(f"  Progress: {len(findings)}/{limit} (offset {offset})")
                
                # Save checkpoint every 50 findings
                if len(findings) % 50 == 0:
                    self._save_checkpoint(findings, offset)
                            
            except Exception as e:
                print(f"  [!] Network error: {e}, saving checkpoint...")
                self._save_checkpoint(findings, offset)
                time.sleep(10)
                
        # Mark complete
        with open(Config.CHECKPOINT_PATH, 'w') as f:
            json.dump({"findings": findings, "offset": offset, "complete": True}, f)
            
        print(f"[✓] Fetched {len(findings)} high-quality findings")
        return findings