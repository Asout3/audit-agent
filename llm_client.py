import requests
import json
import time
from config import Config

class LLMClient:
    def __init__(self):
        self.api_key = Config.OPENROUTER_API_KEY
        self.model = Config.OR_MODEL
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://localhost",
            "X-Title": "DeepAudit",
            "Content-Type": "application/json"
        }
        
    def validate(self) -> bool:
        """Test OpenRouter before wasting time"""
        try:
            resp = requests.post(
                f"{Config.OPENROUTER_BASE_URL}/chat/completions",
                headers=self.headers,
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": "Hi"}],
                    "max_tokens": 5
                },
                timeout=10
            )
            if resp.status_code == 200:
                print(f"[✓] OpenRouter connected ({self.model})")
                return True
            print(f"[✗] OpenRouter error {resp.status_code}: {resp.text[:100]}")
            return False
        except Exception as e:
            print(f"[✗] Cannot reach OpenRouter: {e}")
            return False
        
    def _call_with_retry(self, payload: dict, max_retries=3) -> dict:
        """Retry with exponential backoff (free tier reliability)"""
        for i in range(max_retries):
            try:
                resp = requests.post(
                    f"{Config.OPENROUTER_BASE_URL}/chat/completions",
                    headers=self.headers,
                    json=payload,
                    timeout=60
                )
                
                if resp.status_code == 429:  # Rate limited
                    wait = 2 ** i * 5  # 5s, 10s, 20s
                    print(f"    [!] OR rate limit, waiting {wait}s...")
                    time.sleep(wait)
                    continue
                    
                if resp.status_code == 200:
                    return resp.json()
                    
                print(f"    [!] OR error {resp.status_code}, retry {i+1}/{max_retries}")
                time.sleep(2 ** i)
                
            except Exception as e:
                print(f"    [!] OR network error: {e}, retry {i+1}")
                time.sleep(2 ** i)
                
        return None
        
    def extract_invariant(self, content: str, title: str) -> dict:
        """Extract developer assumptions that were wrong"""
        
        prompt = f"""Analyze this smart contract vulnerability finding and extract the DEEP INVARIANT VIOLATION.

Title: {title}
Content: {content[:6000]}

Format your response as JSON with these exact keys:
{{
    "vuln_class": "Category like Reentrancy, OracleManipulation, AccessControl, etc",
    "assumed_invariant": "What did developers assume was always true? (e.g., 'price cannot change between check and execution')",
    "break_condition": "What specific condition broke this assumption? (e.g., 'flash loan sandwiched the oracle update')",
    "preconditions": ["list", "of", "required", "conditions", "for", "bug"],
    "code_indicators": ["function names", "variables", "patterns"],
    "severity_score": "High/Medium/Low based on exploitability"
}}

Focus on the MENTAL MODEL FAILURE - what assumption about the system was wrong?"""

        result = self._call_with_retry({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 800,
            "response_format": {"type": "json_object"}
        })
        
        if not result:
            return {
                "vuln_class": "Unknown",
                "assumed_invariant": title,
                "break_condition": "Failed to parse",
                "preconditions": [],
                "code_indicators": [],
                "severity_score": "Medium"
            }
            
        try:
            text = result["choices"][0]["message"]["content"]
            # Clean up markdown code blocks if present
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
                
            parsed = json.loads(text.strip())
            return parsed
        except:
            return {
                "vuln_class": "ParseError",
                "assumed_invariant": content[:200],
                "break_condition": "",
                "preconditions": [],
                "code_indicators": [],
                "severity_score": "Medium"
            }
    
    def generate_hypothesis(self, target_code: str, patterns: list, filename: str) -> list:
        """Generate specific attack hypotheses"""
        
        patterns_text = "\n\n".join([
            f"Bug {i+1}: {p['invariant']}\nBreak condition: {p['break_condition']}"
            for i, p in enumerate(patterns[:3])
        ])
        
        prompt = f"""You are auditing this Solidity file: {filename}

CODE:
{target_code[:4000]}

HISTORICAL BUG PATTERNS (similar architecture):
{patterns_text}

TASK: Identify 3 specific, testable hypotheses where this code might violate similar invariants.

For each hypothesis:
1. Identify the specific function and line pattern
2. State the assumed invariant that might be wrong
3. Describe the break condition (attack vector)
4. Assign confidence (High/Medium/Low) based on code similarity

Return JSON array:
[{{"hypothesis": "...", "location": "functionName", "invariant_assumed": "...", "attack_vector": "...", "confidence": "..."}}]"""

        result = self._call_with_retry({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 1000
        })
        
        if not result:
            return []
            
        try:
            text = result["choices"][0]["message"]["content"]
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except:
            return []