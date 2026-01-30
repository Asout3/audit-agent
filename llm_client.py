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
            print(f"[✗] OpenRouter error {resp.status_code}")
            return False
        except Exception as e:
            print(f"[✗] Cannot reach OpenRouter: {e}")
            return False
        
    def _call_with_retry(self, payload: dict, max_retries=3) -> dict:
        for i in range(max_retries):
            try:
                resp = requests.post(
                    f"{Config.OPENROUTER_BASE_URL}/chat/completions",
                    headers=self.headers,
                    json=payload,
                    timeout=60
                )
                
                if resp.status_code == 429:
                    wait = 2 ** i * 10
                    print(f"    [!] Rate limit, waiting {wait}s...")
                    time.sleep(wait)
                    continue
                    
                if resp.status_code != 200:
                    print(f"    [!] OR error {resp.status_code}, retry {i+1}")
                    time.sleep(2 ** i)
                    continue
                
                return resp.json()
                    
            except Exception as e:
                print(f"    [!] Network error: {e}, retry {i+1}")
                time.sleep(2 ** i)
                
        return None
        
    def _validate_extraction(self, result: dict) -> bool:
        """Ensure extraction has required fields"""
        required = ['vuln_class', 'assumed_invariant', 'break_condition']
        return all(
            result.get(field) and 
            result[field] not in ['Unknown', '', 'ParseError', 'ExtractionFailed']
            for field in required
        )
        
    def extract_invariant(self, content: str, title: str) -> dict:
        """Extract with validation and retry"""
        
        def _extract():
            prompt = f"""Analyze this smart contract vulnerability finding and extract the core invariant violation.

Title: {title}
Finding Content: {content[:6000]}

You must identify:
1. What did developers ASSUME was always true? (the invariant)
2. What specific condition BROKE that assumption? (the attack)
3. What functions/code patterns were involved?

Return ONLY valid JSON in this exact format:
{{
    "vuln_class": "High-level category (Reentrancy, OracleManipulation, AccessControl, etc)",
    "assumed_invariant": "What developers assumed was always true (e.g., 'price cannot change during a transaction')",
    "break_condition": "The specific attack that violated it (e.g., 'flash loan manipulated price between check and execution')",
    "preconditions": ["list", "of", "required", "conditions"],
    "code_indicators": ["functionName", "variablePattern", "modifier"],
    "severity_score": "High/Medium/Low"
}}

Focus on the ASSUMPTION FAILURE - what mental model was wrong? Be specific and technical."""

            result = self._call_with_retry({
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 800
            })
            
            if not result:
                return None
                
            try:
                text = result["choices"][0]["message"]["content"]
                # Clean markdown
                if "```json" in text:
                    text = text.split("```json")[1].split("```")[0]
                elif "```" in text:
                    text = text.split("```")[1].split("```")[0]
                return json.loads(text.strip())
            except:
                return None
        
        # Try twice
        for attempt in range(2):
            result = _extract()
            if result and self._validate_extraction(result):
                return result
            print(f"    [!] Invalid extraction, retry {attempt+1}")
        
        # Fallback
        return {
            "vuln_class": "ExtractionFailed",
            "assumed_invariant": title[:100],
            "break_condition": "Failed to parse",
            "preconditions": [],
            "code_indicators": [],
            "severity_score": "Medium"
        }
    
    def generate_hypothesis(self, target_code: str, patterns: list, filename: str) -> list:
        if not patterns:
            return []
            
        patterns_text = "\n\n".join([
            f"Historical Bug {i+1}:\nInvariant: {p['invariant']}\nBroken by: {p['break_condition']}" 
            for i, p in enumerate(patterns[:3]) if p.get('invariant')
        ])
        
        prompt = f"""You are auditing: {filename}

TARGET CODE (focus on entry points and external calls):
{target_code[:4000]}

HISTORICAL INVARIANT VIOLATIONS (similar architecture):
{patterns_text}

TASK: Generate 2-3 specific, testable hypotheses where this target might violate similar invariants.

For each hypothesis provide:
1. The assumed invariant in the target
2. The specific break condition (attack vector)
3. Exact function/location
4. Confidence (High/Medium/Low)

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