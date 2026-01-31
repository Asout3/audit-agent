import json
import time
import requests
from dataclasses import dataclass
from typing import List, Dict
from config import Config

@dataclass
class ExtractionResult:
    vuln_class: str
    assumed_invariant: str
    break_condition: str
    preconditions: List[str]
    code_indicators: List[str]
    severity_score: str

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
        """Test OpenRouter connection"""
        try:
            resp = requests.post(
                f"{Config.OPENROUTER_BASE_URL}/chat/completions",
                headers=self.headers,
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": "Say hi"}],
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
    
    def _call_with_retry(self, payload: dict, max_retries: int = 3) -> dict:
        """Make API call with exponential backoff"""
        for i in range(max_retries):
            try:
                resp = requests.post(
                    f"{Config.OPENROUTER_BASE_URL}/chat/completions",
                    headers=self.headers,
                    json=payload,
                    timeout=60
                )
                
                if resp.status_code == 429:
                    wait = 2 ** (i + 2)
                    print(f"    [!] Rate limited, waiting {wait}s...")
                    time.sleep(wait)
                    continue
                
                if resp.status_code != 200:
                    print(f"    [!] OR error {resp.status_code}, retry {i+1}/{max_retries}")
                    time.sleep(2 ** i)
                    continue
                
                return resp.json()
            except Exception as e:
                print(f"    [!] Network error: {e}, retry {i+1}")
                time.sleep(2 ** i)
        
        return None
    
    def _strict_parse(self, text: str) -> ExtractionResult:
        """Parse LLM response with multiple fallback strategies"""
        try:
            # Clean markdown
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            
            data = json.loads(text.strip())
            
            # Validate and clean
            def clean_str(s):
                if not s or not isinstance(s, str):
                    return ""
                return s.strip()
            
            vuln_class = clean_str(data.get('vuln_class', 'Unknown'))
            if not vuln_class or vuln_class.lower() in ['unknown', 'n/a', 'none']:
                vuln_class = self._infer_vuln_class(data.get('assumed_invariant', '') + data.get('break_condition', ''))
            
            invariant = clean_str(data.get('assumed_invariant', ''))
            if len(invariant) < 10:
                raise ValueError("Invariant too short")
            
            break_cond = clean_str(data.get('break_condition', ''))
            if len(break_cond) < 10:
                raise ValueError("Break condition too short")
            
            # Normalize arrays
            preconditions = data.get('preconditions', [])
            if not isinstance(preconditions, list):
                preconditions = [str(preconditions)] if preconditions else []
            preconditions = [p.strip() for p in preconditions if p and len(str(p)) > 2]
            
            code_indicators = data.get('code_indicators', [])
            if not isinstance(code_indicators, list):
                code_indicators = [str(code_indicators)] if code_indicators else []
            code_indicators = [c.strip() for c in code_indicators if c and len(str(c)) > 1]
            
            severity = data.get('severity_score', 'Medium')
            if severity not in ['High', 'Medium', 'Low']:
                severity = 'Medium'
            
            return ExtractionResult(
                vuln_class=vuln_class,
                assumed_invariant=invariant,
                break_condition=break_cond,
                preconditions=preconditions,
                code_indicators=code_indicators,
                severity_score=severity
            )
            
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            raise ValueError(f"Parse failed: {e}")
    
    def _infer_vuln_class(self, text: str) -> str:
        """Infer vulnerability class from text"""
        text = text.lower()
        if any(w in text for w in ['reentrancy', 're-entrancy', 'reentrant']):
            return "Reentrancy"
        elif any(w in text for w in ['oracle', 'price', 'feed', 'chainlink']):
            return "OracleManipulation"
        elif any(w in text for w in ['access', 'permission', 'auth', 'onlyowner']):
            return "AccessControl"
        elif any(w in text for w in ['flash', 'loan', 'flashloan']):
            return "FlashLoan"
        elif any(w in text for w in ['rounding', 'precision', 'division']):
            return "PrecisionLoss"
        elif any(w in text for w in ['delegatecall', 'delegate']):
            return "DelegatecallInjection"
        elif any(w in text for w in ['integer', 'overflow', 'underflow']):
            return "IntegerOverflow"
        elif any(w in text for w in ['dos', 'denial', 'gas', 'unbounded']):
            return "DoS"
        return "LogicError"
    
    def extract_invariant(self, content: str, title: str, max_retries: int = 3) -> ExtractionResult:
        """Extract invariant with aggressive retry and repair"""
        
        # First try: strict JSON
        base_prompt = f"""Analyze this smart contract vulnerability and extract the invariant violation that the developer assumed was true.

Title: {title}
Content: {content[:7500]}

Identify:
1. What class of vulnerability is this (one or two words)?
2. What did the developer assume was invariant/always true?
3. What specific condition broke that invariant?
4. What code patterns indicate this vulnerability?
5. What preconditions must exist for the attack?

Return valid JSON:
{{
    "vuln_class": "CategoryName",
    "assumed_invariant": "Complete sentence describing the assumption",
    "break_condition": "Complete sentence describing how it was broken",
    "preconditions": ["array", "of", "conditions"],
    "code_indicators": ["functionName", "variablePattern"],
    "severity_score": "High/Medium/Low"
}}

Rules:
- assumed_invariant MUST start with "Assumed that..." or "Developers assumed..."
- break_condition MUST describe the attack mechanism
- preconditions must be strings describing state prerequisites
- vuln_class examples: Reentrancy, OracleManipulation, AccessControl, FlashLoan, PrecisionLoss, DelegatecallInjection"""

        for attempt in range(max_retries):
            try:
                result = self._call_with_retry({
                    "model": self.model,
                    "messages": [{"role": "user", "content": base_prompt}],
                    "temperature": Config.OR_TEMPERATURE,
                    "max_tokens": 800,
                    "response_format": {"type": "json_object"}
                })
                
                if result:
                    text = result["choices"][0]["message"]["content"]
                    return self._strict_parse(text)
                    
            except Exception as e:
                if attempt == max_retries - 1:
                    break
                time.sleep(2 ** attempt)
        
        # Fallback: try with simpler prompt
        return self._emergency_extraction(content, title)
    
    def _emergency_extraction(self, content: str, title: str) -> ExtractionResult:
        """Last resort extraction using simple heuristics"""
        content_lower = (content + title).lower()
        
        # Infer from keywords
        vuln_type = self._infer_vuln_class(content_lower)
        
        # Extract first substantial sentence as invariant
        sentences = content.replace('\n', ' ').split('. ')
        first_real = title
        for s in sentences:
            if len(s) > 20 and 'function' not in s.lower()[:10]:
                first_real = s.strip()
                break
        
        return ExtractionResult(
            vuln_class=vuln_type,
            assumed_invariant=f"Developers assumed {first_real[:120]}",
            break_condition="Invariant violated due to unexpected interaction or edge case",
            preconditions=[],
            code_indicators=[],
            severity_score="Medium"
        )
    
    def generate_hypothesis(self, target_code: str, patterns: List[Dict], func_name: str) -> List[Dict]:
        """Generate vulnerability hypotheses based on similar patterns"""
        if not patterns:
            return []
            
        # Take top 2 patterns for context
        top_patterns = patterns[:2]
        context = "\n\n".join([
            f"Historical Bug {i+1}:\nInvariant: {p.get('invariant', 'Unknown')}\nBroken by: {p.get('break_condition', 'Unknown')[:200]}"
            for i, p in enumerate(top_patterns) if p.get('invariant')
        ])
        
        prompt = f"""Analyze this function for the same invariant violation patterns seen in historical bugs.

Function: {func_name}
Code:
{target_code[:2500]}

Historical patterns to check against:
{context}

Does this function make similar dangerous assumptions? Return JSON array with up to 2 findings:
[
  {{
    "hypothesis": "Specific description of the potential bug",
    "attack_vector": "How an attacker would exploit it",
    "confidence": "High/Medium/Low",
    "invariant_assumed": "What the code assumes",
    "location": "Specific line or condition"
  }}
]

If no match, return empty array []."""

        try:
            result = self._call_with_retry({
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 600,
                "response_format": {"type": "json_object"}
            }, max_retries=2)
            
            if result:
                text = result["choices"][0]["message"]["content"]
                data = json.loads(text)
                return data if isinstance(data, list) else []
        except Exception as e:
            print(f"  [!] Hypothesis generation failed: {e}")
        
        return []
    
    def batch_extract(self, findings: List[Dict], batch_size: int = 3) -> List[Dict]:
        """Extract invariants for multiple findings in one call (faster)"""
        results = []
        
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]
            
            # Single LLM call for batch
            batch_text = "\n\n---\n\n".join([
                f"FINDING {j}:\nTitle: {f.get('title', '')}\nContent: {f.get('content', '')[:1500]}"
                for j, f in enumerate(batch)
            ])
            
            prompt = f"""Extract invariants for {len(batch)} findings. Return JSON array of {len(batch)} objects.

{batch_text}

Return exactly this format:
[
  {{
    "vuln_class": "...",
    "assumed_invariant": "...",
    "break_condition": "...",
    "preconditions": [],
    "code_indicators": [],
    "severity_score": "..."
  }},
  ...repeat for each finding...
]"""

            try:
                result = self._call_with_retry({
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.0,
                    "max_tokens": 1200,
                    "response_format": {"type": "json_object"}
                }, max_retries=2)
                
                if result:
                    text = result["choices"][0]["message"]["content"]
                    data = json.loads(text)
                    if isinstance(data, list) and len(data) == len(batch):
                        for idx, item in enumerate(data):
                            try:
                                inv = item.get('assumed_invariant', '')
                                if len(inv) < 5:
                                    raise ValueError("Too short")
                                results.append({
                                    "finding": batch[idx],
                                    "extraction": ExtractionResult(
                                        vuln_class=item.get('vuln_class', 'Unknown'),
                                        assumed_invariant=inv,
                                        break_condition=item.get('break_condition', ''),
                                        preconditions=item.get('preconditions', []),
                                        code_indicators=item.get('code_indicators', []),
                                        severity_score=item.get('severity_score', 'Medium')
                                    )
                                })
                            except:
                                # Fallback to individual extraction
                                results.append({
                                    "finding": batch[idx],
                                    "extraction": self._emergency_extraction(
                                        batch[idx].get('content', ''),
                                        batch[idx].get('title', '')
                                    )
                                })
                        continue
            except Exception as e:
                print(f"  [!] Batch extraction failed: {e}")
            
            # Fallback: individual extraction
            for f in batch:
                results.append({
                    "finding": f,
                    "extraction": self.extract_invariant(f.get('content', ''), f.get('title', ''))
                })
        
        return results