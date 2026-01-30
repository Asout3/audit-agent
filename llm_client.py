import json
from typing import Dict, List
import requests
import time
from dataclasses import dataclass
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
        
    def _strict_parse(self, text: str) -> ExtractionResult:
        """Strict JSON validation with fallback repair"""
        try:
            # Clean markdown
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            
            data = json.loads(text.strip())
            
            # Validate required fields exist and are non-empty
            required_strings = ['vuln_class', 'assumed_invariant', 'break_condition']
            for field in required_strings:
                if not isinstance(data.get(field), str) or len(data.get(field, '').strip()) < 5:
                    raise ValueError(f"Missing or invalid {field}")
            
            # Validate arrays
            preconditions = data.get('preconditions', [])
            code_indicators = data.get('code_indicators', [])
            if not isinstance(preconditions, list):
                preconditions = [str(preconditions)] if preconditions else []
            if not isinstance(code_indicators, list):
                code_indicators = [str(code_indicators)] if code_indicators else []
            
            # Validate severity
            severity = data.get('severity_score', 'Medium')
            if severity not in ['High', 'Medium', 'Low']:
                severity = 'Medium'
            
            return ExtractionResult(
                vuln_class=data['vuln_class'].strip(),
                assumed_invariant=data['assumed_invariant'].strip(),
                break_condition=data['break_condition'].strip(),
                preconditions=[p.strip() for p in preconditions if p],
                code_indicators=[c.strip() for c in code_indicators if c],
                severity_score=severity
            )
            
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            raise ValueError(f"Parse failed: {e}")
    
    def extract_invariant(self, content: str, title: str, max_retries: int = 3) -> ExtractionResult:
        """Extract with strict validation and aggressive retry"""
        
        base_prompt = f"""Analyze this vulnerability and extract the invariant violation.

Title: {title}
Content: {content[:7000]}

You MUST return valid JSON with exactly these fields:
{{
    "vuln_class": "Short category name",
    "assumed_invariant": "What developers assumed was true (2-3 sentences)",
    "break_condition": "Specific attack that broke it (2-3 sentences)",
    "preconditions": ["condition1", "condition2"],
    "code_indicators": ["functionName", "variablePattern"],
    "severity_score": "High" or "Medium" or "Low"
}}

Rules:
- vuln_class: One word or short phrase (Reentrancy, OracleManipulation, etc)
- assumed_invariant: Must start with "Developers assumed..."
- break_condition: Must describe the specific attack vector
- All string fields must be non-empty
- preconditions must be an array of strings, even if empty []

Return ONLY the JSON object, no markdown, no explanation."""

        for attempt in range(max_retries):
            try:
                resp = requests.post(
                    f"{Config.OPENROUTER_BASE_URL}/chat/completions",
                    headers=self.headers,
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": base_prompt}],
                        "temperature": 0.0,  # Deterministic
                        "max_tokens": 800,
                        "response_format": {"type": "json_object"}
                    },
                    timeout=60
                )
                
                if resp.status_code != 200:
                    time.sleep(2 ** attempt)
                    continue
                
                result_text = resp.json()["choices"][0]["message"]["content"]
                return self._strict_parse(result_text)
                
            except Exception as e:
                if attempt == max_retries - 1:
                    # Final fallback with simplified prompt
                    return self._emergency_extraction(content, title)
                time.sleep(2 ** attempt)
        
        return self._emergency_extraction(content, title)
    
    def _emergency_extraction(self, content: str, title: str) -> ExtractionResult:
        """Last resort: extract anything usable"""
        # Try to infer from title and first paragraph
        first_para = content.split('\n')[0] if content else title
        
        vuln_type = "Unknown"
        if any(w in title.lower() for w in ['reentrancy', 're-entrancy']):
            vuln_type = "Reentrancy"
        elif any(w in title.lower() for w in ['oracle', 'price']):
            vuln_type = "OracleManipulation"
        elif any(w in title.lower() for w in ['access', 'permission', 'auth']):
            vuln_type = "AccessControl"
        
        return ExtractionResult(
            vuln_class=vuln_type,
            assumed_invariant=f"Developers assumed {first_para[:100]}",
            break_condition="Invariant violated due to unexpected interaction",
            preconditions=[],
            code_indicators=[],
            severity_score="Medium"
        )
    
    def generate_hypothesis(self, target_code: str, patterns: List[Dict], func_name: str) -> List[Dict]:
        """Generate hypothesis for a specific function"""
        if not patterns:
            return []
            
        patterns_text = "\n".join([
            f"- {p['invariant']}: {p['break_condition'][:100]}" 
            for p in patterns[:2]
        ])
        
        prompt = f"""Analyze function '{func_name}' for invariant violations.

Function Code:
{target_code[:3000]}

Historical patterns:
{patterns_text}

Return JSON array with max 2 hypotheses:
[{{"hypothesis": "...", "attack_vector": "...", "confidence": "High/Medium/Low"}}]"""

        try:
            resp = requests.post(
                f"{Config.OPENROUTER_BASE_URL}/chat/completions",
                headers=self.headers,
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": 600,
                    "response_format": {"type": "json_object"}
                },
                timeout=30
            )
            
            text = resp.json()["choices"][0]["message"]["content"]
            data = json.loads(text)
            return data if isinstance(data, list) else []
        except:
            return []