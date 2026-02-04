import json
import time
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any, Iterator
from groq import Groq
from config import Config

@dataclass
class ExtractionResult:
    vuln_class: str
    assumed_invariant: str
    break_condition: str
    preconditions: List[str]
    code_indicators: List[str]
    severity_score: str

@dataclass
class HypothesisResult:
    hypothesis: str
    attack_vector: str
    confidence: str
    invariant_assumed: str
    location: str
    remediation: str = ""
    vulnerability_type: str = ""

class LLMClient:
    """Robust Groq SDK client for smart contract analysis"""
    
    def __init__(self):
        self.api_key = Config.GROQ_API_KEY
        if not self.api_key:
            logging.error("GROQ_API_KEY not set in environment")
            # We don't raise here to allow the CLI to show help or other info before failing
        self.model = Config.GROQ_MODEL
        try:
            self.client = Groq(api_key=self.api_key) if self.api_key else None
        except Exception as e:
            logging.error(f"Failed to initialize Groq client: {e}")
            self.client = None
        
    def validate(self) -> bool:
        """Test Groq connection"""
        if not self.client:
            return False
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Respond with 'connected'"}],
                max_tokens=5
            )
            content = response.choices[0].message.content.strip().lower()
            if 'connected' in content:
                return True
            return False
        except Exception as e:
            logging.error(f"Cannot reach Groq: {e}")
            return False
    
    def _call_with_retry(self, messages: List[Dict], stream: bool = False, **kwargs) -> Any:
        """Make API call with exponential backoff and rate limit handling"""
        if not self.client:
            raise ValueError("Groq client not initialized. Check your API key.")
            
        max_retries = kwargs.pop('max_retries', Config.GROQ_MAX_RETRIES)
        
        for i in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    timeout=Config.GROQ_TIMEOUT,
                    stream=stream,
                    **kwargs
                )
                return response
            except Exception as e:
                error_str = str(e).lower()
                if 'rate' in error_str or 'limit' in error_str or '429' in error_str:
                    wait = 2 ** (i + 2)
                    logging.warning(f"Rate limited, waiting {wait}s...")
                    time.sleep(wait)
                    continue
                elif i < max_retries - 1:
                    logging.warning(f"Groq error: {e}, retry {i+1}/{max_retries}")
                    time.sleep(2 ** i)
                    continue
                else:
                    logging.error(f"Groq error after {max_retries} retries: {e}")
                    raise
        
        return None
    
    def get_completion_stream(self, messages: List[Dict], **kwargs) -> Iterator[str]:
        """Get streaming completion from Groq"""
        response = self._call_with_retry(messages, stream=True, **kwargs)
        for chunk in response:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    def _strict_parse(self, text: str) -> ExtractionResult:
        """Parse LLM response for invariant extraction"""
        try:
            # Clean up potential markdown blocks
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            
            data = json.loads(text.strip())
            
            return ExtractionResult(
                vuln_class=data.get('vuln_class', 'LogicError'),
                assumed_invariant=data.get('assumed_invariant', 'Unknown'),
                break_condition=data.get('break_condition', 'Unknown'),
                preconditions=data.get('preconditions', []),
                code_indicators=data.get('code_indicators', []),
                severity_score=data.get('severity_score', 'Medium')
            )
        except Exception as e:
            logging.error(f"Parse failed: {e}")
            raise ValueError(f"Parse failed: {e}")

    def extract_invariant(self, content: str, title: str) -> ExtractionResult:
        """Extract invariant with retry logic"""
        prompt = f"""Analyze this smart contract vulnerability and extract the invariant violation.
Title: {title}
Content: {content[:7000]}

Return valid JSON:
{{
    "vuln_class": "e.g., Reentrancy",
    "assumed_invariant": "Assumed that...",
    "break_condition": "How it broke...",
    "preconditions": ["cond1", "cond2"],
    "code_indicators": ["pattern1"],
    "severity_score": "High/Medium/Low"
}}"""

        try:
            response = self._call_with_retry(
                [{"role": "user", "content": prompt}],
                temperature=0.05,
                response_format={"type": "json_object"}
            )
            return self._strict_parse(response.choices[0].message.content)
        except Exception:
            return self._emergency_extraction(content, title)

    def _emergency_extraction(self, content: str, title: str) -> ExtractionResult:
        return ExtractionResult(
            vuln_class="LogicError",
            assumed_invariant=f"Developers assumed {title[:100]}",
            break_condition="Unknown violation",
            preconditions=[],
            code_indicators=[],
            severity_score="Medium"
        )

    def generate_hypothesis(self, target_code: str, patterns: List[Dict], func_name: str) -> List[Dict]:
        """Generate vulnerability hypotheses based on similar patterns"""
        if not patterns:
            return []
            
        context = "\n\n".join([
            f"Pattern {i+1}:\nInvariant: {p.get('invariant')}\nBreak: {p.get('break_condition')}"
            for i, p in enumerate(patterns[:Config.PATTERNS_PER_CALL])
        ])
        
        prompt = f"""Analyze function '{func_name}' for bugs similar to these historical patterns:
{context}

Function Code:
{target_code[:3000]}

Return a JSON array of findings:
[
  {{
    "hypothesis": "Description",
    "attack_vector": "Step-by-step",
    "confidence": "High/Medium/Low",
    "invariant_assumed": "Assumption",
    "location": "Line/Condition",
    "remediation": "Fix",
    "vulnerability_type": "Class"
  }}
]"""

        try:
            response = self._call_with_retry(
                [{"role": "user", "content": prompt}],
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            text = response.choices[0].message.content
            data = json.loads(text)
            if isinstance(data, dict) and "findings" in data:
                return data["findings"]
            return data if isinstance(data, list) else []
        except Exception as e:
            logging.error(f"Hypothesis generation failed: {e}")
            return []

    def batch_extract(self, findings: List[Dict], batch_size: int = 5) -> List[Dict]:
        """Batch extract invariants for efficiency"""
        results = []
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]
            prompt = f"Extract invariants for these {len(batch)} findings. Return JSON array of objects.\n\n"
            for j, f in enumerate(batch):
                prompt += f"FINDING {j}: {f.get('title')}\n{f.get('content')[:1000]}\n---\n"
            
            try:
                response = self._call_with_retry(
                    [{"role": "user", "content": prompt}],
                    temperature=0.0,
                    response_format={"type": "json_object"}
                )
                data = json.loads(response.choices[0].message.content)
                items = data if isinstance(data, list) else data.get("extractions", [])
                
                for idx, item in enumerate(items):
                    if idx < len(batch):
                        results.append({
                            "finding": batch[idx],
                            "extraction": ExtractionResult(
                                vuln_class=item.get('vuln_class', 'Unknown'),
                                assumed_invariant=item.get('assumed_invariant', 'Unknown'),
                                break_condition=item.get('break_condition', 'Unknown'),
                                preconditions=item.get('preconditions', []),
                                code_indicators=item.get('code_indicators', []),
                                severity_score=item.get('severity_score', 'Medium')
                            )
                        })
            except Exception:
                # Fallback to individual extraction
                for f in batch:
                    results.append({
                        "finding": f,
                        "extraction": self.extract_invariant(f.get('content', ''), f.get('title', ''))
                    })
        return results
