import re
from typing import List, Dict

class StaticAnalyzer:
    """Fast rule-based checks independent of historical data"""
    
    def analyze(self, code: str, filename: str) -> List[Dict]:
        findings = []
        code_lower = code.lower()
        
        # P0: Unchecked low-level calls
        if '.call{value:' in code or '.call(' in code:
            # Find call patterns not checked for success
            calls = re.findall(r'(\w*\.call\{[^}]*\}\([^)]*\))', code)
            for call in calls:
                ctx_start = max(0, code.find(call) - 300)
                ctx_end = code.find(call) + len(call) + 100
                context = code[ctx_start:ctx_end]
                
                if 'require' not in context and 'success' not in context and 'if' not in context:
                    findings.append({
                        "type": "unchecked_low_level_call",
                        "severity": "high",
                        "description": "External call without success check",
                        "code": call[:60],
                        "score": 85
                    })
        
        # P0: Proxy storage collision
        if ('proxy' in filename.lower() or 'upgrade' in filename.lower() or 
            'delegatecall' in code_lower):
            if 'implementation' in code_lower and 'keccak256' not in code_lower:
                findings.append({
                    "type": "proxy_storage_collision",
                    "severity": "high",
                    "description": "Proxy pattern without proper implementation slot",
                    "score": 80
                })
        
        # P1: Oracle staleness
        if any(x in code for x in ['oracle', 'price', 'feed']):
            if 'updatedAt' not in code and 'timestamp' not in code and 'round' not in code:
                findings.append({
                    "type": "stale_oracle",
                    "severity": "medium",
                    "description": "Price oracle used without freshness check",
                    "score": 70
                })
        
        # P1: Decimal mismatch (USDC 6 vs 18)
        if 'decimals' in code_lower:
            if ('6' in code and '18' in code) or ('usdc' in code_lower and '1e18' in code):
                findings.append({
                    "type": "decimal_mismatch",
                    "severity": "high",
                    "description": "Mixed decimals (6 and 18) without proper scaling",
                    "score": 75
                })
        
        # P2: Reentrancy guard missing on external + state change
        if '.call{' in code and 'nonReentrant' not in code:
            if '=' in code[code.find('.call{'):code.find('.call{')+500]:
                findings.append({
                    "type": "potential_reentrancy",
                    "severity": "medium",
                    "description": "External call with state change, no reentrancy guard",
                    "score": 65
                })
        
        # P2: Self-destruct / delegatecall to param
        if 'selfdestruct' in code_lower or 'suicide' in code_lower:
            findings.append({
                "type": "self_destruct",
                "severity": "critical",
                "description": "Self-destruct present",
                "score": 90
            })
        
        return findings