import re
from typing import List, Dict

class StaticAnalyzer:
    """Comprehensive static analysis with false positive filtering"""
    
    def __init__(self):
        self.known_safe_patterns = {
            'delegatecall': [
                'ERC1967', 'transparent', 'upgradeable', 'implementation', 'eip1167', 
                'proxy', 'clones.clone', 'minimal proxy'
            ],
            'assembly': [
                'create2', 'extcodesize', 'returndatasize', 'mload', 'mstore'
            ]
        }
    
    def is_likely_safe_delegatecall(self, context: str) -> bool:
        """Check if delegatecall is part of standard proxy pattern"""
        context_lower = context.lower()
        return any(safe in context_lower for safe in self.known_safe_patterns['delegatecall'])
    
    def analyze(self, code: str, filename: str) -> List[Dict]:
        findings = []
        code_lower = code.lower()
        
        # 1. Unchecked low-level calls (high confidence)
        call_matches = re.finditer(r'(\.\s*call\s*\{[^}]*\}\s*\([^)]*\))', code, re.IGNORECASE)
        for match in call_matches:
            start = max(0, match.start() - 200)
            end = min(len(code), match.end() + 200)
            context = code[start:end]
            
            # Check if checked
            if not any(x in context for x in ['require(', 'if(', 'success', 'return']):
                findings.append({
                    "type": "unchecked_low_level_call",
                    "severity": "high",
                    "description": "Low-level call without success check",
                    "code": match.group(0)[:60],
                    "score": 85,
                    "confidence": "high"
                })
        
        # 2. Delegatecall injection (check if user-controlled)
        if 'delegatecall' in code_lower:
            # Check if target is controllable
            delegate_matches = re.finditer(r'(\w+)\.delegatecall\s*\(', code, re.IGNORECASE)
            for match in delegate_matches:
                target = match.group(1)
                # If target is msg.data, storage slot, or parameter = dangerous
                context_before = code[max(0, match.start()-500):match.start()]
                
                if any(x in context_before for x in ['calldata', 'msg.data', 'storage', 'sload']):
                    findings.append({
                        "type": "arbitrary_delegatecall",
                        "severity": "critical",
                        "description": f"Delegatecall to potentially controllable target: {target}",
                        "score": 95,
                        "confidence": "high"
                    })
                elif not self.is_likely_safe_delegatecall(context_before):
                    findings.append({
                        "type": "delegatecall_no_validation",
                        "severity": "medium",
                        "description": "Delegatecall present - verify target validation",
                        "score": 60,
                        "confidence": "medium"
                    })
        
        # 3. Oracle staleness
        if any(x in code for x in ['oracle', 'price', 'feed']) and 'updatedAt' not in code:
            if not any(x in code for x in ['timestamp', 'round', 'staleness', 'timeout']):
                findings.append({
                    "type": "stale_oracle",
                    "severity": "medium",
                    "description": "Price oracle may not check data freshness",
                    "score": 65,
                    "confidence": "medium"
                })
        
        # 4. Decimal mismatch (USDC 6 vs 18)
        if 'decimals' in code_lower:
            if ('6' in code and '18' in code) or ('usdc' in code_lower and 'e18' in code.lower()):
                if 'scale' not in code_lower and 'normalize' not in code_lower:
                    findings.append({
                        "type": "decimal_mismatch",
                        "severity": "high",
                        "description": "Mixed token decimals without scaling",
                        "score": 75,
                        "confidence": "high"
                    })
        
        # 5. Reentrancy without guard
        ext_calls = re.finditer(r'(\w+\.(call|transfer|send|mint|burn)\s*[\(\{])', code, re.IGNORECASE)
        for match in ext_calls:
            # Check surrounding code
            start = max(0, match.start() - 300)
            end = min(len(code), match.end() + 300)
            context = code[start:end]
            
            if 'nonReentrant' not in context and 'reentrancy' not in context.lower():
                # Check if state changes after
                rest_of_function = code[match.end():match.end()+500]
                if re.search(r'\b(\w+)\s*=|\w+\+\+|--\w+', rest_of_function):
                    findings.append({
                        "type": "reentrancy_no_guard",
                        "severity": "high",
                        "description": "External call followed by state change, no reentrancy guard",
                        "score": 80,
                        "confidence": "medium"
                    })
                    break  # One finding per function is enough
        
        # 6. TX.origin usage
        if 'tx.origin' in code_lower:
            findings.append({
                "type": "tx_origin_auth",
                "severity": "medium",
                "description": "tx.origin used - vulnerable to phishing attacks",
                "score": 60,
                "confidence": "high"
            })
        
        # 7. Self-destruct
        if 'selfdestruct' in code_lower or 'suicide(' in code_lower:
            if 'onlyOwner' not in code and 'controlled' not in code_lower:
                findings.append({
                    "type": "unprotected_selfdestruct",
                    "severity": "critical",
                    "description": "Self-destruct without obvious access control",
                    "score": 90,
                    "confidence": "high"
                })
        
        # 8. Unchecked math (Solidity <0.8 or unchecked blocks)
        if 'unchecked' in code_lower:
            # Find unchecked blocks
            blocks = re.finditer(r'unchecked\s*\{', code, re.IGNORECASE)
            for block in blocks:
                block_end = code.find('}', block.end())
                block_code = code[block.end():block_end]
                
                if any(x in block_code for x in ['+', '-', '*', '/']) and 'SafeMath' not in code:
                    findings.append({
                        "type": "unchecked_math",
                        "severity": "medium",
                        "description": "Unchecked math operations",
                        "score": 55,
                        "confidence": "medium"
                    })
                    break
        
        # 9. Hardcoded addresses
        hardcoded = re.finditer(r'0x[a-fA-F0-9]{40}', code)
        for match in hardcoded:
            addr = match.group(0).lower()
            if addr not in ['0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',  # ETH placeholder
                           '0x0000000000000000000000000000000000000000']:  # Zero address
                # Check if it's a known protocol (skip known ones)
                if not any(x in code for x in ['constant', 'immutable']):
                    findings.append({
                        "type": "hardcoded_address",
                        "severity": "low",
                        "description": f"Hardcoded address: {match.group(0)[:20]}...",
                        "score": 40,
                        "confidence": "low"
                    })
                break  # One is enough
        
        # 10. Timestamp dependence
        if 'block.timestamp' in code_lower or 'now' in code_lower:
            if any(x in code for x in ['<', '>', '=', 'require', 'if']):
                findings.append({
                    "type": "timestamp_dependence",
                    "severity": "low",
                    "description": "Contract logic depends on block timestamp",
                    "score": 45,
                    "confidence": "low"
                })
        
        return findings