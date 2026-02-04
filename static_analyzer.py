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
            delegate_matches = re.finditer(r'(\w+)\.delegatecall\s*\(', code, re.IGNORECASE)
            for match in delegate_matches:
                target = match.group(1)
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
            start = max(0, match.start() - 300)
            end = min(len(code), match.end() + 300)
            context = code[start:end]
            
            if 'nonReentrant' not in context and 'reentrancy' not in context.lower():
                rest_of_function = code[match.end():match.end()+500]
                if re.search(r'\b(\w+)\s*=|\w+\+\+|--\w+', rest_of_function):
                    findings.append({
                        "type": "reentrancy_no_guard",
                        "severity": "high",
                        "description": "External call followed by state change, no reentrancy guard",
                        "score": 80,
                        "confidence": "medium"
                    })
                    break
        
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
            if addr not in ['0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                           '0x0000000000000000000000000000000000000000']:
                if not any(x in code for x in ['constant', 'immutable']):
                    findings.append({
                        "type": "hardcoded_address",
                        "severity": "low",
                        "description": f"Hardcoded address: {match.group(0)[:20]}...",
                        "score": 40,
                        "confidence": "low"
                    })
                break
        
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
        
        # NEW PATTERNS
        
        # 11. Timestamp manipulation
        timestamp_patterns = [
            (r'block\.timestamp\s*[<>]=?\s*\d+', "Timestamp used in inequality - miners can manipulate"),
            (r'block\.timestamp\s*%\s*\d+', "Timestamp used in modulo - predictable pattern"),
            (r'now\s*[<>]=?\s*\d+', "Legacy 'now' keyword - timestamp manipulation risk"),
        ]
        for pattern, desc in timestamp_patterns:
            if re.search(pattern, code):
                findings.append({
                    "type": "timestamp_manipulation",
                    "severity": "medium",
                    "description": desc,
                    "score": 50,
                    "confidence": "medium"
                })
                break
        
        # 12. Storage collision (proxy pattern)
        storage_patterns = [
            r'(uint|bool|address)\s+public\s+\w+\s*=\s*\d+;',
            r'mapping\s*\([^)]+\)\s+public\s+\w+\s*=',
        ]
        for pattern in storage_patterns:
            if re.search(pattern, code):
                # Check if in upgradeable context
                if any(x in code_lower for x in ['proxy', 'implementation', 'upgradeable', 'eip1822']):
                    findings.append({
                        "type": "storage_collision",
                        "severity": "critical",
                        "description": "Storage slot collision risk in upgradeable contract",
                        "score": 85,
                        "confidence": "high"
                    })
                    break
        
        # 13. ERC20 approval double-spend (approve before setting to 0)
        if 'approve(' in code:
            approve_context = re.search(r'function\s+approve\s*\([^)]*\)[^{]*\{([^}]{0,500})', code, re.DOTALL)
            if approve_context:
                impl = approve_context.group(1)
                if 'require(' not in impl and 'if' not in impl.lower():
                    findings.append({
                        "type": "erc20_approval_double_spend",
                        "severity": "high",
                        "description": "approve() without checking current value - front-running risk",
                        "score": 75,
                        "confidence": "medium"
                    })
        
        # 14. Uninitialized proxy
        if re.search(r'fallback\s*\(\s*\)', code, re.IGNORECASE):
            # Check if delegatecall is used without implementation check
            fallback_impl = re.search(r'fallback\s*\(\s*\)[^{]*\{([^}]{0,300})', code, re.DOTALL)
            if fallback_impl and 'delegatecall' in fallback_impl.group(1).lower():
                if 'implementation' not in code_lower or 'address(0)' not in code_lower:
                    findings.append({
                        "type": "uninitialized_proxy",
                        "severity": "critical",
                        "description": "Proxy fallback without implementation zero-address check",
                        "score": 90,
                        "confidence": "high"
                    })
        
        # 15. Weak randomness (using block data)
        weak_random_patterns = [
            r'block\.timestamp\s*[+*/%-]',
            r'blockhash\s*\(',
            r'block\.difficulty',
        ]
        for pattern in weak_random_patterns:
            if re.search(pattern, code):
                findings.append({
                    "type": "weak_randomness",
                    "severity": "high",
                    "description": "Block data used for randomness - predictable by miners",
                    "score": 70,
                    "confidence": "high"
                })
                break
        
        # 16. Improper access control
        access_issues = []
        
        # Check for functions that modify state without access control
        state_modify_patterns = [
            r'function\s+\w+\([^)]*\)\s*public\s*\{',
            r'function\s+\w+\([^)]*\)\s*external\s*\{',
        ]
        
        for pattern in state_modify_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                func_start = match.start()
                func_end = code.find('}', func_start + 200)
                func_body = code[func_start:func_end]
                
                # Check if function modifies state
                if any(x in func_body for x in ['=', 'transfer(', 'mint(', 'burn(', 'approve(']):
                    # Check if access control is present
                    has_access_control = any(
                        x in func_body.lower() for x in [
                            'onlyowner', 'onlyadmin', 'require(msg.sender',
                            'hasrole', 'isowner', 'auth'
                        ]
                    )
                    
                    if not has_access_control:
                        access_issues.append({
                            "type": "missing_access_control",
                            "severity": "high",
                            "description": "Public/external function modifies state without access control",
                            "score": 80,
                            "confidence": "medium"
                        })
        
        findings.extend(access_issues[:3])  # Limit to 3 access control findings
        
        # 17. Proxy selector clash
        if 'fallback()' in code or 'receive()' in code:
            # Check for multiple functions with same selector collision risk
            func_names = re.findall(r'function\s+(\w+)\s*\([^)]*\)', code)
            func_sigs = {}
            for func in func_names:
                sig = func[:4]  # Simplified selector check
                if sig in func_sigs:
                    findings.append({
                        "type": "function_selector_clash",
                        "severity": "medium",
                        "description": f"Potential selector clash: {func_sigs[sig]} and {func}",
                        "score": 55,
                        "confidence": "low"
                    })
                    break
                func_sigs[sig] = func
        
        return findings
