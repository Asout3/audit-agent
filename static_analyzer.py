import re
from typing import List, Dict
import logging

class StaticAnalyzer:
    """Comprehensive static analysis with 35+ vulnerability patterns"""
    
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
        
        # 1. Unchecked low-level calls
        call_matches = re.finditer(r'(\.\s*call\s*\{[^}]*\}\s*\([^)]*\))', code, re.IGNORECASE)
        for match in call_matches:
            start = max(0, match.start() - 200)
            end = min(len(code), match.end() + 200)
            context = code[start:end]
            if not any(x in context for x in ['require(', 'if(', 'success', 'return', 'assert(']):
                findings.append({
                    "type": "unchecked_low_level_call",
                    "severity": "high",
                    "description": "Low-level call without success check",
                    "code": match.group(0)[:60],
                    "score": 85,
                    "confidence": "high",
                    "remediation": "Check the return value of the low-level call and handle failures."
                })
        
        # 2. Delegatecall injection
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
                        "confidence": "high",
                        "remediation": "Avoid delegatecall to user-provided addresses. Use a whitelist if necessary."
                    })

        # 3. Timestamp manipulation dependence
        if 'block.timestamp' in code_lower or 'now' in code_lower:
            if re.search(r'(block\.timestamp|now)\s*[<>]=?\s*', code):
                findings.append({
                    "type": "timestamp_dependence",
                    "severity": "low",
                    "description": "Contract logic depends on block.timestamp for comparisons",
                    "score": 40,
                    "confidence": "medium",
                    "remediation": "Be aware that miners can manipulate timestamps by a few seconds."
                })

        # 4. Storage collision in proxy contracts
        if any(x in code_lower for x in ['proxy', 'implementation', 'upgradeable']):
            if re.search(r'^\s*(uint|bool|address|bytes32)\s+(public|private|internal)?\s+\w+\s*;', code, re.MULTILINE):
                findings.append({
                    "type": "storage_collision_risk",
                    "severity": "high",
                    "description": "Potential storage collision in upgradeable contract",
                    "score": 80,
                    "confidence": "medium",
                    "remediation": "Use EIP-1967 storage slots or inherited storage for upgradeable contracts."
                })

        # 5. ERC20 approval race condition
        if 'approve(' in code and 'increaseAllowance' not in code:
            findings.append({
                "type": "erc20_approval_race",
                "severity": "medium",
                "description": "Standard ERC20 approve() is vulnerable to front-running",
                "score": 55,
                "confidence": "high",
                "remediation": "Use increaseAllowance/decreaseAllowance or set allowance to 0 before changing."
            })

        # 6. Proxy selector clash
        if 'fallback' in code_lower and 'delegatecall' in code_lower:
            findings.append({
                "type": "proxy_selector_clash",
                "severity": "high",
                "description": "Risk of function selector clash between proxy and implementation",
                "score": 75,
                "confidence": "low",
                "remediation": "Use transparent proxy pattern or UUPS with careful selector management."
            })

        # 7. Uninitialized proxy implementation
        if 'constructor()' in code and 'initializer' not in code_lower and any(x in code_lower for x in ['proxy', 'implementation']):
            findings.append({
                "type": "uninitialized_implementation",
                "severity": "critical",
                "description": "Implementation contract might be uninitialized",
                "score": 90,
                "confidence": "medium",
                "remediation": "Call the initializer in the constructor or use _disableInitializers()."
            })

        # 8. Weak randomness
        weak_rand = re.finditer(r'keccak256\s*\(\s*abi\.encodePacked\s*\(\s*([^)]*)\s*\)\s*\)', code)
        for match in weak_rand:
            if any(x in match.group(1) for x in ['block.timestamp', 'block.difficulty', 'blockhash', 'now']):
                findings.append({
                    "type": "weak_randomness",
                    "severity": "high",
                    "description": "Weak randomness source (block properties)",
                    "score": 85,
                    "confidence": "high",
                    "remediation": "Use Chainlink VRF for secure randomness."
                })

        # 9. Improper access control (tx.origin)
        if 'tx.origin' in code_lower:
            findings.append({
                "type": "tx_origin_usage",
                "severity": "medium",
                "description": "Use of tx.origin for authorization is dangerous",
                "score": 65,
                "confidence": "high",
                "remediation": "Use msg.sender instead of tx.origin."
            })

        # 10. Integer overflow/underflow in unchecked blocks
        if 'unchecked' in code_lower:
            findings.append({
                "type": "unchecked_math_usage",
                "severity": "low",
                "description": "Unchecked block used - ensure overflow/underflow is impossible",
                "score": 30,
                "confidence": "medium",
                "remediation": "Only use unchecked blocks when overflow/underflow is mathematically impossible."
            })

        # 11. Delegatecall injection via assembly
        if 'assembly' in code_lower and 'delegatecall' in code_lower:
            findings.append({
                "type": "assembly_delegatecall",
                "severity": "critical",
                "description": "Low-level delegatecall in assembly",
                "score": 95,
                "confidence": "high",
                "remediation": "Ensure the target address is not user-controllable."
            })

        # 12. Signature replay attacks
        if 'ecrecover' in code_lower and 'chainid' not in code_lower:
            findings.append({
                "type": "signature_replay",
                "severity": "high",
                "description": "Signature verification missing chainId (potential cross-chain replay)",
                "score": 80,
                "confidence": "medium",
                "remediation": "Include block.chainid and a nonce in the signed message."
            })

        # 13. Missing contract existence check before low-level calls
        if '.call(' in code and 'extcodesize' not in code_lower:
            findings.append({
                "type": "missing_existence_check",
                "severity": "low",
                "description": "Low-level call to potentially non-existent contract",
                "score": 40,
                "confidence": "low",
                "remediation": "Check if target address has code using extcodesize before calling."
            })

        # 14. Incorrect shift operations
        if '<<' in code or '>>' in code:
            findings.append({
                "type": "bitwise_shift_check",
                "severity": "low",
                "description": "Bitwise shift operation - verify logic",
                "score": 25,
                "confidence": "low",
                "remediation": "Ensure shift directions and amounts are correct."
            })

        # 15. Assert state changes
        assert_matches = re.finditer(r'assert\s*\(([^)]*)\)', code)
        for match in assert_matches:
            if '=' in match.group(1):
                findings.append({
                    "type": "state_change_in_assert",
                    "severity": "medium",
                    "description": "State change inside assert() statement",
                    "score": 60,
                    "confidence": "high",
                    "remediation": "Do not modify state inside assert/require/if conditions."
                })

        # 16. Block number dependence
        if 'block.number' in code_lower:
            findings.append({
                "type": "block_number_dependence",
                "severity": "low",
                "description": "Logic depends on block.number",
                "score": 35,
                "confidence": "medium",
                "remediation": "Ensure block time assumptions are correct (e.g. 12s for Ethereum)."
            })

        # 17. Ether lock
        if 'receive()' in code or 'fallback()' in code or 'payable' in code_lower:
            if not any(x in code_lower for x in ['withdraw', 'transfer', 'send', 'call{value:']):
                findings.append({
                    "type": "ether_lock",
                    "severity": "high",
                    "description": "Contract receives Ether but has no withdrawal function",
                    "score": 85,
                    "confidence": "medium",
                    "remediation": "Implement a withdrawal or rescue function for Ether."
                })

        # 18. Unprotected selfdestruct
        if 'selfdestruct' in code_lower:
            if 'onlyOwner' not in code and 'require(msg.sender' not in code:
                findings.append({
                    "type": "unprotected_selfdestruct",
                    "severity": "critical",
                    "description": "Selfdestruct without access control",
                    "score": 98,
                    "confidence": "high",
                    "remediation": "Restrict selfdestruct to an admin or remove it entirely."
                })

        # 19. Hardcoded secrets
        if re.search(r'(password|secret|key|private)\s*=\s*".+"', code_lower):
            findings.append({
                "type": "hardcoded_secret",
                "severity": "critical",
                "description": "Potential hardcoded secret or password",
                "score": 95,
                "confidence": "medium",
                "remediation": "Never store secrets on-chain; use off-chain secrets or environment variables."
            })

        # 20. Floating pragma
        if 'pragma solidity' in code_lower and '^' in code:
            findings.append({
                "type": "floating_pragma",
                "severity": "low",
                "description": "Floating pragma used (e.g. ^0.8.0)",
                "score": 20,
                "confidence": "high",
                "remediation": "Lock the pragma version to a specific version for deployments."
            })

        # 21. Improper access control (missing modifiers)
        if re.search(r'function\s+\w+\s*\(.*\)\s+(public|external)\s*\{', code):
            if any(x in code_lower for x in ['mint', 'burn', 'withdraw', 'transferOwnership']):
                if not any(x in code_lower for x in ['onlyowner', 'onlyadmin', 'hasrole']):
                    findings.append({
                        "type": "missing_access_control",
                        "severity": "high",
                        "description": "Critical function lacks access control modifier",
                        "score": 85,
                        "confidence": "medium",
                        "remediation": "Add onlyOwner or appropriate access control modifiers."
                    })

        # 22. Multiple Solidity versions (via pragma)
        if len(re.findall(r'pragma solidity', code_lower)) > 1:
            findings.append({
                "type": "multiple_pragmas",
                "severity": "low",
                "description": "Multiple pragma definitions found",
                "score": 15,
                "confidence": "high",
                "remediation": "Use a single consistent Solidity version across the project."
            })

        # 23. Incorrect use of abi.encodePacked with dynamic types
        if 'abi.encodePacked' in code_lower:
            if code_lower.count('string') + code_lower.count('bytes') > 1:
                findings.append({
                    "type": "abi_encodepacked_collision",
                    "severity": "medium",
                    "description": "abi.encodePacked with multiple dynamic types can lead to hash collisions",
                    "score": 50,
                    "confidence": "medium",
                    "remediation": "Use abi.encode() instead of abi.encodePacked()."
                })

        # 24. Missing __gap variable in upgradeable contracts
        if 'upgradeable' in code_lower and 'contract' in code_lower:
            if 'uint256[50] __gap' not in code:
                findings.append({
                    "type": "missing_upgrade_gap",
                    "severity": "medium",
                    "description": "Missing storage gap in upgradeable contract",
                    "score": 45,
                    "confidence": "medium",
                    "remediation": "Add 'uint256[50] __gap;' at the end of storage variables."
                })

        # 25. Costly loop (unbounded)
        if re.search(r'for\s*\(.*;\s*.*;\s*.*\)', code):
            if 'length' in code_lower and not any(x in code_lower for x in ['limit', 'max']):
                findings.append({
                    "type": "unbounded_loop",
                    "severity": "medium",
                    "description": "Potential unbounded loop over array length",
                    "score": 55,
                    "confidence": "low",
                    "remediation": "Limit the maximum number of iterations or use a paging mechanism."
                })

        # 26. Shadowing state variables
        # (Simplified check: local var name same as common state var names)
        for var in ['owner', 'balance', 'totalSupply']:
            if re.search(r'\b' + var + r'\s*=', code) and re.search(r'uint\s+' + var + r'|address\s+' + var, code):
                if code.count(var) > 2:
                    findings.append({
                        "type": "variable_shadowing",
                        "severity": "low",
                        "description": f"Potential shadowing of state variable: {var}",
                        "score": 25,
                        "confidence": "low",
                        "remediation": "Avoid using the same name for local and state variables."
                    })

        # 27. Reentrancy: State change after call
        if '.call{' in code_lower or '.transfer(' in code_lower or '.send(' in code_lower:
            lines = code.split('\n')
            for i, line in enumerate(lines):
                if any(x in line for x in ['.call', '.transfer', '.send']):
                    for next_line in lines[i+1:i+5]:
                        if '=' in next_line and not any(x in next_line for x in ['==', '!=', '>=', '<=']):
                            findings.append({
                                "type": "reentrancy_state_change",
                                "severity": "high",
                                "description": "State variable updated after external call",
                                "score": 88,
                                "confidence": "high",
                                "remediation": "Use the Checks-Effects-Interactions pattern."
                            })
                            break
        
        # 28. Incorrect interface implementation
        if 'interface' in code_lower and 'contract' in code_lower:
            if 'is' in code_lower:
                # Basic check for common interfaces
                for interface in ['IERC20', 'IERC721', 'IERC1155']:
                    if interface in code and 'function' not in code_lower:
                        findings.append({
                            "type": "interface_mismatch",
                            "severity": "medium",
                            "description": f"Contract claims to implement {interface} but logic is missing",
                            "score": 50,
                            "confidence": "low",
                            "remediation": "Ensure all interface functions are correctly implemented."
                        })

        # 29. Use of blockhash(block.number)
        if 'blockhash(block.number)' in code_lower:
            findings.append({
                "type": "blockhash_current_block",
                "severity": "high",
                "description": "blockhash(block.number) always returns 0",
                "score": 80,
                "confidence": "high",
                "remediation": "Use blockhash(block.number - 1) for the previous block's hash."
            })

        # 30. Empty catch block
        if 'catch' in code_lower and '{}' in code:
            findings.append({
                "type": "empty_catch",
                "severity": "low",
                "description": "Empty catch block found - errors might be silently ignored",
                "score": 30,
                "confidence": "medium",
                "remediation": "Emit an event or handle the error in the catch block."
            })

        # 31. Misuse of msg.value in a loop
        if 'msg.value' in code_lower and ('for' in code_lower or 'while' in code_lower):
            findings.append({
                "type": "msg_value_in_loop",
                "severity": "high",
                "description": "msg.value used inside a loop (potential multi-call vulnerability)",
                "score": 85,
                "confidence": "medium",
                "remediation": "Avoid using msg.value inside loops; it stays the same for the whole transaction."
            })

        # 32. Use of deprecated 'suicide'
        if 'suicide(' in code_lower:
            findings.append({
                "type": "deprecated_suicide",
                "severity": "low",
                "description": "Use of deprecated keyword 'suicide'",
                "score": 20,
                "confidence": "high",
                "remediation": "Use 'selfdestruct' instead of 'suicide'."
            })

        # 33. Incorrect use of 'ecrecover'
        if 'ecrecover' in code_lower:
            if 'v < 27' not in code and 'v == 27' not in code:
                findings.append({
                    "type": "ecrecover_malleability",
                    "severity": "medium",
                    "description": "Signature malleability risk in ecrecover",
                    "score": 60,
                    "confidence": "low",
                    "remediation": "Use OpenZeppelin's ECDSA library for signature verification."
                })

        # 34. Missing zero-address check
        if 'address' in code_lower and '=' in code:
            if 'require(' in code_lower and 'address(0)' not in code:
                findings.append({
                    "type": "missing_zero_address_check",
                    "severity": "low",
                    "description": "Missing zero-address check for address update",
                    "score": 35,
                    "confidence": "low",
                    "remediation": "Add require(newAddress != address(0)) before updating address state variables."
                })

        # 35. Return value of transfer/transferFrom not checked
        if re.search(r'\.transferFrom\s*\(', code) or re.search(r'\btransfer\s*\(', code):
            if not any(x in code for x in ['SafeERC20', 'safeTransfer']):
                if 'require' not in code and 'if' not in code:
                    findings.append({
                        "type": "unchecked_erc20_transfer",
                        "severity": "medium",
                        "description": "ERC20 transfer/transferFrom return value not checked",
                        "score": 65,
                        "confidence": "medium",
                        "remediation": "Use OpenZeppelin's SafeERC20 or check the return value."
                    })

        return findings
