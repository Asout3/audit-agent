import re
from pathlib import Path
from typing import List, Dict, Tuple, Set
from collections import defaultdict

# Optional Slither import
try:
    from slither import Slither
    from slither.core.declarations import Function
    SLITHER_AVAILABLE = True
except ImportError:
    SLITHER_AVAILABLE = False
    print("[!] Slither not available, using regex-only analysis")

class CallGraph:
    """Lightweight call graph without Slither"""
    def __init__(self, content: str):
        self.content = content
        self.functions = {}
        self.calls = defaultdict(list)  # func -> [called_funcs]
        self.external_calls = defaultdict(list)
        self.state_reads = defaultdict(set)
        self.state_writes = defaultdict(set)
        
    def parse(self):
        """Parse functions and their relationships using regex"""
        # Find all function definitions
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\{'
        for match in re.finditer(func_pattern, self.content):
            func_name = match.group(1)
            modifiers = match.group(2)
            
            # Extract function body
            start = match.end() - 1
            brace_count = 0
            body_start = start
            in_string = False
            string_char = None
            
            for i in range(start, len(self.content)):
                char = self.content[i]
                if char in ['"', "'"]:
                    if not in_string:
                        in_string = True
                        string_char = char
                    elif char == string_char:
                        in_string = False
                elif not in_string:
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            body = self.content[body_start:i+1]
                            self.functions[func_name] = {
                                'body': body,
                                'modifiers': modifiers,
                                'is_external': 'external' in modifiers or 'public' in modifiers,
                                'is_payable': 'payable' in modifiers
                            }
                            break
        
        # Analyze each function body
        for func_name, data in self.functions.items():
            body = data['body']
            
            # Find internal calls
            for other_func in self.functions.keys():
                if other_func != func_name and re.search(r'\b' + other_func + r'\s*\(', body):
                    self.calls[func_name].append(other_func)
            
            # Find external calls
            ext_patterns = [
                r'(\w+)\.call\{[^}]*\}\([^)]*\)',
                r'(\w+)\.delegatecall\([^)]*\)',
                r'(\w+)\.staticcall\([^)]*\)',
                r'IERC20\([^)]+\)\.(transfer|transferFrom|approve)\([^)]*\)',
                r'(\w+)\.swap\([^)]*\)',
                r'(\w+)\.mint\([^)]*\)',
                r'(\w+)\.burn\([^)]*\)',
            ]
            for pattern in ext_patterns:
                matches = re.findall(pattern, body)
                self.external_calls[func_name].extend(matches)
            
            # Find state reads/writes (simple heuristic)
            state_patterns = re.findall(r'\b(\w+)\s*[+\-]?=', body)
            self.state_writes[func_name] = set(state_patterns)
            
            # Reads are variables used in conditions or right-hand side
            read_patterns = re.findall(r'\b(\w+)\s*\>', body)  # Comparisons
            read_patterns += re.findall(r'if\s*\(\s*(\w+)', body)  # If conditions
            self.state_reads[func_name] = set(read_patterns)

class TargetParser:
    def __init__(self, code_path: str):
        self.path = Path(code_path)
        self.files = list(self.path.rglob("*.sol"))
        
    def is_likely_proxy(self, content: str) -> bool:
        """Detect if contract is a proxy pattern"""
        proxy_indicators = [
            'delegatecall', 'implementation', 'upgradeable', 'TransparentUpgradeableProxy',
            'ERC1967', 'beacon', 'UUPS'
        ]
        return sum(1 for ind in proxy_indicators if ind.lower() in content.lower()) >= 2
    
    def is_gnosis_safe(self, content: str) -> bool:
        """Detect Gnosis Safe style wallet"""
        safe_indicators = ['execTransaction', 'threshold', 'owners', 'signatures', 'nonce']
        return sum(1 for ind in safe_indicators if ind.lower() in content.lower()) >= 3
    
    def detect_architecture(self, content: str) -> Dict[str, bool]:
        """Detect contract type"""
        return {
            "lending": any(x in content for x in ["borrow", "lend", "collateral", "liquidat", "LTV", "debtToken"]),
            "amm": any(x in content for x in ["swap", "pair", "getAmount", "Uniswap", "V3", "pool", "tick", "liquidity"]),
            "perpetual": any(x in content for x in ["perp", "fundingRate", "position", "margin", "leverage", "indexPrice"]),
            "options": any(x in content for x in ["option", "strike", "expiry", "premium", "put", "call"]),
            "bridge": any(x in content for x in ["bridge", "relay", "message", "layerZero", "axelar", "wormhole"]),
            "dao": any(x in content for x in ["proposal", "vote", "governor", "timelock", "veto"]),
            "proxy": self.is_likely_proxy(content),
            "safe": self.is_gnosis_safe(content),
            "oracle": any(x in content for x in ["oracle", "price", "feed", "Chainlink", "getPrice", "latestRound"]),
            "erc20": "ERC20" in content or ("transferFrom" in content and "balanceOf" in content),
            "erc721": "ERC721" in content or "ownerOf" in content,
            "multicall": "multicall" in content.lower() or "aggregate" in content.lower(),
            "flash_loan": any(x in content for x in ["flashLoan", "flash", "flashloan", "FlashLoan"]),
        }
    
    def analyze_cross_function(self, content: str, filename: str) -> List[Dict]:
        """Find cross-function vulnerabilities without Slither"""
        graph = CallGraph(content)
        graph.parse()
        
        findings = []
        
        # Cross-function reentrancy: A reads state, calls B, B does external call + state change
        for func_a, data_a in graph.functions.items():
            if not data_a['is_external']:
                continue
                
            a_reads = graph.state_reads.get(func_a, set())
            a_calls = graph.calls.get(func_a, [])
            
            for called_func in a_calls:
                if called_func not in graph.functions:
                    continue
                    
                b_data = graph.functions[called_func]
                b_externals = graph.external_calls.get(called_func, [])
                b_writes = graph.state_writes.get(called_func, set())
                
                # Check if A reads what B writes
                shared = a_reads.intersection(b_writes)
                
                if shared and b_externals:
                    findings.append({
                        "type": "cross_function_reentrancy",
                        "severity": "critical",
                        "entry_point": func_a,
                        "external_call_function": called_func,
                        "shared_state": list(shared),
                        "description": f"Cross-function reentrancy: {func_a} reads state modified by {called_func} after external call",
                        "attack_path": f"{func_a} -> {called_func} -> external_call -> state_write",
                        "indicators": list(shared)
                    })
        
        # Flash loan entry points: external function that calls multiple external functions
        for func_name, data in graph.functions.items():
            if data['is_external'] and len(graph.external_calls.get(func_name, [])) >= 2:
                findings.append({
                    "type": "flash_loan_vector",
                    "severity": "high",
                    "function": func_name,
                    "external_calls": graph.external_calls[func_name],
                    "description": f"{func_name} makes multiple external calls - potential flash loan manipulation vector",
                    "attack_vector": "Attacker uses flash loan to manipulate state between external calls"
                })
        
        return findings
    
    def extract_function_details(self, content: str, func_match: re.Match) -> Dict:
        """Extract full function with analysis"""
        start = func_match.start()
        func_sig = func_match.group(0)
        func_name = re.search(r'function\s+(\w+)', func_sig).group(1)
        
        # Find function body
        body_start = func_match.end() - 1
        brace_count = 0
        body = ""
        
        for i in range(body_start, len(content)):
            char = content[i]
            # Simple brace counting (doesn't handle strings perfectly but good enough)
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    body = content[body_start:i+1]
                    break
        
        full_func = func_sig + body
        
        # Risk analysis
        risk_score = 0
        has_external_call = '.call' in full_func or 'transfer' in full_func
        has_delegatecall = 'delegatecall' in full_func.lower()
        has_callback = 'callback' in full_func.lower() or 'onERC' in full_func
        has_assembly = 'assembly' in full_func.lower()
        has_selfdestruct = 'selfdestruct' in full_func.lower()
        has_tx_origin = 'tx.origin' in full_func
        
        if has_external_call:
            risk_score += Config.RISK_EXTERNAL_CALL
        if has_delegatecall:
            risk_score += Config.RISK_DELEGATECALL
        if has_callback:
            risk_score += Config.RISK_REENTRANCY_RISK
        if has_assembly:
            risk_score += Config.RISK_ASSEMBLY
        if has_selfdestruct:
            risk_score += 50
        if has_tx_origin:
            risk_score += 20
        
        # Check for state changes after external calls (reentrancy pattern)
        lines = body.split('\n')
        external_call_line = -1
        state_change_line = -1
        
        for i, line in enumerate(lines):
            if any(x in line for x in ['.call', '.transfer', '.send']):
                external_call_line = i
            if any(x in line for x in ['=', '++', '--']) and external_call_line >= 0 and i > external_call_line:
                if any(x in line for x in ['balance', 'supply', 'debt', 'collateral']):
                    state_change_line = i
                    risk_score += Config.RISK_REENTRANCY_RISK
        
        if external_call_line >= 0 and state_change_line > external_call_line:
            risk_score += 25  # Classic reentrancy
        
        return {
            "name": func_name,
            "signature": func_sig[:100],
            "code": full_func,
            "risk_score": risk_score,
            "has_external_call": has_external_call,
            "has_delegatecall": has_delegatecall,
            "has_callback": has_callback,
            "is_entry_point": 'external' in func_sig or 'public' in func_sig,
            "is_payable": 'payable' in func_sig,
            "indicators": {
                "external_call": has_external_call,
                "delegatecall": has_delegatecall,
                "assembly": has_assembly,
                "selfdestruct": has_selfdestruct,
                "tx_origin": has_tx_origin,
                "reentrancy_risk": external_call_line >= 0 and state_change_line > external_call_line
            }
        }
    
    def parse_file(self, file_path: Path) -> Dict:
        """Parse single file comprehensively"""
        try:
            content = file_path.read_text(errors='ignore')
            if len(content) < 50:
                return None
            
            rel_path = str(file_path.relative_to(self.path))
            
            # Skip test files, mocks, interfaces
            if any(x in rel_path.lower() for x in ['test', 'mock', 'interface', 'i_', 'migrations']):
                return None
            
            arch = self.detect_architecture(content)
            cross_func_bugs = self.analyze_cross_function(content, rel_path)
            
            # Determine if this is likely a standard/safe pattern
            is_standard_proxy = arch["proxy"] and ('ERC1967' in content or 'TransparentUpgradeableProxy' in content)
            is_safe = arch["safe"]
            
            # Extract all functions
            functions = []
            func_pattern = r'function\s+\w+\s*\([^)]*\)[^{]*\{'
            
            for match in re.finditer(func_pattern, content):
                try:
                    func_data = self.extract_function_details(content, match)
                    if func_data:
                        functions.append(func_data)
                except:
                    continue
            
            # Sort by risk
            functions.sort(key=lambda x: x["risk_score"], reverse=True)
            
            return {
                "file": rel_path,
                "architecture": arch,
                "is_standard_proxy": is_standard_proxy,
                "is_safe": is_safe,
                "cross_function_bugs": cross_func_bugs,
                "functions": functions,
                "high_risk_count": len([f for f in functions if f["risk_score"] > 30])
            }
            
        except Exception as e:
            print(f"  [!] Failed to parse {file_path}: {e}")
            return None
    
    def parse_all(self) -> List[Dict]:
        """Parse all files"""
        results = []
        print(f"[+] Analyzing {len(self.files)} Solidity files...")
        
        for fp in self.files:
            result = self.parse_file(fp)
            if result:
                results.append(result)
        
        total_funcs = sum(len(r["functions"]) for r in results)
        high_risk = sum(r["high_risk_count"] for r in results)
        cross_bugs = sum(len(r["cross_function_bugs"]) for r in results)
        
        print(f"[✓] Parsed {len(results)} files, {total_funcs} functions ({high_risk} high-risk)")
        if cross_bugs:
            print(f"[✓] Found {cross_bugs} cross-function vulnerabilities")
        
        # Sort by total risk score
        results.sort(key=lambda x: sum(f["risk_score"] for f in x["functions"]), reverse=True)
        return results