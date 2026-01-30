from pathlib import Path
from typing import List, Dict, Tuple
import re

try:
    from slither import Slither
    SLITHER_AVAILABLE = True
except ImportError:
    SLITHER_AVAILABLE = False
    print("[!] Slither not available, using regex fallback")

try:
    from call_graph import CallGraphAnalyzer
except ImportError:
    CallGraphAnalyzer = None

class TargetParser:
    def __init__(self, code_path: str):
        self.path = Path(code_path)
        self.files = list(self.path.rglob("*.sol"))
        
    def extract_functions(self, content: str) -> List[Tuple[str, str]]:
        """Extract individual functions with full code - no truncation"""
        # Pattern to match function definitions
        # Matches: function name(args) modifiers {
        pattern = r'(function\s+\w+\s*\([^)]*\)[^{]*\{)'
        
        matches = []
        for match in re.finditer(pattern, content):
            start = match.start()
            func_start = content[start:]
            
            # Find matching closing brace
            brace_count = 0
            end_pos = 0
            in_string = False
            string_char = None
            
            for i, char in enumerate(func_start):
                if char in ['"', "'"]:
                    if not in_string:
                        in_string = True
                        string_char = char
                    elif char == string_char:
                        in_string = False
                        string_char = None
                    continue
                
                if in_string:
                    continue
                
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            
            func_code = func_start[:end_pos]
            func_name_match = re.search(r'function\s+(\w+)', func_code)
            if func_name_match:
                func_name = func_name_match.group(1)
                matches.append((func_name, func_code))
        
        return matches
    
    def analyze_function(self, func_name: str, func_code: str, file_path: Path, slither_func=None) -> Dict:
        """Deep analysis of single function"""
        code_lower = func_code.lower()
        
        analysis = {
            "file": str(file_path.relative_to(self.path)),
            "function": func_name,
            "code": func_code,
            "is_entry_point": 'external' in func_code or 'public' in func_code,
            "is_payable": 'payable' in func_code,
            "has_reentrancy_guard": 'nonReentrant' in func_code or 'reentrancy' in func_code,
            "external_calls": [],
            "state_changes": [],
            "slither_bugs": [],
            "risk_score": 0,
            "cross_function_vulnerable": False,
            "external_call_chain": None
        }
        
        # Extract external calls using regex
        external_patterns = [
            r'(\w+\.call\{[^}]*\}\([^)]*\))',
            r'(\w+\.delegatecall\([^)]*\))',
            r'(\w+\.transfer\([^)]*\))',
            r'(IERC20\([^)]+\)\.transfer\([^)]*\))',
            r'(IERC20\([^)]+\)\.transferFrom\([^)]*\))',
            r'(\w+\.swap\([^)]*\))',
            r'(\w+\.mint\([^)]*\))',
            r'(\w+\.burn\([^)]*\))',
        ]
        
        for pattern in external_patterns:
            matches = re.findall(pattern, func_code)
            analysis["external_calls"].extend(matches)
        
        # Detect state changes (approximate)
        state_patterns = [
            r'\b(balance|totalSupply|balances|allowances|reserves|debt)\s*[+\-]?=',
            r'\b(_\w+)\s*=',
            r'\b(mapping\s*\([^)]+\)\s+\w+\s*)\[.*\]\s*=',
        ]
        for pattern in state_patterns:
            matches = re.findall(pattern, func_code)
            analysis["state_changes"].extend(matches)
        
        # Slither analysis if available
        if slither_func:
            # Check reentrancy from Slither
            if hasattr(slither_func, 'is_reentrant') and slither_func.is_reentrant:
                external = [str(c) for c in slither_func.external_calls]
                state_after = [str(s) for s in slither_func.state_variables_written]
                if state_after:
                    analysis["slither_bugs"].append({
                        "type": "reentrancy",
                        "function": func_name,
                        "severity": "critical",
                        "details": f"External calls: {external}, State written: {state_after}"
                    })
            
            # Unchecked calls from Slither
            for node in slither_func.nodes:
                node_str = str(node)
                if ('.call{' in node_str or '.call(' in node_str) and 'success' not in node_str:
                    analysis["slither_bugs"].append({
                        "type": "unchecked_call",
                        "function": func_name,
                        "severity": "high"
                    })
        
        # Calculate risk score
        if analysis["external_calls"]:
            analysis["risk_score"] += 20
        if analysis["state_changes"] and analysis["external_calls"]:
            analysis["risk_score"] += 30  # Reentrancy risk
        if analysis["is_payable"]:
            analysis["risk_score"] += 10
        if not analysis["has_reentrancy_guard"] and analysis["external_calls"]:
            analysis["risk_score"] += 25
        if 'delegatecall' in func_code:
            analysis["risk_score"] += 35
        if analysis["slither_bugs"]:
            analysis["risk_score"] += 20 * len(analysis["slither_bugs"])
        
        return analysis
    
    def parse_all(self) -> List[Dict]:
        """Parse all files, return structure with cross-function analysis"""
        results = []
        
        print(f"[+] Analyzing {len(self.files)} Solidity files...")
        print(f"[+] Using: {'Slither AST + Regex' if SLITHER_AVAILABLE else 'Regex only'}")
        
        for file_path in self.files:
            try:
                # Skip test files
                if any(x in str(file_path) for x in ['test/', 'Test', 'mock/', 'Mock', 'Migrations']):
                    continue
                
                content = file_path.read_text(errors='ignore')
                if len(content) < 50:  # Skip empty/interface files
                    continue
                
                # Extract architecture info once per file
                arch_info = {
                    "uses_oracle": any(x in content for x in ["oracle", "price", "feed", "Chainlink", "getPrice"]),
                    "lending": any(x in content for x in ["borrow", "lend", "collateral", "liquidat", "LTV"]),
                    "amm": any(x in content for x in ["swap", "pair", "getAmount", "Uniswap", "V3"]),
                    "cross_chain": any(x in content for x in ["bridge", "message", "layerZero", "axelar"]),
                    "governance": any(x in content for x in ["vote", "proposal", "governor", "timelock"]),
                    "proxy": 'delegatecall' in content or 'upgradeable' in content or 'proxy' in content.lower(),
                    "erc20": "ERC20" in content or ("transferFrom" in content and "balanceOf" in content),
                    "erc721": "ERC721" in content or "ownerOf" in content,
                }
                
                # Extract individual functions
                functions_data = []
                raw_functions = self.extract_functions(content)
                
                # Try to get Slither functions if available
                slither_functions = {}
                if SLITHER_AVAILABLE:
                    try:
                        slither = Slither(str(file_path))
                        for contract in slither.contracts:
                            for func in contract.functions:
                                slither_functions[func.name] = func
                    except:
                        pass
                
                for func_name, func_code in raw_functions:
                    slither_func = slither_functions.get(func_name)
                    func_analysis = self.analyze_function(func_name, func_code, file_path, slither_func)
                    func_analysis["architecture"] = arch_info
                    functions_data.append(func_analysis)
                
                # Cross-function analysis using CallGraphAnalyzer
                cross_function_bugs = []
                if CallGraphAnalyzer and SLITHER_AVAILABLE:
                    try:
                        graph = CallGraphAnalyzer(str(file_path))
                        if graph.build_graph():
                            cross_function_bugs.extend(graph.find_cross_function_reentrancy())
                            cross_function_bugs.extend(graph.find_delegatecall_injection())
                            cross_function_bugs.extend(graph.find_flash_loan_entry_points())
                            
                            # Mark affected functions
                            for bug in cross_function_bugs:
                                if bug["type"] == "cross_function_reentrancy":
                                    entry_point = bug.get("entry_point")
                                    for func in functions_data:
                                        if func["function"] == entry_point:
                                            func["cross_function_vulnerable"] = True
                                            func["external_call_chain"] = bug.get("attack_path")
                                            func["risk_score"] += 50  # Significant boost
                    except Exception as e:
                        pass
                
                # Determine file type and store results
                if cross_function_bugs:
                    results.append({
                        "file": str(file_path.relative_to(self.path)),
                        "type": "cross_function_analysis",
                        "bugs": cross_function_bugs,
                        "functions": functions_data,
                        "architecture": arch_info
                    })
                else:
                    results.append({
                        "file": str(file_path.relative_to(self.path)),
                        "type": "standard",
                        "functions": functions_data,
                        "architecture": arch_info
                    })
                    
            except Exception as e:
                print(f"  [!] Failed to parse {file_path}: {e}")
                continue
        
        # Count total functions found
        total_funcs = sum(len(r.get("functions", [])) for r in results)
        print(f"[✓] Parsed {len(results)} files, extracted {total_funcs} functions")
        
        # Sort by risk within each file
        for r in results:
            r["functions"].sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        
        return results