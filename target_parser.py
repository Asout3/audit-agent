from pathlib import Path
from typing import List, Dict
import re

try:
    from slither import Slither
    SLITHER_AVAILABLE = True
except ImportError:
    SLITHER_AVAILABLE = False
    print("[!] Slither not available, using regex fallback")

class TargetParser:
    def __init__(self, code_path: str):
        self.path = Path(code_path)
        self.files = list(self.path.rglob("*.sol"))
        
    def analyze_with_slither(self, file_path: Path) -> Dict:
        if not SLITHER_AVAILABLE:
            return self.parse_file_regex(file_path)
            
        try:
            slither = Slither(str(file_path))
            analysis = {
                "file": str(file_path.relative_to(self.path)),
                "slither_bugs": [],
                "high_risk_functions": [],
                "entry_points": [],
                "state_variables": [],
                "architecture": {}
            }
            
            for contract in slither.contracts:
                # State variables
                analysis["state_variables"] = [str(s) for s in contract.state_variables]
                
                for function in contract.functions:
                    func_info = {
                        "name": function.name,
                        "external": function.visibility in ['external', 'public'],
                        "payable": function.payable,
                        "modifiers": [str(m) for m in function.modifiers]
                    }
                    
                    if func_info["external"]:
                        analysis["entry_points"].append(function.name)
                    
                    # P0: Reentrancy (state after external call)
                    if function.is_reentrant:
                        external = [str(c) for c in function.external_calls]
                        state_after = [str(s) for s in function.state_variables_written]
                        if state_after:
                            analysis["slither_bugs"].append({
                                "type": "reentrancy",
                                "function": function.name,
                                "severity": "critical",
                                "details": f"External calls: {external}, State written: {state_after}"
                            })
                    
                    # P0: Unchecked calls
                    for node in function.nodes:
                        node_str = str(node)
                        if ('.call{' in node_str or '.call(' in node_str) and 'success' not in node_str:
                            analysis["slither_bugs"].append({
                                "type": "unchecked_call",
                                "function": function.name,
                                "severity": "high"
                            })
                    
                    # P1: Flash loan vectors (external + value transfer)
                    if any(k in function.name.lower() for k in ['flash', 'swap', 'liquidate', 'borrow']):
                        if function.external_calls:
                            analysis["high_risk_functions"].append({
                                "name": function.name,
                                "risk": "flash_loan",
                                "external_calls": len(function.external_calls)
                            })
            
            # Architecture detection
            content = file_path.read_text(errors='ignore')
            analysis["architecture"] = {
                "complexity_score": len(analysis["entry_points"]) * 2 + len(analysis["slither_bugs"]) * 5,
                "uses_oracle": any(x in content for x in ["oracle", "price", "feed"]),
                "lending": any(x in content for x in ["borrow", "collateral", "liquidat"]),
                "amm": any(x in content for x in ["swap", "pair", "getAmount"]),
                "proxy": 'delegatecall' in content or 'upgradeable' in content,
                "erc20": "transferFrom" in content,
                "functions": [f["name"] for f in analysis["high_risk_functions"]]
            }
            
            return analysis
            
        except Exception as e:
            return self.parse_file_regex(file_path)
    
    def parse_file_regex(self, file_path: Path) -> Dict:
        content = file_path.read_text(errors='ignore')
        funcs = re.findall(r'function\s+(\w+)[^{]*\{', content)
        
        return {
            "file": str(file_path.relative_to(self.path)),
            "slither_bugs": [],
            "high_risk_functions": [],
            "entry_points": [],
            "state_variables": [],
            "architecture": {
                "complexity_score": len(funcs),
                "uses_oracle": any(x in content for x in ["oracle", "price"]),
                "lending": any(x in content for x in ["borrow", "collateral"]),
                "amm": any(x in content for x in ["swap", "pair"]),
                "proxy": 'delegatecall' in content,
                "erc20": "transferFrom" in content,
                "functions": funcs
            },
            "content_snippet": content[:10000]
        }
    
    def parse_all(self):
        results = []
        print(f"[+] Analyzing {len(self.files)} files with {'Slither AST' if SLITHER_AVAILABLE else 'Regex'}...")
        
        for i, f in enumerate(self.files):
            if i % 5 == 0:
                print(f"  Progress: {i}/{len(self.files)}")
            try:
                if SLITHER_AVAILABLE:
                    results.append(self.analyze_with_slither(f))
                else:
                    results.append(self.parse_file_regex(f))
            except Exception as e:
                print(f"  [!] Failed to parse {f}: {e}")
                
        return results