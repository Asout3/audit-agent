from pathlib import Path
from typing import List, Dict, Tuple
import re

try:
    from slither import Slither
    SLITHER_AVAILABLE = True
except ImportError:
    SLITHER_AVAILABLE = False

class TargetParser:
    def __init__(self, code_path: str):
        self.path = Path(code_path)
        self.files = list(self.path.rglob("*.sol"))
        
    def extract_functions(self, content: str) -> List[Tuple[str, str]]:
        """Extract individual functions with full code"""
        # Pattern: function name(...) {...} 
        # Handles modifiers, visibility, etc.
        pattern = r'(function\s+\w+\s*\([^)]*\)[^{]*\{)'
        
        matches = []
        for match in re.finditer(pattern, content):
            start = match.start()
            func_start = content[start:]
            
            # Find matching closing brace (naive but works for 95% of cases)
            brace_count = 0
            end_pos = 0
            for i, char in enumerate(func_start):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            
            func_code = func_start[:end_pos]
            func_name = re.search(r'function\s+(\w+)', func_code).group(1)
            matches.append((func_name, func_code))
        
        return matches
    
    def analyze_function(self, func_name: str, func_code: str, file_path: Path) -> Dict:
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
            "risk_score": 0
        }
        
        # Detect external calls
        external_patterns = [
            r'(\w+\.call\{[^}]*\})',
            r'(\w+\.delegatecall\()',
            r'(\w+\.transfer\()',
            r'(IERC20\([^)]+\)\.transfer)',
            r'(\w+\.swap\()',
        ]
        
        for pattern in external_patterns:
            matches = re.findall(pattern, func_code)
            analysis["external_calls"].extend(matches)
        
        # Detect state changes (approximate)
        state_patterns = [
            r'\b(balance|totalSupply|balances|allowances)\s*[+\-]?=',
            r'\b(_\w+)\s*=',
        ]
        for pattern in state_patterns:
            matches = re.findall(pattern, func_code)
            analysis["state_changes"].extend(matches)
        
        # Calculate risk score
        if analysis["external_calls"]:
            analysis["risk_score"] += 20
        if analysis["state_changes"] and analysis["external_calls"]:
            analysis["risk_score"] += 30  # Reentrancy risk
        if analysis["is_payable"]:
            analysis["risk_score"] += 10
        if not analysis["has_reentrancy_guard"] and analysis["external_calls"]:
            analysis["risk_score"] += 20
        
        return analysis
    
    def parse_all(self) -> List[Dict]:
        """Parse all files, return individual functions (not whole files)"""
        all_functions = []
        
        print(f"[+] Parsing {len(self.files)} files into individual functions...")
        
        for file_path in self.files:
            try:
                content = file_path.read_text(errors='ignore')
                
                # Skip test files
                if any(x in str(file_path) for x in ['test', 'Test', 'mock', 'Mock']):
                    continue
                
                # Extract architecture info once per file
                arch_info = {
                    "uses_oracle": any(x in content for x in ["oracle", "price", "feed"]),
                    "lending": any(x in content for x in ["borrow", "collateral"]),
                    "amm": any(x in content for x in ["swap", "pair"]),
                    "proxy": 'delegatecall' in content,
                }
                
                # Extract individual functions
                functions = self.extract_functions(content)
                
                for func_name, func_code in functions:
                    func_analysis = self.analyze_function(func_name, func_code, file_path)
                    func_analysis["architecture"] = arch_info
                    all_functions.append(func_analysis)
                    
            except Exception as e:
                print(f"  [!] Failed to parse {file_path}: {e}")
        
        print(f"[✓] Extracted {len(all_functions)} individual functions")
        
        # Sort by risk score (analyze high-risk first)
        all_functions.sort(key=lambda x: x["risk_score"], reverse=True)
        return all_functions