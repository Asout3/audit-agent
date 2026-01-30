from pathlib import Path
from typing import List, Dict
import re

class TargetParser:
    def __init__(self, code_path: str):
        self.path = Path(code_path)
        self.files = list(self.path.rglob("*.sol"))
        
    def parse_file(self, file_path: Path) -> Dict:
        try:
            content = file_path.read_text(errors='ignore')
        except:
            return None
            
        # Extract all function definitions with their modifiers
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(.*?)\{'
        func_matches = re.findall(func_pattern, content, re.DOTALL)
        
        functions = []
        external_calls = []
        
        for name, params, modifiers in func_matches:
            is_external = 'external' in modifiers or 'public' in modifiers
            is_payable = 'payable' in modifiers
            has_reentrancy_guard = 'nonReentrant' in modifiers
            
            funcs_called = re.findall(r'(\w+)\(', content[content.find(f'function {name}'):content.find(f'function {name}')+5000])
            calls_transfer = any(x in funcs_called for x in ['transfer', 'send', 'call{'])
            
            functions.append({
                "name": name,
                "external": is_external,
                "payable": is_payable,
                "guarded": has_reentrancy_guard,
                "calls_transfer": calls_transfer
            })
            
            if is_external:
                external_calls.append(name)
        
        # Architecture detection (expanded)
        arch = {
            "complexity_score": len(functions) + content.count('assembly') * 5,
            "uses_oracle": any(x in content for x in ["oracle", "price", "feed", "Chainlink", "getPrice"]),
            "lending": any(x in content for x in ["borrow", "lend", "collateral", "liquidat", "LTV"]),
            "amm": any(x in content for x in ["swap", "pair", "getAmount", "Uni", "V3", "liquidity"]),
            "cross_chain": any(x in content for x in ["bridge", "message", "layerZero", "axelar"]),
            "governance": any(x in content for x in ["vote", "proposal", "governor", "timelock", "quorum"]),
            "erc20": "ERC20" in content or ("transferFrom" in content and "balanceOf" in content),
            "erc721": "ERC721" in content or "ownerOf" in content,
            "proxy": any(x in content for x in ["delegatecall", "upgradeable", "proxy"]),
            "flash_loan": any(x in content for x in ["flashLoan", "flash loan", "flashLoan"]),
            "multisig": any(x in content for x in ["multisig", "threshold", "owners"]),
            "external_calls": external_calls,
            "functions": [f["name"] for f in functions],
            "entry_points": [f["name"] for f in functions if f["external"]]
        }
        
        return {
            "file": str(file_path.relative_to(self.path)),
            "architecture": arch,
            "content_snippet": content[:10000],  # More context for LLM
            "function_count": len(functions),
            "external_count": len(external_calls)
        }
    
    def parse_all(self):
        results = []
        print(f"[+] Scanning {len(self.files)} Solidity files...")
        for f in self.files:
            parsed = self.parse_file(f)
            if parsed:
                results.append(parsed)
        print(f"[✓] Parsed {len(results)} files")
        return results