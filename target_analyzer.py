from slither import Slither
from slither.core.declarations import Function
from typing import List, Dict
from rich.console import Console
console = Console()

class TargetAnalyzer:
    def __init__(self, path: str):
        console.print("[+] Compiling with forge...")
        # Force forge build
        import subprocess, os
        os.chdir(path)
        subprocess.run(["forge", "build"], check=True)
        os.chdir("/content/deep-audit")

        console.print("[+] Running Slither...")
        self.slither = Slither(path, solc="solc-0.8.19")

    def get_functions(self) -> List[Dict]:
        funcs = []
        for contract in self.slither.contracts:
            for f in contract.functions_declared:
                if f.is_implemented:
                    funcs.append({
                        "contract": contract.name,
                        "function": f.name,
                        "signature": f.canonical_name,
                        "code": f.source_mapping.content,
                        "risk_score": self._risk_score(f),
                        "is_external": f.visibility in ["external", "public"],
                        "slither_function": f
                    })
        funcs.sort(key=lambda x: x["risk_score"], reverse=True)
        return funcs[:60]  # Top 60

    def _risk_score(self, f: Function) -> int:
        score = 0
        if f.is_external or f.visibility == "public":
            score += 15
        if any(p.low_level_calls for p in f.nodes):
            score += Config.RISK_EXTERNAL
        if any(p.delegatecall for p in f.nodes):
            score += Config.RISK_DELEGATECALL
        if any(p.state_variables_written_after_external for p in f.nodes):
            score += Config.RISK_REENTRANCY
        if "assembly" in f.source_mapping.content:
            score += Config.RISK_ASSEMBLY
        return score

    def get_detectors(self):
        self.slither.run_detectors()
        return self.slither.detectors_results