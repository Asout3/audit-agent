from slither import Slither
from slither.core.declarations import Function
from typing import List, Dict, Optional
from pathlib import Path
import subprocess
import re
from rich.console import Console
from config import Config

console = Console()

class TargetAnalyzer:
    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        console.print(f"[+] Analyzing project: {self.project_path}")

        # Detect dominant solc version from pragma
        self.solc_version = self._detect_solc_version()

        # Attempt forge build (best case)
        forge_success = self._run_forge_build()

        if forge_success:
            console.print("[✓] Forge build succeeded")
            # Slither on Foundry project
            self.slither = Slither(str(self.project_path))
        else:
            console.print("[!] Forge failed or not available → falling back to direct Slither")
            self.slither = Slither(str(self.project_path), solc=self.solc_version)

    def _detect_solc_version(self) -> str:
        """Scan .sol files for pragma solidity and return most common version"""
        version_counts = {}
        pragma_pattern = re.compile(r'pragma\s+solidity\s*(?:\^|>=|<=)?\s*([0-9]+\.[0-9]+\.[0-9]+)')

        for sol_file in self.project_path.rglob("*.sol"):
            try:
                content = sol_file.read_text(errors="ignore")
                matches = pragma_pattern.findall(content)
                for v in matches:
                    version_counts[v] = version_counts.get(v, 0) + 1
            except:
                continue

        if version_counts:
            dominant = max(version_counts, key=version_counts.get)
            console.print(f"[+] Detected dominant solc version: {dominant}")
            return f"solc-{dominant}"
        console.print("[!] No pragma found → defaulting to 0.8.19")
        return "solc-0.8.19"

    def _run_forge_build(self) -> bool:
        """Run forge build with error tolerance"""
        try:
            result = subprocess.run(
                ["forge", "build"],
                cwd=str(self.project_path),
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                return True
            console.print(f"[!] Forge build failed: {result.stderr[:300]}")
        except FileNotFoundError:
            console.print("[!] Forge not in PATH")
        except subprocess.TimeoutExpired:
            console.print("[!] Forge build timed out")
        return False

    def get_functions(self) -> List[Dict]:
        funcs = []
        for contract in self.slither.contracts:
            for f in contract.functions_declared:
                if f.is_implemented and not f.is_constructor:
                    funcs.append({
                        "contract": contract.name,
                        "function": f.name,
                        "signature": str(f.signature),
                        "code": f.source_mapping.content or "",
                        "risk_score": self._risk_score(f),
                        "is_external": f.visibility in ["external", "public"],
                        "slither_function": f
                    })
        funcs.sort(key=lambda x: x["risk_score"], reverse=True)
        console.print(f"[+] Extracted {len(funcs)} functions, analyzing top 60")
        return funcs[:60]

    def _risk_score(self, f: Function) -> int:
        score = 0
        if f.visibility in ["external", "public"]:
            score += 15
        if any(n.contains_low_level_call() for n in f.nodes):
            score += Config.RISK_EXTERNAL
        if any(n.contains_delegatecall() for n in f.nodes):
            score += Config.RISK_DELEGATECALL
        if any(n.state_variables_written_after_call for n in f.nodes):
            score += Config.RISK_REENTRANCY
        if "assembly" in f.source_mapping.content.lower():
            score += Config.RISK_ASSEMBLY
        return score

    def get_detectors(self) -> list:
        console.print("[+] Running Slither detectors...")
        self.slither.run_detectors()
        return self.slither.detectors_results