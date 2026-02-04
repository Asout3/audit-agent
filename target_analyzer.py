from slither import Slither
from slither.core.declarations import Function, Contract
from typing import List, Dict, Optional, Any
from pathlib import Path
import subprocess
import re
import logging
from rich.console import Console
from config import Config

console = Console()

class TargetAnalyzer:
    """Enhanced contract analyzer extracting rich metadata and dependencies"""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        console.print(f"[+] Analyzing project: [bold blue]{self.project_path}[/bold blue]")

        # Detect dominant solc version from pragma
        self.solc_version = self._detect_solc_version()

        # Attempt forge build
        forge_success = self._run_forge_build()

        try:
            if forge_success:
                console.print("[✓] Forge build succeeded")
                self.slither = Slither(str(self.project_path))
            else:
                console.print("[!] Falling back to direct Slither analysis")
                self.slither = Slither(str(self.project_path), solc=self.solc_version)
        except Exception as e:
            console.print(f"[bold red]❌ Slither failed to initialize: {e}[/bold red]")
            raise

    def _detect_solc_version(self) -> str:
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
            return f"solc-{dominant}"
        return "solc-0.8.19"

    def _run_forge_build(self) -> bool:
        try:
            result = subprocess.run(
                ["forge", "build"],
                cwd=str(self.project_path),
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.returncode == 0
        except:
            return False

    def get_functions(self) -> List[Dict]:
        """Extract functions with rich metadata"""
        funcs = []
        for contract in self.slither.contracts:
            inheritance = [c.name for c in contract.inheritance]
            
            for f in contract.functions_declared:
                if f.is_implemented and not f.is_constructor:
                    # Metadata extraction
                    modifiers = [m.name for m in f.modifiers]
                    state_reads = [str(s) for s in f.state_variables_read]
                    state_writes = [str(s) for s in f.state_variables_written]
                    events = [str(e.name) for e in f.events_emitted]
                    
                    funcs.append({
                        "contract": contract.name,
                        "function": f.name,
                        "signature": str(f.signature),
                        "code": f.source_mapping.content or "",
                        "risk_score": self._risk_score(f),
                        "visibility": f.visibility,
                        "is_payable": f.is_payable,
                        "is_view": f.view,
                        "is_pure": f.pure,
                        "modifiers": modifiers,
                        "inheritance": inheritance,
                        "state_reads": state_reads,
                        "state_writes": state_writes,
                        "events": events,
                        "slither_function": f
                    })
        
        funcs.sort(key=lambda x: x["risk_score"], reverse=True)
        limit = Config.FUNCTION_COVERAGE_LIMIT
        console.print(f"[+] Extracted {len(funcs)} functions, analyzing top {min(len(funcs), limit)}")
        return funcs[:limit]

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
        
        content = (f.source_mapping.content or "").lower()
        if "assembly" in content:
            score += Config.RISK_ASSEMBLY
        if "unchecked" in content:
            score += 10
        if "block.timestamp" in content or "now" in content:
            score += Config.RISK_TIMESTAMP
            
        return score

    def get_detectors(self) -> list:
        """Run Slither detectors"""
        console.print("[+] Running [bold cyan]Slither[/bold cyan] detectors...")
        self.slither.run_detectors()
        return self.slither.detectors_results

    def get_project_stats(self) -> Dict:
        """Get statistics about the project"""
        return {
            "contracts": len(self.slither.contracts),
            "functions": sum(len(c.functions) for c in self.slither.contracts),
            "slither_detectors": len(self.slither.detectors_results)
        }
