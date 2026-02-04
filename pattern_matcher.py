from typing import List, Dict
from local_db import LocalDB
from llm_client import LLMClient
from target_analyzer import TargetAnalyzer
from static_analyzer import StaticAnalyzer
from call_graph import CallGraphAnalyzer
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich.syntax import Syntax
from config import Config

console = Console()

class PatternMatcher:
    """Combines multiple analysis techniques into a unified finding report"""
    
    def __init__(self):
        self.db = LocalDB()
        self.llm = LLMClient()

    def analyze(self, analyzer: TargetAnalyzer, sniper: bool = False, 
                cross_contract: bool = False, progress: Optional[Dict] = None) -> List[Dict]:
        findings = []
        
        # 1. Slither detectors
        detectors = analyzer.get_detectors()
        for d in detectors:
            for result in d["instances"]:
                findings.append({
                    "type": f"SLITHER_{d['check'].upper()}",
                    "severity": d['impact'].lower(),
                    "file": result["source_mapping"]["filename"],
                    "description": d["description"],
                    "score": 85 if "high" in d["impact"].lower() else 65,
                    "confidence": "high",
                    "location": f"{result['source_mapping']['filename']}:{result['source_mapping']['lines'][0]}",
                    "source": "Slither"
                })

        # 2. Static Analysis
        static_analyzer = StaticAnalyzer()
        funcs = analyzer.get_functions()
        for func in funcs:
            if func.get('code'):
                static_findings = static_analyzer.analyze(func['code'], func['function'])
                for sf in static_findings:
                    findings.append({
                        "type": sf['type'].upper(),
                        "severity": sf['severity'],
                        "file": f"{func['contract']}::{func['function']}",
                        "description": sf['description'],
                        "score": sf['score'],
                        "confidence": sf.get('confidence', 'medium'),
                        "remediation": sf.get('remediation', ''),
                        "code_snippet": func['code'][:500],
                        "source": "StaticAnalyzer"
                    })

        # 3. Call Graph Analysis
        try:
            cg_analyzer = CallGraphAnalyzer(str(analyzer.project_path))
            if cg_analyzer.build_graph():
                cf_reentrancy = cg_analyzer.find_cross_function_reentrancy()
                for cf in cf_reentrancy:
                    findings.append({
                        "type": "CROSS_FUNCTION_REENTRANCY",
                        "severity": "critical",
                        "file": cf['entry_point'],
                        "description": cf['description'],
                        "attack_vector": cf['attack_path'],
                        "score": 90,
                        "confidence": "high",
                        "source": "CallGraph"
                    })
                
                delegate_inj = cg_analyzer.find_delegatecall_injection()
                for di in delegate_inj:
                    findings.append({
                        "type": "DELEGATECALL_INJECTION",
                        "severity": "critical",
                        "file": di['function'],
                        "description": di['description'],
                        "score": 95,
                        "confidence": "high",
                        "source": "CallGraph"
                    })
        except Exception:
            pass

        # 4. Semantic Matching + LLM Hypotheses
        self.db.load_all_vectors()
        for func in funcs[:50]:
            query = f"{func['contract']} {func['function']} {func.get('signature', '')}"
            similar = self.db.search_similar(query, top_k=Config.PATTERNS_PER_CALL)
            
            if similar and similar[0]["similarity"] > Config.SIMILARITY_THRESHOLD:
                hyps = self.llm.generate_hypothesis(func["code"], similar, func["function"])
                for h in hyps:
                    findings.append({
                        "type": h.get("vulnerability_type", "INVARIANT_VIOLATION").upper(),
                        "severity": h.get("confidence", "Medium").lower(),
                        "file": f"{func['contract']}::{func['function']}",
                        "description": h.get("hypothesis", ""),
                        "attack_vector": h.get("attack_vector", ""),
                        "confidence": h.get("confidence", "Medium"),
                        "remediation": h.get("remediation", ""),
                        "location": h.get("location", ""),
                        "score": 75 if h.get("confidence") == "High" else 55,
                        "code_snippet": func["code"][:500],
                        "source": "SemanticMatcher"
                    })

        findings = self._deduplicate_and_score(findings)
        
        if sniper:
            findings = [f for f in findings if f["score"] >= 80]
            
        return sorted(findings, key=lambda x: x["score"], reverse=True)

    def _deduplicate_and_score(self, findings: List[Dict]) -> List[Dict]:
        unique_findings = []
        seen_keys = {}
        
        for f in findings:
            key = (f["file"], f["type"])
            if key in seen_keys:
                idx = seen_keys[key]
                unique_findings[idx]["score"] = min(100, int(unique_findings[idx]["score"] * 1.2))
                unique_findings[idx]["source"] += f" + {f['source']}"
            else:
                seen_keys[key] = len(unique_findings)
                unique_findings.append(f)
                
        return unique_findings
    
    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings, keeping highest scoring ones"""
        unique_findings = {}
        
        for f in findings:
            key = (f.get("type"), f.get("file"), f.get("description"))
            
            if key in unique_findings:
                # Keep higher scoring finding
                if f.get("score", 0) > unique_findings[key].get("score", 0):
                    unique_findings[key] = f
            else:
                unique_findings[key] = f
        
        return list(unique_findings.values())
    
    def _calculate_final_score(self, finding: Dict) -> float:
        """Calculate final score for a finding"""
        base_score = finding.get("score", 50)
        
        # Boost for severity
        severity = finding.get("severity", "").lower()
        if "critical" in severity:
            base_score *= 1.2
        elif "high" in severity:
            base_score *= 1.1
        
        # Boost for confidence
        confidence = finding.get("confidence", "").lower()
        if confidence == "high":
            base_score *= 1.1
        elif confidence == "low":
            base_score *= 0.9
        
        return min(100, base_score)

    def display(self, results: List[Dict]):
        if not results:
            console.print("[yellow]No findings discovered.[/yellow]")
            return

        for r in results:
            severity = r.get("severity", "medium").lower()
            color = "red" if any(x in severity for x in ["crit", "high"]) else "orange3" if "med" in severity else "blue"
            icon = "🔴" if any(x in severity for x in ["crit", "high"]) else "🟠" if "med" in severity else "🟡"
            
            # Add validation indicator if available
            validation_indicator = r.get("validation_indicator", "")
            title_suffix = f" {validation_indicator}" if validation_indicator else ""
            
            panel_title = f"{icon} {r['type']} (Confidence: {r.get('confidence', 'N/A')}){title_suffix}"
            
            content = f"[bold]Location:[/bold] {r['file']}\n"
            content += f"[bold]Detected By:[/bold] {r.get('source', 'Unknown')}\n\n"
            content += f"[bold]Description:[/bold]\n{r['description']}\n\n"
            
            if r.get("attack_vector"):
                content += f"[bold]⚔️ Attack Vector:[/bold]\n{r['attack_vector']}\n\n"
            
            if r.get("remediation"):
                content += f"[bold]✅ Remediation:[/bold]\n{r['remediation']}\n\n"
            
            if r.get("validation_status"):
                content += f"[bold]🧪 Validation:[/bold] {r['validation_status'].upper()}\n\n"
                
            console.print(Panel(content, title=panel_title, border_style=color))
            if r.get("code_snippet"):
                snippet = Syntax(r["code_snippet"], "solidity", theme="monokai", line_numbers=True)
                console.print(snippet)
            console.print("═" * 80)

        table = Table(title="Audit Summary")
        table.add_column("Severity", justify="left")
        table.add_column("Count", justify="right")
        
        crit = len([f for f in results if any(x in f.get("severity", "").lower() for x in ["crit", "high"])])
        med = len([f for f in results if "med" in f.get("severity", "").lower()])
        low = len([f for f in results if "low" in f.get("severity", "").lower()])
        
        table.add_row("🔴 Critical/High", str(crit), style="red")
        table.add_row("🟠 Medium", str(med), style="orange3")
        table.add_row("🔵 Low", str(low), style="blue")
        console.print(table)
