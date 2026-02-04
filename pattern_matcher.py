from local_db import LocalDB
from llm_client import LLMClient
from target_analyzer import TargetAnalyzer
from static_analyzer import StaticAnalyzer
from call_graph import CallGraphAnalyzer
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
console = Console()

class PatternMatcher:
    def __init__(self):
        self.db = LocalDB()
        self.llm = LLMClient()

    def analyze(self, analyzer: TargetAnalyzer, sniper: bool = False) -> list:
        findings = []
        
        # 1. Run Slither detectors
        detectors = analyzer.get_detectors()
        for d in detectors:
            for result in d["instances"]:
                findings.append({
                    "type": f"[red]SLITHER {d['check']}[/red]",
                    "file": result["source_mapping"]["filename"],
                    "description": d["description"],
                    "score": 80 if "high" in d["impact"].lower() else 60,
                })

        # 2. Run static analysis on high-risk functions
        console.print("[+] Running static analysis...")
        static_analyzer = StaticAnalyzer()
        funcs = analyzer.get_functions()
        
        for func in funcs:
            code = func.get('code', '')
            if code:
                static_findings = static_analyzer.analyze(code, f"{func['contract']}::{func['function']}")
                for sf in static_findings:
                    findings.append({
                        "type": f"[cyan]STATIC {sf['type'].upper()}[/cyan]",
                        "file": f"{func['contract']}::{func['function']}",
                        "description": sf['description'],
                        "score": sf['score'],
                    })
        
        # 3. Run call graph analysis for cross-function bugs
        console.print("[+] Running call graph analysis...")
        try:
            call_graph = CallGraphAnalyzer(str(analyzer.project_path))
            if call_graph.build_graph():
                # Cross-function reentrancy
                cf_reentrancy = call_graph.find_cross_function_reentrancy()
                for cf in cf_reentrancy:
                    findings.append({
                        "type": "[bold magenta]CROSS-FUNCTION REENTRANCY[/bold magenta]",
                        "file": cf['entry_point'],
                        "description": cf['description'],
                        "attack_vector": cf['attack_path'],
                        "score": 90,
                    })
                
                # Delegatecall injection via call graph
                delegate_inj = call_graph.find_delegatecall_injection()
                for di in delegate_inj:
                    findings.append({
                        "type": "[bold red]DELEGATECALL INJECTION[/bold red]",
                        "file": di['function'],
                        "description": di['description'],
                        "score": 95,
                    })
                
                # Flash loan vectors
                flash_vectors = call_graph.find_flash_loan_entry_points()
                for fv in flash_vectors:
                    findings.append({
                        "type": "[yellow]FLASH LOAN VECTOR[/yellow]",
                        "file": fv['function'],
                        "description": f"{fv['description']} (called by: {', '.join(fv['called_by'][:3])})",
                        "score": 75,
                    })
        except Exception as e:
            console.print(f"[!] Call graph analysis failed: {e}")
        
        # 4. Deep semantic analysis with LLM
        console.print(f"[+] Deep analysis on {len(funcs)} high-risk functions")
        self.db.load_all_vectors()

        for i, func in enumerate(funcs):
            query = f"{func['contract']} {func['function']} {func['signature']}"
            similar = self.db.search_similar(query, top_k=3)
            if similar and similar[0]["similarity"] > 0.40:
                hyps = self.llm.generate_hypothesis(func["code"], similar, func["function"])
                for h in hyps:
                    findings.append({
                        "type": "[bold yellow]INVARIANT[/bold yellow]",
                        "file": f"{func['contract']}::{func['function']}",
                        "description": h.get("hypothesis", ""),
                        "attack_vector": h.get("attack_vector", ""),
                        "score": 75,
                    })

        # 5. Enhanced risk scoring - boost score for patterns from multiple analyzers
        findings = self._enhance_risk_scores(findings)
        
        findings.sort(key=lambda x: x["score"], reverse=True)
        if sniper:
            findings = [f for f in findings if f["score"] >= 70]
        return findings
    
    def _enhance_risk_scores(self, findings: list) -> list:
        """Boost scores for findings corroborated by multiple analyzers"""
        # Group findings by file/function
        location_groups = {}
        for f in findings:
            loc = f["file"]
            if loc not in location_groups:
                location_groups[loc] = []
            location_groups[loc].append(f)
        
        # Boost scores for locations with multiple findings
        for loc, loc_findings in location_groups.items():
            if len(loc_findings) > 1:
                for f in loc_findings:
                    # 10% boost for corroborated findings
                    f["score"] = min(100, int(f["score"] * 1.1))
        
        return findings

    def display(self, results: list):
        if not results:
            console.print("[yellow]No high-confidence findings[/yellow]")
            return
        console.print(f"[bold green]Found {len(results)} issues[/bold green]")
        for r in results[:25]:
            extra_info = ""
            if "attack_vector" in r:
                extra_info = f"\n[dim]Attack:[/dim] {r['attack_vector']}"
            console.print(Panel(
                f"[bold]{r['description']}[/bold]\n[dim]File:[/dim] {r['file']}\n[dim]Score:[/dim] {r['score']}{extra_info}",
                title=r["type"],
                border_style="red" if r["score"] >= 80 else "yellow" if r["score"] >= 60 else "blue"
            ))

        table = Table(title="Severity Summary")
        table.add_column("Level")
        table.add_column("Count")
        high = len([r for r in results if r["score"] >= 70])
        med = len([r for r in results if 50 <= r["score"] < 70])
        low = len([r for r in results if r["score"] < 50])
        table.add_row("High (70+)", str(high))
        table.add_row("Medium (50-69)", str(med))
        table.add_row("Low (<50)", str(low))
        console.print(table)
        
        # Show analyzer breakdown
        breakdown = {}
        for r in results:
            analyzer_type = r["type"].split("]")[0].strip("[]").split()[0]
            breakdown[analyzer_type] = breakdown.get(analyzer_type, 0) + 1
        
        if len(breakdown) > 1:
            console.print("\n[bold]Analyzer Breakdown:[/bold]")
            for analyzer, count in sorted(breakdown.items(), key=lambda x: x[1], reverse=True):
                console.print(f"  {analyzer}: {count}")
