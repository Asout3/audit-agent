from local_db import LocalDB
from llm_client import LLMClient
from target_analyzer import TargetAnalyzer 
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
        detectors = analyzer.get_detectors()
        for d in detectors:
            for result in d["instances"]:
                findings.append({
                    "type": f"[red]SLITHER {d['check']}[/red]",
                    "file": result["source_mapping"]["filename"],
                    "description": d["description"],
                    "score": 80 if "high" in d["impact"].lower() else 60,
                })

        funcs = analyzer.get_functions()
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

        findings.sort(key=lambda x: x["score"], reverse=True)
        if sniper:
            findings = [f for f in findings if f["score"] >= 70]
        return findings

    def display(self, results: list):
        if not results:
            console.print("[yellow]No high-confidence findings[/yellow]")
            return
        console.print(f"[bold green]Found {len(results)} issues[/bold green]")
        for r in results[:25]:
            console.print(Panel(
                f"[bold]{r['description']}[/bold]\n[dim]File:[/dim] {r['file']}\n[dim]Score:[/dim] {r['score']}",
                title=r["type"],
                border_style="red" if r["score"] >= 80 else "yellow"
            ))

        table = Table(title="Severity Summary")
        table.add_column("Level")
        table.add_column("Count")
        high = len([r for r in results if r["score"] >= 70])
        med = len([r for r in results if 50 <= r["score"] < 70])
        table.add_row("High", str(high))
        table.add_row("Medium", str(med))
        console.print(table)