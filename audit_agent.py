import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from solodit_fetcher import SoloditFetcher
from llm_client import LLMClient
from local_db import LocalDB
from target_analyzer import TargetAnalyzer
from pattern_matcher import PatternMatcher

console = Console()
WORKSPACE_ROOT = Path(__file__).parent.resolve()

class AuditAgent:
    def __init__(self):
        os.chdir(WORKSPACE_ROOT)
        self.fetcher = SoloditFetcher()
        self.llm = LLMClient()
        self.db = LocalDB()
        self.matcher = PatternMatcher()

    def validate(self):
        console.print(Panel("Health Check", style="bold blue"))
        ok1 = self.fetcher.validate_api()
        ok2 = self.llm.validate()
        if not ok2:
            return False
        if not ok1:
            console.print("[!] Solodit unavailable - proceeding without pattern DB")
        return True

    def build_db(self, count: int = 500):
        if not self.validate():
            return
        console.print(Panel(f"Building DB: max {count} findings", style="bold green"))
        findings = self.fetcher.fetch_findings(severity=["High"], limit=count)
        if not findings:
            console.print("[red]No findings fetched[/red]")
            return

        batch_results = self.llm.batch_extract(findings)
        added = 0
        for item in batch_results:
            f = item['finding']
            result = item['extraction']
            if self.db.add_pattern(
                f.get('id', 'unknown'),
                {
                    "vuln_class": result.vuln_class,
                    "assumed_invariant": result.assumed_invariant,
                    "break_condition": result.break_condition,
                    "preconditions": result.preconditions,
                    "code_indicators": result.code_indicators
                },
                f.get('severity', 'Medium'),
                f.get('quality_score', 0),
                f.get('finders_count', 999),
                f.get('title', ''),
                f.get('source_link', ''),
                "general"
            ):
                added += 1
        console.print(f"[bold green]DB built: {added} patterns added[/bold green]")

    def audit(self, path: str, sniper: bool = False):
        if not self.validate():
            return
        console.print(Panel("Deep Audit", style="bold red"))
        analyzer = TargetAnalyzer(path)
        results = self.matcher.analyze(analyzer, sniper=sniper)
        self.matcher.display(results)