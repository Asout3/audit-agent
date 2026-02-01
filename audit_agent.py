from rich.console import Console
from rich.panel import Panel
from solodit_fetcher import SoloditFetcher
from llm_client import LLMClient
from local_db import LocalDB
from target_analyzer import TargetAnalyzer
from pattern_matcher import PatternMatcher

console = Console()

class AuditAgent:
    def __init__(self):
        self.fetcher = SoloditFetcher()
        self.llm = LLMClient()
        self.db = LocalDB()
        self.matcher = PatternMatcher()

    def validate(self):
        console.print(Panel("Health Check", style="bold blue"))
        ok1 = self.fetcher.validate_api()
        ok2 = self.llm.validate()
        return ok1 and ok2

    def build_db(self, count: int = 500):
        if not self.validate():
            return
        console.print(Panel(f"Building DB: max {count} findings", style="bold green"))
        findings = self.fetcher.fetch_findings(severity=["High"], limit=count)
        added = self.llm.process_findings(findings)
        console.print(f"[bold green]DB built: {added} patterns[/bold green]")

    def audit(self, path: str, sniper: bool = False):
        if not self.validate():
            return
        console.print(Panel("Deep Audit", style="bold red"))
        analyzer = TargetAnalyzer(path)
        results = self.matcher.analyze(analyzer, sniper=sniper)
        self.matcher.display(results)