from typing import List, Dict, Optional
from solodit_fetcher import SoloditFetcher
from llm_client import LLMClient
from local_db import LocalDB
from target_analyzer import TargetAnalyzer
from pattern_matcher import PatternMatcher
from config import Config
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import logging
import json
from pathlib import Path

console = Console()

class AuditAgent:
    """Orchestrator for the Deep Audit Agent"""
    
    def __init__(self, verbosity: int = 1):
        self.fetcher = SoloditFetcher()
        self.llm = LLMClient()
        self.db = LocalDB()
        self.matcher = PatternMatcher()
        self.verbosity = verbosity
        
        if verbosity >= 3:
            logging.basicConfig(level=logging.DEBUG)
        elif verbosity >= 2:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

    def build_db(self, count: int = 500):
        """Build the local pattern database from Solodit"""
        console.print(f"[bold green]Building Pattern Database (Target: {count} findings)...[/bold green]")
        
        findings = self.fetcher.fetch_findings(limit=count)
        if not findings:
            console.print("[red]No findings fetched. Check API key and connection.[/red]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Extracting invariants...", total=len(findings))
            
            # Use batch extraction for speed
            results = self.llm.batch_extract(findings, batch_size=5)
            
            for res in results:
                extraction = res["extraction"]
                finding = res["finding"]
                
                # Check for duplicates by title/content similarity
                if not self.db.is_duplicate(extraction.assumed_invariant):
                    self.db.add_pattern(
                        title=finding["title"],
                        content=finding["content"],
                        invariant=extraction.assumed_invariant,
                        break_condition=extraction.break_condition,
                        vuln_class=extraction.vuln_class,
                        severity=extraction.severity_score,
                        metadata={
                            "finders_count": finding.get("finders_count"),
                            "quality_score": finding.get("quality_score"),
                            "source": finding.get("source_link")
                        }
                    )
                progress.update(task, advance=1)
        
        console.print(f"[bold green]✓ Database built with {self.db.get_stats()['total_patterns']} unique patterns[/bold green]")

    def audit(self, path: str, sniper: bool = False, export_format: Optional[str] = None, output_file: Optional[str] = None):
        """Audit a target project"""
        console.print(f"[bold blue]Starting Deep Audit on {path}...[/bold blue]")
        
        try:
            analyzer = TargetAnalyzer(path)
            findings = self.matcher.analyze(analyzer, sniper=sniper)
            
            if export_format:
                self._export_findings(findings, export_format, output_file)
            else:
                self.matcher.display(findings)
                
            return findings
        except Exception as e:
            console.print(f"[bold red]Audit failed: {e}[/bold red]")
            if self.verbosity >= 2:
                import traceback
                traceback.print_exc()
            return []

    def _export_findings(self, findings: List[Dict], format: str, output_file: Optional[str]):
        """Export findings to various formats"""
        if not output_file:
            output_file = f"audit_report.{format}"
        
        content = ""
        if format == "json":
            content = json.dumps(findings, indent=2)
        elif format == "markdown":
            content = "# Audit Report\n\n"
            for f in findings:
                content += f"## {f['type']}: {f['description']}\n"
                content += f"- **Location**: {f['file']}\n"
                content += f"- **Score**: {f['score']}\n"
                if 'attack_vector' in f:
                    content += f"- **Attack Vector**: {f['attack_vector']}\n"
                content += "\n"
        # Add other formats as needed...
        
        Path(output_file).write_text(content)
        console.print(f"[bold green]✓ Report exported to {output_file}[/bold green]")

    def get_db_info(self):
        """Get database statistics"""
        stats = self.db.get_stats()
        console.print("[bold cyan]Database Statistics:[/bold cyan]")
        for key, val in stats.items():
            console.print(f"  {key}: {val}")
