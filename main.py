#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from solodit_fetcher import SoloditFetcher
from llm_client import LLMClient
from local_db import LocalDB
from target_parser import TargetParser
from pattern_matcher import PatternMatcher
from rich.console import Console
from rich.panel import Panel

console = Console()

class AuditAgent:
    def __init__(self):
        self.db = LocalDB()
        self.fetcher = SoloditFetcher()
        self.llm = LLMClient()
        
    def validate_setup(self):
        """Check APIs before starting"""
        console.print(Panel.fit("API Health Check", style="bold blue"))
        
        ok1 = self.fetcher.validate_api()
        ok2 = self.llm.validate()
        
        if not (ok1 and ok2):
            console.print("[red]✗ Setup failed. Check your API keys.[/red]")
            return False
        return True
        
    def build_db(self, focus: str = None, count: int = 200):
        if not self.validate_setup():
            return
            
        console.print(Panel.fit(f"Building Database: {count} findings", style="bold green"))
        
        findings = self.fetcher.fetch_findings(
            severity=["High", "Critical"],
            protocol_type=focus,
            limit=count
        )
        
        if not findings:
            console.print("[red]No findings retrieved[/red]")
            return
        
        console.print(f"[+] Processing {len(findings)} findings with LLM...")
        
        failed = 0
        for i, f in enumerate(findings):
            if i % 10 == 0:
                console.print(f"  Progress: {i}/{len(findings)} ({failed} failed)")
                
            # Skip if already in DB (resume friendly)
            # (Would need ID check here in production)
            
            pattern = self.llm.extract_invariant(
                f.get("content", f.get("description", "")),
                f.get("title", "Unknown")
            )
            
            if pattern.get("vuln_class") == "ParseError":
                failed += 1
                
            self.db.add_pattern(
                f.get("id", str(i)),
                pattern,
                f.get("severity", "Medium"),
                f.get("title", "")
            )
            
        console.print(f"[✓] Database built: {len(findings)} patterns")
        if failed > 0:
            console.print(f"[yellow]  Note: {failed} findings failed to parse (network issues)[/yellow]")
        
    def audit(self, target_path: str):
        console.print(Panel.fit("Deep Bug Hunt", style="bold red"))
        
        parser = TargetParser(target_path)
        files = parser.parse_all()
        
        if not files:
            console.print("[red]No Solidity files found[/red]")
            return
        
        matcher = PatternMatcher()
        results = matcher.analyze_target(files)
        
        # Display
        if not results:
            console.print("[yellow]No high-confidence patterns found. Try broadening search or building DB with different focus.[/yellow]")
            return
            
        console.print(f"\n[bold green]Found {len(results)} potential issues:[/bold green]\n")
        
        for r in results:
            style = "red" if "CRITICAL" in r['type'] else "yellow" if "Potential" in r['type'] else "cyan"
            console.print(Panel(
                f"[bold]{r['description']}[/bold]\n\n"
                f"File: {r['file']}\n"
                f"Location: {r.get('location', 'N/A')}\n"
                + (f"Attack: {r.get('attack', 'N/A')}\n" if 'attack' in r else ""),
                title=r['type'],
                border_style=style
            ))
            
        # Save JSON
        report_path = Path("audit_report.json")
        with open(report_path, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[dim]Full report saved to: {report_path}[/dim]")

def main():
    parser = argparse.ArgumentParser(description="Deep Bug Hunter - Invariant Analysis")
    parser.add_argument("--build", action="store_true", help="Build database from Solodit")
    parser.add_argument("--focus", type=str, help="Protocol focus (Lending, Perps, Options, etc)")
    parser.add_argument("--count", type=int, default=200, help="Number of findings to fetch")
    parser.add_argument("--audit", type=str, help="Target directory to audit")
    args = parser.parse_args()
    
    agent = AuditAgent()
    
    if args.build:
        agent.build_db(focus=args.focus, count=args.count)
    elif args.audit:
        agent.audit(args.audit)
    else:
        print("Usage:")
        print("  python main.py --build --focus Lending --count 300")
        print("  python main.py --audit ./path/to/contracts")

if __name__ == "__main__":
    main()