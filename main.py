#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from solodit_fetcher import SoloditFetcher
from llm_client import LLMClient
from local_db import LocalDB
from target_parser import TargetParser
from pattern_matcher import PatternMatcher
from static_analyzer import StaticAnalyzer
from rich.console import Console
from rich.panel import Panel

console = Console()

class AuditAgent:
    def __init__(self):
        self.db = LocalDB()
        self.fetcher = SoloditFetcher()
        self.llm = LLMClient()
        
    def validate_setup(self):
        console.print(Panel.fit("API Health Check", style="bold blue"))
        ok1 = self.fetcher.validate_api()
        ok2 = self.llm.validate()
        if not (ok1 and ok2):
            console.print("[red]✗ Setup failed[/red]")
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
                
            pattern = self.llm.extract_invariant(
                f.get("content", ""),
                f.get("title", "Unknown")
            )
            
            if pattern.get("vuln_class") == "ExtractionFailed":
                failed += 1
                
            self.db.add_pattern(
                f.get("id", str(i)),
                pattern,
                f.get("severity", "Medium"),
                f.get("quality_score", 0),
                f.get("finders_count", 1),
                f.get("title", ""),
                f.get("source_link", "")
            )
            
        console.print(f"[✓] Database built: {len(findings)} patterns")
        if failed > 0:
            console.print(f"[yellow]  Note: {failed} findings failed to parse[/yellow]")
        
    def audit(self, target_path: str):
        console.print(Panel.fit("Deep Bug Hunt", style="bold red"))
        
        # Parse target
        parser = TargetParser(target_path)
        files = parser.parse_all()
        
        if not files:
            console.print("[red]No Solidity files found[/red]")
            return
        
        # Static analysis
        static = StaticAnalyzer()
        
        # Pattern matching
        matcher = PatternMatcher()
        results = matcher.analyze_target(files, static)
        
        # Display results
        if not results:
            console.print("[yellow]No findings. Try broadening focus or building DB with more data.[/yellow]")
            return
            
        console.print(f"\n[bold green]Found {len(results)} potential issues:[/bold green]\n")
        
        # Show top 15
        for r in results[:15]:
            style = "red" if "CRITICAL" in r['type'] else "yellow" if "HIGH" in r['type'] else "green" if "DEEP" in r['type'] else "cyan"
            
            extra = ""
            if 'attack_vector' in r:
                extra += f"\n  [dim]Attack:[/dim] {r['attack_vector'][:100]}..."
            if 'based_on' in r and r['based_on']:
                extra += f"\n  [dim]Based on:[/dim] {r['based_on'][:60]}..."
            
            console.print(Panel(
                f"[bold]{r['description']}[/bold]\n"
                f"[dim]File:[/dim] {r['file']}\n"
                f"[dim]Location:[/dim] {r.get('location', 'N/A')}\n"
                f"[dim]Confidence:[/dim] {r.get('confidence', 'N/A')}"
                + extra,
                title=r['type'],
                border_style=style
            ))
        
        # Save full report
        report_path = Path("audit_report.json")
        with open(report_path, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[dim]Full report: {report_path} ({len(results)} total findings)[/dim]")

def main():
    parser = argparse.ArgumentParser(description="Deep Bug Hunter - Production Version")
    parser.add_argument("--build", action="store_true", help="Build database")
    parser.add_argument("--focus", type=str, help="Focus area (Lending, Perps, etc)")
    parser.add_argument("--count", type=int, default=200, help="Number of findings")
    parser.add_argument("--audit", type=str, help="Target directory")
    args = parser.parse_args()
    
    agent = AuditAgent()
    
    if args.build:
        agent.build_db(focus=args.focus, count=args.count)
    elif args.audit:
        agent.audit(args.audit)
    else:
        print("Usage:")
        print("  python main.py --build --focus Lending --count 300")
        print("  python main.py --audit ./protocol-contracts")

if __name__ == "__main__":
    main()