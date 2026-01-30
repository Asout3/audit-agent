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
from rich.table import Table

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
                
            try:
                result = self.llm.extract_invariant(
                    f.get("content", ""),
                    f.get("title", "Unknown")
                )
                
                if result.vuln_class == "ExtractionFailed":
                    failed += 1
                
                self.db.add_pattern(
                    f.get("id", str(i)),
                    {
                        "vuln_class": result.vuln_class,
                        "assumed_invariant": result.assumed_invariant,
                        "break_condition": result.break_condition,
                        "preconditions": result.preconditions,
                        "code_indicators": result.code_indicators
                    },
                    f.get("severity", "Medium"),
                    f.get("quality_score", 0),
                    f.get("finders_count", 1),
                    f.get("title", ""),
                    f.get("source_link", "")
                )
            except Exception as e:
                failed += 1
                print(f"  [!] Error processing finding {i}: {e}")
            
        console.print(f"[✓] Database built: {len(findings)} patterns")
        if failed > 0:
            console.print(f"[yellow]  Note: {failed} findings failed to parse[/yellow]")
        
    def audit(self, target_path: str):
        console.print(Panel.fit("Deep Bug Hunt", style="bold red"))
        
        # Parse target with cross-function analysis
        parser = TargetParser(target_path)
        files = parser.parse_all()
        
        if not files:
            console.print("[red]No Solidity files found[/red]")
            return
        
        # Static analysis
        static = StaticAnalyzer()
        
        # Pattern matching with all features
        matcher = PatternMatcher()
        results = matcher.analyze_target(files, static)
        
        if not results:
            console.print("[yellow]No findings. Try broadening focus or building DB with more data.[/yellow]")
            return
        
        # FINAL SEVERITY CONSOLIDATION AND RANKING
        severity_rank = {
            "CROSS-FUNCTION CRITICAL": 100,
            "CROSS-FUNCTION REENTRANCY": 98,
            "DELEGATECALL INJECTION": 97,
            "HISTORICAL CROSS-FUNCTION MATCH": 95,
            "STATIC CRITICAL": 90,
            "SLITHER CRITICAL": 88,
            "DEEP HYPOTHESIS": 80,
            "FLASH LOAN VECTOR": 85,
            "STATIC HIGH": 75,
            "SLITHER HIGH": 73,
            "PATTERN MATCH": 60,
            "STATIC MEDIUM": 50
        }
        
        for f in results:
            # Extract clean type for ranking
            clean_type = f["type"].replace("[", "").replace("]", "").replace("bold ", "").replace("red", "").replace("yellow", "").replace("green", "").replace("cyan", "").strip()
            f["final_rank"] = severity_rank.get(clean_type, f.get("score", 50))
        
        # Re-sort by final rank
        results.sort(key=lambda x: x["final_rank"], reverse=True)
        
        # Display results
        console.print(f"\n[bold green]Found {len(results)} potential issues (top 20 shown):[/bold green]\n")
        
        for r in results[:20]:
            # Determine color based on rank
            rank = r.get("final_rank", 0)
            if rank >= 95:
                style = "bright_red"
            elif rank >= 80:
                style = "red"
            elif rank >= 70:
                style = "yellow"
            elif rank >= 60:
                style = "green"
            else:
                style = "cyan"
            
            extra_info = ""
            if "attack_path" in r:
                extra_info += f"\n  [dim]Path:[/dim] {r['attack_path']}"
            if "attack_vector" in r and r["attack_vector"]:
                extra_info += f"\n  [dim]Attack:[/dim] {r['attack_vector'][:100]}..."
            if "based_on" in r and r["based_on"]:
                extra_info += f"\n  [dim]Pattern:[/dim] {r['based_on'][:60]}..."
            
            console.print(Panel(
                f"[bold]{r['description'][:200]}[/bold]\n"
                f"[dim]File:[/dim] {r['file']}\n"
                f"[dim]Rank:[/dim] {r['final_rank']}"
                + extra_info,
                title=f"[{r['type']}]",
                border_style=style
            ))
        
        # Summary table
        table = Table(title="Summary by Severity")
        table.add_column("Severity", style="cyan")
        table.add_column("Count", justify="right", style="green")
        
        critical = len([r for r in results if r.get("final_rank", 0) >= 95])
        high = len([r for r in results if 80 <= r.get("final_rank", 0) < 95])
        medium = len([r for r in results if 60 <= r.get("final_rank", 0) < 80])
        low = len([r for r in results if r.get("final_rank", 0) < 60])
        
        table.add_row("Critical (95-100)", str(critical))
        table.add_row("High (80-94)", str(high))
        table.add_row("Medium (60-79)", str(medium))
        table.add_row("Low (<60)", str(low))
        console.print(table)
        
        # Save full report
        report_path = Path("audit_report.json")
        with open(report_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"\n[dim]Full report saved: {report_path} ({len(results)} total findings)[/dim]")

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