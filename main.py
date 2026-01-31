#!/usr/bin/env python3
import argparse
import json
import sys
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
from rich import box

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
        
    def build_db(self, focus: str = None, count: int = 200, batch_mode: bool = True):
        """Build database with optional batch processing"""
        if not self.validate_setup():
            return
            
        console.print(Panel.fit(f"Building Database: {count} findings{' (Batch mode)' if batch_mode else ''}", style="bold green"))
        
        findings = self.fetcher.fetch_findings(
            severity=["High"],  # Only HIGH to avoid invalid values
            protocol_type=focus,
            limit=count
        )
        
        if not findings:
            console.print("[red]No findings retrieved[/red]")
            return
        
        console.print(f"[+] Processing {len(findings)} findings...")
        
        if batch_mode and len(findings) > 10:
            # Use batch extraction
            batch_results = self.llm.batch_extract(findings, batch_size=3)
            added = 0
            for item in batch_results:
                try:
                    f = item['finding']
                    result = item['extraction']
                    
                    if self.db.add_pattern(
                        f.get("id"),
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
                        f.get("source_link", ""),
                        focus or "general"
                    ):
                        added += 1
                except Exception as e:
                    print(f"  [!] Error: {e}")
        else:
            # Individual extraction
            failed = 0
            added = 0
            for i, f in enumerate(findings):
                if i % 10 == 0:
                    console.print(f"  Progress: {i}/{len(findings)} ({failed} failed, {added} added)")
                    
                try:
                    result = self.llm.extract_invariant(
                        f.get("content", ""),
                        f.get("title", "Unknown")
                    )
                    
                    if result.vuln_class == "Unknown" and failed < len(findings) * 0.3:
                        failed += 1
                    
                    if self.db.add_pattern(
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
                        f.get("source_link", ""),
                        focus or "general"
                    ):
                        added += 1
                        
                except Exception as e:
                    failed += 1
        
        total, avg_finders, avg_quality, classes = self.db.get_stats()
        console.print(f"[bold green]✓ Database built: {total} unique patterns[/bold green]")
        if classes:
            console.print(f"[dim]Classes: {', '.join([f'{c[0]}({c[1]})' for c in classes[:5]])}[/dim]")
        
    def audit(self, target_path: str, sniper_mode: bool = False):
        """Run audit on target codebase"""
        console.print(Panel.fit("Deep Bug Hunt", style="bold red"))
        
        # Parse target
        parser = TargetParser(target_path)
        files = parser.parse_all()
        
        if not files:
            console.print("[red]No Solidity files found or all files skipped[/red]")
            return
        
        # Static analysis
        static = StaticAnalyzer()
        
        # Pattern matching
        matcher = PatternMatcher()
        
        if sniper_mode:
            console.print("[yellow]SNIPER MODE: Only critical findings[/yellow]")
        
        results = matcher.analyze_target(files, static)
        
        if not results:
            console.print("[yellow]No findings.[/yellow]")
            console.print("[dim]Try:[/dim]")
            console.print("  1. Build DB with more data: python main.py --build --count 500")
            console.print("  2. Lower similarity threshold in config.py")
            return
        
        # Filter for sniper mode
        if sniper_mode:
            results = [r for r in results if r.get('score', 0) >= 70]
        
        # Display results
        console.print(f"\n[bold green]Found {len(results)} potential issues (top 20 shown):[/bold green]\n")
        
        for r in results[:20]:
            rank = r.get('score', 0)
            
            # Color by severity
            if rank >= 90 or 'cross-function' in r['type'].lower():
                style = "bright_red"
            elif rank >= 70:
                style = "red"
            elif rank >= 55:
                style = "yellow"
            elif rank >= 45:
                style = "green"
            else:
                style = "cyan"
            
            extra = ""
            if 'attack_vector' in r and r['attack_vector']:
                extra += f"\n  [dim]Attack:[/dim] {r['attack_vector'][:120]}..."
            if 'based_on' in r and r['based_on']:
                extra += f"\n  [dim]Based on:[/dim] {r['based_on'][:80]}..."
            if 'indicators' in r and r['indicators']:
                extra += f"\n  [dim]Indicators:[/dim] {', '.join(r['indicators'][:3])}"
            
            console.print(Panel(
                f"[bold]{r['description'][:250]}[/bold]\n"
                f"[dim]File:[/dim] {r['file']}\n"
                f"[dim]Score:[/dim] {rank:.0f} | [dim]Conf:[/dim] {r.get('confidence', 'N/A')}"
                + extra,
                title=f"[{r.get('type', 'UNKNOWN')}]",
                border_style=style,
                box=box.ROUNDED
            ))
        
        # Summary table
        table = Table(title="Summary by Severity", box=box.SIMPLE)
        table.add_column("Severity", style="cyan")
        table.add_column("Count", justify="right", style="green")
        
        critical = len([r for r in results if r.get('score', 0) >= 90 or 'cross-function' in r['type'].lower()])
        high = len([r for r in results if 70 <= r.get('score', 0) < 90])
        medium = len([r for r in results if 50 <= r.get('score', 0) < 70])
        low = len([r for r in results if r.get('score', 0) < 50])
        
        if critical:
            table.add_row("[bold red]CRITICAL (90+)[/bold red]", str(critical))
        if high:
            table.add_row("[red]HIGH (70-89)[/red]", str(high))
        if medium:
            table.add_row("[yellow]MEDIUM (50-69)[/yellow]", str(medium))
        if low:
            table.add_row("[dim]LOW (<50)[/dim]", str(low))
            
        console.print(table)
        
        # Save full report
        report_path = Path("audit_report.json")
        with open(report_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"\n[dim]Full report: {report_path} ({len(results)} total findings)[/dim]")
        
        return results

def main():
    parser = argparse.ArgumentParser(description="Deep Audit Agent - Production Version")
    parser.add_argument("--build", action="store_true", help="Build vulnerability database")
    parser.add_argument("--focus", type=str, help="Focus area (Lending, Perpetual, etc)")
    parser.add_argument("--count", type=int, default=200, help="Number of findings to fetch")
    parser.add_argument("--batch", action="store_true", help="Use batch LLM extraction (faster)")
    parser.add_argument("--audit", type=str, help="Target directory to audit")
    parser.add_argument("--sniper", action="store_true", help="Only show high-confidence findings")
    args = parser.parse_args()
    
    agent = AuditAgent()
    
    if args.build:
        agent.build_db(focus=args.focus, count=args.count, batch_mode=args.batch)
    elif args.audit:
        findings = agent.audit(args.audit, sniper_mode=args.sniper)
        if not findings:
            sys.exit(1)
    else:
        print("Deep Audit Agent - Usage:")
        print("  Build DB:  python main.py --build --focus Lending --count 300 --batch")
        print("  Audit:     python main.py --audit ./protocol-contracts")
        print("  Sniper:    python main.py --audit ./protocol --sniper")

if __name__ == "__main__":
    main()