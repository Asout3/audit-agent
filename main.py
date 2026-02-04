import argparse
import sys
from audit_agent import AuditAgent
from rich.console import Console
from rich.panel import Panel

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Deep Audit Agent - AI Smart Contract Auditor")
    
    # Core commands
    parser.add_argument("--build", action="store_true", help="Build/update the pattern database")
    parser.add_argument("--audit", type=str, help="Path to the contract project to audit")
    parser.add_argument("--sniper", action="store_true", help="Only show high-confidence findings")
    
    # Configuration
    parser.add_argument("--count", type=int, default=500, help="Number of findings to fetch from Solodit during build")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Increase verbosity level")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    
    # Filtering & Export
    parser.add_argument("--severity-filter", choices=["critical", "high", "medium", "low"], help="Filter by minimum severity")
    parser.add_argument("--confidence-filter", choices=["high", "medium", "low"], help="Filter by minimum confidence")
    parser.add_argument("--export", choices=["json", "markdown", "sarif", "html"], help="Export report in specified format")
    parser.add_argument("-o", "--output", type=str, help="Specify output file path")
    
    # Utility
    parser.add_argument("--stats", action="store_true", help="Show pattern database statistics")
    parser.add_argument("--db-info", action="store_true", help="Show detailed database info")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--validate", action="store_true", help="Perform LLM validation on findings to reduce false positives")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    
    if args.no_color:
        console.no_color = True

    agent = AuditAgent(verbosity=args.verbose)

    if args.build:
        agent.build_db(count=args.count)
    elif args.audit:
        agent.audit(
            args.audit, 
            sniper=args.sniper, 
            export_format=args.export,
            output_file=args.output
        )
    elif args.stats or args.db_info:
        agent.get_db_info()
    elif args.interactive:
        console.print("[bold yellow]Interactive mode not fully implemented yet, running standard audit...[/bold yellow]")
        if args.audit:
            agent.audit(args.audit)
        else:
            console.print("[red]Please provide a path with --audit[/red]")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
