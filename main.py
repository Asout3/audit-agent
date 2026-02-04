import argparse
import sys
from audit_agent import AuditAgent
from rich.console import Console
from rich.panel import Panel
from logger import setup_logging
from cache_manager import get_cache_manager

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
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode with detailed logging")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    
    # Filtering & Export
    parser.add_argument("--severity-filter", choices=["critical", "high", "medium", "low"], help="Filter by minimum severity")
    parser.add_argument("--confidence-filter", choices=["high", "medium", "low"], help="Filter by minimum confidence")
    parser.add_argument("--export", choices=["json", "markdown", "sarif", "html"], help="Export report in specified format")
    parser.add_argument("-o", "--output", type=str, help="Specify output file path")
    
    # Advanced features
    parser.add_argument("--generate-tests", action="store_true", help="Generate Foundry test cases for high-confidence findings")
    parser.add_argument("--run-tests", action="store_true", help="Execute generated Foundry tests to validate findings")
    parser.add_argument("--resume", action="store_true", help="Resume interrupted audit from checkpoint")
    parser.add_argument("--cross-contract", action="store_true", help="Enable deep cross-contract analysis")
    
    # Cache management
    parser.add_argument("--clear-cache", choices=["all", "embedding", "slither", "llm"], help="Clear specified cache")
    parser.add_argument("--cache-stats", action="store_true", help="Show cache statistics")
    
    # Pattern database filtering
    parser.add_argument("--min-confidence", type=int, help="Filter patterns by minimum confidence score")
    parser.add_argument("--protocol-type", type=str, help="Filter patterns by protocol category")
    parser.add_argument("--complexity", choices=["easy", "medium", "hard"], help="Filter by exploit complexity")
    
    # Utility
    parser.add_argument("--stats", action="store_true", help="Show pattern database statistics")
    parser.add_argument("--db-info", action="store_true", help="Show detailed database info")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--validate", action="store_true", help="Perform LLM validation on findings to reduce false positives")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    
    # Setup logging
    setup_logging(debug=args.debug)
    
    if args.no_color:
        console.no_color = True
    
    # Handle cache operations
    cache_manager = get_cache_manager()
    
    if args.clear_cache:
        console.print(f"[yellow]Clearing {args.clear_cache} cache...[/yellow]")
        cache_manager.clear_cache(args.clear_cache)
        console.print("[green]✓ Cache cleared[/green]")
        return
    
    if args.cache_stats:
        stats = cache_manager.get_stats()
        console.print("[bold cyan]Cache Statistics:[/bold cyan]")
        console.print(f"  Hits: {stats['hits']}")
        console.print(f"  Misses: {stats['misses']}")
        console.print(f"  Size: {stats['cache_size'] / 1024 / 1024:.2f} MB")
        console.print(f"  Embedding cached: {stats['embedding_cached']}")
        return

    agent = AuditAgent(
        verbosity=args.verbose,
        debug=args.debug
    )

    if args.build:
        agent.build_db(count=args.count)
    elif args.audit:
        agent.audit(
            args.audit, 
            sniper=args.sniper, 
            export_format=args.export,
            output_file=args.output,
            generate_tests=args.generate_tests,
            run_tests=args.run_tests,
            resume=args.resume,
            cross_contract=args.cross_contract,
            min_confidence=args.min_confidence,
            protocol_type=args.protocol_type,
            complexity=args.complexity
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
