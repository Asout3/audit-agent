from typing import List, Dict, Optional
from solodit_fetcher import SoloditFetcher
from llm_client import LLMClient
from local_db import LocalDB
from target_analyzer import TargetAnalyzer
from pattern_matcher import PatternMatcher
from test_generator import TestGenerator
from config import Config
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import json
from pathlib import Path
from logger import get_logger
from cache_manager import get_cache_manager
from exceptions import AuditError, ConfigError
import os

console = Console()
logger = get_logger()

class AuditAgent:
    """Orchestrator for the Deep Audit Agent"""
    
    def __init__(self, verbosity: int = 1, debug: bool = False):
        self.fetcher = SoloditFetcher()
        self.llm = LLMClient()
        self.db = LocalDB()
        self.matcher = PatternMatcher()
        self.test_gen = TestGenerator(self.llm)
        self.cache_manager = get_cache_manager()
        self.verbosity = verbosity
        self.debug = debug
        
        # Pre-flight validation
        self._validate_config()
    
    def _validate_config(self):
        """Validate configuration before running"""
        if not Config.GROQ_API_KEY:
            logger.warning("GROQ_API_KEY not set - LLM features will be limited")
        
        if not Config.SOLODIT_API_KEY:
            logger.warning("SOLODIT_API_KEY not set - database building will not work")
        
        Config.DATA_DIR.mkdir(exist_ok=True)
        logger.debug("Configuration validated")
    
    def _save_progress(self, progress_data: Dict):
        """Save audit progress for resume capability"""
        try:
            Config.PROGRESS_FILE.write_text(json.dumps(progress_data, indent=2))
            logger.debug("Progress saved")
        except Exception as e:
            logger.error(f"Failed to save progress: {e}")
    
    def _load_progress(self) -> Optional[Dict]:
        """Load audit progress from checkpoint"""
        try:
            if Config.PROGRESS_FILE.exists():
                data = json.loads(Config.PROGRESS_FILE.read_text())
                logger.info("Loaded previous progress")
                return data
        except Exception as e:
            logger.error(f"Failed to load progress: {e}")
        return None

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

    def audit(self, path: str, sniper: bool = False, export_format: Optional[str] = None, 
              output_file: Optional[str] = None, generate_tests: bool = False, 
              run_tests: bool = False, resume: bool = False, cross_contract: bool = False,
              min_confidence: Optional[int] = None, protocol_type: Optional[str] = None,
              complexity: Optional[str] = None):
        """Audit a target project with advanced features"""
        
        # Pre-flight checks
        target_path = Path(path)
        if not target_path.exists():
            error_msg = f"Audit path does not exist: {path}"
            logger.error(error_msg)
            console.print(f"[bold red]❌ {error_msg}[/bold red]")
            console.print("\n[yellow]💡 Suggestion:[/yellow] Check the path and try again")
            return []
        
        # Check for Solidity files
        sol_files = list(target_path.rglob("*.sol"))
        if not sol_files:
            error_msg = f"No Solidity files found in {path}"
            logger.error(error_msg)
            console.print(f"[bold red]❌ {error_msg}[/bold red]")
            console.print("\n[yellow]💡 Suggestion:[/yellow] Ensure the path contains .sol files")
            return []
        
        console.print(f"[bold blue]Starting Deep Audit on {path}...[/bold blue]")
        console.print(f"[dim]Found {len(sol_files)} Solidity files[/dim]")
        logger.info(f"Starting audit on {path} with {len(sol_files)} files")
        
        # Resume from checkpoint if requested
        progress = None
        if resume:
            progress = self._load_progress()
            if progress:
                console.print("[green]✓ Resumed from checkpoint[/green]")
        
        try:
            # Load cache for performance
            cached_vectors = self.cache_manager.load_embedding_cache()
            if cached_vectors:
                self.db._vector_cache = cached_vectors
                console.print("[green]✓ Loaded embedding cache (fast mode)[/green]")
            
            # Initialize analyzer
            analyzer = TargetAnalyzer(path)
            logger.info("Target analyzer initialized")
            
            # Run analysis
            findings = self.matcher.analyze(
                analyzer, 
                sniper=sniper,
                cross_contract=cross_contract,
                progress=progress
            )
            logger.info(f"Analysis complete: {len(findings)} findings")
            
            # Apply additional filters
            if min_confidence:
                findings = [f for f in findings if f.get("score", 0) >= min_confidence]
                logger.debug(f"Filtered to {len(findings)} findings with min confidence {min_confidence}")
            
            # Generate and run tests if requested
            if generate_tests or run_tests:
                if self.test_gen.is_available():
                    console.print("\n[bold yellow]Generating Foundry test cases...[/bold yellow]")
                    test_files = self.test_gen.generate_tests_for_findings(findings, target_path)
                    console.print(f"[green]✓ Generated {len(test_files)} test cases[/green]")
                    
                    if run_tests and test_files:
                        console.print("\n[bold yellow]Running Foundry tests...[/bold yellow]")
                        test_results = self.test_gen.run_tests(target_path)
                        findings = self.test_gen.update_findings_with_results(findings, test_results)
                        console.print("[green]✓ Test validation complete[/green]")
                else:
                    console.print("[yellow]⚠ Foundry not available - skipping test generation[/yellow]")
            
            # Save progress
            self._save_progress({
                "path": str(target_path),
                "findings_count": len(findings),
                "timestamp": str(Path().resolve())
            })
            
            # Save cache for next run
            if not cached_vectors and self.db._vector_cache:
                self.cache_manager.save_embedding_cache(self.db._vector_cache)
            
            # Export or display
            if export_format:
                self._export_findings(findings, export_format, output_file)
            else:
                self.matcher.display(findings)
            
            # Show summary
            console.print(f"\n[bold green]✓ Audit complete: {len(findings)} findings[/bold green]")
            if generate_tests:
                confirmed = sum(1 for f in findings if f.get("validation_status") == "confirmed")
                if confirmed > 0:
                    console.print(f"[bold red]⚠ {confirmed} vulnerabilities confirmed by tests![/bold red]")
                
            return findings
            
        except Exception as e:
            error_msg = f"Audit failed: {e}"
            logger.error(error_msg, exc_info=True)
            console.print(f"[bold red]❌ {error_msg}[/bold red]")
            
            if self.debug:
                import traceback
                console.print("\n[dim]" + traceback.format_exc() + "[/dim]")
            else:
                console.print("\n[yellow]💡 Tip:[/yellow] Run with --debug for detailed error information")
            
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
