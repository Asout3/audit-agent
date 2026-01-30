from local_db import LocalDB
from llm_client import LLMClient
from rich.console import Console
from rich.table import Table

console = Console()

class PatternMatcher:
    def __init__(self):
        self.db = LocalDB()
        self.llm = LLMClient()
        
    def analyze_target(self, target_files: list):
        findings = []
        
        # Preload vectors for speed
        print("[+] Indexing patterns...")
        self.db.load_all_vectors()
        stats_total, stats_breakdown = self.db.get_stats()
        print(f"[+] Database: {stats_total} patterns loaded")
        
        for i, tf in enumerate(target_files):
            console.print(f"\n[dim]({i+1}/{len(target_files)}) Analyzing {tf['file']}...[/dim]")
            
            # Skip test files
            if "test" in tf['file'].lower() or "mock" in tf['file'].lower():
                continue
                
            arch = tf['architecture']
            
            # Build rich context for semantic search
            context_parts = [
                " ".join(arch.get("entry_points", [])),
                " ".join([k for k, v in arch.items() if v is True]),
                tf['file']  # Filename often contains hints (e.g., "LendingPool.sol")
            ]
            context = " ".join(filter(None, context_parts))
            
            # 1. Semantic search on invariants
            similar = self.db.search_similar(context, top_k=5)
            
            # 2. Fast indicator grep (exact function name matches)
            indicator_hits = []
            for func in arch.get("functions", []):
                # Search for this function name in historical code_indicators
                matches = self.db.search_similar(func, top_k=3)
                for m in matches:
                    if m['similarity'] > 0.8:
                        indicator_hits.append(m)
            
            # 3. Deep analysis only if we have good context or high complexity
            if similar and arch.get("complexity_score", 0) > 3:
                hypotheses = self.llm.generate_hypothesis(
                    tf['content_snippet'], 
                    similar,
                    tf['file']
                )
                
                for h in hypotheses:
                    if h.get('confidence') == 'High':
                        findings.append({
                            "type": "[bold red]CRITICAL HYPOTHESIS[/bold red]",
                            "file": tf['file'],
                            "description": h.get('hypothesis'),
                            "location": h.get('location', 'Unknown'),
                            "based_on": h.get('invariant_assumed'),
                            "attack": h.get('attack_vector'),
                            "confidence": "High"
                        })
                    elif h.get('confidence') == 'Medium':
                        findings.append({
                            "type": "[yellow]Potential Issue[/yellow]",
                            "file": tf['file'],
                            "description": h.get('hypothesis'),
                            "location": h.get('location', 'Unknown'),
                            "confidence": "Medium"
                        })
            
            # Add strong pattern matches
            for match in similar[:2]:
                if match['similarity'] > 0.75:
                    findings.append({
                        "type": "[cyan]Pattern Match[/cyan]",
                        "file": tf['file'],
                        "description": f"Similar to bug: {match['invariant'][:80]}...",
                        "break_condition": match['break_condition'][:100],
                        "similarity": f"{match['similarity']:.2f}",
                        "confidence": "Pattern"
                    })
                    
        return findings