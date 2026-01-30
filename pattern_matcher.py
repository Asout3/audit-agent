from local_db import LocalDB
from llm_client import LLMClient
from rich.console import Console
from rich.table import Table

console = Console()

class PatternMatcher:
    def __init__(self):
        self.db = LocalDB()
        self.llm = LLMClient()
        
    def composite_score(self, similarity: float, pattern: dict, static_bug: dict = None) -> tuple:
        """Calculate confidence: 0-100"""
        score = 0
        
        # Similarity component (0-35 pts)
        score += similarity * 35
        
        # Rarity component (0-25 pts) - fewer finders = higher value
        finders = pattern.get('finders_count', 1)
        score += max(0, 25 - (finders * 3))
        
        # Quality component (0-20 pts)
        quality = pattern.get('quality_score', 3)
        score += (quality / 5) * 20
        
        # Static analysis overlap (0-20 pts)
        if static_bug:
            if static_bug['type'].lower() in pattern.get('vuln_class', '').lower():
                score += 20
        
        if score >= 75:
            return "High", score
        elif score >= 55:
            return "Medium", score
        else:
            return "Low", score
        
    def analyze_target(self, target_files: list, static_analyzer=None):
        findings = []
        
        print("[+] Indexing patterns...")
        self.db.load_all_vectors()
        total, avg_finders, classes = self.db.get_stats()
        print(f"[+] Database: {total} patterns (avg {avg_finders:.1f} finders)")
        
        for i, tf in enumerate(target_files):
            console.print(f"\n[dim]({i+1}/{len(target_files)}) {tf['file']}[/dim]")
            
            # Skip if no content
            content = tf.get('content_snippet', '')
            if not content:
                content = str(tf.get('architecture', ''))
            
            # 1. Static analysis (fast, deterministic)
            static_bugs = []
            if static_analyzer:
                static_bugs = static_analyzer.analyze(content, tf['file'])
                for bug in static_bugs:
                    findings.append({
                        "type": "[red]STATIC CRITICAL[/red]" if bug['severity'] == 'critical' else "[yellow]STATIC HIGH[/yellow]",
                        "file": tf['file'],
                        "description": bug['description'],
                        "location": bug.get('code', 'N/A')[:50],
                        "confidence": "Static",
                        "score": bug['score']
                    })
            
            # 2. Slither findings (if available)
            for bug in tf.get('slither_bugs', []):
                conf = "High" if bug['severity'] == 'critical' else "Medium"
                findings.append({
                    "type": "[bold red]SLITHER CRITICAL[/bold red]" if bug['severity'] == 'critical' else "[bold yellow]SLITHER HIGH[/bold yellow]",
                    "file": tf['file'],
                    "description": f"{bug['type']}: {bug.get('details', '')[:100]}",
                    "location": bug['function'],
                    "confidence": conf,
                    "score": 90 if bug['severity'] == 'critical' else 75
                })
            
            # 3. Semantic pattern matching
            arch = tf.get('architecture', {})
            context = f"{' '.join(arch.get('functions', []))} {' '.join(tf.get('entry_points', []))} {' '.join([k for k, v in arch.items() if v is True])}"
            
            similar = self.db.search_similar(context, top_k=5)
            
            # 4. LLM deep analysis
            if similar:
                # Find best matching static bug for context
                best_static = static_bugs[0] if static_bugs else None
                
                hypotheses = self.llm.generate_hypothesis(
                    content,
                    similar,
                    tf['file']
                )
                
                for h in hypotheses:
                    # Validate against static analysis
                    conf, score = self.composite_score(
                        similar[0]['similarity'] if similar else 0.5,
                        similar[0] if similar else {},
                        best_static
                    )
                    
                    if h.get('confidence') == 'High' or score >= 70:
                        findings.append({
                            "type": "[bold green]DEEP HYPOTHESIS[/bold green]",
                            "file": tf['file'],
                            "description": h.get('hypothesis'),
                            "location": h.get('location', '?'),
                            "attack_vector": h.get('attack_vector'),
                            "based_on": h.get('invariant_assumed'),
                            "confidence": f"{conf} ({score:.0f})",
                            "score": score
                        })
            
            # 5. Pattern matches (medium confidence)
            for match in similar[:2]:
                _, score = self.composite_score(match['similarity'], match)
                if score >= 50:
                    findings.append({
                        "type": "[cyan]PATTERN MATCH[/cyan]",
                        "file": tf['file'],
                        "description": f"Similar to: {match['invariant'][:80]}...",
                        "break_condition": match['break_condition'][:80],
                        "confidence": f"Score: {score:.0f}",
                        "score": score
                    })
                    
        # Sort by score
        findings.sort(key=lambda x: x.get('score', 0), reverse=True)
        return findings