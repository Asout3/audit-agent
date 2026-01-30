from local_db import LocalDB
from llm_client import LLMClient, ExtractionResult
from rich.console import Console
from rich.panel import Panel
from typing import List, Dict

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
        
        # Flatten all functions from all files
        all_functions = []
        cross_function_bugs = []
        
        for file_data in target_files:
            if file_data.get("type") == "cross_function_analysis":
                # Capture cross-function bugs
                cross_function_bugs.extend([
                    {**bug, "file": file_data["file"]} 
                    for bug in file_data.get("bugs", [])
                ])
            
            # Add individual functions
            for func in file_data.get("functions", []):
                all_functions.append({
                    **func,
                    "file": file_data.get("file", "unknown"),
                    "cross_bugs": file_data.get("bugs", [])
                })
        
        # PRIORITY 1: Cross-function vulnerabilities (CRITICAL)
        cross_func_funcs = [f for f in all_functions if f.get("cross_function_vulnerable")]
        if cross_func_funcs:
            print(f"[!!!] Found {len(cross_func_funcs)} cross-function vulnerabilities")
            for func in cross_func_funcs:
                findings.append({
                    "type": "[bold red]CROSS-FUNCTION CRITICAL[/bold red]",
                    "file": func["file"],
                    "function": func["function"],
                    "description": "State read in entry point, external call + state write in downstream function",
                    "attack_path": func.get("external_call_chain", "Unknown chain"),
                    "confidence": "Critical",
                    "score": 100
                })
        
        # Also add raw cross-function bugs from analysis
        for bug in cross_function_bugs:
            if bug["type"] == "cross_function_reentrancy":
                findings.append({
                    "type": "[bold red]CROSS-FUNCTION REENTRANCY[/bold red]",
                    "file": bug.get("file", "unknown"),
                    "function": f"{bug.get('entry_point')} → {bug.get('external_call_function')}",
                    "description": f"Shared state: {', '.join(bug.get('shared_state', []))}",
                    "attack_path": bug.get("attack_path"),
                    "confidence": "Critical",
                    "score": 98
                })
            elif bug["type"] == "delegatecall_injection":
                findings.append({
                    "type": "[bold red]DELEGATECALL INJECTION[/bold red]",
                    "file": bug.get("file", "unknown"),
                    "function": bug.get("function"),
                    "description": bug.get("description"),
                    "confidence": "Critical",
                    "score": 97
                })
            elif bug["type"] == "flash_loan_callback_vector":
                findings.append({
                    "type": "[bold yellow]FLASH LOAN VECTOR[/bold yellow]",
                    "file": bug.get("file", "unknown"),
                    "function": bug.get("function"),
                    "description": f"Callable from: {', '.join(bug.get('called_by', []))}",
                    "confidence": "High",
                    "score": 85
                })
        
        # PRIORITY 2: High-risk function analysis (top 25)
        high_risk_funcs = sorted(
            [f for f in all_functions if f.get("risk_score", 0) > 20], 
            key=lambda x: x.get("risk_score", 0), 
            reverse=True
        )[:25]
        
        print(f"[+] Deep analysis on {len(high_risk_funcs)} high-risk functions...")
        
        for i, func in enumerate(high_risk_funcs):
            if i % 5 == 0:
                console.print(f"  [dim]Analyzing {i+1}/{len(high_risk_funcs)}: {func['function']}[/dim]")
            
            # Skip if already flagged as cross-function vulnerable
            if func.get("cross_function_vulnerable"):
                continue
            
            # 1. Static analysis on this specific function
            if static_analyzer:
                static_bugs = static_analyzer.analyze(func.get("code", ""), func["function"])
                for bug in static_bugs:
                    findings.append({
                        "type": "[red]STATIC CRITICAL[/red]" if bug['severity'] == 'critical' else "[yellow]STATIC HIGH[/yellow]",
                        "file": f"{func['file']}::{func['function']}",
                        "description": bug["description"],
                        "code": bug.get("code", "N/A")[:50],
                        "confidence": "High",
                        "score": bug["score"]
                    })
            
            # 2. Slither findings (if available)
            for bug in func.get("slither_bugs", []):
                findings.append({
                    "type": "[bold red]SLITHER CRITICAL[/bold red]" if bug["severity"] == "critical" else "[bold yellow]SLITHER HIGH[/bold yellow]",
                    "file": f"{func['file']}::{func['function']}",
                    "description": f"{bug['type']}: {bug.get('details', '')[:100]}",
                    "location": bug["function"],
                    "confidence": "High",
                    "score": 90 if bug["severity"] == "critical" else 75
                })
            
            # 3. Semantic pattern matching
            arch = func.get("architecture", {})
            context = f"{func['function']} {' '.join(func.get('external_calls', []))} {' '.join([k for k, v in arch.items() if v])}"
            
            similar = self.db.search_similar(context, top_k=3)
            
            # 4. LLM deep analysis for high-similarity matches
            if similar and similar[0]["similarity"] > 0.55:
                # Check for historical cross-function patterns
                cross_func_historical = [s for s in similar if "cross" in s.get("invariant", "").lower() or "function" in s.get("invariant", "").lower()]
                
                if cross_func_historical and func.get("external_calls"):
                    findings.append({
                        "type": "[bold red]HISTORICAL CROSS-FUNCTION MATCH[/bold red]",
                        "file": f"{func['file']}::{func['function']}",
                        "description": f"Matches historical multi-function bug: {cross_func_historical[0]['invariant'][:80]}",
                        "confidence": "High",
                        "score": 95
                    })
                
                # Standard hypothesis generation
                hypotheses = self.llm.generate_hypothesis(
                    func.get("code", ""),
                    similar,
                    func["function"]
                )
                
                for h in hypotheses:
                    conf, score = self.composite_score(
                        similar[0]["similarity"] if similar else 0.5,
                        similar[0] if similar else {},
                        static_bugs[0] if static_bugs else None
                    )
                    
                    if h.get("confidence") == "High" or score >= 70:
                        findings.append({
                            "type": "[bold green]DEEP HYPOTHESIS[/bold green]",
                            "file": f"{func['file']}::{func['function']}",
                            "description": h.get("hypothesis", ""),
                            "location": h.get("location", "Unknown"),
                            "attack_vector": h.get("attack_vector", ""),
                            "based_on": h.get("invariant_assumed", ""),
                            "confidence": f"{conf} ({score:.0f})",
                            "score": score
                        })
            
            # 5. Pattern matches (medium confidence)
            for match in similar[:2]:
                _, score = self.composite_score(match["similarity"], match)
                if score >= 50:
                    findings.append({
                        "type": "[cyan]PATTERN MATCH[/cyan]",
                        "file": f"{func['file']}::{func['function']}",
                        "description": f"Similar to: {match['invariant'][:80]}...",
                        "break_condition": match.get("break_condition", "")[:80],
                        "confidence": f"Score: {score:.0f}",
                        "score": score
                    })
        
        # Sort by score descending
        findings.sort(key=lambda x: x.get("score", 0), reverse=True)
        return findings