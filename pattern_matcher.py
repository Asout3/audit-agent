from typing import List, Dict, Tuple
from local_db import LocalDB
from llm_client import LLMClient
from rich.console import Console

console = Console()

class PatternMatcher:
    def __init__(self):
        self.db = LocalDB()
        self.llm = LLMClient()
        
    def calculate_confidence(self, similarity: float, pattern: dict, static_findings: list = None) -> Tuple[str, float]:
        """Calculate confidence score: 0-100"""
        score = 0
        
        # Similarity component (max 40)
        score += similarity * 40
        
        # Rarity bonus (max 25) - fewer finders = more valuable
        finders = pattern.get('finders_count', 1)
        if finders <= 2:
            score += 25
        elif finders <= 5:
            score += 15
        else:
            score += max(0, 10 - finders)
        
        # Quality bonus (max 20)
        quality = pattern.get('quality_score', 0)
        score += (quality / 5) * 20
        
        # Static analysis confirmation (max 15)
        if static_findings:
            for sf in static_findings:
                if sf['type'].lower() in pattern.get('vuln_class', '').lower():
                    score += 15
                    break
        
        # Boost for high similarity
        if similarity > 0.75:
            score += 10
        
        if score >= 80:
            return "Critical", score
        elif score >= 65:
            return "High", score
        elif score >= 50:
            return "Medium", score
        else:
            return "Low", score
    
    def generate_search_query(self, func_data: dict, arch: dict) -> str:
        """Generate rich search query from function context"""
        query_parts = [func_data['name']]
        
        # Add architecture context
        if arch.get('lending'):
            query_parts.extend(['borrow', 'collateral', 'liquidation'])
        if arch.get('perpetual'):
            query_parts.extend(['funding', 'margin', 'position', 'leverage'])
        if arch.get('amm'):
            query_parts.extend(['swap', 'liquidity', 'price'])
        if arch.get('oracle'):
            query_parts.extend(['oracle', 'price', 'feed'])
        
        # Add indicators
        indicators = func_data.get('indicators', {})
        if indicators.get('external_call'):
            query_parts.append('external call reentrancy')
        if indicators.get('delegatecall'):
            query_parts.append('delegatecall injection')
        if indicators.get('reentrancy_risk'):
            query_parts.append('state change after call')
        
        return ' '.join(query_parts)
    
    def analyze_target(self, target_files: list, static_analyzer=None) -> List[Dict]:
        """Main analysis loop"""
        findings = []
        
        print("[+] Loading pattern database...")
        self.db.load_all_vectors()
        total, avg_finders, avg_quality, classes = self.db.get_stats()
        print(f"[+] Database: {total} patterns (avg {avg_finders:.1f} finders, {avg_quality:.1f} quality)")
        print(f"[+] Top classes: {', '.join([f'{c[0]}({c[1]})' for c in classes[:3]])}")
        
        # PRIORITY 1: Cross-function vulnerabilities
        cross_func_findings = []
        for file_data in target_files:
            cross_bugs = file_data.get('cross_function_bugs', [])
            for bug in cross_bugs:
                cross_func_findings.append({
                    "type": f"[bold red]CROSS-FUNCTION {bug['type'].upper()}[/bold red]",
                    "file": file_data['file'],
                    "function": bug.get('entry_point', bug.get('function', 'unknown')),
                    "description": bug['description'],
                    "attack_path": bug.get('attack_path', ''),
                    "attack_vector": bug.get('description', ''),
                    "confidence": "Critical",
                    "score": 95 if 'reentrancy' in bug['type'] else 85,
                    "indicators": bug.get('indicators', []),
                    "matched_patterns": ["cross_function_analysis"]
                })
        
        if cross_func_findings:
            print(f"[!!!] Found {len(cross_func_findings)} cross-function vulnerabilities")
            findings.extend(cross_func_findings)
        
        # Collect all functions sorted by risk
        all_functions = []
        for file_data in target_files:
            arch = file_data.get('architecture', {})
            for func in file_data.get('functions', []):
                all_functions.append({
                    **func,
                    "file": file_data['file'],
                    "architecture": arch
                })
        
        # Sort by risk, take top 30
        all_functions.sort(key=lambda x: x['risk_score'], reverse=True)
        high_risk_funcs = [f for f in all_functions if f['risk_score'] > 15][:30]
        
        print(f"[+] Deep analysis on {len(high_risk_funcs)} high-risk functions...")
        
        for i, func in enumerate(high_risk_funcs):
            if i % 5 == 0:
                console.print(f"  [dim]{i+1}/{len(high_risk_funcs)}: {func['file']}::{func['name']} (risk: {func['risk_score']})[/dim]")
            
            # 1. Static analysis
            static_bugs = []
            if static_analyzer:
                static_bugs = static_analyzer.analyze(func['code'], func['name'])
                for bug in static_bugs:
                    findings.append({
                        "type": f"[red]STATIC {bug['severity'].upper()}[/red]",
                        "file": f"{func['file']}::{func['name']}",
                        "description": bug['description'],
                        "confidence": bug.get('confidence', 'medium'),
                        "score": bug['score'],
                        "code_snippet": bug.get('code', '')[:100],
                        "matched_patterns": []
                    })
            
            # 2. Semantic pattern matching
            search_query = self.generate_search_query(func, func['architecture'])
            similar = self.db.search_similar(
                search_query, 
                top_k=3,
                min_score=Config.MIN_SIMILARITY
            )
            
            # 3. LLM hypothesis generation for high-similarity matches
            if similar and similar[0]['similarity'] > 0.45:
                hypotheses = self.llm.generate_hypothesis(
                    func['code'],
                    similar,
                    func['name']
                )
                
                for h in hypotheses:
                    conf, score = self.calculate_confidence(
                        similar[0]['similarity'],
                        similar[0],
                        static_bugs
                    )
                    
                    # High confidence = hypothesis, medium = pattern match
                    if h.get('confidence') == 'High' or score >= 60:
                        findings.append({
                            "type": f"[bold yellow]INVARIANT VIOLATION[/bold yellow]",
                            "file": f"{func['file']}::{func['name']}",
                            "description": h.get('hypothesis', 'Unknown invariant violation'),
                            "attack_vector": h.get('attack_vector', ''),
                            "based_on": f"{similar[0]['invariant'][:80]}...",
                            "confidence": f"{conf} ({score:.0f})",
                            "score": score,
                            "similarity": similar[0]['similarity'],
                            "matched_patterns": [similar[0]['invariant']]
                        })
            
            # 4. Direct pattern matches (lower confidence)
            for match in similar[:2]:
                conf, score = self.calculate_confidence(match['similarity'], match, static_bugs)
                
                # Only report if score decent and not already reported via hypothesis
                if score >= 45:
                    # Check if we already have a better finding for this
                    existing = [f for f in findings if f['file'] == f"{func['file']}::{func['name']}" and f['score'] > score]
                    if not existing:
                        findings.append({
                            "type": f"[cyan]PATTERN MATCH[/cyan]",
                            "file": f"{func['file']}::{func['name']}",
                            "description": f"Similar to: {match['invariant'][:100]}...",
                            "break_condition": match.get('break_condition', '')[:100],
                            "confidence": f"{conf} ({score:.0f})",
                            "score": score,
                            "similarity": match['similarity'],
                            "matched_patterns": [match['invariant']],
                            "original_severity": match.get('severity', 'Unknown')
                        })
        
        # Sort by score
        findings.sort(key=lambda x: x.get('score', 0), reverse=True)
        return findings
    
    def get_stats(self):
        return self.db.get_stats()