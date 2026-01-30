    def analyze_target(self, target_functions: list, static_analyzer=None):
        findings = []
        
        print("[+] Indexing patterns...")
        self.db.load_all_vectors()
        
        # Only analyze top 20 highest-risk functions (optimization)
        high_risk_funcs = [f for f in target_functions if f["risk_score"] > 20][:20]
        
        print(f"[+] Deep analysis on {len(high_risk_funcs)} high-risk functions...")
        
        for func in high_risk_funcs:
            console.print(f"\n  [dim]{func['file']}::{func['function']} (risk: {func['risk_score']})[/dim]")
            
            # 1. Static analysis on this specific function
            if static_analyzer:
                static_bugs = static_analyzer.analyze(func["code"], func["function"])
                for bug in static_bugs:
                    findings.append({
                        "type": "STATIC",
                        "file": f"{func['file']}::{func['function']}",
                        "description": bug["description"],
                        "confidence": "High",
                        "score": bug["score"]
                    })
            
            # 2. Semantic search using function code (not whole file)
            context = f"{func['function']} {' '.join(func['external_calls'])} {func['architecture']}"
            similar = self.db.search_similar(context, top_k=3)
            
            # 3. LLM deep analysis - now with complete function code, no truncation
            if similar and similar[0]["similarity"] > 0.6:
                hypotheses = self.llm.generate_hypothesis(
                    func["code"],  # Full function code, no truncation!
                    similar,
                    func["function"]
                )
                
                for h in hypotheses:
                    if h.get("confidence") == "High":
                        findings.append({
                            "type": "DEEP HYPOTHESIS",
                            "file": f"{func['file']}::{func['function']}",
                            "description": h["hypothesis"],
                            "confidence": "High",
                            "score": 85
                        })
        
        return sorted(findings, key=lambda x: x["score"], reverse=True)