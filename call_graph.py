from typing import Dict, List, Set, Tuple
from collections import defaultdict

try:
    from slither import Slither
    SLITHER_AVAILABLE = True
except ImportError:
    SLITHER_AVAILABLE = False

class CallGraphAnalyzer:
    """Analyze cross-function control flow to find multi-function bugs"""
    
    def __init__(self, contract_path: str):
        self.path = contract_path
        self.call_graph = defaultdict(list)  # func_name -> [called_functions]
        self.external_calls = {}  # func_name -> [external_call_nodes]
        self.state_reads = {}     # func_name -> [state_vars_read]
        self.state_writes = {}    # func_name -> [state_vars_written]
        
    def build_graph(self):
        """Build call graph using Slither"""
        if not SLITHER_AVAILABLE:
            return False
            
        try:
            slither = Slither(self.path)
            
            for contract in slither.contracts:
                for function in contract.functions:
                    func_name = function.name
                    
                    # Internal calls
                    self.call_graph[func_name] = [
                        str(internal) for internal in function.internal_calls
                    ]
                    
                    # External calls (to other contracts)
                    self.external_calls[func_name] = [
                        str(call) for call in function.external_calls
                    ]
                    
                    # State variables
                    self.state_reads[func_name] = [
                        str(s) for s in function.state_variables_read
                    ]
                    self.state_writes[func_name] = [
                        str(s) for s in function.state_variables_written
                    ]
            return True
        except:
            return False
    
    def find_cross_function_reentrancy(self) -> List[Dict]:
        """
        Find patterns like:
        Function A: reads balance (check)
        Function A: calls Function B
        Function B: external call + state change (effect)
        """
        findings = []
        
        for func_a in self.call_graph:
            # Check if func_a calls other functions
            for called_func in self.call_graph[func_a]:
                if called_func not in self.external_calls:
                    continue
                    
                # Check: func_a reads state, called_func does external call + writes state
                a_reads = set(self.state_reads.get(func_a, []))
                b_writes = set(self.state_writes.get(called_func, []))
                b_externals = self.external_calls.get(called_func, [])
                
                # Overlap in state variables = check in A, effect in B
                shared_state = a_reads.intersection(b_writes)
                
                if shared_state and b_externals:
                    findings.append({
                        "type": "cross_function_reentrancy",
                        "severity": "critical",
                        "entry_point": func_a,
                        "external_call_function": called_func,
                        "shared_state": list(shared_state),
                        "description": f"{func_a} reads state that {called_func} modifies after external call",
                        "attack_path": f"{func_a} → {called_func} → external_call → state_change"
                    })
        
        return findings
    
    def find_delegatecall_injection(self) -> List[Dict]:
        """Find delegatecall through proxy functions"""
        findings = []
        
        for func, calls in self.call_graph.items():
            if 'delegatecall' in str(calls).lower():
                # Check if delegatecall target is controllable
                if 'msg.data' in str(self.external_calls.get(func, [])):
                    findings.append({
                        "type": "delegatecall_injection",
                        "severity": "critical",
                        "function": func,
                        "description": "Delegatecall to controllable address via msg.data"
                    })
        
        return findings
    
    def find_flash_loan_entry_points(self) -> List[Dict]:
        """Find functions that do external calls then callbacks"""
        findings = []
        
        for func in self.external_calls:
            # Function does external call
            if not self.external_calls[func]:
                continue
                
            # And it's called by other functions (callback risk)
            callers = [f for f, calls in self.call_graph.items() if func in calls]
            
            if callers:
                findings.append({
                    "type": "flash_loan_callback_vector",
                    "severity": "high",
                    "function": func,
                    "called_by": callers,
                    "description": "External call function reachable from multiple paths (flash loan risk)"
                })
        
        return findings