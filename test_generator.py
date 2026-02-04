"""Foundry test case generation for vulnerability validation"""
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from logger import get_logger
from llm_client import LLMClient
from exceptions import AuditError

logger = get_logger()


class TestGenerator:
    """Generate and execute Foundry test cases for vulnerability validation"""
    
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()
        self.foundry_available = self._check_foundry()
    
    def _check_foundry(self) -> bool:
        """Check if Foundry is installed"""
        try:
            result = subprocess.run(
                ["forge", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"Foundry detected: {result.stdout.strip()}")
                return True
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning("Foundry not found - test generation will be skipped")
        return False
    
    def is_available(self) -> bool:
        """Check if test generation is available"""
        return self.foundry_available
    
    def should_generate_test(self, finding: Dict) -> bool:
        """Determine if a finding warrants test generation"""
        # Only generate for HIGH/CRITICAL with confidence > 80%
        severity = finding.get("severity", "").upper()
        confidence = finding.get("confidence", "").upper()
        score = finding.get("score", 0)
        
        high_severity = severity in ["HIGH", "CRITICAL"]
        high_confidence = confidence == "HIGH" or score >= 80
        
        return high_severity and high_confidence
    
    def generate_test(self, finding: Dict, target_code: str, contract_name: str) -> Optional[str]:
        """Generate a Foundry test case for a finding"""
        if not self.llm.client:
            logger.error("LLM client not available for test generation")
            return None
        
        vuln_type = finding.get("type", "Unknown")
        description = finding.get("description", "")
        attack_vector = finding.get("attack_vector", "")
        func_name = finding.get("function", "unknown")
        
        prompt = f"""Generate a Foundry (Forge) test case to validate this vulnerability.

Contract: {contract_name}
Function: {func_name}
Vulnerability Type: {vuln_type}
Description: {description}
Attack Vector: {attack_vector}

Target Code:
{target_code[:2000]}

Requirements:
1. Create a complete Foundry test file
2. Import necessary contracts and interfaces
3. Set up realistic test environment
4. Implement the exploit step-by-step
5. Use assertions to prove the vulnerability exists
6. Follow Foundry best practices
7. Add comments explaining each step

Return ONLY valid Solidity code for the test file, starting with:
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
"""

        try:
            logger.debug(f"Generating test for {vuln_type} in {func_name}")
            
            response = self.llm._call_with_retry(
                [{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=2000
            )
            
            test_code = response.choices[0].message.content.strip()
            
            # Clean up markdown if present
            if "```solidity" in test_code:
                test_code = test_code.split("```solidity")[1].split("```")[0].strip()
            elif "```" in test_code:
                test_code = test_code.split("```")[1].split("```")[0].strip()
            
            # Validate it's Solidity code
            if not test_code.startswith("// SPDX-License-Identifier"):
                logger.warning("Generated test doesn't have valid Solidity header")
                return None
            
            logger.info(f"Generated test for {vuln_type}")
            return test_code
            
        except Exception as e:
            logger.error(f"Failed to generate test: {e}")
            return None
    
    def save_test(self, test_code: str, finding: Dict, test_dir: Path) -> Optional[Path]:
        """Save generated test to file"""
        try:
            test_dir.mkdir(parents=True, exist_ok=True)
            
            # Create safe filename
            vuln_type = finding.get("type", "Unknown").replace(" ", "_")
            func_name = finding.get("function", "unknown").replace(".", "_")
            test_name = f"testExploit_{vuln_type}_{func_name}"
            test_file = test_dir / f"{test_name}.t.sol"
            
            # Avoid overwriting
            counter = 1
            while test_file.exists():
                test_file = test_dir / f"{test_name}_{counter}.t.sol"
                counter += 1
            
            test_file.write_text(test_code)
            logger.info(f"Saved test: {test_file}")
            return test_file
            
        except Exception as e:
            logger.error(f"Failed to save test: {e}")
            return None
    
    def generate_tests_for_findings(self, findings: List[Dict], target_path: Path) -> Dict[str, Path]:
        """Generate tests for all qualifying findings"""
        if not self.foundry_available:
            logger.warning("Foundry not available - skipping test generation")
            return {}
        
        test_dir = target_path / "test" / "exploits"
        generated_tests = {}
        
        for finding in findings:
            if not self.should_generate_test(finding):
                continue
            
            # Get contract name and code
            contract_name = finding.get("contract", "Target")
            file_path = finding.get("file", "")
            func_name = finding.get("function", "")
            
            # Read target code if available
            target_code = ""
            if file_path:
                try:
                    full_path = target_path / file_path
                    if full_path.exists():
                        target_code = full_path.read_text()
                except Exception as e:
                    logger.error(f"Failed to read target code: {e}")
            
            # Generate test
            test_code = self.generate_test(finding, target_code, contract_name)
            if not test_code:
                continue
            
            # Save test
            test_file = self.save_test(test_code, finding, test_dir)
            if test_file:
                finding_id = f"{finding.get('type')}_{func_name}"
                generated_tests[finding_id] = test_file
        
        logger.info(f"Generated {len(generated_tests)} test cases")
        return generated_tests
    
    def run_tests(self, target_path: Path) -> Dict[str, str]:
        """Run Foundry tests and return results"""
        if not self.foundry_available:
            logger.warning("Foundry not available - skipping test execution")
            return {}
        
        test_results = {}
        test_dir = target_path / "test" / "exploits"
        
        if not test_dir.exists():
            logger.warning("No test directory found")
            return {}
        
        try:
            logger.info("Running Foundry tests...")
            
            # Run forge test with JSON output
            result = subprocess.run(
                ["forge", "test", "--json", "--match-path", str(test_dir / "*.t.sol")],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes max
            )
            
            # Parse results
            if result.returncode == 0:
                logger.info("All tests passed - vulnerabilities confirmed!")
                test_results["status"] = "confirmed"
            else:
                logger.info("Some tests failed - possible false positives")
                test_results["status"] = "mixed"
            
            # Try to parse JSON output
            try:
                output_lines = result.stdout.strip().split('\n')
                for line in output_lines:
                    if line.startswith('{'):
                        test_data = json.loads(line)
                        # Extract test results
                        if "test_results" in test_data:
                            for test_name, test_info in test_data["test_results"].items():
                                status = "confirmed" if test_info.get("success") else "false_positive"
                                test_results[test_name] = status
            except json.JSONDecodeError:
                # Fallback to simple parsing
                logger.debug("Could not parse JSON output, using simple parsing")
                pass
            
            # Store raw output for debugging
            test_results["stdout"] = result.stdout
            test_results["stderr"] = result.stderr
            
        except subprocess.TimeoutExpired:
            logger.error("Test execution timed out")
            test_results["status"] = "timeout"
        except Exception as e:
            logger.error(f"Failed to run tests: {e}")
            test_results["status"] = "error"
        
        return test_results
    
    def update_findings_with_results(self, findings: List[Dict], test_results: Dict[str, str]) -> List[Dict]:
        """Update findings with validation status from test results"""
        for finding in findings:
            func_name = finding.get("function", "")
            vuln_type = finding.get("type", "")
            finding_key = f"{vuln_type}_{func_name}"
            
            # Check if we have test results for this finding
            validation_status = "unverified"
            
            for test_name, status in test_results.items():
                if finding_key in test_name or vuln_type in test_name:
                    validation_status = status
                    break
            
            finding["validation_status"] = validation_status
            
            # Add visual indicator
            if validation_status == "confirmed":
                finding["validation_indicator"] = "✅ CONFIRMED"
            elif validation_status == "false_positive":
                finding["validation_indicator"] = "❌ FALSE POSITIVE"
            else:
                finding["validation_indicator"] = "⏳ UNVERIFIED"
        
        return findings


def get_validation_emoji(status: str) -> str:
    """Get emoji for validation status"""
    return {
        "confirmed": "✅",
        "false_positive": "❌",
        "unverified": "⏳",
        "timeout": "⏱️",
        "error": "⚠️"
    }.get(status, "❓")
