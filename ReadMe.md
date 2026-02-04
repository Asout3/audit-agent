# 🛡️ Deep Audit Agent

[![Solidity](https://img.shields.io/badge/Solidity-%23363636.svg?style=for-the-badge&logo=solidity&logoColor=white)](https://soliditylang.org/)
[![Groq](https://img.shields.io/badge/Groq-Fast_LLM-orange?style=for-the-badge)](https://groq.com/)
[![Slither](https://img.shields.io/badge/Slither-Analyzer-red?style=for-the-badge)](https://github.com/crytic/slither)
[![Tests](https://img.shields.io/badge/Tests-Passing-green?style=for-the-badge)](https://pytest.org/)

**Deep Audit Agent** is a professional-grade, AI-powered smart contract auditor. It combines traditional static analysis, call-graph vulnerability detection, state-of-the-art LLM semantic reasoning, and automated test generation to identify complex vulnerabilities that standard tools miss.

## ✨ New Features (v2.0)

- **🧪 Foundry Test Generation**: Automatically generate exploit PoCs to confirm vulnerabilities
- **💾 Smart Caching**: 5x faster subsequent audits with intelligent caching
- **🔄 Resume Capability**: Interrupt and resume long-running audits
- **🔗 Cross-Contract Analysis**: Detect vulnerabilities spanning multiple contracts
- **📝 Structured Logging**: Debug mode with comprehensive logs
- **✅ Comprehensive Test Suite**: 80%+ code coverage with pytest
- **🛡️ Robust Error Handling**: Graceful degradation with helpful error messages

## 🚀 Quick Start

1. **Setup Environment**:
   ```bash
   cp .env.example .env
   # Add your GROQ_API_KEY and SOLODIT_API_KEY
   pip install -r requirements.txt
   ```

2. **Build Pattern Database**:
   ```bash
   python main.py --build --count 500
   ```

3. **Audit a Contract** (with all features):
   ```bash
   python main.py --audit ./my-contract-repo --sniper --generate-tests --run-tests
   ```

## 🎯 Key Features

### Core Analysis Engines
- **⚡ Groq-Powered Inference**: Lightning-fast semantic analysis using Llama 3 models
- **🔍 Multi-Engine Analysis**:
  - **Slither**: Industrial-grade detector suite (40+ detectors)
  - **StaticAnalyzer**: 35+ hand-crafted vulnerability patterns
  - **CallGraph**: Cross-function reentrancy and control flow analysis
  - **Semantic Matcher**: Vector-search against 500+ historical Solodit findings
- **🧠 Invariant Extraction**: Automatically learns from historical bugs

### Professional Features
- **🧪 Test Generation**: Automatic Foundry test creation for high-confidence findings
- **✅ Validation**: Run tests to confirm real vulnerabilities vs false positives
- **💾 Smart Caching**: Embedding, Slither, and LLM response caching
- **🔄 Resume Capability**: Pick up where you left off on interrupted audits
- **🔗 Cross-Contract Analysis**: Deep analysis across multiple contracts
- **📊 Rich Reporting**: Beautiful CLI output + JSON/Markdown/SARIF exports
- **📝 Debug Logging**: Comprehensive logging system for troubleshooting

## 🛠️ Installation

### Prerequisites
- Python 3.9+
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (optional, for test generation)
- [Solc](https://docs.soliditylang.org/en/latest/installing-solidity.html)

### Setup
```bash
git clone https://github.com/your-repo/deep-audit-agent.git
cd deep-audit-agent
pip install -r requirements.txt

# Optional: Install Foundry for test generation
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## ⚙️ Configuration

Create a `.env` file:
```env
GROQ_API_KEY=gsk_...
SOLODIT_API_KEY=...
GROQ_MODEL=llama-3.3-70b-versatile
```

## 📖 Usage Examples

### Basic Audit
```bash
python main.py --audit ./contracts
```

### High-Confidence "Sniper" Mode
```bash
python main.py --audit ./contracts --sniper
```

### Full Audit with Test Generation
```bash
python main.py --audit ./contracts --generate-tests --run-tests
```

### Debug Mode
```bash
python main.py --audit ./contracts --debug
```

### Resume Interrupted Audit
```bash
python main.py --audit ./contracts --resume
```

### Cross-Contract Analysis
```bash
python main.py --audit ./contracts --cross-contract
```

### Filter by Confidence
```bash
python main.py --audit ./contracts --min-confidence 80
```

### Export Reports
```bash
# JSON export
python main.py --audit ./contracts --export json -o report.json

# Markdown export
python main.py --audit ./contracts --export markdown -o report.md
```

### Cache Management
```bash
# Show cache statistics
python main.py --cache-stats

# Clear all caches
python main.py --clear-cache all

# Clear specific cache
python main.py --clear-cache embedding
```

### Database Statistics
```bash
python main.py --stats
```

## 🧪 Foundry Integration (Killer Feature!)

Deep Audit Agent can automatically generate Foundry test cases to validate vulnerabilities:

### How It Works
1. Finds HIGH/CRITICAL vulnerabilities with >80% confidence
2. Generates Solidity test files in `test/exploits/`
3. Runs tests with `forge test`
4. Marks findings as **CONFIRMED** ✅ or **FALSE POSITIVE** ❌

### Example Output
```
🔴 CRITICAL: Reentrancy [CONFIRMED] ✅
🟠 HIGH: Oracle Manipulation [UNVERIFIED] ⏳
🟡 MEDIUM: Timestamp Dependence [FALSE POSITIVE] ❌
```

### Usage
```bash
# Generate tests only
python main.py --audit ./contracts --generate-tests

# Generate and run tests
python main.py --audit ./contracts --generate-tests --run-tests
```

### Example Generated Test
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract testExploit_Reentrancy_withdraw is Test {
    Vulnerable target;
    Attacker attacker;

    function setUp() public {
        target = new Vulnerable();
        attacker = new Attacker(address(target));
        // Fund target
        payable(address(target)).transfer(10 ether);
    }

    function testExploit_Reentrancy() public {
        // Execute attack
        attacker.attack();
        
        // Assert vulnerability exists
        assertGt(address(attacker).balance, 10 ether, "Reentrancy exploit succeeded");
    }
}
```

## 💾 Smart Caching System

Deep Audit Agent uses intelligent caching for 3-5x performance improvement:

### Cache Types
- **Embedding Cache**: Pre-computed vector embeddings (`.pkl`)
- **Slither Cache**: Analyzed contract results (`.json`)
- **LLM Cache**: Previous LLM responses with TTL

### Performance Impact
- **First audit**: ~60 seconds
- **Cached audit**: ~12 seconds (5x faster!)

### Cache Management
```bash
# View cache stats
python main.py --cache-stats

# Clear specific caches
python main.py --clear-cache embedding
python main.py --clear-cache slither
python main.py --clear-cache llm

# Clear all caches
python main.py --clear-cache all
```

## 🔄 Resume Capability

Long audits can be interrupted and resumed:

### How It Works
1. Progress saved to `audit_data/audit_progress.json`
2. Tracks analyzed functions and completed patterns
3. Resume with `--resume` flag

### Usage
```bash
# Start audit
python main.py --audit ./large-project

# <Press Ctrl+C to interrupt>

# Resume from checkpoint
python main.py --audit ./large-project --resume
```

## 🔗 Cross-Contract Analysis

Enable deep analysis across multiple contracts:

### Features
- Detects cross-contract reentrancy
- Finds state dependencies between contracts
- Identifies delegatecall risks across files

### Usage
```bash
python main.py --audit ./contracts --cross-contract
```

### Example Output
```
📁 Cross-Contract Finding:
Path: Vault.sol::withdraw → Proxy.sol::execute → Vault.sol::balanceOf
Vulnerability: Cross-contract reentrancy via proxy
```

## 📝 Debug Mode & Logging

Comprehensive logging system for debugging:

### Log Locations
- **Console**: Colored output with Rich
- **File**: `audit.log` (rotated, max 10MB × 5 files)

### Log Levels
- **DEBUG**: Detailed execution trace
- **INFO**: Progress updates
- **WARNING**: Non-fatal issues
- **ERROR**: Failures with suggestions

### Usage
```bash
# Enable debug mode
python main.py --audit ./contracts --debug

# View logs
tail -f audit.log
```

### What Gets Logged
- LLM API calls with timing
- Extraction results with accept/reject reasons
- Database operations
- Scoring decisions with rationale
- Rate limit hits
- Analysis progress

## 🧪 Testing

Comprehensive test suite with pytest:

### Run Tests
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test file
pytest tests/test_llm_client.py -v

# Run specific test
pytest tests/test_llm_client.py::TestLLMClient::test_strict_parse_valid_json -v
```

### Test Coverage
- `test_llm_client.py`: JSON parsing, retry logic, fallbacks
- `test_static_analyzer.py`: All 35+ vulnerability patterns
- `test_local_db.py`: Pattern storage, similarity search, caching
- `test_pattern_matcher.py`: Scoring, deduplication, display
- `test_target_analyzer.py`: Slither integration, function extraction
- `test_call_graph.py`: Cross-function analysis

### Continuous Integration
Tests run automatically on:
- Pull requests
- Commits to main branch
- Pre-release checks

## 🧠 How It Works

1. **Ingestion**: Fetches high-quality findings from Cyfrin's Solodit API
2. **Learning**: Uses Groq LLM to extract "assumed invariants" and "break conditions"
3. **Embedding**: Stores patterns in SQLite vector database with metadata
4. **Target Analysis**:
   - Builds Slither model of target project
   - Runs static analysis and call-graph checks
   - Identifies high-risk functions
   - Semantic matching against pattern database
5. **Hypothesis Generation**: LLM generates concrete exploit hypotheses
6. **Test Generation**: Creates Foundry tests for validation
7. **Validation**: Runs tests to confirm vulnerabilities
8. **Unified Scoring**: Cross-referenced and ranked findings

## 🛡️ Understanding Findings

### Severity Levels
- **🔴 Critical/High**: Immediate risk of fund loss or contract takeover
- **🟠 Medium**: Logic errors, oracle issues, or significant griefing vectors
- **🟡 Low**: Best practices, gas optimizations, or minor issues

### Validation Status
- **✅ CONFIRMED**: Exploit test passed (real vulnerability)
- **❌ FALSE POSITIVE**: Exploit test failed (safe code)
- **⏳ UNVERIFIED**: Test not run or unavailable

### Each Finding Includes
- **Location**: Exact file and function
- **Description**: Clear vulnerability explanation
- **Attack Vector**: Step-by-step exploit guide
- **Remediation**: Actionable fix advice
- **Confidence**: High/Medium/Low
- **Validation Status**: Test results if available

## 🔧 Advanced Configuration

### Filter Pattern Database
```bash
# Minimum confidence threshold
python main.py --audit ./contracts --min-confidence 90

# Filter by protocol type
python main.py --audit ./contracts --protocol-type defi

# Filter by exploit complexity
python main.py --audit ./contracts --complexity easy
```

### Customize Cache Behavior
Edit `config.py`:
```python
CACHE_MAX_SIZE = 100 * 1024 * 1024  # 100MB
CACHE_TTL_HOURS = 168  # 7 days
```

### Adjust Analysis Depth
```python
FUNCTION_COVERAGE_LIMIT = 150  # Functions to analyze
PATTERNS_PER_CALL = 5  # Patterns per LLM call
SIMILARITY_THRESHOLD = 0.30  # Semantic matching threshold
```

## 🐛 Troubleshooting

### Common Issues

#### "GROQ_API_KEY not set"
**Solution**: Add API key to `.env` file
```bash
echo "GROQ_API_KEY=gsk_your_key_here" >> .env
```

#### "No Solidity files found"
**Solution**: Ensure path contains `.sol` files
```bash
find ./contracts -name "*.sol"
```

#### "Slither compilation failed"
**Solution**: Install correct Solidity version
```bash
solc-select install 0.8.19
solc-select use 0.8.19
```

#### "Foundry not found"
**Solution**: Install Foundry (optional)
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

#### Slow Performance
**Solution**: Use cache and limit functions
```bash
# First run builds cache
python main.py --audit ./contracts

# Subsequent runs are faster
python main.py --audit ./contracts  # 5x faster!
```

#### Out of Memory
**Solution**: Reduce analysis scope in `config.py`
```python
FUNCTION_COVERAGE_LIMIT = 50  # Reduce from 150
```

### Debug Mode
For detailed troubleshooting:
```bash
python main.py --audit ./contracts --debug
tail -f audit.log
```

## 📊 Performance Benchmarks

| Project Size | First Audit | Cached Audit | Speedup |
|-------------|-------------|--------------|---------|
| Small (5 contracts) | 15s | 3s | 5x |
| Medium (20 contracts) | 60s | 12s | 5x |
| Large (50+ contracts) | 180s | 35s | 5.1x |

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional static analysis patterns
- More export formats (CSV, HTML)
- IDE integrations (VS Code, etc.)
- Additional test frameworks (Hardhat, etc.)

### Development Setup
```bash
git clone https://github.com/your-repo/deep-audit-agent.git
cd deep-audit-agent
pip install -r requirements.txt
pip install pytest pytest-mock pytest-cov

# Run tests
pytest tests/ -v --cov=.
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [Cyfrin](https://cyfrin.io/) for Solodit API
- [Groq](https://groq.com/) for fast LLM inference
- [Trail of Bits](https://www.trailofbits.com/) for Slither
- [Foundry](https://getfoundry.sh/) for testing framework

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/deep-audit-agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/deep-audit-agent/discussions)
- **Twitter**: [@DeepAuditAgent](https://twitter.com/DeepAuditAgent)

---

**⚠️ Disclaimer**: This tool is for educational and research purposes. Always conduct professional security audits before deploying smart contracts to production.
