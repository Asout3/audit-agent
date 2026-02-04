# 🛡️ Deep Audit Agent

[![Solidity](https://img.shields.io/badge/Solidity-%23363636.svg?style=for-the-badge&logo=solidity&logoColor=white)](https://soliditylang.org/)
[![Groq](https://img.shields.io/badge/Groq-Fast_LLM-orange?style=for-the-badge)](https://groq.com/)
[![Slither](https://img.shields.io/badge/Slither-Analyzer-red?style=for-the-badge)](https://github.com/crytic/slither)

**Deep Audit Agent** is the ultimate AI-powered smart contract auditor. It combines traditional static analysis, call-graph vulnerability detection, and state-of-the-art LLM semantic reasoning to identify complex vulnerabilities that standard tools miss.

## 🚀 Quick Start

1. **Setup Environment**:
   ```bash
   cp .env.example .env
   # Add your GROQ_API_KEY and SOLODIT_API_KEY
   ```

2. **Build Pattern Database**:
   ```bash
   python main.py --build --count 500
   ```

3. **Audit a Contract**:
   ```bash
   python main.py --audit ./my-contract-repo --sniper
   ```

## ✨ Features

- **⚡ Groq-Powered Inference**: Lightning-fast semantic analysis using Llama 3 models on Groq.
- **🔍 Multi-Engine Analysis**:
  - **Slither**: Industrial-grade detector suite.
  - **StaticAnalyzer**: 35+ hand-crafted vulnerability patterns.
  - **CallGraph**: Cross-function reentrancy and control flow analysis.
  - **Semantic Matcher**: Vector-search against 500+ historical Solodit findings.
- **🧠 Invariant Extraction**: Automatically learns from historical bugs to find similar logic flaws in your code.
- **📊 Rich Reporting**: Beautiful, color-coded CLI output with attack vectors and remediations.
- **📤 Multiple Exports**: Export findings to JSON, Markdown, SARIF, and more.

## 🛠️ Installation

### Prerequisites
- Python 3.9+
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (recommended)
- [Solc](https://docs.soliditylang.org/en/latest/installing-solidity.html)

### Setup
```bash
git clone https://github.com/your-repo/deep-audit-agent.git
cd deep-audit-agent
pip install -r requirements.txt
```

## ⚙️ Configuration

Create a `.env` file:
```env
GROQ_API_KEY=gsk_...
SOLODIT_API_KEY=...
GROQ_MODEL=llama-3.3-70b-versatile
```

## 📖 Usage Examples

### Standard Audit
```bash
python main.py --audit ./contracts
```

### High-Confidence "Sniper" Mode
```bash
python main.py --audit ./contracts --sniper
```

### Exporting to Markdown
```bash
python main.py --audit ./contracts --export markdown -o report.md
```

### Check Database Stats
```bash
python main.py --stats
```

## 🧠 How It Works

1. **Ingestion**: Fetches the latest high-quality findings from Cyfrin's Solodit API.
2. **Learning**: Uses Groq LLM to extract "assumed invariants" and their "break conditions" from historical bugs.
3. **Embedding**: Stores these patterns in a local SQLite vector database.
4. **Target Analysis**:
   - Builds a Slither model of the target project.
   - Runs static analysis and call-graph checks.
   - Identifies high-risk functions and matches them against the pattern database.
5. **Hypothesis Generation**: LLM generates concrete exploit hypotheses for matching patterns.
6. **Unified Scoring**: Findings are cross-referenced and ranked by severity and confidence.

## 🛡️ Understanding Findings

- **🔴 Critical/High**: Immediate risk of fund loss or contract takeover.
- **🟠 Medium**: Logic errors, oracle issues, or significant griefing vectors.
- **🟡 Low**: Best practices, gas optimizations, or minor informational issues.

Each finding includes:
- **Location**: Exact file and function.
- **Description**: Clear explanation of the vulnerability.
- **Attack Vector**: Step-by-step guide on how the bug could be exploited.
- **Remediation**: Actionable advice on how to fix the issue.

## 🤝 Contributing

Contributions are welcome! Please see our contributing guidelines for more details.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
