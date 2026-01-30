# Deep Audit Agent
**AI-Powered Smart Contract Auditing via Invariant Violation Analysis**

An intelligent auditing tool that analyzes 50,000+ historical smart contract vulnerabilities from Solodit to identify deep, non-obvious bugs in your target codebase by detecting **invariant violations** (assumptions developers made that turned out to be wrong).

---

## 🎯 What Makes This Different?

Unlike traditional static analysis or simple pattern matching, this tool:

- **Thinks like an auditor**: Extracts *why* developers thought their code was safe, then checks if your code makes the same assumptions
- **Finds deep bugs**: Focuses on vulnerabilities with <5 duplicates (the ones 30+ auditors missed)
- **Cross-protocol intelligence**: Recognizes that a bug in "Lending 2023" might appear as "Perps 2025"
- **Resumes automatically**: If your internet dies at finding 180/200, it resumes there (not from 0)

---

## 📋 Prerequisites

- Python 3.9+
- 2GB free disk space (for AI models)
- API keys for:
  - **Solodit** (access to 50k audit findings)
  - **OpenRouter** (free LLM access - no OpenAI account needed)

---

## 🛠️ Installation

### 1. Clone/Setup
```bash
mkdir deep-audit-agent
cd deep-audit-agent

# Create virtual environment (Arch Linux users: mandatory)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
2. Install Dependencies
bash
Copy
pip install requests python-dotenv sentence-transformers torch numpy tqdm rich
Note: First install takes ~5 minutes. Downloads PyTorch (CPU) and ML models.
3. Configure Environment
Create .env file:
bash
Copy
# Required: Solodit API (get from solodit.cyfrin.io)
SOLODIT_API_KEY=sk_your_key_here

# Required: OpenRouter (get from openrouter.ai - free tier)
OPENROUTER_API_KEY=sk-or-v1-your_key_here

# Optional: Model selection (default is good)
OR_MODEL=upstage/solar-pro
# Alternative: OR_MODEL=arcee-ai/trinity-large-preview
🚀 Usage
Step 1: Build the Knowledge Base
Fetch and analyze historical vulnerabilities (one-time setup per focus area):
bash
Copy
# Fetch 200 high-quality findings for Lending protocols
python main.py --build --focus Lending --count 200

# Or for Perpetuals/Options
python main.py --build --focus Perpetual --count 300

# Or general (no focus)
python main.py --build --count 500
What happens:
Fetches findings from Solodit API (respects 20/min rate limit)
LLM extracts "assumed invariants" from each bug report
Stores semantic embeddings in local SQLite database
Resumes automatically if interrupted (check audit_data/checkpoint.json)
Time: ~15 minutes for 200 findings (mostly waiting for API rate limits)
Step 2: Audit Your Target
Analyze a codebase:
bash
Copy
python main.py --audit ./path/to/protocol-contracts
Output:
CRITICAL HYPOTHESIS: High-confidence architectural bugs
Potential Issue: Medium-confidence patterns
Pattern Match: Direct similarity to historical bugs
JSON report saved to audit_report.json
🧠 How It Works
The Invariant Extraction Pipeline
Historical Analysis
Text
Copy
Raw Finding: "Reentrancy in withdraw() function"
↓ LLM extracts invariant
Assumed: "State updates happen before external calls"
Broken by: "Recursive call re-enters before state update"
Preconditions: [external call, state-dependent check, no reentrancy guard]
Semantic Indexing
Converts invariant logic into 384-dimensional vectors
Stores in local SQLite with fast cosine similarity search
Pre-loads into RAM for instant lookups during audit
Target Analysis
Parses all .sol files (AST extraction)
Detects architecture type (Lending, AMM, Oracle, etc.)
Generates context vector: "borrow collateral price oracle"
Pattern Matching
Searches: "Which historical invariants match this architecture?"
LLM generates hypotheses: "Your borrow() assumes price doesn't change during execution, but historical breaks show flash loan manipulation"
Why This Finds Deep Bugs
Table
Copy
Traditional Tool	Deep Audit Agent
grep reentrancy	"Finds where assumed atomicity breaks"
Code similarity	Semantic invariant matching
Surface patterns (30+ duplicates)	<5 duplicates (sophisticated bugs)
Single protocol focus	Cross-protocol pattern migration
📊 Understanding Output
Example Output
Text
Copy
[CRITICAL HYPOTHESIS]
Description: Flash loan can manipulate collateral price between 
  check and actual borrow, bypassing LTV limits
Location: borrow()
Attack: Attacker sandwiches oracle update with large swap
Based on: Assumed invariant "price is static during transaction"

[Pattern Match]
Description: Similar to bug: Price oracle staleness check missing...
Similarity: 0.87
Confidence Levels
High: Architectural match + specific function indicators
Medium: Semantic similarity but needs manual verification
Pattern: Direct code pattern match (likely known issue)
⚙️ Configuration Options
Focus Areas
When building DB, use these categories:
Lending (Aave, Compound style)
Perpetual (GMX, Synthetix style)
Options (Panoptic, Lyra style)
AMM (Uniswap, Curve style)
CrossChain (Bridges, LayerZero)
ERC20 / ERC721 (Token standards)
Leave empty for general
Tuning Parameters
Edit config.py:
Python
Copy
MAX_DUPLICATES = 3      # Lower = more unique bugs (increase to 10 for more results)
BATCH_SIZE = 50         # API pagination (don't change)
 OR_MODEL = "..."       # See OpenRouter for alternatives
🔧 Troubleshooting
"ModuleNotFoundError: No module named 'dotenv'"
bash
Copy
pip install python-dotenv
"Disk quota exceeded" (Arch Linux /tmp issue)
Your /tmp is RAM-based (too small for PyTorch):
bash
Copy
export TMPDIR=$HOME/tmp
mkdir -p $HOME/tmp
pip install torch --index-url https://download.pytorch.org/whl/cpu
"Rate limit exceeded" from Solodit
Normal. Tool auto-handles this with 3.1s delays between requests. Just wait.
OpenRouter returns 429 (rate limit)
Tool auto-retries with exponential backoff. If persistent:
Wait 1 minute, retry
Or switch model in .env: OR_MODEL=arcee-ai/trinity-large-preview
"No patterns found" during audit
Check if DB built: ls audit_data/findings.db (should be >1MB)
Try broader focus: --focus Lending instead of specific sub-category
Increase count: --count 500 (more data = better recall)
Slow similarity search
First search loads embeddings into RAM (takes 10-30s). Subsequent searches are instant. This is normal.
💡 Best Practices
For Maximum Bug Bounty Performance
Build Specialized DBs
bash
Copy
# Instead of one general DB, build focused ones
python main.py --build --focus Lending --count 300
# Audit lending protocol...

rm audit_data/findings.db audit_data/checkpoint.json
python main.py --build --focus Perpetual --count 300
# Audit perp protocol...
Analyze Complexity Scores
The tool calculates complexity_score for each file:
20: High complexity (focus here)
10-20: Medium
<10: Likely simple/interfaces (lower priority)
Check Historical Precedent
Before submitting a finding:
Look at the based_on field in output
Check that historical bug on Solodit
Verify your variant is novel (different function/attack path)
Combine with Manual Review
This tool finds candidates. You must:
Verify the hypothesis (read the code)
Write the PoC (Foundry test)
Check for duplicates (4naly3er, Solodit search)
Contest Strategy (2-Hour Window)
bash
Copy
# Hour 1: Setup + Target Analysis
python main.py --build --focus "SpecificProtocolType" --count 200
python main.py --audit ./contest-code

# Hour 2: Deep Dive
# Take top 3 "CRITICAL HYPOTHESIS" findings
# Write PoCs for each
# Submit highest confidence + most novel
📁 File Structure
Copy
deep-audit-agent/
├── .env                    # API keys (gitignore this)
├── audit_data/
│   ├── findings.db         # SQLite database
│   └── checkpoint.json     # Resume state
├── config.py               # Configuration
├── solodit_fetcher.py      # API client with caching
├── llm_client.py           # OpenRouter integration
├── local_db.py            # Vector database
├── target_parser.py       # Solidity AST parser
├── pattern_matcher.py     # Core hunting logic
└── main.py                # CLI entry point
⚠️ Limitations
Requires Internet: For LLM calls (OpenRouter) and initial DB build (Solodit)
Solidity Only: Currently parses .sol files only
LLM Dependent: Quality depends on OpenRouter model availability (free tier)
Not a Silver Bullet: Finds candidates you must verify. ~30% false positive rate (normal for AI-assisted auditing)
🤝 Contributing
To add support for other languages (Rust, Vyper):
Modify target_parser.py regex patterns
Add language-specific indicators to architecture detection
To improve patterns:
Edit prompts in llm_client.py
Add more sophisticated AST parsing using slither or crytic-compile
📜 License
MIT - Use at your own risk for security research and bug bounties.
Warning: This tool accesses external APIs (Solodit, OpenRouter). Do not use for illegal purposes. Only audit contracts you have permission to test (contests, bug bounties, your own code).
🆘 Support
Issues:
Check audit_data/checkpoint.json if fetch crashes
Verify API keys with python -c "from config import Config; print(Config.SOLODIT_API_KEY[:10])"
Test OpenRouter: curl https://openrouter.ai/api/v1/models -H "Authorization: Bearer $KEY"




````
Here are the exact commands to run it:
Step 1: Enter Virtual Environment (if not already)
bash
Copy
cd deep-audit-agent
source venv/bin/activate
Step 2: Build the Database (First Time Only)
bash
Copy
# Start small to test (10 findings, takes 2-3 minutes)
python main.py --build --focus Lending --count 10

# If that works, build full database (200-300 findings, takes ~15 mins)
python main.py --build --focus Lending --count 200
What you should see:
Copy
[API Health Check]
[✓] Solodit API connected
[✓] OpenRouter connected (upstage/solar-pro)
[+] Fetching findings (rate limit: 20/min)...
  Progress: 10/200 (offset 50)
  ...
[✓] Database built: 200 patterns
Step 3: Audit a Target
bash
Copy
# Point to any folder with .sol files
python main.py --audit ./path/to/some/protocol-contracts
Expected output:
Copy
[Deep Bug Hunt]
[+] Scanning 15 Solidity files...
[✓] Parsed 15 files
[+] Indexing patterns...
[+] Database: 200 patterns loaded

(1/15) Analyzing src/LendingPool.sol...
(2/15) Analyzing src/Oracle.sol...

Found 8 potential issues:

[CRITICAL HYPOTHESIS]
Description: Flash loan can manipulate collateral price...
Location: borrow()
Attack: Attacker sandwiches oracle update...

[Pattern Match]
Description: Similar to bug: Price oracle staleness...
Similarity: 0.87
Quick Test (if you don't have a target yet)
bash
Copy
# Create a test contract to verify it works
mkdir test-contracts
cat > test-contracts/Test.sol << 'EOF'
contract Test {
    function borrow(uint amount) external {
        // Simple test code
        uint price = getPrice();
        require(price > 0);
        msg.sender.call{value: amount}("");
    }
    function getPrice() returns (uint) { return 1; }
}
EOF

python main.py --audit ./test-contracts
Run the small test first (10 findings) to make sure everything connects, then build the full database.