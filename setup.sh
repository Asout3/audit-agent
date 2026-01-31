#!/bin/bash
echo "[+] Installing Deep Audit Agent dependencies..."

# Python deps
pip install requests python-dotenv sentence-transformers torch numpy tqdm rich

# Optional but recommended: Slither for AST analysis
pip install slither-analyzer 2>/dev/null || echo "[!] Slither optional, install manually if desired"

echo "[✓] Setup complete"
echo ""
echo "Next steps:"
echo "1. Create .env file with your API keys"
echo "2. python main.py --build --focus Lending --count 200 --batch"
echo "3. python main.py --audit ./your-contracts"