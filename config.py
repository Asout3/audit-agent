from pathlib import Path
import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SOLODIT_API_KEY = os.getenv("SOLODIT_API_KEY")
    SOLODIT_BASE_URL = "https://solodit.cyfrin.io/api/v1/solodit"
    SOLODIT_RATE_LIMIT_DELAY = 4.0

    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    OR_MODEL = os.getenv("OR_MODEL", "arcee-ai/trinity-large-preview:free")
    OR_TEMPERATURE = 0.02

    DATA_DIR = Path("audit_data")
    DB_PATH = DATA_DIR / "patterns.db"
    DATA_DIR.mkdir(exist_ok=True)

    BATCH_SIZE = 100
    MAX_DUPLICATES = 10
    SIMILARITY_THRESHOLD = 0.38

    RISK_EXTERNAL = 20
    RISK_DELEGATECALL = 45
    RISK_REENTRANCY = 40
    RISK_ASSEMBLY = 25