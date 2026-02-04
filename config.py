from pathlib import Path
import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SOLODIT_API_KEY = os.getenv("SOLODIT_API_KEY")
    SOLODIT_BASE_URL = "https://solodit.cyfrin.io/api/v1/solodit"
    SOLODIT_RATE_LIMIT_DELAY = 4.0

    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    GROQ_TEMPERATURE = 0.02
    GROQ_MAX_RETRIES = 3
    GROQ_TIMEOUT = 60

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
    RISK_TIMESTAMP = 15
    RISK_STORAGE_COLLISION = 30
    RISK_APPROVAL_DOUBLE_SPEND = 50
    RISK_WEAK_RANDOMNESS = 35