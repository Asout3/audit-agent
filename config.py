import os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

class Config:
    SOLODIT_API_KEY = os.getenv("SOLODIT_API_KEY")
    SOLODIT_BASE_URL = "https://api.solodit.cyfrin.io/v1"
    SOLODIT_RATE_LIMIT_DELAY = 3.1
    
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    OR_MODEL = os.getenv("OR_MODEL", "upstage/solar-pro")
    OR_TEMPERATURE = 0.1
    
    DATA_DIR = Path("./audit_data")
    DB_PATH = DATA_DIR / "findings.db"
    CHECKPOINT_PATH = DATA_DIR / "checkpoint.json"  # NEW: Resume support
    
    MAX_DUPLICATES = 3
    BATCH_SIZE = 50

Config.DATA_DIR.mkdir(parents=True, exist_ok=True)