import os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

class Config:
    SOLODIT_API_KEY = os.getenv("SOLODIT_API_KEY")
    SOLODIT_BASE_URL = "https://solodit.cyfrin.io/api/v1"
    SOLODIT_RATE_LIMIT_DELAY = 3.5  # Increased to be safe
    
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    OR_MODEL = os.getenv("OR_MODEL", "arcee-ai/trinity-large-preview:free")
    OR_TEMPERATURE = 0.05  # Lower for consistency
    
    DATA_DIR = Path("./audit_data")
    DB_PATH = DATA_DIR / "findings.db"
    CHECKPOINT_PATH = DATA_DIR / "checkpoint.json"
    
    # Tuned for better recall
    MAX_DUPLICATES = 10  # Increased from 5 to get more variety
    BATCH_SIZE = 100
    SIMILARITY_THRESHOLD = 0.42  # Lowered from 0.5
    MIN_SIMILARITY = 0.35  # Absolute floor
    
    # Risk scoring weights
    RISK_EXTERNAL_CALL = 15
    RISK_DELEGATECALL = 40
    RISK_PAYABLE = 10
    RISK_REENTRANCY_RISK = 35  # external + state change
    RISK_ASSEMBLY = 20
    RISK_FLASH_LOAN_VECTOR = 25
    RISK_CROSS_FUNCTION = 50

Config.DATA_DIR.mkdir(parents=True, exist_ok=True)