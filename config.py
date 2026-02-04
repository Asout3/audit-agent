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
    GROQ_TEMPERATURE = 0.05
    GROQ_MAX_RETRIES = 5
    GROQ_TIMEOUT = 90

    DATA_DIR = Path("audit_data")
    DB_PATH = DATA_DIR / "patterns.db"
    DATA_DIR.mkdir(exist_ok=True)

    BATCH_SIZE = 100
    MAX_DUPLICATES = 15
    SIMILARITY_THRESHOLD = 0.30  # Lowered from 0.40 for broader matching
    FUNCTION_COVERAGE_LIMIT = 150 # Increased from 60
    PATTERNS_PER_CALL = 5        # Increased from 2

    RISK_EXTERNAL = 20
    RISK_DELEGATECALL = 45
    RISK_REENTRANCY = 40
    RISK_ASSEMBLY = 25
    RISK_TIMESTAMP = 15
    RISK_STORAGE_COLLISION = 30
    RISK_APPROVAL_DOUBLE_SPEND = 50
    RISK_WEAK_RANDOMNESS = 35
    
    # Logging configuration
    LOG_FILE = "audit.log"
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Cache configuration
    CACHE_DIR = DATA_DIR / "cache"
    CACHE_MAX_SIZE = 100 * 1024 * 1024  # 100MB
    CACHE_TTL_HOURS = 168  # 7 days
    
    # Test generation
    TEST_CONFIDENCE_THRESHOLD = 80
    FOUNDRY_TEST_DIR = "test/exploits"
    
    # Resume capability
    PROGRESS_FILE = DATA_DIR / "audit_progress.json"