from pathlib import Path
import os
from dotenv import load_dotenv


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(
    "/content/drive/MyDrive/email forensics  with advance features"
)


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

ENV_FILE = PROJECT_ROOT / ".env"

if ENV_FILE.exists():
    load_dotenv(ENV_FILE, override=True)


# ============================================================
# APPLICATION
# ============================================================

APP_ENV = os.getenv("APP_ENV", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


# ============================================================
# NVIDIA NIM
# ============================================================

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")

NVIDIA_MODEL_NAME = os.getenv(
    "NVIDIA_MODEL_NAME",
    "nvidia/nemotron-3-super-120b-a12b"
)

NVIDIA_BASE_URL = os.getenv(
    "NVIDIA_BASE_URL",
    "https://integrate.api.nvidia.com/v1"
)


# ============================================================
# PROJECT DATA DIRECTORIES
# ============================================================

DATASETS_DIR = PROJECT_ROOT / "datasets"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
DATABASE_DIR = PROJECT_ROOT / "database"

INGEST_DIR = PROJECT_ROOT / "ingest"
PARSERS_DIR = PROJECT_ROOT / "parsers"
THREAT_INTEL_DIR = PROJECT_ROOT / "threat_intel"
AI_ENGINE_DIR = PROJECT_ROOT / "ai_engine"
REPORTING_DIR = PROJECT_ROOT / "reporting"
TESTS_DIR = PROJECT_ROOT / "tests"


# ============================================================
# DATA SUBDIRECTORIES
# ============================================================

RAW_DATA_DIR = DATASETS_DIR / "raw"
PROCESSED_DATA_DIR = DATASETS_DIR / "processed"

RAW_EVIDENCE_DIR = EVIDENCE_DIR / "raw"
PROCESSED_EVIDENCE_DIR = EVIDENCE_DIR / "processed"

FORENSIC_REPORTS_DIR = REPORTS_DIR / "forensic"
AI_REPORTS_DIR = REPORTS_DIR / "ai"
AUDIT_REPORTS_DIR = REPORTS_DIR / "audit"


# ============================================================
# DATABASE
# ============================================================

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./database/secure_email_forensics.db"
)


# ============================================================
# CREATE REQUIRED DIRECTORIES
# ============================================================

REQUIRED_DIRECTORIES = [
    DATASETS_DIR,
    EVIDENCE_DIR,
    MODELS_DIR,
    REPORTS_DIR,
    DATABASE_DIR,
    INGEST_DIR,
    PARSERS_DIR,
    THREAT_INTEL_DIR,
    AI_ENGINE_DIR,
    REPORTING_DIR,
    TESTS_DIR,

    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,

    RAW_EVIDENCE_DIR,
    PROCESSED_EVIDENCE_DIR,

    FORENSIC_REPORTS_DIR,
    AI_REPORTS_DIR,
    AUDIT_REPORTS_DIR,
]


for directory in REQUIRED_DIRECTORIES:
    directory.mkdir(parents=True, exist_ok=True)
