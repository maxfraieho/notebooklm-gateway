"""
Configuration loaded from environment variables.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Base paths
BASE_DIR = Path(__file__).parent.parent.resolve()

# Server
PORT = int(os.getenv("PORT", "5000"))
HOST = os.getenv("HOST", "0.0.0.0")

# MinIO / S3
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "mcpstorage")

# NotebookLM
STORAGE_STATE_PATH = Path(os.getenv("STORAGE_STATE_PATH", "./secrets/storage_state.json"))
if not STORAGE_STATE_PATH.is_absolute():
    STORAGE_STATE_PATH = BASE_DIR / STORAGE_STATE_PATH

# Data paths
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
if not DATA_DIR.is_absolute():
    DATA_DIR = BASE_DIR / DATA_DIR

JOBS_FILE = Path(os.getenv("JOBS_FILE", "./data/jobs.json"))
if not JOBS_FILE.is_absolute():
    JOBS_FILE = BASE_DIR / JOBS_FILE

# CORS
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")
CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() == "true"

# Service-to-service authentication
NOTEBOOKLM_SERVICE_TOKEN = os.getenv("NOTEBOOKLM_SERVICE_TOKEN", "")

# Chat settings
CHAT_TIMEOUT_SECONDS = int(os.getenv("CHAT_TIMEOUT_SECONDS", "90"))
CHAT_MAX_HISTORY_MESSAGES = int(os.getenv("CHAT_MAX_HISTORY_MESSAGES", "12"))
CHAT_MAX_HISTORY_CHARS = int(os.getenv("CHAT_MAX_HISTORY_CHARS", "25000"))

# Limits
MAX_STORAGE_STATE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_SOURCES_PER_IMPORT = int(os.getenv("MAX_SOURCES_PER_IMPORT", "20"))
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "50"))  # 50MB per file

# Allowed file extensions for import
ALLOWED_EXTENSIONS = {
    ".pdf", ".txt", ".md", ".docx", ".doc",
    ".pptx", ".ppt", ".xlsx", ".xls",
    ".html", ".htm", ".epub",
}

# Job processing
JOB_MAX_RETRIES = int(os.getenv("JOB_MAX_RETRIES", "3"))
JOB_RETRY_DELAY_SECONDS = int(os.getenv("JOB_RETRY_DELAY_SECONDS", "5"))
JOB_TIMEOUT_SECONDS = int(os.getenv("JOB_TIMEOUT_SECONDS", "120"))  # 2 min per source

# Idempotency
IDEMPOTENCY_TTL_SECONDS = int(os.getenv("IDEMPOTENCY_TTL_SECONDS", "3600"))  # 1 hour
IDEMPOTENCY_FILE = DATA_DIR / "idempotency.json"

# NotebookLM library expects storage state at this path
NOTEBOOKLM_LIBRARY_PATH = Path.home() / ".notebooklm" / "storage_state.json"


def ensure_dirs():
    """Create required directories if they don't exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STORAGE_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    NOTEBOOKLM_LIBRARY_PATH.parent.mkdir(parents=True, exist_ok=True)


def sync_storage_state():
    """
    Sync storage_state.json to where notebooklm-py library expects it.
    The library reads from ~/.notebooklm/storage_state.json by default.
    """
    import shutil
    if STORAGE_STATE_PATH.exists():
        shutil.copy2(STORAGE_STATE_PATH, NOTEBOOKLM_LIBRARY_PATH)
        return True
    return False
