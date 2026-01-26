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
MINIO_BUCKET_RAW = os.getenv("MINIO_BUCKET_RAW", "raw")

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


def ensure_dirs():
    """Create required directories if they don't exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STORAGE_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
