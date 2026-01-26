"""
MinIO/S3 service for downloading objects.
"""
import tempfile
from pathlib import Path
from typing import Optional
from minio import Minio
from minio.error import S3Error

from app import config


_client: Optional[Minio] = None


def get_client() -> Minio:
    """Get or create MinIO client singleton."""
    global _client
    if _client is None:
        _client = Minio(
            config.MINIO_ENDPOINT,
            access_key=config.MINIO_ACCESS_KEY,
            secret_key=config.MINIO_SECRET_KEY,
            secure=config.MINIO_SECURE,
        )
    return _client


def check_connection() -> tuple[bool, str]:
    """Check if MinIO is accessible."""
    try:
        client = get_client()
        # Try to list buckets as a health check
        client.list_buckets()
        return True, "MinIO connection OK"
    except Exception as e:
        return False, f"MinIO error: {str(e)}"


def download_to_temp(bucket: str, key: str) -> tuple[Path, str]:
    """
    Download object from MinIO to a temporary file.

    Returns:
        Tuple of (temp_file_path, original_filename)

    Raises:
        S3Error: If object doesn't exist or access denied
    """
    client = get_client()

    # Get original filename from key
    original_filename = Path(key).name

    # Create temp file with proper extension
    suffix = Path(key).suffix or ""
    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=suffix,
        prefix="notebooklm_"
    )
    temp_path = Path(temp_file.name)
    temp_file.close()

    try:
        client.fget_object(bucket, key, str(temp_path))
        return temp_path, original_filename
    except S3Error as e:
        # Clean up temp file on error
        temp_path.unlink(missing_ok=True)
        raise


def object_exists(bucket: str, key: str) -> bool:
    """Check if object exists in MinIO."""
    try:
        client = get_client()
        client.stat_object(bucket, key)
        return True
    except S3Error:
        return False
