"""
JSON-based state storage with file locking.
Thread-safe read/write for jobs and other state.
"""
import json
import fcntl
import asyncio
from pathlib import Path
from typing import Any, Optional
from contextlib import contextmanager

from app import config


@contextmanager
def _file_lock(file_path: Path, mode: str):
    """Context manager for file locking."""
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Create file if it doesn't exist
    if not file_path.exists():
        file_path.write_text("{}")

    with open(file_path, mode) as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield f
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def read_json(file_path: Path) -> dict:
    """Read JSON file with locking."""
    if not file_path.exists():
        return {}

    with _file_lock(file_path, "r") as f:
        content = f.read()
        if not content.strip():
            return {}
        return json.loads(content)


def write_json(file_path: Path, data: dict) -> None:
    """Write JSON file with locking."""
    with _file_lock(file_path, "r+") as f:
        f.seek(0)
        f.truncate()
        json.dump(data, f, indent=2, ensure_ascii=False)


def update_json(file_path: Path, key: str, value: Any) -> None:
    """Update a single key in JSON file atomically."""
    with _file_lock(file_path, "r+") as f:
        content = f.read()
        data = json.loads(content) if content.strip() else {}
        data[key] = value
        f.seek(0)
        f.truncate()
        json.dump(data, f, indent=2, ensure_ascii=False)


def delete_from_json(file_path: Path, key: str) -> Optional[Any]:
    """Delete a key from JSON file atomically. Returns deleted value or None."""
    with _file_lock(file_path, "r+") as f:
        content = f.read()
        data = json.loads(content) if content.strip() else {}
        value = data.pop(key, None)
        f.seek(0)
        f.truncate()
        json.dump(data, f, indent=2, ensure_ascii=False)
        return value


# Convenience functions for jobs
def get_jobs() -> dict:
    return read_json(config.JOBS_FILE)


def get_job(job_id: str) -> Optional[dict]:
    jobs = get_jobs()
    return jobs.get(job_id)


def save_job(job_id: str, job_data: dict) -> None:
    update_json(config.JOBS_FILE, job_id, job_data)


def delete_job(job_id: str) -> Optional[dict]:
    return delete_from_json(config.JOBS_FILE, job_id)
