"""
Background job processing for source imports.
Uses asyncio queue with retry/backoff and timeout.
"""
import asyncio
import uuid
import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict, field

from app import config
from app.services import state_store, minio_service, notebooklm_service

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class SourceResult:
    source: dict
    status: str  # "success" or "error"
    source_id: Optional[str] = None
    error: Optional[str] = None
    retries: int = 0


@dataclass
class JobInfo:
    job_id: str
    notebook_id: str
    status: JobStatus
    sources: list[dict]
    progress: int  # 0-100
    created_at: str
    updated_at: str
    notebook_url: Optional[str] = None
    error: Optional[str] = None
    results: Optional[list[dict]] = None
    idempotency_key: Optional[str] = None
    current_step: int = 0
    total_steps: int = 0


# Global job queue
_job_queue: Optional[asyncio.Queue] = None
_worker_task: Optional[asyncio.Task] = None


def get_queue() -> asyncio.Queue:
    """Get or create the job queue."""
    global _job_queue
    if _job_queue is None:
        _job_queue = asyncio.Queue()
    return _job_queue


def create_job(
    notebook_id: str,
    sources: list[dict],
    idempotency_key: Optional[str] = None,
) -> JobInfo:
    """
    Create a new import job.

    Args:
        notebook_id: Target notebook ID
        sources: List of source specs (type, bucket/key or url)
        idempotency_key: Optional key for idempotent requests

    Returns:
        JobInfo with job_id
    """
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    job = JobInfo(
        job_id=job_id,
        notebook_id=notebook_id,
        status=JobStatus.QUEUED,
        sources=sources,
        progress=0,
        created_at=now,
        updated_at=now,
        notebook_url=f"https://notebooklm.google.com/notebook/{notebook_id}",
        idempotency_key=idempotency_key,
        current_step=0,
        total_steps=len(sources),
    )

    # Save to state
    state_store.save_job(job_id, asdict(job))

    # Save idempotency mapping if key provided
    if idempotency_key:
        save_idempotency_key(idempotency_key, job_id)

    return job


def get_job(job_id: str) -> Optional[JobInfo]:
    """Get job info by ID."""
    data = state_store.get_job(job_id)
    if data is None:
        return None

    return JobInfo(
        job_id=data["job_id"],
        notebook_id=data["notebook_id"],
        status=JobStatus(data["status"]),
        sources=data["sources"],
        progress=data["progress"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        notebook_url=data.get("notebook_url"),
        error=data.get("error"),
        results=data.get("results"),
        idempotency_key=data.get("idempotency_key"),
        current_step=data.get("current_step", 0),
        total_steps=data.get("total_steps", len(data["sources"])),
    )


def update_job(
    job_id: str,
    status: Optional[JobStatus] = None,
    progress: Optional[int] = None,
    error: Optional[str] = None,
    results: Optional[list[dict]] = None,
    current_step: Optional[int] = None,
) -> None:
    """Update job status."""
    data = state_store.get_job(job_id)
    if data is None:
        return

    if status is not None:
        data["status"] = status.value
    if progress is not None:
        data["progress"] = progress
    if error is not None:
        data["error"] = error
    if results is not None:
        data["results"] = results
    if current_step is not None:
        data["current_step"] = current_step

    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    state_store.save_job(job_id, data)


# Idempotency helpers
def get_job_by_idempotency_key(key: str) -> Optional[str]:
    """Get job_id by idempotency key. Returns None if not found or expired."""
    data = state_store.read_json(config.IDEMPOTENCY_FILE)
    entry = data.get(key)
    if entry is None:
        return None

    # Check TTL
    created_at = datetime.fromisoformat(entry["created_at"])
    now = datetime.now(timezone.utc)
    age_seconds = (now - created_at).total_seconds()

    if age_seconds > config.IDEMPOTENCY_TTL_SECONDS:
        # Expired - clean up
        state_store.delete_from_json(config.IDEMPOTENCY_FILE, key)
        return None

    return entry["job_id"]


def save_idempotency_key(key: str, job_id: str) -> None:
    """Save idempotency key -> job_id mapping."""
    state_store.update_json(
        config.IDEMPOTENCY_FILE,
        key,
        {
            "job_id": job_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )


async def process_source_with_retry(
    notebook_id: str,
    source_spec: dict,
    temp_files: list[Path],
) -> SourceResult:
    """
    Process a single source with retry/backoff.

    Returns:
        SourceResult with status and optional error
    """
    source_type = source_spec.get("type")
    last_error = None

    for attempt in range(config.JOB_MAX_RETRIES):
        try:
            # Apply timeout to the operation
            async with asyncio.timeout(config.JOB_TIMEOUT_SECONDS):
                if source_type == "minio":
                    bucket = source_spec.get("bucket")
                    key = source_spec.get("key")

                    logger.info(f"Downloading {bucket}/{key} from MinIO (attempt {attempt + 1})")
                    temp_path, filename = minio_service.download_to_temp(bucket, key)
                    temp_files.append(temp_path)

                    # Check file size
                    file_size_mb = temp_path.stat().st_size / (1024 * 1024)
                    if file_size_mb > config.MAX_FILE_SIZE_MB:
                        return SourceResult(
                            source=source_spec,
                            status="error",
                            error=f"File too large: {file_size_mb:.1f}MB (max {config.MAX_FILE_SIZE_MB}MB)",
                        )

                    # Upload to NotebookLM
                    result = await notebooklm_service.add_source_file(
                        notebook_id,
                        temp_path,
                        title=filename,
                    )
                    return SourceResult(
                        source=source_spec,
                        status="success",
                        source_id=result.get("source_id"),
                        retries=attempt,
                    )

                elif source_type == "url":
                    url = source_spec.get("url")
                    logger.info(f"Adding URL source: {url} (attempt {attempt + 1})")

                    result = await notebooklm_service.add_source_url(
                        notebook_id,
                        url,
                    )
                    return SourceResult(
                        source=source_spec,
                        status="success",
                        source_id=result.get("source_id"),
                        retries=attempt,
                    )

                else:
                    return SourceResult(
                        source=source_spec,
                        status="error",
                        error=f"Unknown source type: {source_type}",
                    )

        except asyncio.TimeoutError:
            last_error = f"Timeout after {config.JOB_TIMEOUT_SECONDS}s"
            logger.warning(f"Source processing timed out (attempt {attempt + 1}): {source_spec}")

        except Exception as e:
            last_error = str(e)
            logger.warning(f"Source processing failed (attempt {attempt + 1}): {e}")

        # Backoff before retry (exponential: 5s, 10s, 20s, ...)
        if attempt < config.JOB_MAX_RETRIES - 1:
            delay = config.JOB_RETRY_DELAY_SECONDS * (2 ** attempt)
            logger.info(f"Retrying in {delay}s...")
            await asyncio.sleep(delay)

    # All retries exhausted
    return SourceResult(
        source=source_spec,
        status="error",
        error=f"Failed after {config.JOB_MAX_RETRIES} attempts: {last_error}",
        retries=config.JOB_MAX_RETRIES,
    )


async def process_job(job: JobInfo) -> None:
    """
    Process a single import job.
    Downloads files from MinIO / adds URLs to notebook.
    """
    logger.info(f"Processing job {job.job_id} for notebook {job.notebook_id}")

    update_job(job.job_id, status=JobStatus.RUNNING, progress=0, current_step=0)

    results: list[dict] = []
    total = len(job.sources)
    temp_files: list[Path] = []
    failed_count = 0

    try:
        for i, source_spec in enumerate(job.sources):
            # Update progress
            progress = int((i / total) * 100)
            update_job(job.job_id, progress=progress, current_step=i + 1)

            # Process with retry
            result = await process_source_with_retry(
                job.notebook_id,
                source_spec,
                temp_files,
            )
            results.append(asdict(result))

            if result.status == "error":
                failed_count += 1

        # Determine final status
        if failed_count == total:
            # All failed
            update_job(
                job.job_id,
                status=JobStatus.FAILED,
                progress=100,
                error=f"All {total} sources failed to import",
                results=results,
                current_step=total,
            )
        elif failed_count > 0:
            # Partial success
            update_job(
                job.job_id,
                status=JobStatus.COMPLETED,
                progress=100,
                error=f"{failed_count}/{total} sources failed",
                results=results,
                current_step=total,
            )
        else:
            # Full success
            update_job(
                job.job_id,
                status=JobStatus.COMPLETED,
                progress=100,
                results=results,
                current_step=total,
            )

        logger.info(f"Job {job.job_id} completed: {total - failed_count}/{total} succeeded")

    except Exception as e:
        logger.error(f"Job {job.job_id} failed with unexpected error: {e}")
        update_job(
            job.job_id,
            status=JobStatus.FAILED,
            error=f"Unexpected error: {str(e)}",
            results=results,
        )

    finally:
        # Clean up temp files
        for temp_path in temp_files:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


async def job_worker() -> None:
    """Background worker that processes jobs from the queue."""
    logger.info("Job worker started")
    queue = get_queue()

    while True:
        try:
            job = await queue.get()
            await process_job(job)
            queue.task_done()
        except asyncio.CancelledError:
            logger.info("Job worker cancelled")
            break
        except Exception as e:
            logger.error(f"Job worker error: {e}")
            await asyncio.sleep(1)  # Brief pause on error


def enqueue_job(job: JobInfo) -> None:
    """Add a job to the processing queue."""
    queue = get_queue()
    queue.put_nowait(job)


def start_worker() -> asyncio.Task:
    """Start the background job worker."""
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(job_worker())
    return _worker_task


def stop_worker() -> None:
    """Stop the background job worker."""
    global _worker_task
    if _worker_task is not None and not _worker_task.done():
        _worker_task.cancel()
