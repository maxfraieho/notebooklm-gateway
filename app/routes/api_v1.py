"""
REST API v1 for NotebookLM operations.
"""
import logging
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app import config
from app.errors import (
    APIError,
    NotAuthenticatedError,
    NotFoundError,
    ValidationError,
    NotebookLMError,
    IdempotencyConflictError,
    ErrorCode,
)
from app.services import notebooklm_service, jobs

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["api"])


# --- Dependency ---

async def require_auth():
    """Dependency that ensures user is authenticated."""
    if not notebooklm_service.is_authenticated():
        raise NotAuthenticatedError()


# --- Request/Response Models ---

class CreateNotebookRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)


class CreateNotebookResponse(BaseModel):
    notebook_id: str
    notebook_url: str
    title: str


class SourceSpec(BaseModel):
    type: str = Field(..., description="Source type: 'minio' or 'url'")
    bucket: Optional[str] = Field(None, description="MinIO bucket (for type='minio')")
    key: Optional[str] = Field(None, description="MinIO object key (for type='minio')")
    url: Optional[str] = Field(None, description="URL (for type='url')")


class ImportSourcesRequest(BaseModel):
    sources: list[SourceSpec] = Field(..., min_length=1)
    idempotency_key: Optional[str] = Field(
        None,
        description="Optional key for idempotent requests. Same key returns existing job.",
        max_length=128,
    )


class ImportSourcesResponse(BaseModel):
    job_id: str
    status: str
    notebook_url: str


class ShareRequest(BaseModel):
    emails: list[str] = Field(..., min_length=1)
    role: str = Field("reader", description="Role: 'reader' or 'writer'")


class ShareResponse(BaseModel):
    ok: bool
    shared_with: list[str]
    role: str


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=1)
    system_prompt: Optional[str] = None
    show_sources: bool = True


class ReferenceResponse(BaseModel):
    citation_number: int
    source_title: str
    cited_text: str


class ChatResponse(BaseModel):
    answer: str
    references: list[ReferenceResponse]


class SourceResultResponse(BaseModel):
    source: dict
    status: str
    source_id: Optional[str] = None
    error: Optional[str] = None
    retries: int = 0


class JobResponse(BaseModel):
    job_id: str
    status: str  # queued, running, completed, failed
    progress: int  # 0-100
    current_step: int
    total_steps: int
    notebook_url: Optional[str] = None
    error: Optional[str] = None
    results: Optional[list[SourceResultResponse]] = None


# --- Endpoints ---

@router.post("/notebooks", response_model=CreateNotebookResponse)
async def create_notebook(
    request: CreateNotebookRequest,
    _: None = Depends(require_auth),
):
    """Create a new notebook."""
    try:
        result = await notebooklm_service.create_notebook(request.title)
        return CreateNotebookResponse(**result)
    except Exception as e:
        logger.error(f"Failed to create notebook: {e}")
        raise NotebookLMError(
            message=f"Failed to create notebook: {str(e)}",
            details={"title": request.title},
        )


@router.get("/notebooks")
async def list_notebooks(_: None = Depends(require_auth)):
    """List all notebooks."""
    try:
        notebooks = await notebooklm_service.list_notebooks()
        return {"notebooks": notebooks}
    except Exception as e:
        logger.error(f"Failed to list notebooks: {e}")
        raise NotebookLMError(message=f"Failed to list notebooks: {str(e)}")


@router.post("/notebooks/{notebook_id}/sources/import", response_model=ImportSourcesResponse)
async def import_sources(
    notebook_id: str,
    request: ImportSourcesRequest,
    _: None = Depends(require_auth),
):
    """
    Start async job to import sources into a notebook.

    Sources can be:
    - MinIO: {"type": "minio", "bucket": "raw", "key": "path/to/file.pdf"}
    - URL: {"type": "url", "url": "https://example.com/article"}

    Use idempotency_key to prevent duplicate imports on retry.
    """
    # Check idempotency key first
    if request.idempotency_key:
        existing_job_id = jobs.get_job_by_idempotency_key(request.idempotency_key)
        if existing_job_id:
            existing_job = jobs.get_job(existing_job_id)
            if existing_job:
                # Return existing job (idempotent response)
                return ImportSourcesResponse(
                    job_id=existing_job.job_id,
                    status=existing_job.status.value,
                    notebook_url=existing_job.notebook_url,
                )

    # Validate source count
    if len(request.sources) > config.MAX_SOURCES_PER_IMPORT:
        raise ValidationError(
            message=f"Too many sources. Maximum is {config.MAX_SOURCES_PER_IMPORT}",
            details={"count": len(request.sources), "max": config.MAX_SOURCES_PER_IMPORT},
        )

    # Validate each source
    for i, source in enumerate(request.sources):
        if source.type == "minio":
            if not source.bucket or not source.key:
                raise ValidationError(
                    message=f"Source {i + 1}: MinIO sources require 'bucket' and 'key'",
                    details={"source_index": i, "source": source.model_dump()},
                )
            # Validate file extension
            ext = Path(source.key).suffix.lower()
            if ext and ext not in config.ALLOWED_EXTENSIONS:
                raise ValidationError(
                    message=f"Source {i + 1}: File type '{ext}' not allowed",
                    details={
                        "source_index": i,
                        "extension": ext,
                        "allowed": list(config.ALLOWED_EXTENSIONS),
                    },
                )
        elif source.type == "url":
            if not source.url:
                raise ValidationError(
                    message=f"Source {i + 1}: URL sources require 'url'",
                    details={"source_index": i},
                )
            # Basic URL validation
            if not source.url.startswith(("http://", "https://")):
                raise ValidationError(
                    message=f"Source {i + 1}: Invalid URL format",
                    details={"source_index": i, "url": source.url},
                )
        else:
            raise ValidationError(
                message=f"Source {i + 1}: Unknown type '{source.type}'. Use 'minio' or 'url'",
                details={"source_index": i, "type": source.type},
            )

    # Create job
    job = jobs.create_job(
        notebook_id=notebook_id,
        sources=[s.model_dump() for s in request.sources],
        idempotency_key=request.idempotency_key,
    )

    # Enqueue for processing
    jobs.enqueue_job(job)

    return ImportSourcesResponse(
        job_id=job.job_id,
        status=job.status.value,
        notebook_url=job.notebook_url,
    )


@router.get("/notebooks/{notebook_id}/sources")
async def list_sources(
    notebook_id: str,
    _: None = Depends(require_auth),
):
    """List sources in a notebook."""
    try:
        sources = await notebooklm_service.list_sources(notebook_id)
        return {"sources": sources}
    except Exception as e:
        logger.error(f"Failed to list sources: {e}")
        raise NotebookLMError(
            message=f"Failed to list sources: {str(e)}",
            details={"notebook_id": notebook_id},
        )


@router.post("/notebooks/{notebook_id}/share", response_model=ShareResponse)
async def share_notebook(
    notebook_id: str,
    request: ShareRequest,
    _: None = Depends(require_auth),
):
    """
    Share a notebook with specified emails.

    NOTE: May not be supported by current notebooklm-py version.
    """
    try:
        result = await notebooklm_service.share_notebook(
            notebook_id,
            emails=request.emails,
            role=request.role,
        )
        return ShareResponse(**result)
    except NotImplementedError as e:
        raise APIError(
            code=ErrorCode.NOT_IMPLEMENTED,
            message=str(e),
            status_code=501,
            details={"notebook_id": notebook_id},
        )
    except Exception as e:
        logger.error(f"Failed to share notebook: {e}")
        raise NotebookLMError(
            message=f"Failed to share notebook: {str(e)}",
            details={"notebook_id": notebook_id},
        )


@router.post("/notebooks/{notebook_id}/chat", response_model=ChatResponse)
async def chat_with_notebook(
    notebook_id: str,
    request: ChatRequest,
    _: None = Depends(require_auth),
):
    """
    Ask a question to a notebook and get answer with references.
    """
    try:
        result = await notebooklm_service.chat(
            notebook_id=notebook_id,
            question=request.question,
            system_prompt=request.system_prompt,
            show_sources=request.show_sources,
        )
        return ChatResponse(
            answer=result.answer,
            references=[
                ReferenceResponse(
                    citation_number=ref.citation_number,
                    source_title=ref.source_title,
                    cited_text=ref.cited_text,
                )
                for ref in result.references
            ],
        )
    except Exception as e:
        logger.error(f"Chat failed: {e}")
        raise NotebookLMError(
            message=f"Chat failed: {str(e)}",
            details={"notebook_id": notebook_id},
        )


@router.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job_status(job_id: str):
    """
    Get status of an import job.

    Poll this endpoint to track import progress.
    Status values: queued, running, completed, failed
    """
    job = jobs.get_job(job_id)
    if job is None:
        raise NotFoundError(resource="Job", resource_id=job_id)

    return JobResponse(
        job_id=job.job_id,
        status=job.status.value,
        progress=job.progress,
        current_step=job.current_step,
        total_steps=job.total_steps,
        notebook_url=job.notebook_url,
        error=job.error,
        results=[SourceResultResponse(**r) for r in job.results] if job.results else None,
    )
