"""
REST API v1 for NotebookLM operations.
"""
import asyncio
import logging
import re
import uuid
from pathlib import Path
from typing import Optional, Literal
from fastapi import APIRouter, Depends, Header
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
from app.services.github_service import github_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["api"])


# --- Dependencies ---

async def require_auth():
    """Dependency that ensures user is authenticated."""
    if not notebooklm_service.is_authenticated():
        raise NotAuthenticatedError()


async def require_service_token(authorization: Optional[str] = Header(None)):
    """
    Dependency for service-to-service authentication via Bearer token.
    Used by Worker/external services to call protected endpoints.
    """
    if not config.NOTEBOOKLM_SERVICE_TOKEN:
        raise APIError(
            code=ErrorCode.NOT_AUTHENTICATED,
            message="Service token not configured on server",
            status_code=503,
        )

    if not authorization:
        raise APIError(
            code=ErrorCode.NOT_AUTHENTICATED,
            message="Authorization header required",
            status_code=401,
        )

    if not authorization.startswith("Bearer "):
        raise APIError(
            code=ErrorCode.NOT_AUTHENTICATED,
            message="Invalid authorization format. Use: Bearer <token>",
            status_code=401,
        )

    token = authorization[7:]
    if token != config.NOTEBOOKLM_SERVICE_TOKEN:
        raise APIError(
            code=ErrorCode.AUTH_FAILED,
            message="Invalid service token",
            status_code=403,
        )

    if not notebooklm_service.is_authenticated():
        raise NotAuthenticatedError("NotebookLM storage_state.json not configured")


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
    error_code: Optional[str] = None
    error_details: Optional[dict] = None
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


# --- Diagnostics ---

class MinioDiagnosticsResponse(BaseModel):
    minio_ok: bool
    endpoint: str
    secure: bool
    bucket: str
    error: Optional[str] = None
    test_prefix: Optional[str] = None
    objects_found: Optional[int] = None


@router.get("/diagnostics/minio", response_model=MinioDiagnosticsResponse)
async def minio_diagnostics(zone_id: Optional[str] = None):
    """
    Check MinIO connectivity and list objects for a zone prefix.

    Use this to verify MinIO configuration before import.
    """
    from app.services import minio_service

    endpoint = config.MINIO_ENDPOINT
    secure = config.MINIO_SECURE
    bucket = config.MINIO_BUCKET

    try:
        ok, msg = minio_service.check_connection()
        if not ok:
            return MinioDiagnosticsResponse(
                minio_ok=False,
                endpoint=endpoint,
                secure=secure,
                bucket=bucket,
                error=msg,
            )

        objects_found = None
        test_prefix = None
        if zone_id:
            test_prefix = f"zones/{zone_id}/notes/"
            client = minio_service.get_client()
            objects = list(client.list_objects(bucket, prefix=test_prefix))
            objects_found = len(objects)

        return MinioDiagnosticsResponse(
            minio_ok=True,
            endpoint=endpoint,
            secure=secure,
            bucket=bucket,
            test_prefix=test_prefix,
            objects_found=objects_found,
        )
    except Exception as e:
        return MinioDiagnosticsResponse(
            minio_ok=False,
            endpoint=endpoint,
            secure=secure,
            bucket=bucket,
            error=str(e),
        )


# --- Service-to-Service API (Worker/UI) ---

NOTEBOOK_URL_PATTERN = re.compile(
    r"https?://notebooklm\.google\.com/notebook/([a-f0-9\-]+)"
)

KIND_SYSTEM_PROMPTS = {
    "answer": "Відповідай коротко та чітко українською.",
    "summary": "Зроби стислий структурований конспект (5–10 пунктів) + висновок.",
    "study_guide": "Зроби навчальний гайд: ключові терміни, пояснення, 10 питань для самоперевірки.",
    "flashcards": "Згенеруй 10–20 flashcards у форматі: Q: ...\\nA: ...",
}


class HistoryMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class WorkerChatRequest(BaseModel):
    notebook_url: str = Field(..., alias="notebookUrl", description="NotebookLM URL with notebook ID")
    message: str = Field(..., min_length=1, description="User's question")
    kind: Literal["answer", "summary", "study_guide", "flashcards"] = Field(
        "answer", description="Type of response to generate"
    )
    history: list[HistoryMessage] = Field(
        default_factory=list, description="Conversation history (max 12 messages)"
    )

    model_config = {"populate_by_name": True}


class WorkerChatResponse(BaseModel):
    answer: str
    request_id: Optional[str] = None


class ServiceHealthResponse(BaseModel):
    authenticated: bool
    message: str
    notebook_count: Optional[int] = None


def parse_notebook_url(url: str) -> str:
    """Extract notebook_id from NotebookLM URL."""
    match = NOTEBOOK_URL_PATTERN.search(url)
    if not match:
        raise ValidationError(
            "Invalid notebookUrl format",
            details={"notebookUrl": url, "expected": "https://notebooklm.google.com/notebook/{id}"},
        )
    return match.group(1)


def build_full_question(message: str, history: list[HistoryMessage], system_prompt: str) -> str:
    """Build full question from message, history, and system prompt."""
    max_messages = config.CHAT_MAX_HISTORY_MESSAGES
    max_chars = config.CHAT_MAX_HISTORY_CHARS

    recent_history = history[-max_messages:] if len(history) > max_messages else history

    history_text = ""
    total_chars = 0
    for msg in recent_history:
        role_label = "USER" if msg.role == "user" else "ASSISTANT"
        line = f"{role_label}: {msg.content}\n"
        if total_chars + len(line) > max_chars:
            break
        history_text += line
        total_chars += len(line)

    parts = []
    if system_prompt:
        parts.append(f"INSTRUCTIONS: {system_prompt}")
    if history_text.strip():
        parts.append(f"CONTEXT (recent conversation):\n{history_text.strip()}")
    parts.append(f"USER QUESTION:\n{message}")

    return "\n\n---\n\n".join(parts)


@router.post("/chat", response_model=WorkerChatResponse)
async def worker_chat(
    request: WorkerChatRequest,
    _: None = Depends(require_service_token),
):
    """
    Chat endpoint for Cloudflare Worker / Lovable UI.

    Requires Bearer token authentication via NOTEBOOKLM_SERVICE_TOKEN.
    """
    request_id = str(uuid.uuid4())

    notebook_id = parse_notebook_url(request.notebook_url)
    system_prompt = KIND_SYSTEM_PROMPTS.get(request.kind, "")
    full_question = build_full_question(request.message, request.history, system_prompt)

    logger.info(
        f"[{request_id}] Chat request: notebook_id={notebook_id}, kind={request.kind}, "
        f"message_len={len(request.message)}, history_len={len(request.history)}"
    )

    try:
        result = await asyncio.wait_for(
            notebooklm_service.chat(
                notebook_id=notebook_id,
                question=full_question,
                system_prompt=None,
                show_sources=False,
            ),
            timeout=config.CHAT_TIMEOUT_SECONDS,
        )

        logger.info(f"[{request_id}] Chat success: answer_len={len(result.answer)}")

        return WorkerChatResponse(
            answer=result.answer,
            request_id=request_id,
        )

    except asyncio.TimeoutError:
        logger.error(f"[{request_id}] Chat timeout after {config.CHAT_TIMEOUT_SECONDS}s")
        raise NotebookLMError(
            message=f"Chat timeout after {config.CHAT_TIMEOUT_SECONDS}s",
            details={"notebook_id": notebook_id, "kind": request.kind, "request_id": request_id},
        )
    except Exception as e:
        logger.error(f"[{request_id}] Chat error: {e}")
        raise NotebookLMError(
            message=f"Chat failed: {str(e)}",
            details={"notebook_id": notebook_id, "request_id": request_id},
        )


class ServiceHealthResponseV2(BaseModel):
    authenticated: bool
    message: str
    notebook_count: Optional[int] = None
    services: dict = {}


@router.get("/health", response_model=ServiceHealthResponseV2)
async def service_health(
    _: None = Depends(require_service_token),
):
    """
    Health check for service-to-service authentication.

    Returns NotebookLM authentication status and notebook count.
    """
    from app.services import minio_service
    
    auth_status = await notebooklm_service.validate_auth()
    minio_ok, _ = minio_service.check_connection()

    return ServiceHealthResponseV2(
        authenticated=auth_status.ok,
        message=auth_status.message,
        notebook_count=auth_status.notebook_count,
        services={
            "notebooklm": auth_status.ok,
            "minio": minio_ok,
            "github": github_service.configured,
        },
    )


class GitCommitRequest(BaseModel):
    path: str = Field(..., min_length=1, description="File path in repo")
    content: str = Field(..., description="File content")
    message: str = Field("Update note via proposal", description="Commit message")
    authorName: str = Field("Garden Guest", description="Git author name")
    proposalId: Optional[str] = Field(None, description="Proposal ID for tracking")


class GitCommitResponse(BaseModel):
    success: bool
    sha: Optional[str] = None
    url: Optional[str] = None
    error: Optional[str] = None
    hint: Optional[str] = None


def validate_git_path(path: str) -> tuple[bool, str]:
    """Validate git file path for security."""
    if not path:
        return False, "Path is required"
    if path.startswith("/") or path.startswith("\\"):
        return False, "Absolute paths not allowed"
    if ".." in path:
        return False, "Path traversal not allowed"
    if not path.startswith("src/site/notes/"):
        return False, "Path must start with src/site/notes/"
    return True, ""


@router.post("/git/commit", response_model=GitCommitResponse)
async def git_commit(
    request: GitCommitRequest,
    _: None = Depends(require_service_token),
):
    """
    Commit a file to GitHub repository.
    Called by Cloudflare Worker after accepting a proposal.
    """
    if not github_service.configured:
        return GitCommitResponse(
            success=False,
            error="GitHub integration not configured",
            hint="Set GITHUB_TOKEN via /api/github/config or environment variables",
        )
    
    valid, error = validate_git_path(request.path)
    if not valid:
        return GitCommitResponse(success=False, error=error)
    
    author_email = f"{request.authorName.lower().replace(' ', '.')}@garden.guest"
    
    result = await github_service.commit_file(
        path=request.path,
        content=request.content,
        message=request.message,
        author_name=request.authorName,
        author_email=author_email,
    )
    
    return GitCommitResponse(**result)


class GitHubConfigRequest(BaseModel):
    token: str = Field(..., min_length=1)
    repo: str = Field(..., min_length=1)
    branch: str = Field("main")


class GitHubStatusResponse(BaseModel):
    configured: bool
    repo: Optional[str] = None
    branch: Optional[str] = None
    valid: Optional[bool] = None
    error: Optional[str] = None


@router.post("/api/github/config")
async def save_github_config(
    request: GitHubConfigRequest,
    _: None = Depends(require_service_token),
):
    """Save GitHub configuration (token stored in env/secrets). Requires service token."""
    import json
    
    github_service.configure(request.token, request.repo, request.branch)
    
    valid, msg = await github_service.validate_token()
    if not valid:
        return {"success": False, "error": msg}
    
    config.GITHUB_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    config.GITHUB_CONFIG_FILE.write_text(json.dumps({
        "token": request.token,
        "repo": request.repo,
        "branch": request.branch,
    }))
    
    return {"success": True, "message": "GitHub configured successfully"}


@router.get("/api/github/status", response_model=GitHubStatusResponse)
async def get_github_status(
    _: None = Depends(require_service_token),
):
    """Check if GitHub is configured. Requires service token."""
    configured = github_service.configured
    
    if not configured:
        return GitHubStatusResponse(configured=False)
    
    valid, error = await github_service.validate_token()
    
    return GitHubStatusResponse(
        configured=True,
        repo=github_service.repo,
        branch=github_service.branch,
        valid=valid,
        error=error if not valid else None,
    )
