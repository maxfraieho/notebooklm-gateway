"""
NotebookLM service - wraps notebooklm-py library.
Handles authentication validation, notebook operations, and chat.
Playwright/notebooklm-py imports are lazy to allow the server to start
even when Chromium is not installed (git/minio endpoints still work).
"""
import os
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from app import config

logger = logging.getLogger(__name__)

_notebooklm_available = None


def _check_notebooklm():
    """Lazy-check whether notebooklm-py + Playwright are importable."""
    global _notebooklm_available
    if _notebooklm_available is None:
        try:
            import notebooklm  # noqa: F401
            _notebooklm_available = True
        except Exception as e:
            logger.warning(f"notebooklm-py unavailable ({e}); NotebookLM endpoints will return 503")
            _notebooklm_available = False
    return _notebooklm_available


def _get_client_class():
    """Import and return NotebookLMClient (raises if unavailable)."""
    if not _check_notebooklm():
        raise RuntimeError(
            "notebooklm-py / Playwright is not installed. "
            "NotebookLM operations are unavailable in this environment."
        )
    from notebooklm import NotebookLMClient
    return NotebookLMClient


@dataclass
class AuthStatus:
    ok: bool
    message: str
    notebook_count: Optional[int] = None


@dataclass
class ChatReference:
    citation_number: int
    source_title: str
    cited_text: str


@dataclass
class ChatResult:
    answer: str
    references: list[ChatReference]


def is_authenticated() -> bool:
    """Check if storage_state.json exists."""
    return config.STORAGE_STATE_PATH.exists()


async def get_client():
    """
    Create NotebookLM client from stored cookies.

    Raises:
        FileNotFoundError: If storage_state.json doesn't exist
        RuntimeError: If notebooklm-py is not available
    """
    if not is_authenticated():
        raise FileNotFoundError("Not authenticated. Upload storage_state.json first.")

    os.environ["NOTEBOOKLM_STORAGE_STATE"] = str(config.STORAGE_STATE_PATH)

    ClientClass = _get_client_class()
    return await ClientClass.from_storage()


async def validate_auth() -> AuthStatus:
    """
    Validate authentication by attempting to list notebooks.
    """
    if not _check_notebooklm():
        return AuthStatus(ok=False, message="NotebookLM library not available in this environment")

    if not is_authenticated():
        return AuthStatus(ok=False, message="storage_state.json not found")

    try:
        async with await get_client() as client:
            notebooks = await client.notebooks.list()
            return AuthStatus(
                ok=True,
                message="Authentication valid",
                notebook_count=len(notebooks)
            )
    except Exception as e:
        error_type = type(e).__name__
        return AuthStatus(ok=False, message=f"Auth validation failed: {error_type}")


async def list_notebooks() -> list[dict]:
    """List all notebooks."""
    async with await get_client() as client:
        notebooks = await client.notebooks.list()
        return [{"id": nb.id, "title": nb.title} for nb in notebooks]


async def create_notebook(title: str) -> dict:
    """Create a new notebook."""
    async with await get_client() as client:
        notebook = await client.notebooks.create(title=title)
        return {
            "notebook_id": notebook.id,
            "notebook_url": f"https://notebooklm.google.com/notebook/{notebook.id}",
            "title": notebook.title,
        }


async def add_source_file(notebook_id: str, file_path: Path, title: Optional[str] = None) -> dict:
    """Add a file as a source to a notebook."""
    async with await get_client() as client:
        source = await client.sources.add_file(
            notebook_id=notebook_id,
            file_path=str(file_path),
            wait=True,
        )
        return {
            "source_id": source.id,
            "title": source.title,
            "status": "uploaded",
        }


async def add_source_url(notebook_id: str, url: str) -> dict:
    """Add a URL as a source to a notebook."""
    async with await get_client() as client:
        source = await client.sources.add_url(
            notebook_id=notebook_id,
            url=url,
        )
        return {
            "source_id": source.id,
            "title": source.title,
            "status": "added",
        }


async def list_sources(notebook_id: str) -> list[dict]:
    """List sources in a notebook."""
    async with await get_client() as client:
        sources = await client.sources.list(notebook_id)
        return [{"id": src.id, "title": src.title} for src in sources]


async def chat(
    notebook_id: str,
    question: str,
    system_prompt: Optional[str] = None,
    show_sources: bool = True,
) -> ChatResult:
    """Ask a question to a notebook and get answer with references."""
    async with await get_client() as client:
        if system_prompt:
            full_question = f"{system_prompt}\n\n{question}"
        else:
            full_question = question

        result = await client.chat.ask(notebook_id, full_question)

        references = []
        if show_sources and hasattr(result, 'references') and result.references:
            sources = await client.sources.list(notebook_id)
            source_map = {src.id: src for src in sources}

            for ref in result.references:
                source = source_map.get(ref.source_id)
                source_title = source.title if source else "Unknown source"
                cited_text = (ref.cited_text or "")[:500]
                references.append(ChatReference(
                    citation_number=ref.citation_number,
                    source_title=source_title,
                    cited_text=cited_text,
                ))

        return ChatResult(answer=result.answer, references=references)


async def share_notebook(notebook_id: str, emails: list[str], role: str = "reader") -> dict:
    """Share a notebook with specified emails."""
    async with await get_client() as client:
        if not hasattr(client.notebooks, 'share'):
            raise NotImplementedError(
                "Sharing is not supported by current notebooklm-py version. "
                "TODO: Implement when API becomes available."
            )

        await client.notebooks.share(notebook_id, emails=emails, role=role)
        return {"ok": True, "shared_with": emails, "role": role}
