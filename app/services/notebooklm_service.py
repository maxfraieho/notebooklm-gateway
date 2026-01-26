"""
NotebookLM service - wraps notebooklm-py library.
Handles authentication validation, notebook operations, and chat.
"""
import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from notebooklm import NotebookLMClient

from app import config


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


async def get_client() -> NotebookLMClient:
    """
    Create NotebookLM client from stored cookies.

    Raises:
        FileNotFoundError: If storage_state.json doesn't exist
    """
    if not is_authenticated():
        raise FileNotFoundError("Not authenticated. Upload storage_state.json first.")

    # Set environment variable for notebooklm-py
    os.environ["NOTEBOOKLM_STORAGE_STATE"] = str(config.STORAGE_STATE_PATH)

    return await NotebookLMClient.from_storage()


async def validate_auth() -> AuthStatus:
    """
    Validate authentication by attempting to list notebooks.

    Returns:
        AuthStatus with ok=True and notebook count, or ok=False with error message
    """
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
        # Don't expose full error details for security
        error_type = type(e).__name__
        return AuthStatus(ok=False, message=f"Auth validation failed: {error_type}")


async def list_notebooks() -> list[dict]:
    """List all notebooks."""
    async with await get_client() as client:
        notebooks = await client.notebooks.list()
        return [{"id": nb.id, "title": nb.title} for nb in notebooks]


async def create_notebook(title: str) -> dict:
    """
    Create a new notebook.

    Returns:
        Dict with notebook_id and notebook_url
    """
    async with await get_client() as client:
        notebook = await client.notebooks.create(title=title)
        return {
            "notebook_id": notebook.id,
            "notebook_url": f"https://notebooklm.google.com/notebook/{notebook.id}",
            "title": notebook.title,
        }


async def add_source_file(notebook_id: str, file_path: Path, title: Optional[str] = None) -> dict:
    """
    Add a file as a source to a notebook.

    Args:
        notebook_id: Target notebook ID
        file_path: Path to the file to upload
        title: Optional title for the source

    Returns:
        Dict with source_id and status
    """
    async with await get_client() as client:
        source = await client.sources.upload(
            notebook_id=notebook_id,
            file_path=str(file_path),
            display_name=title,
        )
        return {
            "source_id": source.id,
            "title": source.title,
            "status": "uploaded",
        }


async def add_source_url(notebook_id: str, url: str) -> dict:
    """
    Add a URL as a source to a notebook.

    Args:
        notebook_id: Target notebook ID
        url: URL to add as source

    Returns:
        Dict with source_id and status
    """
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
    """
    Ask a question to a notebook and get answer with references.

    Args:
        notebook_id: Target notebook ID
        question: Question to ask
        system_prompt: Optional system prompt to prepend
        show_sources: Whether to include source references

    Returns:
        ChatResult with answer and references
    """
    async with await get_client() as client:
        # Build full question with system prompt
        if system_prompt:
            full_question = f"{system_prompt}\n\n{question}"
        else:
            full_question = question

        result = await client.chat.ask(notebook_id, full_question)

        references = []
        if show_sources and hasattr(result, 'references') and result.references:
            # Get sources for mapping
            sources = await client.sources.list(notebook_id)
            source_map = {src.id: src for src in sources}

            for ref in result.references:
                source = source_map.get(ref.source_id)
                source_title = source.title if source else "Unknown source"
                cited_text = (ref.cited_text or "")[:500]  # Limit length
                references.append(ChatReference(
                    citation_number=ref.citation_number,
                    source_title=source_title,
                    cited_text=cited_text,
                ))

        return ChatResult(answer=result.answer, references=references)


async def share_notebook(notebook_id: str, emails: list[str], role: str = "reader") -> dict:
    """
    Share a notebook with specified emails.

    NOTE: This may not be supported by notebooklm-py.
    Returns 501 Not Implemented if the method doesn't exist.
    """
    async with await get_client() as client:
        # Check if share method exists
        if not hasattr(client.notebooks, 'share'):
            raise NotImplementedError(
                "Sharing is not supported by current notebooklm-py version. "
                "TODO: Implement when API becomes available."
            )

        # Try to call share method
        await client.notebooks.share(notebook_id, emails=emails, role=role)
        return {"ok": True, "shared_with": emails, "role": role}
