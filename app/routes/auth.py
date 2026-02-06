"""
Authentication routes - web interface for uploading storage_state.json.
"""
import json
import logging
from fastapi import APIRouter, Request, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app import config
from app.services import notebooklm_service
from app.services import persistent_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Templates
templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@router.get("", response_class=HTMLResponse)
async def auth_page(request: Request):
    """Display auth page with upload form."""
    return templates.TemplateResponse(
        "auth.html",
        {"request": request}
    )


@router.post("/upload")
async def upload_storage_state(
    request: Request,
    file: UploadFile = File(...),
):
    """
    Upload storage_state.json and validate it.

    Validates:
    - File size <= 5MB
    - Valid JSON format
    - Authentication works (can list notebooks)
    """
    # Check file size
    content = await file.read()
    if len(content) > config.MAX_STORAGE_STATE_SIZE:
        return templates.TemplateResponse(
            "auth_result.html",
            {
                "request": request,
                "success": False,
                "message": f"File too large. Maximum size is {config.MAX_STORAGE_STATE_SIZE // (1024*1024)}MB",
            }
        )

    # Validate JSON format
    try:
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("Root must be an object")
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Invalid JSON uploaded: {e}")
        return templates.TemplateResponse(
            "auth_result.html",
            {
                "request": request,
                "success": False,
                "message": "Invalid JSON format. Please upload a valid storage_state.json",
            }
        )

    # Save the file
    try:
        config.STORAGE_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.STORAGE_STATE_PATH.write_bytes(content)
        config.sync_storage_state()
        persistent_store.put("storage_state_json", content.decode("utf-8"))
        logger.info("storage_state.json saved, synced, and persisted to DB")
    except Exception as e:
        logger.error(f"Failed to save storage_state.json: {e}")
        return templates.TemplateResponse(
            "auth_result.html",
            {
                "request": request,
                "success": False,
                "message": "Failed to save file. Check server permissions.",
            }
        )

    # Validate authentication by listing notebooks
    auth_status = await notebooklm_service.validate_auth()

    if auth_status.ok:
        return templates.TemplateResponse(
            "auth_result.html",
            {
                "request": request,
                "success": True,
                "message": f"Authentication successful! Found {auth_status.notebook_count} notebooks.",
                "notebook_count": auth_status.notebook_count,
            }
        )
    else:
        # Remove invalid file and DB entry
        config.STORAGE_STATE_PATH.unlink(missing_ok=True)
        persistent_store.delete("storage_state_json")
        return templates.TemplateResponse(
            "auth_result.html",
            {
                "request": request,
                "success": False,
                "message": f"Authentication failed: {auth_status.message}. Please re-login and try again.",
            }
        )


@router.get("/status")
async def auth_status():
    """
    Check authentication status.

    Returns:
        JSON with ok, message, and optionally notebook_count
    """
    auth_status = await notebooklm_service.validate_auth()
    return {
        "ok": auth_status.ok,
        "message": auth_status.message,
        "notebook_count": auth_status.notebook_count,
    }


@router.delete("/logout")
async def logout():
    """
    Remove stored credentials.
    """
    removed = False
    if config.STORAGE_STATE_PATH.exists():
        config.STORAGE_STATE_PATH.unlink()
        removed = True
    if config.NOTEBOOKLM_LIBRARY_PATH.exists():
        config.NOTEBOOKLM_LIBRARY_PATH.unlink()
        removed = True
    persistent_store.delete("storage_state_json")
    if removed:
        logger.info("Credentials removed from all storage locations (file + DB)")
        return {"ok": True, "message": "Logged out successfully"}
    return {"ok": True, "message": "No credentials to remove"}
