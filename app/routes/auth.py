"""
Authentication routes - web interface for uploading storage_state.json.
"""
import json
import logging
from fastapi import APIRouter, Request, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app import config
from app.services import notebooklm_service
from app.services import persistent_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@router.get("", response_class=HTMLResponse)
async def auth_page():
    """Redirect to main admin panel."""
    return RedirectResponse(url="/", status_code=302)


@router.post("/upload")
async def upload_storage_state(
    file: UploadFile = File(...),
):
    """
    Upload storage_state.json and validate it.
    Returns JSON response for AJAX calls.
    """
    content = await file.read()
    if len(content) > config.MAX_STORAGE_STATE_SIZE:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": f"File too large. Maximum size is {config.MAX_STORAGE_STATE_SIZE // (1024*1024)}MB"}
        )

    try:
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("Root must be an object")
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Invalid JSON uploaded: {e}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Invalid JSON format. Please upload a valid storage_state.json"}
        )

    try:
        config.STORAGE_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.STORAGE_STATE_PATH.write_bytes(content)
        config.sync_storage_state()
        persistent_store.put("storage_state_json", content.decode("utf-8"))
        logger.info("storage_state.json saved, synced, and persisted to DB")
    except Exception as e:
        logger.error(f"Failed to save storage_state.json: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to save file. Check server permissions."}
        )

    auth_status = await notebooklm_service.validate_auth()

    if auth_status.ok:
        return {"success": True, "message": f"Authentication successful! Found {auth_status.notebook_count} notebooks.", "notebook_count": auth_status.notebook_count}
    else:
        config.STORAGE_STATE_PATH.unlink(missing_ok=True)
        persistent_store.delete("storage_state_json")
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": f"Authentication failed: {auth_status.message}. Please re-login and try again."}
        )


@router.get("/status")
async def auth_status():
    """
    Check authentication status.
    Returns JSON with ok, message, and optionally notebook_count.
    """
    if not config.STORAGE_STATE_PATH.exists():
        return {"ok": False, "message": "storage_state.json not found", "notebook_count": None}

    return {"ok": True, "message": "storage_state.json loaded", "notebook_count": None}


@router.delete("/logout")
async def logout():
    """Remove stored credentials."""
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
