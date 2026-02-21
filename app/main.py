"""
NotebookLM Backend Server

A headless backend for NotebookLM integration.
Provides REST API for notebook operations and web interface for auth.

WARNING: This server has NO authentication. Do NOT expose to public internet.
For internal/development use only.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app import config

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
from app.routes import auth, api_v1
from app.services import jobs
from app.services import persistent_store
from app.errors import APIError, api_error_handler, http_exception_handler, generic_exception_handler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def restore_from_db():
    """Restore storage_state.json and GitHub config from database on startup."""
    restored = []

    storage_data = persistent_store.get("storage_state_json")
    if storage_data:
        try:
            config.STORAGE_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            config.STORAGE_STATE_PATH.write_text(storage_data)
            config.sync_storage_state()
            restored.append("storage_state.json")
        except Exception as e:
            logger.error(f"Failed to restore storage_state.json from DB: {e}")
    elif config.STORAGE_STATE_PATH.exists():
        try:
            file_data = config.STORAGE_STATE_PATH.read_text()
            persistent_store.put("storage_state_json", file_data)
            config.sync_storage_state()
            restored.append("storage_state.json (from file, saved to DB)")
        except Exception as e:
            logger.error(f"Failed to seed storage_state.json to DB from file: {e}")

    github_cfg = persistent_store.get_json("github_config")
    if github_cfg:
        try:
            import os
            from app.services.github_service import github_service
            token = github_cfg.get("token", "")
            repo = github_cfg.get("repo", "")
            branch = github_cfg.get("branch", "main")
            if token and repo:
                github_service.configure(token, repo, branch)
                os.environ["GITHUB_TOKEN"] = token
                os.environ["GITHUB_REPO"] = repo
                os.environ["GITHUB_BRANCH"] = branch
                restored.append(f"github({repo})")
        except Exception as e:
            logger.error(f"Failed to restore GitHub config from DB: {e}")

    minio_cfg = persistent_store.get_json("minio_config")
    if minio_cfg:
        try:
            from app.services import minio_service
            endpoint = minio_cfg.get("endpoint", "")
            access_key = minio_cfg.get("access_key", "")
            secret_key = minio_cfg.get("secret_key", "")
            bucket = minio_cfg.get("bucket", "")
            secure = minio_cfg.get("secure", True)
            if endpoint and access_key and secret_key:
                minio_service.reconfigure(endpoint, access_key, secret_key, bucket, secure)
                restored.append(f"minio({endpoint}/{bucket})")
        except Exception as e:
            logger.error(f"Failed to restore MinIO config from DB: {e}")

    if restored:
        logger.info(f"Restored from DB: {', '.join(restored)}")
    return restored


def load_github_config():
    """Load GitHub config from file on startup (fallback)."""
    import json
    if config.GITHUB_CONFIG_FILE.exists():
        try:
            cfg = json.loads(config.GITHUB_CONFIG_FILE.read_text())
            import os
            os.environ.setdefault("GITHUB_TOKEN", cfg.get("token", ""))
            os.environ.setdefault("GITHUB_REPO", cfg.get("repo", ""))
            os.environ.setdefault("GITHUB_BRANCH", cfg.get("branch", "main"))
            logger.info(f"GitHub config loaded from file: repo={cfg.get('repo', '')}")
            return True
        except Exception as e:
            logger.warning(f"Failed to load GitHub config: {e}")
    return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("Starting NotebookLM Backend...")
    
    # Log MinIO configuration (masked)
    access_key_prefix = config.MINIO_ACCESS_KEY[:4] + "****" if len(config.MINIO_ACCESS_KEY) > 4 else "****"
    logger.info(f"MinIO config: endpoint={config.MINIO_ENDPOINT}, access_key={access_key_prefix}, bucket={config.MINIO_BUCKET}, secure={config.MINIO_SECURE}")
    
    # Ensure directories exist before loading configs
    config.ensure_dirs()
    
    # Init persistent DB store and restore data
    persistent_store.init_db()
    restored = restore_from_db()
    
    # Load GitHub config from file (fallback if not restored from DB)
    if not any("github" in r for r in restored):
        load_github_config()
    github_configured = bool(config.GITHUB_TOKEN or config.GITHUB_CONFIG_FILE.exists())
    logger.info(f"GitHub config: configured={github_configured}, repo={config.GITHUB_REPO}")
    
    # Sync storage state to library location
    if config.sync_storage_state():
        logger.info("Storage state synced to notebooklm-py library path")

    # Start background job worker
    jobs.start_worker()
    logger.info("Job worker started")

    yield

    # Shutdown
    logger.info("Shutting down...")
    jobs.stop_worker()


app = FastAPI(
    title="NotebookLM Backend",
    description="""
## NotebookLM Integration API

A headless backend for integrating with Google NotebookLM.

### Authentication
This server uses Google session cookies for authentication.
Upload your `storage_state.json` at `/auth` to enable API access.

### Error Format
All errors return:
```json
{
    "error": {
        "code": "ERROR_CODE",
        "message": "Human-readable message",
        "details": {}
    }
}
```

### Warning
⚠️ **NOT FOR PUBLIC PRODUCTION USE**

This server has no API authentication. All endpoints are publicly accessible.
Only run on trusted networks or behind additional authentication layer.
""",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ALLOW_ORIGINS,
    allow_credentials=config.CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handlers for unified error format
app.add_exception_handler(APIError, api_error_handler)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# Include routers
app.include_router(auth.router)
app.include_router(api_v1.router)


@app.get("/health")
async def health_check():
    """
    Health check endpoint.

    Returns server status and authentication state.
    Always returns 200 OK even if not authenticated.
    """
    import os
    auth_ok = config.STORAGE_STATE_PATH.exists()
    return {
        "status": "healthy",
        "authenticated": auth_ok,
        "version": "0.1.0",
        "service_id": os.getenv("REPL_SLUG", "unknown"),
        "repl_owner": os.getenv("REPL_OWNER", "unknown"),
    }


@app.get("/debug/minio")
async def debug_minio():
    """
    Debug endpoint for MinIO connection diagnostics.
    
    Returns connection status and masked configuration.
    Never exposes full secrets.
    """
    from app.services import minio_service
    from minio.error import S3Error
    
    # Masked access key (first 4 chars only)
    access_key_masked = config.MINIO_ACCESS_KEY[:4] + "****" if len(config.MINIO_ACCESS_KEY) > 4 else "****"
    
    result = {
        "config": {
            "endpoint": config.MINIO_ENDPOINT,
            "access_key": access_key_masked,
            "bucket": config.MINIO_BUCKET,
            "secure": config.MINIO_SECURE,
        },
        "ok": False,
        "error_type": None,
        "error_message": None,
        "buckets": None,
    }
    
    try:
        # Reset client singleton to pick up any env changes
        minio_service._client = None
        client = minio_service.get_client()
        
        # Try list_buckets as health check
        buckets = client.list_buckets()
        bucket_names = [b.name for b in buckets]
        
        result["ok"] = True
        result["buckets"] = bucket_names
        
        # Check if target bucket exists
        if config.MINIO_BUCKET in bucket_names:
            result["target_bucket_exists"] = True
            # Try to list a few objects
            try:
                objects = list(client.list_objects(config.MINIO_BUCKET, prefix="zones/"))[:3]
                result["sample_objects"] = [obj.object_name for obj in objects]
            except Exception as e:
                result["sample_objects_error"] = str(e)
        else:
            result["target_bucket_exists"] = False
            
    except S3Error as e:
        result["error_type"] = e.code
        result["error_message"] = str(e)
    except Exception as e:
        result["error_type"] = type(e).__name__
        result["error_message"] = str(e)
    
    return result


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root endpoint - serves admin panel."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/github/config")
async def save_github_config_public(request: Request):
    """Save GitHub configuration from web UI (no auth required for admin panel)."""
    import json
    from app.services.github_service import github_service
    
    body = await request.json()
    token = body.get("token", "").strip()
    repo = body.get("repo", "").strip()
    branch = body.get("branch", "main").strip()
    
    if not token or not repo:
        return {"success": False, "error": "Token and repo are required"}
    
    github_service.configure(token, repo, branch)
    
    config.GITHUB_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    config.GITHUB_CONFIG_FILE.write_text(json.dumps({
        "token": token,
        "repo": repo,
        "branch": branch,
    }))
    
    persistent_store.put_json("github_config", {
        "token": token,
        "repo": repo,
        "branch": branch,
    })
    
    return {"success": True, "repo": repo}


@app.get("/api/github/status")
async def get_github_status_public():
    """Check if GitHub is configured (for web UI)."""
    from app.services.github_service import github_service
    
    if not github_service.configured:
        return {"configured": False}
    
    return {
        "configured": True,
        "repo": github_service.repo,
        "branch": github_service.branch,
    }


@app.post("/api/minio/config")
async def save_minio_config_public(request: Request):
    """Save MinIO configuration from web UI (no auth required for admin panel)."""
    from app.services import minio_service

    body = await request.json()
    endpoint = body.get("endpoint", "").strip()
    access_key = body.get("access_key", "").strip()
    secret_key = body.get("secret_key", "").strip()
    bucket = body.get("bucket", "").strip()
    secure = body.get("secure", True)

    if not endpoint or not access_key or not secret_key or not bucket:
        return {"success": False, "error": "All fields are required"}

    cleaned_endpoint = endpoint.replace("https://", "").replace("http://", "")
    minio_service.reconfigure(cleaned_endpoint, access_key, secret_key, bucket, secure)

    ok, msg = minio_service.check_connection()
    if not ok:
        return {"success": False, "error": msg}

    persistent_store.put_json("minio_config", {
        "endpoint": cleaned_endpoint,
        "access_key": access_key,
        "secret_key": secret_key,
        "bucket": bucket,
        "secure": secure,
    })

    return {"success": True, "message": f"MinIO configured: {endpoint}/{bucket}"}


@app.get("/api/minio/status")
async def get_minio_status_public():
    """Check MinIO configuration status (for web UI)."""
    from app.services import minio_service

    endpoint = config.MINIO_ENDPOINT
    bucket = config.MINIO_BUCKET
    has_keys = bool(config.MINIO_ACCESS_KEY and config.MINIO_SECRET_KEY and bucket)

    if not has_keys:
        return {"configured": False, "endpoint": endpoint, "bucket": bucket}

    ok, msg = minio_service.check_connection()
    return {
        "configured": True,
        "connected": ok,
        "endpoint": endpoint,
        "bucket": bucket,
        "secure": config.MINIO_SECURE,
        "error": msg if not ok else None,
    }


@app.get("/api/info")
async def api_info():
    """API info endpoint - returns JSON status."""
    if config.STORAGE_STATE_PATH.exists():
        return {
            "service": "NotebookLM Backend",
            "version": "0.1.0",
            "authenticated": True,
            "endpoints": {
                "docs": "/docs",
                "health": "/health",
                "auth_status": "/auth/status",
                "api": "/v1",
            },
        }
    return {
        "service": "NotebookLM Backend",
        "version": "0.1.0",
        "authenticated": False,
        "message": "Upload storage_state.json at /auth to enable API",
        "endpoints": {
            "auth": "/auth",
            "docs": "/docs",
            "health": "/health",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=config.HOST,
        port=config.PORT,
        reload=True,
    )
