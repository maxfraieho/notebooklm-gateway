"""
NotebookLM Backend Server

A headless backend for NotebookLM integration.
Provides REST API for notebook operations and web interface for auth.

WARNING: This server has NO authentication. Do NOT expose to public internet.
For internal/development use only.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import config
from app.routes import auth, api_v1
from app.services import jobs
from app.errors import APIError, api_error_handler, http_exception_handler, generic_exception_handler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("Starting NotebookLM Backend...")
    config.ensure_dirs()
    
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
    auth_ok = config.STORAGE_STATE_PATH.exists()
    return {
        "status": "healthy",
        "authenticated": auth_ok,
        "version": "0.1.0",
    }


@app.get("/")
async def root():
    """Root endpoint - returns API info."""
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
