# NotebookLM Backend

## Overview
A headless backend server for Google NotebookLM integration. Provides REST API for notebook operations without requiring a browser/GUI on the server.

## Project Structure
```
notebooklm-backend/
├── app/
│   ├── main.py              # FastAPI app + CORS + error handlers
│   ├── config.py            # Configuration from environment variables
│   ├── errors.py            # Unified error handling
│   ├── routes/
│   │   ├── auth.py          # Auth web interface
│   │   └── api_v1.py        # REST API
│   ├── services/
│   │   ├── notebooklm_service.py  # NotebookLM operations
│   │   ├── minio_service.py       # MinIO/S3 operations
│   │   ├── state_store.py         # JSON state persistence
│   │   └── jobs.py                # Background queue + retry
│   └── templates/
│       ├── auth.html
│       └── auth_result.html
├── data/                    # JSON state files
├── secrets/                 # Cookies storage
├── scripts/
│   └── local_login.md       # Login instructions
├── requirements.txt
├── .env.example
└── README.md
```

## Tech Stack
- Python 3.11
- FastAPI + Uvicorn
- PostgreSQL (persistent key-value store for auth & config)
- Jinja2 (templates)
- Playwright (browser automation for NotebookLM)
- MinIO client (S3-compatible storage)

## Running the Application
The server runs on port 5000 using uvicorn:
```
python -m uvicorn app.main:app --host 0.0.0.0 --port 5000
```

## Key Endpoints
- `/` - API info
- `/health` - Health check
- `/auth` - Auth web interface to upload cookies
- `/docs` - OpenAPI documentation
- `/v1/notebooks` - List/create notebooks
- `/v1/notebooks/{id}/sources/import` - Import sources
- `/v1/notebooks/{id}/chat` - Chat with notebook (internal, requires storage_state.json)
- `/v1/diagnostics/minio` - MinIO connectivity check (optional `?zone_id=` to list per-note files)
- `/v1/jobs/{job_id}` - Poll import job status
- `/v1/chat` - Worker/UI chat endpoint (requires Bearer token)
- `/v1/health` - Service-to-service health check (requires Bearer token)
- `/v1/git/commit` - Commit file to GitHub (requires Bearer token)
- `/v1/git/delete` - Delete file from GitHub (requires Bearer token)
- `/v1/git/status` - GitHub integration diagnostics (requires Bearer token)

## Configuration
Environment variables are configured in `.env.example`. Key settings:
- `PORT`: Server port (default: 5000)
- `MINIO_ENDPOINT`: MinIO hostname without protocol (e.g., `apiminio.exodus.pp.ua`)
- `MINIO_ACCESS_KEY`: MinIO access key
- `MINIO_SECRET_KEY`: MinIO secret key
- `MINIO_BUCKET`: Bucket name (e.g., `mcpstorage`)
- `MINIO_SECURE`: Use HTTPS (`true`/`false`)
- `STORAGE_STATE_PATH`: Path to Google auth cookies
- `CORS_ALLOW_ORIGINS`: Allowed CORS origins

### MinIO Architecture
- Fixed bucket with zone folders: `{MINIO_BUCKET}/zones/{zoneId}/`
- Files per zone: `notes.json`, `notes.jsonl`, `notes.md`
- Backend downloads from MinIO and uploads to NotebookLM

## Recent Changes
- 2026-02-06: Added PostgreSQL persistent storage for storage_state.json and GitHub config
  - Data survives republish/restart - no need to re-upload storage_state.json each time
  - Uses kv_store table in PostgreSQL for key-value persistence
  - On startup, restores storage_state.json and GitHub config from DB automatically
  - Auth upload and GitHub config save now persist to DB alongside file system
- 2026-02-06: Fixed WorkerChatRequest model - accepts both snake_case (notebook_url) and camelCase (notebookUrl)
- 2026-02-06: Added NOTEBOOKLM_SERVICE_TOKEN secret for service-to-service auth
- 2026-02-05: Added GitHub integration for auto-committing accepted proposals
  - Target repo: `maxfraieho/project-genesis`
  - New endpoint: `/v1/git/commit` - Commit files to GitHub (requires service token)
  - New endpoints: `/api/github/config` and `/api/github/status` - Configure/check GitHub settings (public, for web UI)
  - New endpoints: `/v1/api/github/config` and `/v1/api/github/status` - Configure/check GitHub settings (requires service token)
  - Path validation enforces `src/site/notes/` prefix for security
  - GitHub config loaded from file or environment variables on startup
  - Web UI admin panel at `/` for configuring GitHub token and repository
- 2026-02-05: Added `/debug/minio` endpoint for MinIO diagnostics (connection test, bucket listing)
- 2026-02-05: Fixed MinIO endpoint parsing - handles both with/without https:// prefix
- 2026-01-27: Added `/v1/chat` and `/v1/health` endpoints for Worker/UI with Bearer token auth (NOTEBOOKLM_SERVICE_TOKEN)
- 2026-01-27: Added `/v1/diagnostics/minio` endpoint for connectivity check and zone file listing
- 2026-01-27: Fixed notebooklm-py API - correct method is `sources.add_file(notebook_id, file_path, wait=True)`, no display_name parameter
- 2026-01-27: Fixed MinIO configuration - endpoint must be hostname only (without https://), added MINIO_SECURE=true, renamed MINIO_BUCKET_RAW to MINIO_BUCKET
- 2026-01-26: Fixed NotebookLM storage state path issue - notebooklm-py library expects file at ~/.notebooklm/storage_state.json, added sync functionality to copy from secrets/ on startup and after upload
- 2026-01-26: Initial Replit environment setup, configured to run on port 5000

## User Preferences
- None recorded yet

## Notes
- This server has NO API authentication - for internal/development use only
- Playwright/Chromium is required for NotebookLM client operations
- User must upload `storage_state.json` at `/auth` to enable API
