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
- `/v1/notebooks/{id}/chat` - Chat with notebook

## Configuration
Environment variables are configured in `.env.example`. Key settings:
- `PORT`: Server port (default: 5000)
- `MINIO_*`: MinIO/S3 connection settings
- `STORAGE_STATE_PATH`: Path to Google auth cookies
- `CORS_ALLOW_ORIGINS`: Allowed CORS origins

## Recent Changes
- 2026-01-26: Initial Replit environment setup, configured to run on port 5000

## User Preferences
- None recorded yet

## Notes
- This server has NO API authentication - for internal/development use only
- Playwright/Chromium is required for NotebookLM client operations
- User must upload `storage_state.json` at `/auth` to enable API
