# NotebookLM Backend

A headless backend server for Google NotebookLM integration. Provides REST API for notebook operations without requiring a browser/GUI on the server.

## ⚠️ WARNING: NOT FOR PUBLIC PRODUCTION

**This server has NO API authentication.**

All endpoints are publicly accessible. Only run on:
- Localhost for development
- Internal networks with firewall protection
- Behind an authentication proxy (nginx, Traefik, etc.)

**Do NOT expose directly to the internet.**

---

## Features

- **Headless operation** - No browser/GUI needed on server
- **Web-based auth** - Upload cookies via web interface
- **REST API** - Create notebooks, import sources, chat
- **MinIO integration** - Import files from S3-compatible storage
- **Background jobs** - Async source import with retry/backoff
- **Idempotency** - Prevent duplicate imports with idempotency keys
- **CORS support** - Ready for React/frontend integration
- **Unified error format** - Consistent error responses

---

## Quick Start

### 1. Install dependencies

```bash
cd notebooklm-backend
python -m venv venv
source venv/bin/activate  # or: venv\Scripts\activate (Windows)

pip install -r requirements.txt
playwright install chromium
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your MinIO credentials
```

### 3. Get authentication cookies (on local machine with GUI)

```bash
# On your LOCAL machine (with browser)
pip install notebooklm-py playwright
playwright install chromium

# Login to Google
notebooklm login

# This creates storage_state.json in current directory
```

### 4. Start the server

```bash
# Development
python -m app.main

# Production
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 5. Upload cookies

Open http://localhost:8000/auth in browser and upload `storage_state.json`

Or via CLI:
```bash
curl -X POST http://localhost:8000/auth/upload \
  -F "file=@storage_state.json"
```

### 6. Verify

```bash
curl http://localhost:8000/auth/status
# {"ok": true, "message": "Authentication valid", "notebook_count": 5}
```

---

## API Usage

### Create a Notebook

```bash
curl -X POST http://localhost:8000/v1/notebooks \
  -H "Content-Type: application/json" \
  -d '{"title": "My Research Notebook"}'
```

Response:
```json
{
  "notebook_id": "abc123...",
  "notebook_url": "https://notebooklm.google.com/notebook/abc123...",
  "title": "My Research Notebook"
}
```

### Import Sources from MinIO

```bash
curl -X POST http://localhost:8000/v1/notebooks/{notebook_id}/sources/import \
  -H "Content-Type: application/json" \
  -d '{
    "sources": [
      {"type": "minio", "bucket": "raw", "key": "documents/report.pdf"},
      {"type": "url", "url": "https://example.com/article"}
    ],
    "idempotency_key": "import-abc-123"
  }'
```

Response:
```json
{
  "job_id": "uuid-here",
  "status": "queued",
  "notebook_url": "https://notebooklm.google.com/notebook/..."
}
```

**Idempotency:** Same `idempotency_key` returns existing job instead of creating duplicate.

### Check Import Job Status

```bash
curl http://localhost:8000/v1/jobs/{job_id}
```

Response:
```json
{
  "job_id": "...",
  "status": "completed",
  "progress": 100,
  "current_step": 2,
  "total_steps": 2,
  "notebook_url": "...",
  "results": [
    {
      "source": {"type": "minio", "bucket": "raw", "key": "report.pdf"},
      "status": "success",
      "source_id": "...",
      "retries": 0
    }
  ]
}
```

**Status values:** `queued` → `running` → `completed` | `failed`

### Chat with Notebook

```bash
curl -X POST http://localhost:8000/v1/notebooks/{notebook_id}/chat \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What are the main findings?",
    "system_prompt": "Answer in Ukrainian. Be concise.",
    "show_sources": true
  }'
```

Response:
```json
{
  "answer": "Основні висновки дослідження...",
  "references": [
    {
      "citation_number": 1,
      "source_title": "report.pdf",
      "cited_text": "The study found that..."
    }
  ]
}
```

### Share Notebook

```bash
curl -X POST http://localhost:8000/v1/notebooks/{notebook_id}/share \
  -H "Content-Type: application/json" \
  -d '{
    "emails": ["colleague@example.com"],
    "role": "reader"
  }'
```

**Note:** Sharing may not be supported by current notebooklm-py version. Returns 501 if unavailable.

---

## Error Format

All errors return unified format:

```json
{
  "error": {
    "code": "NOT_AUTHENTICATED",
    "message": "Upload storage_state.json at /auth",
    "details": {}
  }
}
```

**Error codes:**
- `NOT_AUTHENTICATED` - Need to upload cookies
- `VALIDATION_ERROR` - Invalid request data
- `NOT_FOUND` - Resource not found
- `NOTEBOOKLM_ERROR` - NotebookLM API error
- `MINIO_ERROR` - MinIO/S3 error
- `NOT_IMPLEMENTED` - Feature not available

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (always 200) |
| `/auth` | GET | Auth web interface |
| `/auth/upload` | POST | Upload storage_state.json |
| `/auth/status` | GET | Check auth status |
| `/v1/notebooks` | GET | List notebooks |
| `/v1/notebooks` | POST | Create notebook |
| `/v1/notebooks/{id}/sources` | GET | List sources |
| `/v1/notebooks/{id}/sources/import` | POST | Import sources (async) |
| `/v1/notebooks/{id}/share` | POST | Share notebook |
| `/v1/notebooks/{id}/chat` | POST | Chat with notebook |
| `/v1/jobs/{id}` | GET | Get job status |

Full API docs: http://localhost:8000/docs

---

## Configuration

Environment variables (`.env`):

```bash
# Server
PORT=8000
HOST=0.0.0.0

# MinIO
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_SECURE=false
MINIO_BUCKET_RAW=raw

# Paths
STORAGE_STATE_PATH=./secrets/storage_state.json
DATA_DIR=./data
JOBS_FILE=./data/jobs.json

# CORS (for React frontend)
CORS_ALLOW_ORIGINS=http://localhost:5173,http://localhost:3000
CORS_ALLOW_CREDENTIALS=true

# Limits
MAX_SOURCES_PER_IMPORT=20
MAX_FILE_SIZE_MB=50

# Job processing
JOB_MAX_RETRIES=3
JOB_RETRY_DELAY_SECONDS=5
JOB_TIMEOUT_SECONDS=120

# Idempotency
IDEMPOTENCY_TTL_SECONDS=3600
```

### Allowed file types

`.pdf`, `.txt`, `.md`, `.docx`, `.doc`, `.pptx`, `.ppt`, `.xlsx`, `.xls`, `.html`, `.htm`, `.epub`

---

## Architecture

```
notebooklm-backend/
├── app/
│   ├── main.py              # FastAPI app + CORS + error handlers
│   ├── config.py            # Configuration
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
├── data/                    # JSON state files (gitignored)
├── secrets/                 # Cookies (gitignored)
├── scripts/
│   └── local_login.md       # Login instructions
├── requirements.txt
├── .env.example
└── README.md
```

---

## For React Frontend (Lovable)

The API is ready for React integration:

1. **CORS enabled** - Configure `CORS_ALLOW_ORIGINS` in `.env`

2. **Job polling** - Use `useQuery` with `refetchInterval`:
```typescript
const { data } = useQuery({
  queryKey: ['job', jobId],
  queryFn: () => fetch(`/v1/jobs/${jobId}`).then(r => r.json()),
  refetchInterval: (data) =>
    data?.status === 'completed' || data?.status === 'failed'
      ? false
      : 2000,
});
```

3. **Error handling** - All errors have consistent `error.code` and `error.message`

4. **Idempotency** - Use `idempotency_key` for safe retries

---

## Limitations & TODOs

1. **No API authentication** - Add API keys or JWT for production
2. **Share endpoint** - May return 501 if not supported by notebooklm-py
3. **Single user** - One storage_state.json at a time
4. **Session expiry** - Cookies may expire; re-login periodically
5. **No rate limiting** - NotebookLM may have rate limits

---

## Troubleshooting

### 503 "Not authenticated"

Upload `storage_state.json` at `/auth`

### Import job stuck at "queued"

Check server logs. MinIO connection issues or NotebookLM errors.

### "Authentication failed" after upload

Session expired. Re-run `notebooklm login` on local machine.

### Job failed with timeout

Increase `JOB_TIMEOUT_SECONDS` in `.env` or check NotebookLM availability.

### Playwright browser errors

```bash
playwright install chromium
playwright install-deps chromium  # Linux only
```

---

## License

Internal use only. Not for redistribution.
