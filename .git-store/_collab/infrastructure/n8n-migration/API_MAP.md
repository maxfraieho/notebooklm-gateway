# API Map: Cloudflare Worker Endpoints

Повна карта всіх endpoints з Cloudflare Worker `infrastructure/cloudflare/worker/index.js`.

---

## Загальна статистика

- **Всього endpoints:** 28
- **Public (без auth):** 16
- **Protected (Owner JWT):** 12
- **Streaming:** 1 (SSE)
- **Stateful:** 1 (MCP JSON-RPC)

---

## CORS Configuration

```javascript
// Всі responses мають ці headers:
{
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Id, X-Zone-Id, X-Zone-Code',
  'Access-Control-Max-Age': '86400'
}
```

---

## Response Formats

### Success Response
```json
{
  "success": true,
  // ... data fields
}
```

### Error Response
```json
{
  "success": false,
  "error": "Human-readable message",
  "errorCode": "ERROR_CODE",        // optional
  "errorDetails": {}                 // optional
}
```

---

## PUBLIC ENDPOINTS

### 1. OPTIONS * (CORS Preflight)

```
Method: OPTIONS
Path: any
Auth: none
Response: 204 No Content + CORS headers
```

### 2. GET /health

```
Method: GET
Path: /health
Auth: none
Handler: handleHealth()

Response 200:
{
  "status": "ok",
  "version": "3.0",
  "timestamp": "2026-02-02T10:00:00.000Z",
  "features": ["rest-api", "mcp-jsonrpc", "sse-transport", "minio-storage"],
  "runtime": "vanilla-cloudflare-workers"
}
```

### 3. POST /auth/status

```
Method: POST
Path: /auth/status
Auth: none
Handler: handleAuthStatus()

Response 200:
{
  "success": true,
  "initialized": true,
  "notebookLMReady": true,
  "notebookLMMessage": "Authentication valid",
  "notebookCount": 5
}
```

### 4. POST /auth/setup

```
Method: POST
Path: /auth/setup
Auth: none
Handler: handleAuthSetup()

Request:
{
  "password": "your-password"
}

Response 200:
{
  "success": true
}

Error 400:
{
  "success": false,
  "error": "Already initialized"
}
```

### 5. POST /auth/login

```
Method: POST
Path: /auth/login
Auth: none
Handler: handleAuthLogin()

Request:
{
  "password": "your-password"
}

Response 200:
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

Error 401:
{
  "success": false,
  "error": "Invalid password"
}
```

### 6. POST /auth/refresh

```
Method: POST
Path: /auth/refresh
Auth: Bearer token (any valid)
Handler: handleAuthRefresh()

Headers:
  Authorization: Bearer <old-token>

Response 200:
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

Error 401:
{
  "success": false,
  "error": "Invalid or expired token"
}
```

### 7. POST /auth/validate

```
Method: POST
Path: /auth/validate
Auth: none
Handler: handleAuthValidate()

Request:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

Response 200:
{
  "success": true,
  "valid": true,
  "expiresAt": 1738500000000
}
```

### 8. GET /zones/validate/:zoneId

```
Method: GET
Path: /zones/validate/{zoneId}?code={accessCode}
Auth: none (but requires valid accessCode)
Handler: handleZonesValidate()

Query params:
  code: ACCESS-XXXXXXXX

Response 200:
{
  "success": true,
  "id": "abc12345",
  "name": "Zone Name",
  "description": "Zone description",
  "folders": ["path/to/folder/"],
  "noteCount": 10,
  "notes": [
    {
      "slug": "note-slug",
      "title": "Note Title",
      "content": "Note content...",
      "tags": ["tag1", "tag2"]
    }
  ],
  "expiresAt": 1738500000000,
  "accessType": "read"
}

Error 403:
{
  "success": false,
  "error": "Invalid access code"
}

Error 410:
{
  "success": false,
  "error": "Zone expired",
  "errorCode": "ZONE_EXPIRED",
  "errorDetails": { "expired": true }
}
```

### 9. GET /zones/:zoneId/notes

```
Method: GET
Path: /zones/{zoneId}/notes
Auth: none
Handler: handleZonesNotes()

Response 200:
{
  "success": true,
  "notes": [...],
  "expiresAt": "2026-02-03T10:00:00.000Z"
}
```

### 10. GET /zones/:zoneId/notebooklm

```
Method: GET
Path: /zones/{zoneId}/notebooklm
Auth: none
Handler: handleZoneNotebookLMStatus()

Response 200:
{
  "success": true,
  "zoneId": "abc12345",
  "notebooklm": {
    "notebookId": "notebook-uuid",
    "notebookUrl": "https://notebooklm.google.com/notebook/...",
    "importJobId": "job-uuid",
    "status": "completed",
    "createdAt": "2026-02-02T10:00:00.000Z",
    "lastError": null
  }
}
```

### 11. GET /zones/:zoneId/notebooklm/job/:jobId

```
Method: GET
Path: /zones/{zoneId}/notebooklm/job/{jobId}
Auth: none
Handler: handleZoneNotebookLMJobStatus()

Response 200 (proxied from NotebookLM backend):
{
  "job_id": "job-uuid",
  "status": "completed",
  "progress": 100,
  "current_step": 2,
  "total_steps": 2,
  "notebook_url": "https://notebooklm.google.com/notebook/...",
  "results": [...]
}
```

### 12. GET /comments/:articleSlug

```
Method: GET
Path: /comments/{articleSlug}
Auth: none (but owners see pending comments)
Handler: handleCommentsGet()

Response 200:
{
  "success": true,
  "comments": [
    {
      "id": "comment-uuid",
      "articleSlug": "article/path",
      "parentId": null,
      "author": {
        "id": "author-uuid",
        "name": "Guest",
        "domain": "exodus.pp.ua",
        "isOwner": false,
        "type": "human"
      },
      "content": "Comment text...",
      "createdAt": "2026-02-02T10:00:00.000Z",
      "updatedAt": null,
      "status": "approved",
      "origin": "local"
    }
  ],
  "total": 1
}
```

### 13. POST /comments/create

```
Method: POST
Path: /comments/create
Auth: none (but owner comments auto-approved)
Handler: handleCommentsCreate()

Headers (optional):
  X-Zone-Id: zone-id
  X-Zone-Code: ACCESS-XXXXXXXX

Request:
{
  "articleSlug": "article/path",
  "content": "Comment text",
  "parentId": null,
  "authorName": "Guest Name",
  "authorType": "human",
  "agentModel": null,
  "zoneId": "zone-id",
  "zoneCode": "ACCESS-XXXXXXXX"
}

Response 200:
{
  "success": true,
  "comment": {
    "id": "comment-uuid",
    ...
  }
}
```

### 14. GET /annotations/:articleSlug

```
Method: GET
Path: /annotations/{articleSlug}
Auth: none
Handler: handleAnnotationsGet()

Response 200:
{
  "success": true,
  "annotations": [
    {
      "id": "annotation-uuid",
      "articleSlug": "article/path",
      "highlightedText": "selected text",
      "startOffset": 100,
      "endOffset": 150,
      "paragraphIndex": 3,
      "commentId": "linked-comment-uuid",
      "createdAt": "2026-02-02T10:00:00.000Z",
      "createdBy": {...},
      "comment": {...}
    }
  ],
  "total": 1
}
```

### 15. POST /annotations/create

```
Method: POST
Path: /annotations/create
Auth: none
Handler: handleAnnotationsCreate()

Request:
{
  "articleSlug": "article/path",
  "highlightedText": "selected text",
  "startOffset": 100,
  "endOffset": 150,
  "paragraphIndex": 3,
  "content": "Optional comment",
  "authorName": "Guest",
  "authorType": "human"
}

Response 200:
{
  "success": true,
  "annotation": {...},
  "commentId": "comment-uuid-if-content-provided"
}
```

### 16. POST /mcp

```
Method: POST
Path: /mcp?session={sessionId}
Auth: session-based
Handler: handleMCPRPC()

Request (JSON-RPC 2.0):
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {}
}

Response 200:
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "serverInfo": {
      "name": "garden-mcp-server",
      "version": "3.0.0"
    },
    "capabilities": {
      "tools": {},
      "resources": {}
    }
  }
}

MCP Methods:
- initialize
- tools/list
- tools/call (search_notes, get_note, list_notes, get_tags)
- resources/list
- resources/read
```

### 17. GET /sse

```
Method: GET
Path: /sse?session={sessionId}
Auth: session-based
Handler: handleSSE()

Response: text/event-stream

Events:
event: open
data: {"status":"connected","sessionId":"session-uuid"}

event: message
data: {"jsonrpc":"2.0","method":"notifications/initialized",...}

:ping (every 30s)
```

---

## PROTECTED ENDPOINTS (Owner JWT Required)

All protected endpoints require:
```
Headers:
  Authorization: Bearer <owner-jwt-token>
```

### 18. POST /sessions/create

```
Method: POST
Path: /sessions/create
Auth: Owner JWT
Handler: handleSessionsCreate()

Request:
{
  "folders": ["path/to/"],
  "ttlMinutes": 60,
  "notes": [
    {
      "slug": "note-slug",
      "title": "Note Title",
      "content": "Note content",
      "tags": ["tag1"]
    }
  ]
}

Response 200:
{
  "success": true,
  "sessionId": "session-uuid",
  "sessionUrl": "https://host/mcp?session=session-uuid",
  "expiresAt": "2026-02-02T11:00:00.000Z",
  "noteCount": 1,
  "storage": "minio",
  "formats": {
    "json": "https://minio/bucket/sessions/uuid/notes.json",
    "jsonl": "https://minio/bucket/sessions/uuid/notes.jsonl",
    "markdown": "https://minio/bucket/sessions/uuid/notes.md"
  }
}
```

### 19. POST /sessions/revoke

```
Method: POST
Path: /sessions/revoke
Auth: Owner JWT
Handler: handleSessionsRevoke()

Request:
{
  "sessionId": "session-uuid"
}

Response 200:
{
  "success": true
}
```

### 20. GET /sessions/list

```
Method: GET
Path: /sessions/list
Auth: Owner JWT
Handler: handleSessionsList()

Response 200:
{
  "success": true,
  "message": "Use KV list API or maintain session index"
}
```

### 21. POST /zones/create

```
Method: POST
Path: /zones/create
Auth: Owner JWT
Handler: handleZonesCreate()

Request:
{
  "name": "Zone Name",
  "description": "Zone description",
  "allowedPaths": ["path/to/"],
  "ttlMinutes": 1440,
  "notes": [...],
  "accessType": "read",
  "createNotebookLM": true,
  "notebookTitle": "Optional title",
  "notebookShareEmails": ["email@example.com"],
  "notebookSourceMode": "minio"
}

Response 200:
{
  "success": true,
  "zoneId": "abc12345",
  "accessCode": "ACCESS-XXXXXXXX",
  "zoneUrl": "https://exodus.pp.ua/zone/abc12345",
  "expiresAt": "2026-02-03T10:00:00.000Z",
  "noteCount": 10,
  "notebooklm": {
    "notebookId": "notebook-uuid",
    "notebookUrl": "https://notebooklm.google.com/notebook/...",
    "importJobId": "job-uuid",
    "status": "queued"
  }
}
```

### 22. DELETE /zones/:zoneId

```
Method: DELETE
Path: /zones/{zoneId}
Auth: Owner JWT
Handler: handleZonesDelete()

Response 200:
{
  "success": true
}
```

### 23. GET /zones/list

```
Method: GET
Path: /zones/list
Auth: Owner JWT
Handler: handleZonesList()

Response 200:
{
  "success": true,
  "zones": [
    {
      "id": "abc12345",
      "name": "Zone Name",
      "description": "Description",
      "folders": ["path/"],
      "noteCount": 10,
      "accessType": "read",
      "createdAt": 1738400000000,
      "expiresAt": 1738500000000,
      "accessCode": "ACCESS-XXXXXXXX"
    }
  ]
}
```

### 24. POST /zones/:zoneId/notebooklm/retry-import

```
Method: POST
Path: /zones/{zoneId}/notebooklm/retry-import
Auth: Owner JWT
Handler: handleZoneNotebookLMRetryImport()

Response 200:
{
  "success": true,
  "zoneId": "abc12345",
  "notebooklm": {
    "notebookId": "notebook-uuid",
    "notebookUrl": "...",
    "importJobId": "new-job-uuid",
    "status": "queued"
  }
}
```

### 25. POST /notebooklm/chat

```
Method: POST
Path: /notebooklm/chat
Auth: Owner JWT
Handler: handleNotebookLMChat()

Request:
{
  "notebookUrl": "https://notebooklm.google.com/notebook/...",
  "message": "What is this about?",
  "kind": "answer",
  "history": [
    {"role": "user", "content": "Previous question"},
    {"role": "assistant", "content": "Previous answer"}
  ]
}

Response 200:
{
  "success": true,
  "answer": "This notebook contains...",
  "references": [...]
}
```

### 26. PATCH /comments/:commentId

```
Method: PATCH
Path: /comments/{commentId}
Auth: Owner JWT
Handler: handleCommentsUpdate()

Request:
{
  "status": "approved",
  "content": "Updated content"
}

Response 200:
{
  "success": true,
  "comment": {...}
}
```

### 27. DELETE /comments/:commentId

```
Method: DELETE
Path: /comments/{commentId}
Auth: Owner JWT
Handler: handleCommentsDelete()

Response 200:
{
  "success": true
}
```

### 28. DELETE /annotations/:annotationId

```
Method: DELETE
Path: /annotations/{annotationId}
Auth: Owner JWT
Handler: handleAnnotationsDelete()

Response 200:
{
  "success": true
}
```

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `JWT_SECRET` | Secret for JWT signing | `your-secret-key` |
| `MINIO_ENDPOINT` | MinIO S3 endpoint | `https://apiminio.exodus.pp.ua` |
| `MINIO_BUCKET` | MinIO bucket name | `garden-notes` |
| `MINIO_ACCESS_KEY` | MinIO access key | `access-key` |
| `MINIO_SECRET_KEY` | MinIO secret key | `secret-key` |
| `NOTEBOOKLM_BASE_URL` | NotebookLM backend | `https://notebooklm-gateway.replit.app` |
| `NOTEBOOKLM_TIMEOUT_MS` | Timeout for NotebookLM | `15000` |
| `NOTEBOOKLM_SERVICE_TOKEN` | Optional auth token | `token` |

---

## KV Storage Keys

| Pattern | Description | TTL |
|---------|-------------|-----|
| `owner_initialized` | Boolean flag | permanent |
| `owner_password_hash` | SHA256 hash | permanent |
| `session:{id}` | Session data | ttlMinutes |
| `zone:{id}` | Zone data | ttlMinutes |
| `zones:index` | Array of zone IDs | permanent |
| `zone_notebooklm:{id}` | NotebookLM mapping | ttlMinutes |
| `comment:{id}` | Comment data | permanent |
| `comments:index:{slug}` | Comment IDs for article | permanent |
| `annotation:{id}` | Annotation data | permanent |
| `annotations:index:{slug}` | Annotation IDs | permanent |
