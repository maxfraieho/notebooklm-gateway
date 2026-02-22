# Memory API Contract v1

> REST API specification for the DiffMem-like memory subsystem.

## Base Path

All memory endpoints are prefixed with `/v1/memory`.

Gateway proxy: `CF Worker /v1/memory/* → Replit backend /v1/memory/*`

## Authentication

All endpoints require `Authorization: Bearer <OWNER_TOKEN>` header (via gateway).

## Endpoints

---

### 1. Get Context

Assemble query-relevant context at varying depths.

```
POST /v1/memory/{userId}/context
```

**Request:**
```json
{
  "conversation": [
    { "role": "user", "content": "What projects am I working on?" }
  ],
  "depth": "wide",
  "entityTypes": ["project", "person"],
  "maxTokens": 5000
}
```

**Response (200):**
```json
{
  "success": true,
  "context": "## Projects\n\n### Garden Bloom\n...",
  "entities": [
    {
      "entityId": "projects/garden-bloom",
      "name": "Garden Bloom",
      "entityType": "project",
      "relevance": 0.92,
      "fullContent": true,
      "includesHistory": false
    }
  ],
  "tokenCount": 3200,
  "depth": "wide"
}
```

**Depth behavior:**
- `basic` — Returns ALWAYS_LOAD blocks from top-ranked entities
- `wide` — BM25 search over conversation + ALWAYS_LOAD blocks
- `deep` — Full file content of matched entities
- `temporal` — Full files + git diffs for last N commits

---

### 2. Search Memory

BM25 / semantic / hybrid search over current memory state.

```
POST /v1/memory/{userId}/search
```

**Request:**
```json
{
  "query": "garden bloom roadmap",
  "k": 5,
  "entityTypes": ["project", "concept"],
  "method": "bm25"
}
```

**Response (200):**
```json
{
  "success": true,
  "results": [
    {
      "entityId": "projects/garden-bloom",
      "name": "Garden Bloom",
      "entityType": "project",
      "score": 0.85,
      "snippet": "## Roadmap\n- Phase 1: Memory subsystem...",
      "filePath": "entities/projects/garden-bloom.md"
    }
  ],
  "query": "garden bloom roadmap",
  "method": "bm25",
  "totalEntities": 42
}
```

---

### 3. Orchestrated Search

LLM-powered search: LLM generates sub-queries, searches, and synthesizes an answer.

```
POST /v1/memory/{userId}/orchestrated-search
```

**Request:**
```json
{
  "conversation": [
    { "role": "user", "content": "What did I work on last week?" }
  ],
  "k": 5
}
```

**Response (200):**
```json
{
  "success": true,
  "answer": "Last week you focused on...",
  "subQueries": ["recent work", "last week activities", "project updates"],
  "sources": [
    { "entityId": "timelines/2026-02", "score": 0.9, "snippet": "..." }
  ]
}
```

---

### 4. Process and Commit

Process a transcript/input, extract entities, and commit to git in one step.

```
POST /v1/memory/{userId}/process-and-commit
```

**Request:**
```json
{
  "memoryInput": "Had a meeting with Alice about garden-bloom roadmap...",
  "sessionId": "session-2026-02-22",
  "sessionDate": "2026-02-22",
  "autoCommit": true
}
```

**Response (200):**
```json
{
  "success": true,
  "sessionId": "session-2026-02-22",
  "entitiesAffected": [
    { "entityId": "people/alice", "action": "updated", "name": "Alice" },
    { "entityId": "projects/garden-bloom", "action": "updated", "name": "Garden Bloom" }
  ],
  "commitSha": "a1b2c3d",
  "commitMessage": "memory: session-2026-02-22 — updated alice, garden-bloom"
}
```

---

### 5. Process Session (Stage Only)

Process transcript without committing. Changes are staged in git working tree.

```
POST /v1/memory/{userId}/process-session
```

Same request as process-and-commit, but `autoCommit` is ignored (always false).

**Response (200):**
```json
{
  "success": true,
  "sessionId": "session-002",
  "entitiesAffected": [
    { "entityId": "people/alice", "action": "updated", "name": "Alice" }
  ]
}
```

---

### 6. Commit Session

Commit previously staged changes.

```
POST /v1/memory/{userId}/commit-session
```

**Request:**
```json
{
  "sessionId": "session-002",
  "message": "Updated Alice's profile after meeting"
}
```

**Response (200):**
```json
{
  "success": true,
  "sessionId": "session-002",
  "commitSha": "d4e5f6g",
  "commitMessage": "Updated Alice's profile after meeting",
  "filesChanged": 2
}
```

---

### 7. Get Entity

Read a single memory entity by ID.

```
GET /v1/memory/{userId}/entity/{entityId}
```

**Response (200):**
```json
{
  "success": true,
  "entity": {
    "entityId": "people/alice",
    "entityType": "person",
    "name": "Alice Johnson",
    "content": "# Alice Johnson\n\n...",
    "tags": ["colleague", "product-manager"],
    "updatedAt": 1740000000000,
    "createdAt": 1735000000000,
    "commitCount": 12
  }
}
```

---

### 8. Get Entity Diff

Get git diffs for an entity.

```
POST /v1/memory/{userId}/diff
```

**Request:**
```json
{
  "entityId": "people/alice",
  "depth": 3,
  "since": "2026-02-01",
  "until": "2026-02-22"
}
```

**Response (200):**
```json
{
  "success": true,
  "entityId": "people/alice",
  "diffs": [
    {
      "commitSha": "a1b2c3d",
      "commitMessage": "memory: session-005",
      "author": "agent",
      "date": 1740000000000,
      "diff": "@@ -10,3 +10,5 @@\n+### 2026-02-20\n+- Discussed roadmap",
      "additions": 2,
      "deletions": 0
    }
  ]
}
```

---

### 9. Get User Status

```
GET /v1/memory/{userId}/status
```

**Response (200):**
```json
{
  "success": true,
  "userId": "garden-owner",
  "initialized": true,
  "entityCount": 42,
  "lastCommitAt": 1740000000000,
  "repoSize": 524288,
  "indexStatus": "ready"
}
```

---

### 10. Recent Timeline

```
GET /v1/memory/{userId}/recent-timeline?daysBack=30&limit=50
```

**Response (200):**
```json
{
  "success": true,
  "entries": [
    {
      "date": "2026-02-22",
      "commitSha": "a1b2c3d",
      "commitMessage": "memory: session-010",
      "entitiesAffected": [
        { "entityId": "people/alice", "name": "Alice", "action": "updated" }
      ]
    }
  ],
  "period": { "from": "2026-01-23", "to": "2026-02-22" }
}
```

---

### 11. Onboard User

Initialize memory repo for a new user.

```
POST /v1/memory/{userId}/onboard
```

**Request:**
```json
{
  "userInfo": "Garden owner, digital garden enthusiast, focuses on knowledge management",
  "sessionId": "onboard-001"
}
```

**Response (200):**
```json
{
  "success": true,
  "userId": "garden-owner",
  "sessionId": "onboard-001",
  "entitiesCreated": 3
}
```

---

### 12. Sync with Remote

```
POST /v1/memory/sync
```

**Response (200):**
```json
{
  "success": true,
  "syncStatus": "synced",
  "commitsAhead": 0,
  "commitsBehind": 0,
  "lastSyncAt": 1740000000000
}
```

---

### 13. Health Check

```
GET /v1/memory/health
```

**Response (200):**
```json
{
  "ok": true,
  "gitReady": true,
  "indexReady": true,
  "entityCount": 42,
  "uptime": 3600
}
```

---

## Error Responses

All errors follow the standard Garden Bloom error format:

```json
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "Entity 'people/unknown' not found in memory"
  }
}
```

Standard error codes: see `src/types/mcpGateway.ts` → `GatewayErrorCode`.

## Rate Limits

- Context/Search: 30 req/min per user
- Process/Commit: 10 req/min per user
- Orchestrated search: 5 req/min per user (LLM-intensive)

## Polling

- Memory status: 30s interval
- Sync status: 60s interval
- No SSE/WebSocket for MVP (polling-first strategy)
