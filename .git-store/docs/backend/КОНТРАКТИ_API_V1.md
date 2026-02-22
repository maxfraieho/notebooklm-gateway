---
tags:
  - domain:api
  - status:canonical
  - format:contract
created: 2026-02-15
updated: 2026-02-21
tier: 1
title: "КОНТРАКТИ API V1"
dg-publish: true
dg-metatags:
dg-home:
---

# API Contracts V1

> Створено: 2026-02-15
> Автор: Головний архітектор системи
> Статус: Специфікація (канонічна)
> Мова: Українська (канонічна)
> Джерела: INBOX_ТА_PROPOSAL_АРХІТЕКТУРА.md §6, КАНОНІЧНА_АРХІТЕКТУРА_ВИКОНАННЯ.md §2.5, LOVABLE_УЗГОДЖЕННЯ.md §2–4

---

## 0. Загальні правила

### 0.1 Base URL

```
https://garden-api.exodus.pp.ua
```

Усі endpoints проксюються через Cloudflare Worker. Frontend використовує `mcpGatewayClient.ts` як єдиний клієнт.

### 0.2 Автентифікація

| Тип | Header | Опис |
|-----|--------|------|
| Owner | `Authorization: Bearer <JWT>` | Повний доступ |
| Zone Guest | `X-Zone-Code: ZONE-XXXX-YYYY` | Обмежений доступ до зони |
| Agent | `X-Agent-Identity: agent:<slug>` + internal HMAC | Тільки з runtime |
| Webhook | HMAC signature у body | Зареєстроване джерело |

### 0.3 Загальні правила

| Правило | Опис |
|---------|------|
| **Content-Type** | `application/json` для всіх request/response |
| **Idempotency** | Мутуючі операції ідемпотентні за `id` або `correlationId` |
| **Rate limit** | 60 req/min per identity (Owner), 20 req/min (Agent), 10 req/min (Webhook) |
| **Correlation ID** | Опціональний header `X-Correlation-Id` для tracing |
| **Error format** | Єдиний формат помилок (див. §0.4) |
| **Timestamps** | Усі timestamps у ISO 8601 UTC |

### 0.4 Error Response

```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Intent action not in agent safe_outputs",
    "details": {
      "field": "intent.action",
      "value": "propose-delete",
      "allowed": ["propose-edit", "propose-summary"]
    }
  },
  "correlationId": "corr_abc123"
}
```

| HTTP Status | Коли |
|-------------|------|
| 400 | Невалідний request body |
| 401 | Відсутній або невалідний JWT/token |
| 403 | Недостатні права (Guest → Owner-only endpoint) |
| 404 | Resource не знайдено |
| 409 | Конфлікт (concurrent modification, invalid state transition) |
| 429 | Rate limit перевищено |
| 500 | Internal server error |
| 502 | Upstream error (MinIO, Orchestration Layer недоступні) |

---

## 1. Inbox

### 1.1 POST /inbox/submit

Створити Inbox Entry (намір змінити стан системи).

**Auth:** Owner (JWT) | Zone Guest (zone code) | Agent (identity)

**Request:**

```json
{
  "intent": {
    "action": "propose-edit",
    "target": "notes/violin.pp.ua/sonata-bwv1001",
    "payload": {
      "diff": {
        "type": "append",
        "position": "after-frontmatter",
        "text": "## Резюме\n\nСоната BWV 1001..."
      },
      "reasoning": "Нотатка не має резюме",
      "citations": [
        {"source": "violin-taxonomy.md", "quote": "BWV 1001 — перша соната..."}
      ]
    }
  },
  "metadata": {
    "correlation_id": "run_2026-02-14_080000_abc123",
    "priority": "normal"
  }
}
```

**Response (202 Accepted):**

```json
{
  "inbox_id": "inbox_2026-02-14_abc123",
  "status": "pending",
  "proposal_id": "prop_2026-02-14_xyz789",
  "correlationId": "run_2026-02-14_080000_abc123"
}
```

**Примітка:** Якщо auto-approve rule matched — `proposal_id` одразу повертається зі статусом `auto_approved`. UI може перевірити через GET /proposals/{id}.

---

### 1.2 GET /inbox/stats

Статистика Inbox.

**Auth:** Owner

**Response (200 OK):**

```json
{
  "pending": 3,
  "processed_today": 12,
  "rejected_today": 1,
  "expired_today": 0
}
```

---

### 1.3 GET /inbox/entries

Список Inbox entries.

**Auth:** Owner

**Query params:**

| Param | Тип | Default | Опис |
|-------|-----|---------|------|
| `status` | string | `pending` | Фільтр: `pending`, `processed`, `rejected`, `expired` |
| `limit` | number | 20 | Кількість записів |
| `offset` | number | 0 | Зміщення для пагінації |

**Response (200 OK):**

```json
{
  "entries": [
    {
      "id": "inbox_2026-02-14_abc123",
      "source": {
        "type": "agent",
        "identity": "agent:archivist-violin"
      },
      "intent": {
        "action": "propose-summary",
        "target": "notes/violin.pp.ua/sonata-bwv1001"
      },
      "metadata": {
        "priority": "normal",
        "ttl_hours": 72,
        "correlation_id": "run_2026-02-14_080000_abc123"
      },
      "status": "pending",
      "created_at": "2026-02-14T12:00:00Z",
      "proposal_id": null
    }
  ],
  "total": 3,
  "limit": 20,
  "offset": 0
}
```

---

## 2. Agent Run

### 2.1 POST /agents/run

Ініціювати виконання агента.

**Auth:** Owner

**Request:**

```json
{
  "agent_slug": "archivist-violin",
  "params": {
    "target_folder": "violin.pp.ua",
    "max_notes": 5
  }
}
```

**Response (200 OK):**

```json
{
  "run_id": "run_2026-02-14_080000_abc123",
  "agent_slug": "archivist-violin",
  "status": "requested",
  "correlationId": "run_2026-02-14_080000_abc123"
}
```

---

### 2.2 GET /runs/{runId}/status

Поточний статус виконання.

**Auth:** Owner

**Response (200 OK):**

```json
{
  "run_id": "run_2026-02-14_080000_abc123",
  "agent_slug": "archivist-violin",
  "status": "running",
  "trigger": "manual",
  "started_at": "2026-02-14T08:00:00Z",
  "finished_at": null,
  "current_step": "nlm-query",
  "steps_total": 4,
  "steps_completed": 2,
  "proposals_created": [],
  "error": null
}
```

Коли `status: "queued"`:

```json
{
  "run_id": "run_2026-02-14_090000_def456",
  "agent_slug": "archivist-violin",
  "status": "queued",
  "trigger": "manual",
  "started_at": null,
  "finished_at": null,
  "current_step": null,
  "steps_total": null,
  "steps_completed": 0,
  "proposals_created": [],
  "error": null,
  "queue_position": 2
}
```

---

### 2.3 GET /runs/{runId}/steps

Покрокові результати виконання.

**Auth:** Owner

**Response (200 OK):**

```json
{
  "run_id": "run_2026-02-14_080000_abc123",
  "steps": [
    {
      "step_number": 1,
      "step_name": "load-context",
      "status": "completed",
      "started_at": "2026-02-14T08:00:01Z",
      "finished_at": "2026-02-14T08:00:03Z",
      "duration_ms": 2100,
      "output_summary": "Завантажено 5 джерел з sources/",
      "error": null
    },
    {
      "step_number": 2,
      "step_name": "nlm-query",
      "status": "running",
      "started_at": "2026-02-14T08:00:04Z",
      "finished_at": null,
      "duration_ms": null,
      "output_summary": null,
      "error": null
    },
    {
      "step_number": 3,
      "step_name": "create-proposal",
      "status": "pending",
      "started_at": null,
      "finished_at": null,
      "duration_ms": null,
      "output_summary": null,
      "error": null
    }
  ]
}
```

---

## 3. Proposals

### 3.1 GET /proposals/pending

Список proposals, що очікують рішення.

**Auth:** Owner

**Query params:**

| Param | Тип | Default | Опис |
|-------|-----|---------|------|
| `agent` | string | — | Фільтр за agent slug |
| `action` | string | — | Фільтр за action type |
| `limit` | number | 20 | Кількість |
| `offset` | number | 0 | Зміщення |

**Response (200 OK):**

```json
{
  "proposals": [
    {
      "id": "prop_2026-02-14_xyz789",
      "status": "pending",
      "created_at": "2026-02-14T12:00:05Z",
      "expires_at": "2026-02-17T12:00:05Z",
      "source": {
        "type": "agent",
        "identity": "agent:archivist-violin",
        "run_id": "run_2026-02-14_080000_abc123"
      },
      "action": "propose-summary",
      "target": {
        "type": "note",
        "path": "notes/violin.pp.ua/sonata-bwv1001.md"
      },
      "content": {
        "summary": "Додати структуроване резюме нотатки BWV 1001"
      }
    }
  ],
  "total": 5,
  "limit": 20,
  "offset": 0
}
```

---

### 3.2 GET /proposals/{id}

Повні деталі proposal (для detail/review view).

**Auth:** Owner

**Response (200 OK):**

```json
{
  "id": "prop_2026-02-14_xyz789",
  "inbox_entry_id": "inbox_2026-02-14_abc123",
  "status": "pending",
  "created_at": "2026-02-14T12:00:05Z",
  "updated_at": "2026-02-14T12:00:05Z",
  "expires_at": "2026-02-17T12:00:05Z",

  "source": {
    "type": "agent",
    "identity": "agent:archivist-violin",
    "run_id": "run_2026-02-14_080000_abc123"
  },

  "action": "propose-summary",
  "target": {
    "type": "note",
    "path": "notes/violin.pp.ua/sonata-bwv1001.md"
  },

  "content": {
    "summary": "Додати структуроване резюме нотатки BWV 1001",
    "diff": {
      "type": "append",
      "position": "after-frontmatter",
      "text": "## Резюме\n\nСоната BWV 1001 для скрипки соло..."
    },
    "reasoning": "Нотатка не має резюме. NotebookLM підтвердив ключові тези на основі 3 джерел.",
    "citations": [
      {
        "source": "violin-taxonomy.md",
        "quote": "BWV 1001 — перша соната для скрипки соло, Adagio-Fuga-Siciliana-Presto"
      }
    ]
  },

  "approval": {
    "decided_by": null,
    "decided_at": null,
    "decision_note": null
  },

  "apply_result": {
    "git_commit": null,
    "minio_path": null,
    "error": null
  },

  "base_revision": "abc123def",
  "target_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb924"
}
```

---

### 3.3 PATCH /proposals/{id}

Approve або Reject proposal.

**Auth:** Owner

**Request (approve):**

```json
{
  "status": "approved",
  "decision_note": "Якість резюме задовільна"
}
```

**Request (reject):**

```json
{
  "status": "rejected",
  "decision_note": "Резюме не відображає ключову тезу про аплікатуру"
}
```

**Правила:**

| Поточний status | Дозволені transitions | Примітка |
|-----------------|----------------------|----------|
| `pending` | `approved`, `rejected` | Нормальний шлях |
| `failed` | `rejected` | Owner скасовує failed proposal |
| `approved` | — | Не можна змінити після approval |
| `applied` | — | Не можна змінити |
| `rejected` | — | Final state |

**Response (200 OK):**

```json
{
  "id": "prop_2026-02-14_xyz789",
  "status": "approved",
  "approval": {
    "decided_by": "owner",
    "decided_at": "2026-02-14T14:30:00Z",
    "decision_note": "Якість резюме задовільна"
  }
}
```

**Error (409 Conflict):**

```json
{
  "error": {
    "code": "INVALID_TRANSITION",
    "message": "Cannot transition from 'applied' to 'rejected'"
  }
}
```

---

### 3.4 GET /proposals/history

Архів обробленних proposals.

**Auth:** Owner

**Query params:**

| Param | Тип | Default | Опис |
|-------|-----|---------|------|
| `status` | string | `applied,rejected` | Фільтр за статусом |
| `agent` | string | — | Фільтр за agent slug |
| `from` | string | — | ISO 8601 date, від |
| `to` | string | — | ISO 8601 date, до |
| `limit` | number | 20 | Кількість |
| `offset` | number | 0 | Зміщення |

**Response:** Аналогічний GET /proposals/pending.

---

### 3.5 PATCH /proposals/batch

Масове approve/reject кількох proposals за один запит.

**Auth:** Owner

**Request:**

```json
{
  "proposal_ids": [
    "prop_2026-02-14_xyz789",
    "prop_2026-02-14_abc456",
    "prop_2026-02-14_def012"
  ],
  "status": "approved",
  "decision_note": "Масове схвалення — пакет violin summaries"
}
```

**Правила:**

| Поле | Обов'язкове | Опис |
|------|-------------|------|
| `proposal_ids` | Так | Масив ID (1–50). Понад 50 → 400 |
| `status` | Так | `approved` або `rejected` |
| `decision_note` | При reject | Обов'язковий при `rejected`, опціональний при `approved` |

**Поведінка:**
- Кожен proposal обробляється **незалежно**. Якщо один proposal не може перейти у запитаний стан (наприклад, уже `applied`), він потрапляє у `errors`, але інші обробляються.
- Операція **не є транзакцією** — часткове виконання можливе.
- Idempotency: повторний batch з тим самим набором → ті ж proposals залишаються у тому ж стані.

**Response (200 OK):**

```json
{
  "updated": 2,
  "skipped": 1,
  "errors": [
    {
      "proposal_id": "prop_2026-02-14_def012",
      "code": "INVALID_TRANSITION",
      "message": "Cannot transition from 'applied' to 'approved'"
    }
  ]
}
```

**Error (400 Bad Request):**

```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "proposal_ids must contain 1–50 items",
    "details": {
      "field": "proposal_ids",
      "count": 0
    }
  }
}
```

---

## 4. Artifacts

### 4.1 GET /runs/{runId}/artifacts

Артефакти, створені під час run.

**Auth:** Owner

**Response (200 OK):**

```json
{
  "run_id": "run_2026-02-14_080000_abc123",
  "artifacts": [
    {
      "name": "proposal-summary-sonata-bwv1001.json",
      "type": "application/json",
      "size_bytes": 2048,
      "created_at": "2026-02-14T08:02:30Z",
      "download_url": "/runs/run_2026-02-14_080000_abc123/artifacts/proposal-summary-sonata-bwv1001.json"
    }
  ]
}
```

---

### 4.2 GET /runs/{runId}/artifacts/{filename}

Завантажити конкретний артефакт.

**Auth:** Owner

**Response:** Binary content з відповідним Content-Type.

---

## 5. Agents

### 5.1 GET /agents

Список зареєстрованих агентів.

**Auth:** Owner

**Response (200 OK):**

```json
{
  "agents": [
    {
      "slug": "archivist-violin",
      "name": "Архіваріус Violin",
      "status": "active",
      "version": "1.2.0",
      "description": "Аналізує нові нотатки та створює резюме",
      "last_run": "2026-02-14T08:00:00Z",
      "last_run_status": "completed",
      "pending_proposals": 2
    }
  ]
}
```

---

### 5.2 GET /agents/{slug}

Деталі агента (parsed `_agent.md`).

**Auth:** Owner

**Response (200 OK):**

```json
{
  "slug": "archivist-violin",
  "name": "Архіваріус Violin",
  "version": "1.2.0",
  "description": "Аналізує нові нотатки та створює резюме",
  "status": "active",
  "model": "claude-sonnet-4-5-20250929",
  "tools": ["notebooklm-query", "read-context", "read-notes", "create-proposal"],
  "safe_outputs": ["propose-summary", "propose-tag"],
  "triggers": {
    "manual": true,
    "cron": "0 8 * * 1-5",
    "events": ["note/created"]
  },
  "context": {
    "folder": "violin.pp.ua",
    "max_sources": 5,
    "notebook_id": "nb_violin_main"
  },
  "created_at": "2026-02-01T10:00:00Z",
  "updated_at": "2026-02-14T12:00:00Z",
  "generated_from": "main-flow.drakon.json"
}
```

### 5.3 PATCH /agents/{slug}/status

Змінити lifecycle-статус агента (activate, pause, resume).

**Auth:** Owner

**[РІШЕННЯ]** Замість окремих `POST /agents/:id/activate` та `PATCH /agents/:id` — один endpoint зі зміною `status`. Це канонічний варіант; інші згадки у документах є shorthand для цього endpoint.

**Request:**

```json
{
  "status": "active",
  "reason": "Агент протестований, готовий до production"
}
```

**Дозволені transitions:**

| Поточний status | Дозволені transitions | Примітка |
|-----------------|----------------------|----------|
| `draft` | `active` | Activation Gate: Owner підтверджує agent definition |
| `active` | `paused` | Тимчасова зупинка (cron не тригериться, manual run заборонений) |
| `paused` | `active` | Відновлення роботи |
| `active`, `paused` | `archived` | Повне вимкнення (незворотне без re-registration) |
| `error` | `active`, `paused` | Відновлення після помилки з Owner confirmation |
| `archived` | — | Final state |

**Response (200 OK):**

```json
{
  "slug": "archivist-violin",
  "status": "active",
  "previous_status": "draft",
  "changed_at": "2026-02-14T15:00:00Z",
  "changed_by": "owner",
  "reason": "Агент протестований, готовий до production"
}
```

**Error (409 Conflict):**

```json
{
  "error": {
    "code": "INVALID_AGENT_TRANSITION",
    "message": "Cannot transition from 'archived' to 'active'"
  }
}
```

---

## 6. Run History

### 6.1 GET /runs

Список runs з фільтрацією (історія виконань).

**Auth:** Owner

**Query params:**

| Param | Тип | Default | Опис |
|-------|-----|---------|------|
| `agent` | string | — | Фільтр за agent slug |
| `status` | string | — | Фільтр: `requested`, `queued`, `running`, `completed`, `failed` |
| `from` | string | — | ISO 8601 date, від |
| `to` | string | — | ISO 8601 date, до |
| `limit` | number | 20 | Кількість (макс. 100) |
| `offset` | number | 0 | Зміщення для пагінації |

**Response (200 OK):**

```json
{
  "runs": [
    {
      "run_id": "run_2026-02-14_080000_abc123",
      "agent_slug": "archivist-violin",
      "status": "completed",
      "trigger": "manual",
      "started_at": "2026-02-14T08:00:00Z",
      "finished_at": "2026-02-14T08:05:30Z",
      "duration_ms": 330000,
      "steps_total": 4,
      "steps_completed": 4,
      "proposals_created": ["prop_2026-02-14_xyz789"],
      "error": null
    },
    {
      "run_id": "run_2026-02-13_080000_def456",
      "agent_slug": "archivist-violin",
      "status": "failed",
      "trigger": "cron",
      "started_at": "2026-02-13T08:00:00Z",
      "finished_at": "2026-02-13T08:02:10Z",
      "duration_ms": 130000,
      "steps_total": 4,
      "steps_completed": 2,
      "proposals_created": [],
      "error": "NLM_UNAVAILABLE: NotebookLM API returned 503"
    }
  ],
  "total": 15,
  "limit": 20,
  "offset": 0
}
```

**Приклади запитів:**

```
GET /runs?agent=archivist-violin&limit=10
GET /runs?status=failed&from=2026-02-01
GET /runs?agent=archivist-violin&status=completed&from=2026-02-10&to=2026-02-14
```

---

## 7. Idempotency та Correlation

### 7.1 Correlation ID

**[РІШЕННЯ]** Усі мутуючі operations приймають `X-Correlation-Id` header або `correlationId` у body. Це дозволяє:

- Tracing крізь Inbox → Proposal → Apply
- Дедуплікацію (той самий correlationId = ідемпотентність)
- Зв'язування run → proposal → apply у логах

### 7.2 Idempotency

| Endpoint | Ідемпотентність | Ключ |
|----------|-----------------|------|
| POST /inbox/submit | Так (за correlationId) | `correlationId` |
| POST /agents/run | Так (за correlationId) | `correlationId` |
| PATCH /proposals/{id} | Так (за id + status) | `id` + `status` |

Повторний POST /inbox/submit з тим самим `correlationId` повертає 200 з існуючим `inbox_id`.

### 7.3 Rate Limiting

| Identity | Ліміт | Вікно | Response при перевищенні |
|----------|-------|-------|------------------------|
| Owner | 60 req/min | Sliding window | 429 + `Retry-After` header |
| Agent | 20 req/min | Sliding window | 429 |
| Webhook | 10 req/min | Sliding window | 429 |
| Zone Guest | 30 req/min | Sliding window | 429 |

---

## Appendix A: Error Codes (enum)

Консолідований перелік `error.code` значень, що використовуються у `error.code` поле відповідей (§0.4).

| error.code | HTTP | Retryable | Category | Опис |
|------------|------|-----------|----------|------|
| `VALIDATION_FAILED` | 400 | Ні | Client | Невалідні поля в request body |
| `INVALID_JSON` | 400 | Ні | Client | Malformed JSON у body |
| `AUTH_REQUIRED` | 401 | Ні | Auth | Відсутній або невалідний auth token |
| `TOKEN_EXPIRED` | 401 | Ні (refresh) | Auth | JWT expired; клієнт має оновити token |
| `FORBIDDEN` | 403 | Ні | Auth | Недостатні права для операції |
| `NOT_FOUND` | 404 | Ні | Client | Resource не знайдено |
| `INVALID_TRANSITION` | 409 | Ні | Conflict | Proposal state transition не дозволений (§3.3) |
| `INVALID_AGENT_TRANSITION` | 409 | Ні | Conflict | Agent status transition не дозволений (§5.3) |
| `CONCURRENT_MODIFICATION` | 409 | Так (retry) | Conflict | Target змінено іншим процесом (optimistic concurrency) |
| `DUPLICATE_ENTRY` | 409 | Ні | Conflict | Entry з таким correlationId вже існує |
| `RATE_LIMITED` | 429 | Так (backoff) | Throttle | Rate limit перевищено; див. `Retry-After` header |
| `INTERNAL_ERROR` | 500 | Так (retry) | Server | Непередбачена серверна помилка |
| `UPSTREAM_UNAVAILABLE` | 502 | Так (retry) | Server | MinIO, Orchestration Layer або FastAPI недоступні |
| `NLM_UNAVAILABLE` | 502 | Так (retry) | Server | NotebookLM API недоступний |
| `AGENT_TIMEOUT` | 504 | Так (retry) | Server | Agent run перевищив максимальний час виконання |

**Retryable:** "Так" означає, що клієнт може повторити запит після pause/backoff. "Так (retry)" — retry з тим самим payload. "Так (backoff)" — retry з exponential backoff. "Ні (refresh)" — потрібна дія користувача (оновлення token).

**Category:**
- `Client` — помилка в запиті клієнта; виправити request
- `Auth` — проблема автентифікації/авторизації
- `Conflict` — конфлікт стану; перечитати ресурс та повторити
- `Throttle` — перевищено ліміти; зачекати
- `Server` — серверна проблема; retry з backoff

---

## Appendix B: SSE Event Stream (post-MVP)

**[РІШЕННЯ]** SSE (Server-Sent Events) endpoint **відкладено на post-MVP**. MVP використовує polling (§3.1 у INBOX_ТА_ЦИКЛ_ЗАПУСКУ_V1.md).

**Причина відкладення:**
- Polling достатній для MVP use case (один Owner, 1–3 активних runs)
- SSE вимагає persistent connection management у Cloudflare Worker (Workers мають 30s execution limit без Durable Objects)
- Клієнт повинен підтримувати graceful fallback до polling

**Майбутній endpoint (не реалізовувати зараз):**

```
GET /events/stream
Accept: text/event-stream
Authorization: Bearer <JWT>
```

**Очікувані event types (draft, не фіналізовані):**

| event.type | Payload | Опис |
|------------|---------|------|
| `run.status.changed` | `{run_id, status, agent_slug}` | Run змінив стан |
| `run.step.completed` | `{run_id, step_number, step_name}` | Крок run завершено |
| `proposal.created` | `{proposal_id, agent_slug, action}` | Новий proposal |
| `proposal.status.changed` | `{proposal_id, status}` | Proposal змінив стан |
| `inbox.new` | `{count}` | Нові Inbox entries |

**[ОБМЕЖЕННЯ]** Lovable **НЕ ПОВИНЕН** імплементувати SSE клієнт для MVP. Ці типи подій наведені лише для планування. Формалізація schema відбудеться при переході до SSE-реалізації.

**Fallback:** Якщо SSE буде реалізований post-MVP, клієнт повинен:
1. Спробувати SSE connection
2. При помилці/timeout — fallback до polling з інтервалами з §3.1 INBOX_ТА_ЦИКЛ_ЗАПУСКУ_V1.md
3. Не показувати користувачу різницю між SSE та polling

---

## Appendix C — Non-Proposal Gateway Endpoints

Canonical Gateway Endpoints — stable, vendor-agnostic.

| Method | Endpoint | Auth | Опис |
|--------|----------|------|------|
| GET | `/comments/{slug}` | Owner / Zone Guest | Коментарі до нотатки |
| POST | `/comments/create` | Owner / Zone Guest | Створити коментар |
| PATCH | `/comments/{id}` | Owner | Оновити коментар |
| DELETE | `/comments/{id}` | Owner | Видалити коментар |
| GET | `/annotations/{slug}` | Owner | Анотації до нотатки |
| POST | `/annotations/create` | Owner / Zone Guest | Створити анотацію |
| DELETE | `/annotations/{id}` | Owner | Видалити анотацію |
| POST | `/sessions/create` | Owner | Створити MCP сесію |
| POST | `/sessions/revoke` | Owner | Відкликати MCP сесію |
| GET | `/zones/validate/{id}` | Public | Валідація зони за кодом |
| GET | `/zones/list` | Owner | Список зон |
| DELETE | `/zones/{id}` | Owner | Видалити зону |
| POST | `/auth/*` | Public | Автентифікація |
| POST | `/v1/notes/commit` | Owner | Створити/оновити нотатку через GitHub |
| DELETE | `/v1/notes/{slug}` | Owner | Видалити нотатку через GitHub |
| POST | `/v1/drakon/commit` | Owner | Створити/оновити DRAKON діаграму |

---

## Семантичні зв'язки

**Цей документ деталізує:**
- [[КАНОНІЧНА_АРХІТЕКТУРА_ВИКОНАННЯ]] — HTTP interface до Runtime Architecture компонентів
- [[INBOX_ТА_PROPOSAL_АРХІТЕКТУРА]] — REST endpoints для Proposal lifecycle (§1–§3.3)

**Цей документ залежить від:**
- [[INBOX_ТА_PROPOSAL_АРХІТЕКТУРА]] — повна специфікація Proposal lifecycle
- [[INBOX_ТА_ЦИКЛ_ЗАПУСКУ_V1]] — state machines для UI-орієнтованого lifecycle
- [[БЕЗПЕКА_СИСТЕМИ]] — auth headers, rate limiting policies (§0.2, §7.3)
- [[КАНОНІЧНА_МОДЕЛЬ_АВТОРИТЕТУ_СХОВИЩА]] — authority model (хто має право на write endpoints)

**Від цього документа залежать:**
- [[LOVABLE_УЗГОДЖЕННЯ_З_АРХІТЕКТУРОЮ_ВИКОНАННЯ]] — frontend invariants на основі цих API contracts
- [[ДИРЕКТИВА_УЗГОДЖЕННЯ_FRONTEND_V1]] — критичні невідповідності UI з цими contracts

---

## Див. також

- **INBOX_ТА_PROPOSAL_АРХІТЕКТУРА.md** — повна специфікація lifecycle
- **INBOX_ТА_ЦИКЛ_ЗАПУСКУ_V1.md** — state machines для UI
- **СИСТЕМА_PROPOSAL_V1.md** — proposal semantics для UI
- **LOVABLE_УЗГОДЖЕННЯ_З_АРХІТЕКТУРОЮ_ВИКОНАННЯ.md** — контракт frontend з runtime
- **КАНОНІЧНА_АРХІТЕКТУРА_ВИКОНАННЯ.md** — runtime architecture

---

*Цей документ є канонічною специфікацією API контрактів системи Garden Seedling.*
