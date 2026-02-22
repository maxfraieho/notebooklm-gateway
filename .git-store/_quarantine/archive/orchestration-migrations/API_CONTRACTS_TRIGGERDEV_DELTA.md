# API Contracts: Trigger.dev Migration Delta

> Створено: 2026-02-15
> Автор: Головний архітектор системи
> Статус: Аудит контрактів (DRY-RUN)
> Мова: Українська (канонічна)
> Базується на: API_CONTRACTS_V1.md, TARGET_ORCHESTRATION_MODEL_TRIGGERDEV_V1.md

---

## 0. Висновок

### **NO CHANGE** — API контракти не змінюються.

Зміна orchestrator (Inngest → Trigger.dev) **не впливає** на API_CONTRACTS_V1.md та frontend контракти.

Обґрунтування нижче.

---

## 1. Аналіз впливу по секціях API_CONTRACTS_V1.md

### 1.1 §0 — Загальні правила

| Елемент | Зміна | Обґрунтування |
|---------|-------|---------------|
| Base URL | **NO CHANGE** | `https://garden-api.exodus.pp.ua` — Worker endpoint, не orchestrator |
| Автентифікація | **NO CHANGE** | JWT/zone code/agent identity — orchestrator-agnostic |
| Content-Type | **NO CHANGE** | JSON — orchestrator-agnostic |
| Idempotency | **NO CHANGE** | `correlationId` — Worker-level, не orchestrator |
| Rate limiting | **NO CHANGE** | Worker-level enforcement |
| Error format | **NO CHANGE** | Unified JSON error — Worker generates |

### 1.2 §1 — Inbox

| Endpoint | Зміна | Обґрунтування |
|----------|-------|---------------|
| `POST /inbox/submit` | **NO CHANGE** | Worker → MinIO. Orchestrator не задіяний |
| `GET /inbox/stats` | **NO CHANGE** | Worker → MinIO read |
| `GET /inbox/entries` | **NO CHANGE** | Worker → MinIO read |

### 1.3 §2 — Agent Run

| Endpoint | Зміна | Обґрунтування |
|----------|-------|---------------|
| `POST /agents/run` | **NO CHANGE** | Worker приймає request, делегує orchestrator. Response format (`run_id`, `status`) не залежить від vendor |
| `GET /runs/{runId}/status` | **NO CHANGE** | Worker читає `status.json` з MinIO. Хто пише (Inngest/Trigger.dev) — прозоро для API |
| `GET /runs/{runId}/steps` | **NO CHANGE** | Worker читає `steps/*.json` з MinIO. Format ідентичний |

**[FACT]** Run status та step data зберігаються у MinIO. API контракт описує MinIO schema, не orchestrator API. Заміна orchestrator не змінює MinIO schema.

### 1.4 §3 — Proposals

| Endpoint | Зміна | Обґрунтування |
|----------|-------|---------------|
| `GET /proposals/pending` | **NO CHANGE** | MinIO read |
| `GET /proposals/{id}` | **NO CHANGE** | MinIO read |
| `PATCH /proposals/{id}` | **NO CHANGE** | Worker → MinIO write + Git commit |
| `GET /proposals/history` | **NO CHANGE** | MinIO read |
| `PATCH /proposals/batch` | **NO CHANGE** | Worker → MinIO write |

### 1.5 §4 — Artifacts

| Endpoint | Зміна | Обґрунтування |
|----------|-------|---------------|
| `GET /runs/{runId}/artifacts` | **NO CHANGE** | MinIO read |

### 1.6 §5 — Agents

| Endpoint | Зміна | Обґрунтування |
|----------|-------|---------------|
| `GET /agents` | **NO CHANGE** | MinIO `registry.json` read |
| `GET /agents/{slug}` | **NO CHANGE** | MinIO `_agent.md` parsed |
| `PATCH /agents/{slug}/status` | **NO CHANGE** | Worker → MinIO write |

### 1.7 §6 — Run History

| Endpoint | Зміна | Обґрунтування |
|----------|-------|---------------|
| `GET /runs` | **NO CHANGE** | MinIO read (runs listing) |

### 1.8 §7 — Idempotency & Correlation

| Елемент | Зміна | Обґрунтування |
|---------|-------|---------------|
| Correlation ID | **NO CHANGE** | Worker-level tracing |
| Idempotency keys | **NO CHANGE** | Worker-level dedup |
| Rate limiting | **NO CHANGE** | Worker-level enforcement |

---

## 2. Error Codes Audit

### 2.1 Appendix A — Error Codes

| error.code | Зміна | Деталі |
|------------|-------|--------|
| `VALIDATION_FAILED` | **NO CHANGE** | Client error |
| `INVALID_JSON` | **NO CHANGE** | Client error |
| `AUTH_REQUIRED` | **NO CHANGE** | Auth |
| `TOKEN_EXPIRED` | **NO CHANGE** | Auth |
| `FORBIDDEN` | **NO CHANGE** | Auth |
| `NOT_FOUND` | **NO CHANGE** | Client |
| `INVALID_TRANSITION` | **NO CHANGE** | State machine |
| `INVALID_AGENT_TRANSITION` | **NO CHANGE** | State machine |
| `CONCURRENT_MODIFICATION` | **NO CHANGE** | Optimistic concurrency |
| `DUPLICATE_ENTRY` | **NO CHANGE** | Idempotency |
| `RATE_LIMITED` | **NO CHANGE** | Throttle |
| `INTERNAL_ERROR` | **NO CHANGE** | Server |
| `UPSTREAM_UNAVAILABLE` | **COSMETIC ONLY** | Опис: "MinIO, Inngest або FastAPI недоступні" → "MinIO, orchestrator або FastAPI недоступні" |
| `NLM_UNAVAILABLE` | **NO CHANGE** | NotebookLM-specific |
| `AGENT_TIMEOUT` | **NO CHANGE** | Generic timeout |

**[DECISION]** Єдина зміна — cosmetic: у описі `UPSTREAM_UNAVAILABLE` замінити "Inngest" на "orchestrator". Це не впливає на `error.code` значення, HTTP status, чи retryable semantics.

### 2.2 Нові error codes

**[DECISION]** Trigger.dev міграція **не додає** нових error codes. Trigger.dev errors маппляться на існуючі:

| Trigger.dev error | Mapping на V1 error code |
|-------------------|-------------------------|
| Task timeout | `AGENT_TIMEOUT` (504) |
| Trigger.dev unavailable | `UPSTREAM_UNAVAILABLE` (502) |
| Concurrency limit reached | Run → `queued` status (не error) |
| Retry exhausted | `INTERNAL_ERROR` (500) або `AGENT_TIMEOUT` (504) |

---

## 3. Frontend Contract Impact

### 3.1 Polling endpoints

| Endpoint | Зміна | Обґрунтування |
|----------|-------|---------------|
| `GET /runs/{runId}/status` | **NO CHANGE** | Frontend polling MinIO через Worker |
| `GET /inbox/stats` | **NO CHANGE** | MinIO read |
| `GET /proposals/pending` | **NO CHANGE** | MinIO read |

### 3.2 Run states

| State | Зміна | Обґрунтування |
|-------|-------|---------------|
| `requested` | **NO CHANGE** | Worker sets before orchestrator call |
| `queued` | **NO CHANGE** | Orchestrator sets (same semantics) |
| `running` | **NO CHANGE** | Orchestrator sets (same semantics) |
| `completed` | **NO CHANGE** | Orchestrator sets (same semantics) |
| `failed` | **NO CHANGE** | Orchestrator sets (same semantics) |

### 3.3 TypeScript interfaces

**[FACT]** Жоден TypeScript interface у `src/types/` не містить Inngest-specific типів. Усі типи описують MinIO schemas та Worker API responses.

### 3.4 SSE (post-MVP)

| Event type | Зміна | Обґрунтування |
|-----------|-------|---------------|
| `run.status.changed` | **NO CHANGE** | Worker generates from MinIO |
| `run.step.completed` | **NO CHANGE** | Worker generates from MinIO |
| `proposal.created` | **NO CHANGE** | Worker generates from MinIO |
| `proposal.status.changed` | **NO CHANGE** | Worker generates from MinIO |
| `inbox.new` | **NO CHANGE** | Worker generates from MinIO |

---

## 4. Vendor Opaqueness Verification

**[FACT]** UI не має знати про orchestrator vendor.

| Перевірка | Результат |
|-----------|----------|
| API_CONTRACTS_V1.md містить Inngest-specific endpoint? | **НІ** — всі endpoints Worker-level |
| API responses містять Inngest-specific fields? | **НІ** — всі fields MinIO-schema |
| Error codes Inngest-specific? | **НІ** — generic error codes |
| Run states Inngest-specific? | **НІ** — бізнес-стани, не orchestrator states |
| Frontend polling залежить від Inngest? | **НІ** — polling MinIO через Worker |

**[FACT]** API_CONTRACTS_V1.md є **orchestrator-agnostic by design**. Цільова архітектура правильно ізолювала orchestrator за Worker gateway.

---

## 5. Рекомендації

| # | Рекомендація | Пріоритет |
|---|-------------|-----------|
| 1 | Замінити "Inngest" → "orchestrator" у описі `UPSTREAM_UNAVAILABLE` (cosmetic) | Низький |
| 2 | Додати у Appendix A footnote: "Orchestrator = Trigger.dev (раніше Inngest)" | Низький |
| 3 | Перевірити, що `status.json` schema validator (якщо буде) не містить Inngest-specific fields | При реалізації |
| 4 | Переконатися, що `manifest.json` не містить Inngest-specific metadata | При реалізації |

---

*Цей документ підтверджує, що API контракти V1 не потребують змін при міграції Inngest → Trigger.dev. Orchestrator vendor є opaque для API layer.*
