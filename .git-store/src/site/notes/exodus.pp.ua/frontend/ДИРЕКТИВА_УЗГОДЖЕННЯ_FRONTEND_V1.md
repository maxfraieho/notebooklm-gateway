---
{"tags":["domain:frontend","status:canonical","format:guide"],"created":"2026-02-15","updated":"2026-02-21","tier":2,"title":"ДИРЕКТИВА УЗГОДЖЕННЯ FRONTEND V1","dg-publish":true,"dg-metatags":null,"dg-home":null,"permalink":"/exodus.pp.ua/frontend/ДИРЕКТИВА_УЗГОДЖЕННЯ_FRONTEND_V1/","dgPassFrontmatter":true,"noteIcon":""}
---


# Frontend Alignment Directive V1

> Автор: Principal Architect (Claude Opus 4.6)
> Дата: 2026-02-15
> Статус: CANONICAL
> Аудиторія: Lovable frontend developers
> Scope: ТІЛЬКИ frontend зміни для узгодження з canonical API contracts

---

## Резюме (1 сторінка)

Frontend Garden Seedling має **критичні розбіжності** з canonical backend API contracts. Цей документ містить точні інструкції що і де виправити.

**Масштаб проблеми:**

| Категорія | Серйозність | Кількість файлів |
|-----------|-------------|------------------|
| Proposal API endpoints невірні | 🔴 P0 | 2 (client + UI) |
| ErrorCode enum неповний | 🔴 P0 | 1 (types) |
| Gateway URL дублюється | 🔴 P0 | 8 файлів |
| Direct fetch() bypass gateway | 🟡 P1 | 17+ файлів |
| Correlation ID відсутній | 🟡 P1 | 0 (потрібно додати) |
| ProposalStatus неповний | 🔴 P0 | 1 (types) |

**Canonical джерела істини:**
- `docs/backend/КОНТРАКТИ_API_V1.md` — API endpoints, error codes, headers
- `docs/architecture/СИСТЕМА_PROPOSAL_V1.md` — proposal state machine, approval semantics
- `docs/frontend/LOVABLE_УЗГОДЖЕННЯ_З_АРХІТЕКТУРОЮ_ВИКОНАННЯ.md` — frontend invariants

**Головний інваріант:** Frontend НІКОЛИ не звертається до Mastra, Orchestration Layer, FastAPI або MinIO напряму. Єдиний канал — `mcpGatewayClient.ts` → Cloudflare Worker.

---

## A. Contract Truth Table

### A.1 Gateway Invariant

| # | Правило | Canonical джерело | Поточний стан | Дія |
|---|---------|-------------------|---------------|-----|
| G1 | Єдине джерело URL: `getGatewayBaseUrl()` з `mcpGatewayClient.ts` | LOVABLE_УЗГОДЖЕННЯ §1.2, RUNTIME_ARCHITECTURE_INDEX Invariant 7 | **ПОРУШЕНО** — 8 файлів визначають власну константу `MCP_GATEWAY_URL` або `GATEWAY_URL` | P0: видалити всі локальні константи, імпортувати `getGatewayBaseUrl()` |
| G2 | Всі HTTP-запити через `requestJson<T>()` | LOVABLE_УЗГОДЖЕННЯ §1.2 Invariant 1 | **ПОРУШЕНО** — 17+ файлів використовують `fetch()` напряму | P1: мігрувати на `requestJson()` або спеціалізовані методи клієнта |
| G3 | Auth token додається автоматично gateway клієнтом | API_CONTRACTS_V1 §0.2 | Працює в `requestJson()`, **НЕ працює** в direct `fetch()` | Вирішується через G2 |

**Файли з порушенням G1 (дубльований URL):**

| Файл | Рядок | Ім'я константи |
|------|-------|----------------|
| `src/pages/NotePage.tsx` | ~10 | `MCP_GATEWAY_URL` |
| `src/hooks/useAnnotations.ts` | ~14 | `GATEWAY_URL` |
| `src/hooks/useZoneValidation.ts` | ~35 | `MCP_GATEWAY_URL` |
| `src/hooks/useOwnerAuth.tsx` | ~38 | `MCP_GATEWAY_URL` |
| `src/hooks/useComments.ts` | ~15 | `GATEWAY_URL` |
| `src/hooks/useMCPSessions.ts` | ~49 | `MCP_GATEWAY_URL` |
| `src/components/garden/ZoneCommentSection.tsx` | ~18 | `MCP_GATEWAY_URL` |
| `src/hooks/useAccessZones.ts` | ~72 | ✅ Вже використовує `getGatewayBaseUrl()` |

### A.2 Proposal Endpoints & Bodies

| # | Операція | Canonical (API_CONTRACTS_V1 §3.3) | Поточний frontend | Дія |
|---|----------|-----------------------------------|--------------------|-----|
| P1 | Approve proposal | `PATCH /proposals/{id}` body: `{"status": "approved", "decision_note": "..."}` | **НЕВІРНО**: `POST /proposals/{id}/accept` з порожнім body | P0: переписати `acceptProposal()` |
| P2 | Reject proposal | `PATCH /proposals/{id}` body: `{"status": "rejected", "decision_note": "..."}` (decision_note ОБОВ'ЯЗКОВИЙ, min 10 chars) | **НЕВІРНО**: `POST /proposals/{id}/reject` з порожнім body | P0: переписати `rejectProposal()`, додати textarea для decision_note |
| P3 | Batch approve/reject | `PATCH /proposals/batch` body: `{"proposal_ids": [...], "status": "approved"\|"rejected", "decision_note": "..."}` | **ВІДСУТНЄ** | P1: додати `batchUpdateProposals()` |
| P4 | Proposal statuses | `pending → approved \| rejected \| auto_approved \| expired`, потім `applying → applied \| failed` | **НЕПОВНИЙ**: ProposalStatus type відсутні `auto_approved`, `applying`, `expired`, `failed` | P0: оновити ProposalStatus type |
| P5 | `reviewing` стан | UI-only; НЕ серверний стан. Використовується лише для оптимістичного UI | Не реалізовано явно | P1: додати як UI-local state |

**Canonical approve request:**
```
PATCH /api/v1/proposals/{proposal_id}
Content-Type: application/json
Authorization: Bearer {token}

{
  "status": "approved",
  "decision_note": "Підтверджено після перегляду"
}
```

**Canonical reject request:**
```
PATCH /api/v1/proposals/{proposal_id}
Content-Type: application/json
Authorization: Bearer {token}

{
  "status": "rejected",
  "decision_note": "Не відповідає вимогам зони — потрібно уточнити формулювання"
}
```

**Canonical batch request:**
```
PATCH /api/v1/proposals/batch
Content-Type: application/json
Authorization: Bearer {token}

{
  "proposal_ids": ["uuid-1", "uuid-2"],
  "status": "approved",
  "decision_note": "Batch approval після ревю"
}
```

### A.3 Error Model (Appendix A)

| # | Правило | Canonical (API_CONTRACTS_V1 Appendix A) | Поточний frontend | Дія |
|---|---------|----------------------------------------|--------------------|-----|
| E1 | Error response format | `{"error": {"code": "...", "message": "...", "details": {...}}}` | Частково реалізовано в `requestJson()` | Перевірити відповідність |
| E2 | ErrorCode enum — 14 кодів | Повний список нижче | **НЕПОВНИЙ** — відсутні ~10 кодів | P0: додати всі коди |
| E3 | `retryable` поле | Кожен код має retryable flag | **ВІДСУТНЄ** | P1: додати retry logic |
| E4 | `Retry-After` header | Надається при 429 та 503 | **НЕ ПАРСИТЬСЯ** | P1: додати parsing |

**Canonical ErrorCode enum (повний список):**

| Код | HTTP | Retryable | Категорія |
|-----|------|-----------|-----------|
| `AUTH_REQUIRED` | 401 | ❌ | Auth |
| `FORBIDDEN` | 403 | ❌ | Auth |
| `TOKEN_EXPIRED` | 401 | ❌ | Auth |
| `NOT_FOUND` | 404 | ❌ | Resource |
| `VALIDATION_FAILED` | 422 | ❌ | Input |
| `INVALID_JSON` | 400 | ❌ | Input |
| `INVALID_TRANSITION` | 409 | ❌ | State |
| `INVALID_AGENT_TRANSITION` | 409 | ❌ | State |
| `CONCURRENT_MODIFICATION` | 409 | ✅ | State |
| `DUPLICATE_ENTRY` | 409 | ❌ | State |
| `RATE_LIMITED` | 429 | ✅ | Throttle |
| `UPSTREAM_UNAVAILABLE` | 502 | ✅ | Infra |
| `NLM_UNAVAILABLE` | 503 | ✅ | Infra |
| `AGENT_TIMEOUT` | 504 | ✅ | Infra |

**Коди наявні у frontend (`src/types/mcpGateway.ts`):**
`AUTH_REQUIRED`, `FORBIDDEN`, `NOT_FOUND`, `RATE_LIMITED` — **лише 4 з 14**.

### A.4 Correlation ID

| # | Правило | Canonical (API_CONTRACTS_V1 §7.1) | Поточний frontend | Дія |
|---|---------|-----------------------------------|--------------------|-----|
| C1 | Header `X-Correlation-Id` на всіх mutating requests (POST, PATCH, DELETE) | Обов'язковий для трейсингу | **ВІДСУТНІЙ** — 0 використань | P1: генерувати UUID v4, додавати в `requestJson()` |
| C2 | Correlation ID логується у console для debug | Рекомендовано | Відсутнє | P1: додати logging |
| C3 | Backend повертає той самий ID у response header | Для end-to-end tracing | Frontend не читає response headers | P1: зберігати для error reporting |

---

## B. Lovable Implementation Directive

### B.1 P0 — Mandatory Changes (блокують інтеграцію)

#### P0-1: Виправити Proposal API endpoints

**Файл:** `src/lib/api/mcpGatewayClient.ts`

**acceptProposal() (~рядок 510-518):**
- Замінити `POST /proposals/${proposalId}/accept` на `PATCH /proposals/${proposalId}`
- Body: `{ status: "approved", decision_note: string }`
- decision_note може бути порожнім при approve (опціональний)

**rejectProposal() (~рядок 520-528):**
- Замінити `POST /proposals/${proposalId}/reject` на `PATCH /proposals/${proposalId}`
- Body: `{ status: "rejected", decision_note: string }`
- decision_note **ОБОВ'ЯЗКОВИЙ** при reject, мінімум 10 символів

**Файл:** `src/components/garden/ProposalsInbox.tsx`

**handleReject (~рядки 95-109):**
- Додати textarea або modal для введення `decision_note`
- Валідувати: `decision_note.length >= 10`
- Показувати помилку якщо менше 10 символів

**handleAccept (~рядки 59-93):**
- Додати опціональне поле для `decision_note` (може бути порожнім)

#### P0-2: Оновити GatewayErrorCode enum

**Файл:** `src/types/mcpGateway.ts` (~рядки 13-25)

Додати відсутні коди до `GatewayErrorCode`:
```typescript
type GatewayErrorCode =
  // Auth
  | 'AUTH_REQUIRED'
  | 'FORBIDDEN'
  | 'TOKEN_EXPIRED'
  // Resource
  | 'NOT_FOUND'
  // Input
  | 'VALIDATION_FAILED'
  | 'INVALID_JSON'
  // State
  | 'INVALID_TRANSITION'
  | 'INVALID_AGENT_TRANSITION'
  | 'CONCURRENT_MODIFICATION'
  | 'DUPLICATE_ENTRY'
  // Throttle
  | 'RATE_LIMITED'
  // Infra
  | 'UPSTREAM_UNAVAILABLE'
  | 'NLM_UNAVAILABLE'
  | 'AGENT_TIMEOUT';
```

#### P0-3: Оновити ProposalStatus type

**Файл:** `src/types/mcpGateway.ts`

Canonical statuses (PROPOSAL_SYSTEM_V1 §2):
```typescript
type ProposalStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'auto_approved'
  | 'expired'
  | 'applying'
  | 'applied'
  | 'failed';
```

Оновити `EditProposal` interface відповідно.

#### P0-4: Елімінувати дублювання Gateway URL

Для кожного з 7 файлів (список у Truth Table A.1):
1. Видалити локальну константу `MCP_GATEWAY_URL` / `GATEWAY_URL`
2. Додати імпорт: `import { getGatewayBaseUrl } from '@/lib/api/mcpGatewayClient'`
3. Замінити використання на `getGatewayBaseUrl()`

**Або (краще):** мігрувати ці файли на використання методів `mcpGatewayClient` замість прямих `fetch()` — це одночасно вирішує P0-4 та частину P1-1.

### B.2 P1 — Recommended Changes (покращують надійність)

#### P1-1: Мігрувати direct fetch() на gateway client

17+ файлів використовують `fetch()` напряму. Пріоритет міграції:

| Пріоритет | Файл | fetch() викликів | Причина |
|-----------|------|------------------|---------|
| Високий | `src/hooks/useComments.ts` | 4 | Mutating operations без auth |
| Високий | `src/hooks/useAnnotations.ts` | 3 | Mutating operations |
| Високий | `src/hooks/useZoneValidation.ts` | 2 | Auth-sensitive |
| Середній | `src/hooks/useAccessZones.ts` | 2 | Auth-sensitive |
| Середній | `src/components/garden/ZoneCommentSection.tsx` | 2 | User-facing |
| Середній | `src/hooks/useOwnerAuth.tsx` | 1 | Auth flow |
| Середній | `src/hooks/useMCPSessions.ts` | 1 | Session management |
| Середній | `src/pages/NotePage.tsx` | 1 | Data fetching |
| Низький | `src/hooks/useDrakonDiagram.ts` | 1 | Static asset |
| Низький | `src/components/garden/ZoneQRDialog.tsx` | 1 | Static asset |

Для кожного файлу:
1. Замінити `fetch(url, { method, headers, body })` на відповідний метод `mcpGatewayClient`
2. Або використати `requestJson<T>()` напряму
3. Видалити локальну побудову headers (auth, content-type)

#### P1-2: Додати Correlation ID

**Файл:** `src/lib/api/mcpGatewayClient.ts`

У `requestJson()`:
```typescript
// Для mutating requests (POST, PATCH, DELETE) — генерувати та додавати header
if (['POST', 'PATCH', 'DELETE'].includes(method)) {
  const correlationId = crypto.randomUUID();
  headers['X-Correlation-Id'] = correlationId;
  console.debug(`[gateway] ${method} ${url} correlation=${correlationId}`);
}
```

#### P1-3: Додати batch proposal support

**Файл:** `src/lib/api/mcpGatewayClient.ts`

Додати метод:
```typescript
async function batchUpdateProposals(
  proposalIds: string[],
  status: 'approved' | 'rejected',
  decisionNote: string
): Promise<BatchProposalResponse>
```

Endpoint: `PATCH /proposals/batch`

**Файл:** `src/components/garden/ProposalsInbox.tsx`

Додати UI для "Select All" + batch approve/reject.

#### P1-4: Retry-After header parsing

**Файл:** `src/lib/api/mcpGatewayClient.ts`

При отриманні 429 або 503:
1. Прочитати `Retry-After` header
2. Показати користувачу час очікування
3. Опціонально: авто-retry після вказаного інтервалу

#### P1-5: CONCURRENT_MODIFICATION handling

При отриманні 409 з кодом `CONCURRENT_MODIFICATION`:
1. Показати toast: "Дані змінились. Оновлюємо..."
2. Invalidate відповідний TanStack Query cache
3. Re-fetch актуальні дані

---

## C. Anti-Patterns (ЗАБОРОНЕНО)

| # | Anti-pattern | Чому заборонено | Що робити замість |
|---|-------------|-----------------|-------------------|
| AP1 | `const MCP_GATEWAY_URL = import.meta.env.VITE_...` у будь-якому файлі крім `mcpGatewayClient.ts` | Порушує Gateway Invariant (G1). Зміна URL вимагає правки N файлів | Імпортувати `getGatewayBaseUrl()` |
| AP2 | `fetch(url)` для API calls поза `mcpGatewayClient.ts` | Bypass auth, error handling, timeout, headers | Використовувати `requestJson()` або методи клієнта |
| AP3 | `POST /proposals/{id}/accept` або `/reject` | Не існує в canonical API | `PATCH /proposals/{id}` з body `{status, decision_note}` |
| AP4 | Reject без `decision_note` | Canonical вимагає min 10 chars для reject | Показати textarea, валідувати довжину |
| AP5 | Ігнорування error.code у відповідях | Втрачається інформація для retry logic та UX | Парсити `error.code`, реагувати відповідно до категорії |
| AP6 | Hardcoded proposal statuses (тільки pending/approved/rejected) | Пропускає canonical states | Використовувати повний ProposalStatus type |

---

## D. Acceptance Criteria Checklist

### D.1 Grep-перевірки (автоматизовані)

```bash
# Має повернути 0 результатів (окрім mcpGatewayClient.ts):
grep -rn "MCP_GATEWAY_URL\|GATEWAY_URL" src/ --include="*.ts" --include="*.tsx" \
  | grep -v "mcpGatewayClient.ts" \
  | grep -v "getGatewayBaseUrl"
# Очікувано: 0 рядків

# Має повернути 0 результатів:
grep -rn "/accept\|/reject" src/lib/api/mcpGatewayClient.ts
# Очікувано: 0 рядків (старі endpoints видалені)

# Має повернути результати (нові endpoints):
grep -rn "PATCH.*proposals" src/lib/api/mcpGatewayClient.ts
# Очікувано: ≥2 рядки (approve + reject)

# decision_note присутній:
grep -rn "decision_note" src/lib/api/mcpGatewayClient.ts
# Очікувано: ≥2 рядки

# Correlation ID header:
grep -rn "X-Correlation-Id" src/lib/api/mcpGatewayClient.ts
# Очікувано: ≥1 рядок (P1)
```

### D.2 TypeScript перевірки

- [ ] `GatewayErrorCode` містить всі 14 кодів з Appendix A
- [ ] `ProposalStatus` містить всі 8 canonical станів
- [ ] `EditProposal` interface відповідає canonical `Proposal`
- [ ] `npm run build` проходить без помилок після змін
- [ ] `npm run lint` проходить без помилок

### D.3 Функціональні перевірки

- [ ] Approve proposal відправляє `PATCH /proposals/{id}` з `{"status": "approved"}`
- [ ] Reject proposal відправляє `PATCH /proposals/{id}` з `{"status": "rejected", "decision_note": "..."}` (min 10 chars)
- [ ] Reject без decision_note показує помилку валідації в UI
- [ ] Жоден файл крім `mcpGatewayClient.ts` не містить hardcoded gateway URL
- [ ] Error responses парсяться з поля `error.code`

### D.4 Інваріанти (НІКОЛИ не порушувати)

1. **Single Gateway** — `mcpGatewayClient.ts` = єдиний HTTP клієнт для backend API
2. **No Direct Backend** — frontend НІКОЛИ не звертається до Mastra, Orchestration Layer, FastAPI, MinIO
3. **Opaque Runtime** — frontend не знає деталей agent runtime (Mastra internals)
4. **Canonical States** — ProposalStatus та ErrorCode ТОЧНО відповідають canonical docs
5. **Decision Note Required** — reject ЗАВЖДИ вимагає decision_note ≥ 10 символів

---

## Changelog

| Версія | Дата | Зміни |
|--------|------|-------|
| V1 | 2026-02-15 | Initial directive: truth table, P0/P1 changes, acceptance criteria |

---

*Canonical джерела: КОНТРАКТИ_API_V1.md, СИСТЕМА_PROPOSAL_V1.md, LOVABLE_УЗГОДЖЕННЯ_З_АРХІТЕКТУРОЮ_ВИКОНАННЯ.md*


---

## Семантичні зв'язки

**Цей документ є частиною:**
- [[exodus.pp.ua/frontend/LOVABLE_УЗГОДЖЕННЯ_З_АРХІТЕКТУРОЮ_ВИКОНАННЯ\|LOVABLE_УЗГОДЖЕННЯ_З_АРХІТЕКТУРОЮ_ВИКОНАННЯ]] — деталізує критичні невідповідності

**Цей документ залежить від:**
- [[exodus.pp.ua/frontend/LOVABLE_УЗГОДЖЕННЯ_З_АРХІТЕКТУРОЮ_ВИКОНАННЯ\|LOVABLE_УЗГОДЖЕННЯ_З_АРХІТЕКТУРОЮ_ВИКОНАННЯ]] — основний контракт Frontend з архітектурою
- [[exodus.pp.ua/architecture/foundation/АРХІТЕКТУРНИЙ_КОРІНЬ\|АРХІТЕКТУРНИЙ_КОРІНЬ]] — аксіоми A5, A6: Gateway authority, Frontend reads only
- [[exodus.pp.ua/backend/КОНТРАКТИ_API_V1\|КОНТРАКТИ_API_V1]] — API contracts для коригування

**Від цього документа залежать:**
- [[exodus.pp.ua/frontend/ПЛАН_МІГРАЦІЇ_FRONTEND_V1\|ПЛАН_МІГРАЦІЇ_FRONTEND_V1]] — план виконання директиви

---

*Цей документ визначає критичні невідповідності між Frontend реалізацією та canonical архітектурою.*
