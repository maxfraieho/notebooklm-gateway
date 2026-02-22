---
{"tags":["domain:frontend","status:historical","format:guide"],"created":"2026-02-21","updated":"2026-02-21","tier":2,"title":"ПЛАН МІГРАЦІЇ FRONTEND V1","dg-publish":true,"dg-metatags":null,"dg-home":null,"permalink":"/exodus.pp.ua/frontend/ПЛАН_МІГРАЦІЇ_FRONTEND_V1/","dgPassFrontmatter":true,"noteIcon":""}
---


# Frontend V1 Migration Plan

> Створено: 2026-02-15
> Автор: Головний архітектор системи
> Статус: Архітектурний план (для Owner та Lovable)
> Джерела: КОНТРАКТИ_API_V1.md, mcpGatewayClient.ts, mcpGateway.ts

---

## 1. Migration Philosophy

### 1.1 Принцип

Frontend є **projection layer** — він відображає стан системи, але не визначає його. Канонічне джерело правди — MinIO + FastAPI Worker. Frontend отримує дані через єдиний gateway клієнт (`mcpGatewayClient.ts`) і відображає їх через TanStack Query кеш.

### 1.2 Правила міграції

| Правило | Опис |
|---------|------|
| **Gateway-only** | Жоден компонент не робить `fetch()` напряму. Тільки через `mcpGatewayClient.ts` |
| **Types-first** | Спочатку типи (з КОНТРАКТИ_API_V1.md), потім клієнт, потім UI |
| **No shadow state** | Frontend не зберігає стан, який суперечить backend. TanStack Query — єдиний кеш |
| **Polling MVP** | SSE відкладено на post-MVP. Використовувати polling з backoff |
| **Backward-compatible** | Існуючий UI (zones, proposals, NotebookLM) продовжує працювати під час міграції |

### 1.3 Порядок міграції

```
Phase 1: Canonical Types Layer       ← типи з КОНТРАКТИ_API_V1.md
Phase 2: Gateway Migration           ← централізація fetch, нові endpoints
Phase 3: Legacy Cleanup              ← видалення прямих fetch, дублів URL
Phase 4: UI Migration                ← нові UI компоненти (Inbox, Runs, Agents)
```

Кожна фаза завершується `npm run build` без помилок.

---

## 2. Canonical Types Layer

### 2.1 Поточний стан `src/types/mcpGateway.ts`

**Що є:**
- `ProposalStatus`: `'pending' | 'accepted' | 'rejected'`
- `EditProposal`, `AcceptProposalResponse`, `CreateProposalRequest`
- `GatewayErrorCode` (13 кодів: NETWORK_OFFLINE, TIMEOUT, AUTH_REQUIRED, ...)
- `ApiError` з `retryable: boolean`
- Zone types: `CreateZoneRequest`, `CreateZoneResponse`, `ZoneListItem`
- NotebookLM types: `NotebookLMMapping`, `NotebookLMJobStatus`, `NotebookLMChatRequest/Response`

**Що відсутнє (потрібно додати з КОНТРАКТИ_API_V1.md):**

| Тип | Джерело | Опис |
|-----|---------|------|
| `InboxEntry` | §1.3 | Запис у Inbox з intent, metadata, status |
| `InboxStats` | §1.2 | Статистика: pending, processed_today, rejected_today, expired_today |
| `Run` | §2.2 | Активний run: id, agent_slug, status, started_at, steps |
| `RunStep` | §2.3 | Крок run: step_number, name, status, started_at, output |
| `RunStatus` | §2 | Enum: `queued`, `running`, `completed`, `failed`, `cancelled` |
| `Agent` | §5.1 | Агент: slug, name, description, status, safe_outputs |
| `AgentStatus` | §5.3 | Enum: `active`, `paused`, `disabled` |
| `V1ErrorCode` | Appendix A | 15 кодів: VALIDATION_FAILED, INVALID_JSON, AUTH_REQUIRED, ... |

### 2.2 ProposalStatus mismatch

**Критична розбіжність:**

| Де | Значення |
|----|----------|
| Frontend (`mcpGateway.ts`) | `'pending' \| 'accepted' \| 'rejected'` |
| V1 API (КОНТРАКТИ_API_V1.md §3.3) | `'pending' \| 'approved' \| 'rejected' \| 'applied' \| 'failed'` |

**Проблеми:**
1. `accepted` → має бути `approved` (V1 API використовує `approved`)
2. Відсутні стани `applied` та `failed`
3. Transition table у frontend невідома — backend має strict state machine

**Рішення:**
- Замінити `ProposalStatus` на V1-сумісний enum: `'pending' | 'approved' | 'rejected' | 'applied' | 'failed'`
- Оновити всі UI компоненти, що використовують `accepted` → `approved`
- Додати UI стани для `applied` (зелений, фінальний) та `failed` (червоний, дозволяє reject)

### 2.3 GatewayErrorCode alignment

**Поточний стан:**

Frontend має 13 кодів у `GatewayErrorCode` (NETWORK_OFFLINE, TIMEOUT, AUTH_REQUIRED, UNAUTHORIZED, FORBIDDEN, ZONE_EXPIRED, ZONE_NOT_FOUND, NOT_FOUND, RATE_LIMITED, SERVER_ERROR, BAD_REQUEST, UNKNOWN).

V1 API має 15 кодів у Appendix A (VALIDATION_FAILED, INVALID_JSON, AUTH_REQUIRED, TOKEN_EXPIRED, FORBIDDEN, NOT_FOUND, INVALID_TRANSITION, INVALID_AGENT_TRANSITION, CONCURRENT_MODIFICATION, DUPLICATE_ENTRY, RATE_LIMITED, INTERNAL_ERROR, UPSTREAM_UNAVAILABLE, NLM_UNAVAILABLE, AGENT_TIMEOUT).

**Рішення:**
- Створити `V1ErrorCode` type з усіма 15 кодами з Appendix A
- Зберегти існуючий `GatewayErrorCode` для client-side помилок (NETWORK_OFFLINE, TIMEOUT)
- Mapping function: `mapV1Error(code: V1ErrorCode): GatewayErrorCode` для уніфікації в UI

### 2.4 Файлова структура (ціль)

```
src/types/
├── mcpGateway.ts          ← існуючі types (zones, NotebookLM) — залишити
├── v1/
│   ├── inbox.ts           ← InboxEntry, InboxStats, InboxSubmitRequest
│   ├── runs.ts            ← Run, RunStep, RunStatus
│   ├── proposals.ts       ← V1 ProposalStatus, V1 Proposal (з approval block)
│   ├── agents.ts          ← Agent, AgentStatus
│   ├── errors.ts          ← V1ErrorCode enum, mapV1Error()
│   └── index.ts           ← re-exports
```

---

## 3. Gateway Migration Plan

### 3.1 Поточний стан `src/lib/api/mcpGatewayClient.ts`

**Існуючі endpoint groups (639 рядків):**
- Proposals: list, accept, reject, create
- Zones: create, list, delete, validate
- NotebookLM: create, status, chat, list
- Notes: CRUD
- DRAKON: diagrams
- Chats: list, create, delete

**Відсутні endpoint groups (з КОНТРАКТИ_API_V1.md):**

| Group | Endpoints | Пріоритет |
|-------|-----------|-----------|
| **Inbox** | POST /inbox/submit, GET /inbox/stats, GET /inbox/entries | P0 (MVP core) |
| **Runs** | POST /agents/run, GET /runs/{id}/status, GET /runs/{id}/steps, GET /runs | P0 (MVP core) |
| **Agents** | GET /agents, GET /agents/{slug}, PATCH /agents/{slug}/status | P1 (agent catalog) |
| **Artifacts** | GET /runs/{id}/artifacts | P2 (post-MVP) |

### 3.2 Base URL consolidation

**Проблема:** 10 файлів використовують `MCP_GATEWAY_URL` або `getGatewayBaseUrl()`:

| Файл | Паттерн |
|------|---------|
| `src/lib/api/mcpGatewayClient.ts` | `getGatewayBaseUrl()` ← канонічний |
| `src/hooks/useComments.ts` | дублює URL константу, 4× direct fetch |
| `src/hooks/useAnnotations.ts` | дублює URL константу, 3× direct fetch |
| `src/hooks/useMCPSessions.ts` | дублює URL константу, 2× direct fetch |
| `src/hooks/useAccessZones.ts` | дублює URL константу, 2× direct fetch |
| `src/hooks/useZoneValidation.ts` | дублює URL константу, 2× direct fetch |
| `src/hooks/useOwnerAuth.tsx` | дублює URL константу, 1× direct fetch |
| `src/pages/NotePage.tsx` | дублює URL константу, 1× direct fetch |
| `src/pages/AdminDiagnosticsPage.tsx` | дублює URL константу |
| `src/components/garden/ZoneCommentSection.tsx` | дублює URL константу, 2× direct fetch |

**Рішення:**
1. Всі файли імпортують `getGatewayBaseUrl()` з `mcpGatewayClient.ts`
2. Видалити локальні `MCP_GATEWAY_URL` константи
3. Перемістити direct fetch calls у відповідні методи `mcpGatewayClient.ts`

### 3.3 Нові gateway методи (ціль)

```
mcpGatewayClient.ts:
  // Inbox (P0)
  + submitInboxEntry(request: InboxSubmitRequest): Promise<InboxSubmitResponse>
  + getInboxStats(): Promise<InboxStats>
  + getInboxEntries(params?: InboxQueryParams): Promise<InboxEntry[]>

  // Runs (P0)
  + triggerAgentRun(agentSlug: string, params: RunTriggerRequest): Promise<RunTriggerResponse>
  + getRunStatus(runId: string): Promise<Run>
  + getRunSteps(runId: string): Promise<RunStep[]>
  + listRuns(params?: RunsQueryParams): Promise<RunsListResponse>

  // Agents (P1)
  + listAgents(): Promise<Agent[]>
  + getAgent(slug: string): Promise<Agent>
  + updateAgentStatus(slug: string, status: AgentStatus): Promise<Agent>

  // Artifacts (P2)
  + getRunArtifacts(runId: string): Promise<Artifact[]>
```

### 3.4 Auth headers

Поточний клієнт передає auth через `getAuthHeaders()`. Перевірити, що він підтримує:

| Тип | Header | Статус |
|-----|--------|--------|
| Owner JWT | `Authorization: Bearer <JWT>` | Є (useOwnerAuth) |
| Zone Guest | `X-Zone-Code: ZONE-XXXX-YYYY` | Є (zone endpoints) |
| Agent | `X-Agent-Identity: agent:<slug>` | Не потрібен (backend-only) |
| Correlation ID | `X-Correlation-Id` | Додати — для tracing |

---

## 4. Legacy Cleanup Plan

### 4.1 Direct fetch elimination

**Правило:** після міграції жоден файл за межами `mcpGatewayClient.ts` не має `fetch()` до gateway.

| Файл | Кількість fetch | Міграція |
|------|-----------------|----------|
| `useComments.ts` | 4 | → `mcpGatewayClient.comments.*` |
| `useAnnotations.ts` | 3 | → `mcpGatewayClient.annotations.*` |
| `useMCPSessions.ts` | 2 | → `mcpGatewayClient.sessions.*` |
| `useAccessZones.ts` | 2 | → `mcpGatewayClient.zones.*` |
| `useZoneValidation.ts` | 2 | → `mcpGatewayClient.zones.validate()` |
| `useOwnerAuth.tsx` | 1 | → `mcpGatewayClient.auth.*` |
| `NotePage.tsx` | 1 | → `mcpGatewayClient.notes.*` |
| `ZoneCommentSection.tsx` | 2 | → `mcpGatewayClient.comments.*` |
| **Всього** | **17 fetch calls** | |

### 4.2 URL constant cleanup

Видалити 9 локальних копій `MCP_GATEWAY_URL`. Єдине джерело — `getGatewayBaseUrl()` у `mcpGatewayClient.ts`.

### 4.3 Type alignment checklist

| Поточний тип | V1 тип | Дія |
|--------------|--------|-----|
| `ProposalStatus: 'accepted'` | `'approved'` | Замінити значення |
| `ProposalStatus` (3 стани) | 5 станів | Додати `applied`, `failed` |
| `GatewayErrorCode` | `V1ErrorCode` | Створити mapping, зберегти обидва |
| `EditProposal.status` | V1 proposal з `approval` block | Розширити тип |

---

## 5. UI Migration Strategy

### 5.1 Нові UI компоненти (MVP)

| Компонент | Пріоритет | Дані з | Опис |
|-----------|-----------|--------|------|
| **InboxDashboard** | P0 | GET /inbox/stats, /inbox/entries | Огляд inbox: лічильники + список entries |
| **RunTimeline** | P0 | GET /runs/{id}/status, /runs/{id}/steps | Візуалізація run: кроки, статуси, час |
| **ProposalReview** (оновлення) | P0 | GET /proposals/pending, PATCH /proposals/{id} | Існуючий компонент + нові стани (applied, failed) |
| **AgentCatalog** | P1 | GET /agents | Список агентів: slug, status, опис |
| **AgentDetail** | P1 | GET /agents/{slug} | Деталі агента: safe_outputs, runs history |
| **BatchApproval** | P1 | PATCH /proposals/batch | Масове approve/reject proposals |

### 5.2 Polling strategy (MVP)

SSE відкладено. Polling pattern для TanStack Query:

| Екран | Endpoint | Інтервал | Умова зупинки |
|-------|----------|----------|---------------|
| InboxDashboard | GET /inbox/stats | 30s | — (завжди активний) |
| RunTimeline (active run) | GET /runs/{id}/status | 3s | status ∈ {completed, failed, cancelled} |
| RunTimeline (steps) | GET /runs/{id}/steps | 5s | run.status ∈ {completed, failed, cancelled} |
| ProposalReview | GET /proposals/pending | 15s | — (завжди активний) |

Використовувати TanStack Query `refetchInterval` + `refetchIntervalInBackground: false`.

### 5.3 Error handling в UI

V1 API повертає unified error format (§0.4). Frontend mapping:

| V1 ErrorCode | UI реакція |
|--------------|------------|
| `VALIDATION_FAILED` | Показати деталі помилки біля відповідного поля |
| `AUTH_REQUIRED`, `TOKEN_EXPIRED` | Redirect на login, спроба refresh token |
| `FORBIDDEN` | Toast: "Недостатньо прав" |
| `NOT_FOUND` | Toast: "Ресурс не знайдено" |
| `INVALID_TRANSITION` | Toast: "Дію неможливо виконати — стан змінився" + refetch |
| `CONCURRENT_MODIFICATION` | Auto-retry (1 раз) з refetch |
| `RATE_LIMITED` | Toast: "Зачекайте" + disable кнопки на `Retry-After` секунд |
| `UPSTREAM_UNAVAILABLE` | Toast: "Сервіс тимчасово недоступний" + auto-retry з backoff |
| `AGENT_TIMEOUT` | Toast: "Агент не відповів вчасно" + опція retry |

---

## 6. Risk Analysis

### 6.1 Ризики міграції

| Ризик | Ймовірність | Вплив | Мітигація |
|-------|-------------|-------|-----------|
| **ProposalStatus rename breaks existing data** | Висока | Середній | Backend повертає `approved`; frontend mapping `accepted→approved` як transitional layer |
| **17 direct fetch calls — regression при міграції** | Середня | Високий | Міграція по одному файлу; `npm run build` після кожного |
| **Polling overload при багатьох active runs** | Низька | Середній | Conditional polling: тільки для active runs (status !== terminal) |
| **Type mismatch між frontend і backend** | Середня | Високий | Types-first approach: спочатку типи з API spec, потім клієнт |
| **TanStack Query cache inconsistency** | Низька | Середній | `invalidateQueries` при mutation; optimistic updates тільки для approve/reject |
| **Breaking change в V1 API** | Низька | Високий | КОНТРАКТИ_API_V1.md є канонічною; зміни тільки з оновленням документа |

### 6.2 Що НЕ міграти в MVP

| Функціонал | Причина |
|------------|---------|
| SSE Event Stream | Відкладено (Appendix B КОНТРАКТИ_API_V1.md) |
| Artifacts UI | P2, залежить від MinIO direct access |
| Agent editing | MVP — тільки перегляд та pause/unpause |
| Batch operations UI (крім proposals) | Складність UX, один Owner у MVP |
| Offline support | MVP передбачає постійне з'єднання |

### 6.3 Definition of Done

Міграція вважається завершеною коли:

- [ ] `src/types/v1/` містить усі типи з КОНТРАКТИ_API_V1.md
- [ ] `ProposalStatus` використовує V1 значення (`approved` замість `accepted`)
- [ ] Жоден файл за межами `mcpGatewayClient.ts` не містить direct `fetch()` до gateway
- [ ] Жоден файл не містить локальну `MCP_GATEWAY_URL` константу
- [ ] `mcpGatewayClient.ts` має методи для Inbox, Runs, Agents endpoints
- [ ] `npm run build` проходить без помилок
- [ ] `npm run lint` проходить без помилок

---

*Цей документ є архітектурним планом міграції frontend на V1 API. Він не містить коду — лише специфікації для імплементації Owner та Lovable.*


---

## Семантичні зв'язки

**Цей документ є частиною:**
- [[exodus.pp.ua/frontend/ДИРЕКТИВА_УЗГОДЖЕННЯ_FRONTEND_V1\|ДИРЕКТИВА_УЗГОДЖЕННЯ_FRONTEND_V1]] — операційний план виконання директиви

**Цей документ залежить від:**
- [[exodus.pp.ua/frontend/ДИРЕКТИВА_УЗГОДЖЕННЯ_FRONTEND_V1\|ДИРЕКТИВА_УЗГОДЖЕННЯ_FRONTEND_V1]] — визначає що потребує міграції
- [[exodus.pp.ua/backend/КОНТРАКТИ_API_V1\|КОНТРАКТИ_API_V1]] — цільовий API після міграції
- [[exodus.pp.ua/architecture/core/КАНОНІЧНА_АРХІТЕКТУРА_ВИКОНАННЯ\|КАНОНІЧНА_АРХІТЕКТУРА_ВИКОНАННЯ]] — архітектурна ціль міграції

> **Статус:** Historical — план було виконано. Зберігається для провенансу еволюції Frontend.

---

*Цей документ є планом міграції Frontend до canonical архітектури. Зберігається в historical контексті.*
