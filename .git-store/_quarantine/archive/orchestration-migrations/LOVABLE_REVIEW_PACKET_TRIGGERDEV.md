# Lovable Review Packet: Trigger.dev Migration

> Створено: 2026-02-15
> Автор: Головний архітектор системи
> Статус: Review packet для Lovable-агента
> Мова: Українська (канонічна)
> Мета: Перевірити, що frontend не залежить від Inngest-специфіки і контракти стабільні

---

## 0. Контекст для Lovable

Orchestrator системи мігрується з **Inngest** на **Trigger.dev**. Це backend-only зміна. Frontend **не повинен** бути залежним від orchestrator vendor.

**Очікуваний результат review:** підтвердити, що Lovable frontend код не потребує змін.

---

## 1. Файли для читання

Lovable-агент повинен прочитати ці файли для проведення review:

| # | Файл | Навіщо |
|---|------|--------|
| 1 | `docs/backend/API_CONTRACTS_V1.md` | Канонічні API контракти — перевірити, що вони orchestrator-agnostic |
| 2 | `docs/backend/API_CONTRACTS_TRIGGERDEV_DELTA.md` | Результат delta-аудиту — підтвердити NO CHANGE |
| 3 | `docs/architecture/INBOX_AND_RUN_LIFECYCLE_V1.md` | Run lifecycle — перевірити, що UI polling не залежить від orchestrator |
| 4 | `docs/frontend/LOVABLE_УЗГОДЖЕННЯ_З_RUNTIME_АРХІТЕКТУРОЮ.md` | Frontend контракт — перевірити Інваріант 6 (runtime opaque) |
| 5 | `docs/frontend/FRONTEND_V1_MIGRATION_PLAN.md` | Frontend migration plan — перевірити, що він не згадує Inngest |
| 6 | `src/lib/api/mcpGatewayClient.ts` | API client — перевірити відсутність Inngest-specific endpoints |
| 7 | `src/types/mcpGateway.ts` | TypeScript types — перевірити відсутність Inngest-specific типів |

---

## 2. Checks (5 перевірок)

### Check 1: Projection Integrity

**Питання:** Чи frontend залишається чистою projection layer після міграції?

**Що перевірити:**
- `mcpGatewayClient.ts` не містить URL/endpoint до Inngest або Trigger.dev
- Усі API calls йдуть через Worker (`garden-api.exodus.pp.ua`)
- Frontend не імпортує Inngest SDK або Trigger.dev SDK
- `useRunStatus`, `useAgentRun` hooks (якщо існують) використовують тільки Worker endpoints

**Формат відповіді:**

```
CHECK 1: Projection Integrity
Result: PASS | PARTIAL | FAIL
Evidence: [конкретні файли/рядки]
Issues: [якщо PARTIAL/FAIL]
```

---

### Check 2: API Contracts Stability

**Питання:** Чи API контракти залишаються стабільними?

**Що перевірити:**
- `API_CONTRACTS_V1.md` — endpoints, request/response schemas
- `API_CONTRACTS_TRIGGERDEV_DELTA.md` — підтверджує NO CHANGE
- TypeScript types у `src/types/` — відповідають V1 API schemas
- Error codes у frontend — маппляться на V1 error codes

**Формат відповіді:**

```
CHECK 2: API Contracts Stability
Result: PASS | PARTIAL | FAIL
Evidence: [конкретні файли/рядки]
Issues: [якщо PARTIAL/FAIL]
```

---

### Check 3: Lifecycle Correctness

**Питання:** Чи Run lifecycle у frontend відповідає V1 специфікації?

**Що перевірити:**
- Run states: `requested → queued → running → completed | failed`
- Polling intervals: 5s для active run, 30s для inbox
- Terminal state detection: polling зупиняється при `completed`/`failed`
- UI badges/spinners відповідають кожному стану

**Формат відповіді:**

```
CHECK 3: Lifecycle Correctness
Result: PASS | PARTIAL | FAIL
Evidence: [конкретні файли/рядки]
Issues: [якщо PARTIAL/FAIL]
```

---

### Check 4: Error Model

**Питання:** Чи error handling у frontend orchestrator-agnostic?

**Що перевірити:**
- Error codes у frontend не містять Inngest-specific кодів
- `UPSTREAM_UNAVAILABLE` (502) не деталізує vendor у UI
- Retry logic (якщо є) не залежить від orchestrator
- Error messages для user — generic ("Сервіс тимчасово недоступний"), не vendor-specific

**Формат відповіді:**

```
CHECK 4: Error Model
Result: PASS | PARTIAL | FAIL
Evidence: [конкретні файли/рядки]
Issues: [якщо PARTIAL/FAIL]
```

---

### Check 5: Contamination Search

**Питання:** Чи frontend code base містить Inngest-specific references?

**Що перевірити:**
- `grep -ri "inngest" src/` → має бути порожнім
- `grep -ri "trigger.dev" src/` → має бути порожнім (frontend не знає vendor)
- Перевірити comments, string literals, URLs
- Перевірити `package.json` — жодних orchestrator SDK залежностей

**Формат відповіді:**

```
CHECK 5: Contamination Search
Result: PASS | PARTIAL | FAIL
Evidence: [grep results]
Issues: [якщо знайдено references]
```

---

## 3. Зведений формат відповіді

Lovable-агент повинен повернути відповідь у такому форматі:

```markdown
# Lovable Review: Trigger.dev Migration

## Summary
Overall: PASS | PARTIAL | FAIL

## Check Results

| # | Check | Result | Issues |
|---|-------|--------|--------|
| 1 | Projection Integrity | PASS/PARTIAL/FAIL | — |
| 2 | API Contracts Stability | PASS/PARTIAL/FAIL | — |
| 3 | Lifecycle Correctness | PASS/PARTIAL/FAIL | — |
| 4 | Error Model | PASS/PARTIAL/FAIL | — |
| 5 | Contamination Search | PASS/PARTIAL/FAIL | — |

## Details
[Per-check evidence and issues]

## Recommendations
[If any checks are PARTIAL/FAIL]
```

---

## 4. Очікуваний результат

**[ASSUMPTION]** Усі 5 checks повинні бути **PASS**, оскільки:
- Frontend спроєктований як projection layer (Інваріант 6)
- API контракти orchestrator-agnostic (підтверджено [DELTA])
- Frontend code не повинен містити orchestrator vendor references

Якщо будь-який check = **PARTIAL** або **FAIL** — це означає, що frontend має implicit залежність від orchestrator, яку потрібно виправити **перед** міграцією (Phase 3 cutover).

---

*Цей документ є review packet для Lovable-агента. Він перевіряє, що frontend не залежить від orchestrator vendor і готовий до міграції Inngest → Trigger.dev.*
