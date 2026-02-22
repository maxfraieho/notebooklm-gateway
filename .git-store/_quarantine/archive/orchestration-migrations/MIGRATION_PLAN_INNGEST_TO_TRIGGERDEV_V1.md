# План міграції Inngest → Trigger.dev V1

> Створено: 2026-02-15
> Автор: Головний архітектор системи
> Статус: План міграції (DRY-RUN)
> Мова: Українська (канонічна)
> Базується на: MIGRATION_INNGEST_TO_TRIGGERDEV_INVENTORY.md, TARGET_ORCHESTRATION_MODEL_TRIGGERDEV_V1.md

---

## 0. Загальна стратегія

**[DECISION]** Міграція виконується у **5 фаз** (0–4). Кожна фаза має:
- Goals (цілі)
- Changes (зміни — документи/контракти)
- Risks (ризики)
- Acceptance Criteria / Definition of Done

**[DECISION]** Міграція є **документаційна** на фазах 0–1 та **реалізаційна** на фазах 2–4. Цей документ описує архітектурний план, не код.

---

## Phase 0 — Pre-migration hardening (docs-only)

### Goals

1. Підготувати canonical docs до vendor-agnostic формулювань
2. Оновити глосарій: ввести термін "Orchestrator" як абстракцію
3. Зафіксувати "Orchestrator Adapter Interface" як архітектурний шар

### Changes Required

| Документ | Зміна | Тип |
|----------|-------|-----|
| `GLOSSARY.md` | Додати термін **"Orchestrator"** — абстрактний шар оркестрації (Inngest, Trigger.dev — реалізації) | UPDATE |
| `GLOSSARY.md` | Додати термін **"Trigger.dev"** — нова реалізація orchestrator | ADD |
| `GLOSSARY.md` | Позначити "Inngest" як `DEPRECATED → Trigger.dev` | UPDATE |
| `АРХІТЕКТУРНА_БАЗА_СИСТЕМИ.md` | У §2 (canonical sources): `Mastra + Inngest` → `Mastra + Orchestrator (Trigger.dev)` | UPDATE |
| `DOCUMENTATION_INVENTORY.md` | Додати нові міграційні документи до інвентаря | UPDATE |
| Усі docs | Де Inngest згадується як **інтерфейс** (не vendor): замінити на "Orchestrator" | REVIEW |
| Усі docs | Де Inngest згадується як **vendor**: залишити з позначкою `(мігрується на Trigger.dev)` | REVIEW |

### Risks

| Ризик | Ймовірність | Вплив | Мітигація |
|-------|-------------|-------|-----------|
| Передчасне видалення Inngest-специфічних деталей до верифікації Trigger.dev | Середня | Високий | Phase 0 лише додає абстракцію, не видаляє деталі |
| Неузгодженість термінології між документами | Низька | Середній | Checklist у Acceptance Criteria |

### Acceptance Criteria / DoD

- [ ] GLOSSARY.md містить визначення "Orchestrator", "Trigger.dev"
- [ ] GLOSSARY.md позначає "Inngest" як deprecated
- [ ] АРХІТЕКТУРНА_БАЗА_СИСТЕМИ.md використовує "Orchestrator (Trigger.dev)" замість "Inngest"
- [ ] DOCUMENTATION_INVENTORY.md оновлений
- [ ] Жодний canonical doc не втратив інформації (лише додано абстракцію)
- [ ] `npm run build` не зачіпається (docs-only)

---

## Phase 1 — Abstraction layer (архітектурно)

### Goals

1. Визначити **Orchestrator Adapter Interface** — мінімальний набір методів для orchestrator
2. Документально зафіксувати, що конкретний vendor (Inngest/Trigger.dev) реалізує цей інтерфейс
3. Підготувати mapping Inngest API → Orchestrator Interface → Trigger.dev API

### Changes Required

| Документ | Зміна | Тип |
|----------|-------|-----|
| **НОВИЙ:** `ORCHESTRATOR_ADAPTER_INTERFACE.md` | Мінімальний інтерфейс orchestrator | CREATE |
| `ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` | §2.3 — позначити як "реалізація Orchestrator Interface через Inngest" | UPDATE |
| `TARGET_ORCHESTRATION_MODEL_TRIGGERDEV_V1.md` | Посилання на Orchestrator Interface | UPDATE |

### Orchestrator Adapter Interface (концептуально, без коду)

| Метод | Опис | Inngest mapping | Trigger.dev mapping |
|-------|------|-----------------|---------------------|
| `emitEvent(name, payload)` | Надіслати подію оркестратору | `inngest.send({ name, data })` | `tasks.trigger(taskId, payload)` |
| `scheduleRecurring(id, cron, taskDef)` | Зареєструвати cron-задачу | Inngest cron function | Trigger.dev scheduled task |
| `cancelRun(runId)` | Скасувати активний run | Inngest cancel | Trigger.dev cancel run |
| `getRunStatus(runId)` | Отримати статус run від orchestrator | Inngest API | Trigger.dev API |
| `defineTask(id, steps, config)` | Зареєструвати task з кроками | Inngest function + steps | Trigger.dev task definition |
| `config.retries` | Retry policy | `{ attempts, backoff }` | `{ maxAttempts, factor, minTimeout }` |
| `config.concurrency` | Concurrency limit | `{ limit, key }` | `{ limit, key }` |
| `config.timeout` | Timeout per step / total | `step.run(fn, { timeout })` | Task/step timeout config |

**[DECISION]** Orchestrator Interface — це **логічний контракт**, не runtime interface. Він визначає "що orchestrator повинен вміти", не як саме.

### Risks

| Ризик | Ймовірність | Вплив | Мітигація |
|-------|-------------|-------|-----------|
| Over-abstraction: інтерфейс стане занадто generic | Середня | Середній | Мінімальний інтерфейс (7 методів), не framework |
| Trigger.dev не підтримує щось із інтерфейсу | Низька | Високий | Верифікація кожного методу перед Phase 2 |

### Acceptance Criteria / DoD

- [ ] `ORCHESTRATOR_ADAPTER_INTERFACE.md` створено
- [ ] Усі 7 методів мають Inngest та Trigger.dev mapping
- [ ] Жоден метод не є Inngest-only або Trigger.dev-only
- [ ] ЦІЛЬОВА_АРХІТЕКТУРА оновлена з посиланням на інтерфейс
- [ ] Verified: Trigger.dev SDK підтримує всі 7 capabilities (ASSUMPTION → FACT)

---

## Phase 2 — Dual-run (optional)

### Goals

1. Trigger.dev запускає паралельно в **dry-run mode**
2. Порівняти: чи Trigger.dev wrapper записує ті ж `status.json` / `manifest.json` / `steps/*.json`
3. Не створювати proposals (dry-run = без side effects на canonical storage)

### Changes Required

| Документ/компонент | Зміна | Тип |
|-------------------|-------|-----|
| Agent Service | Додати Trigger.dev SDK поряд з Inngest | IMPLEMENTATION |
| Agent Service | Feature flag: `ORCHESTRATOR=inngest|triggerdev|dual` | IMPLEMENTATION |
| MinIO | Dual-run записує в `runs/<runId>-dryrun/` (окрема директорія) | CONVENTION |
| Monitoring | Порівняння output: Inngest run vs Trigger.dev dry-run | MANUAL |

### Критерії успіху dual-run

| Критерій | Опис | Як перевірити |
|----------|------|---------------|
| **Status parity** | `status.json` від Trigger.dev має ідентичні стани та transitions | Порівняти JSON diff |
| **Step parity** | `steps/*.json` від Trigger.dev мають ідентичну структуру | Порівняти JSON diff |
| **Timing parity** | Trigger.dev не повільніший за Inngest на >20% | Порівняти `duration_ms` |
| **Retry behavior** | Trigger.dev retry при NLM 503 → аналогічний recovery | Manual test: зупинити FastAPI, перевірити retry |
| **Concurrency** | Другий run того ж агента → queued (не паралельний) | Manual test: запустити 2 runs |

### Risks

| Ризик | Ймовірність | Вплив | Мітигація |
|-------|-------------|-------|-----------|
| Dual-run подвоює навантаження на FastAPI/NLM | Середня | Середній | Dry-run НЕ викликає NLM; лише mock steps |
| Trigger.dev SDK конфлікт з Inngest SDK | Низька | Високий | Окремі endpoint handlers |
| Складність підтримки dual-mode | Середня | Середній | Feature flag, видалити після cutover |

### Acceptance Criteria / DoD

- [ ] Trigger.dev dry-run записує `runs/<runId>-dryrun/status.json`
- [ ] JSON diff між Inngest та Trigger.dev `status.json` — порожній (або задокументовані відмінності)
- [ ] Step results мають ідентичну структуру
- [ ] Concurrency enforcement працює
- [ ] Retry behavior підтверджений
- [ ] **Або**: Phase 2 пропущена (Owner вирішує, що dual-run не потрібний)

**[DECISION]** Phase 2 є **опціональною**. Owner може вирішити пропустити її і перейти одразу до Phase 3 (cutover), якщо Trigger.dev capabilities верифіковані в Phase 1.

---

## Phase 3 — Cutover

### Goals

1. Переключити orchestrator з Inngest на Trigger.dev
2. Забезпечити rollback plan
3. Зберегти availability (zero downtime)

### Changes Required

| Компонент | Зміна | Тип |
|-----------|-------|-----|
| Agent Service | `ORCHESTRATOR=triggerdev` (feature flag) | CONFIG |
| Worker | `POST /inngest` → Trigger.dev endpoint | IMPLEMENTATION |
| Worker | Event routing: `agent/run.requested` → Trigger.dev trigger | IMPLEMENTATION |
| Cron schedules | Inngest cron → Trigger.dev scheduled tasks | IMPLEMENTATION |
| Monitoring | Inngest dashboard → Trigger.dev dashboard | OPS |

### Момент перемикання

**[DECISION]** Cutover через **environment variable**:

```
ORCHESTRATOR_PROVIDER=triggerdev   # або "inngest" для rollback
```

Agent Service при startup:
1. Читає `ORCHESTRATOR_PROVIDER`
2. Ініціалізує відповідний SDK
3. Реєструє tasks/functions
4. Worker routing — без змін (Worker делегує Agent Service, не orchestrator напряму)

### Rollback Plan

| Крок | Дія | Час |
|------|-----|-----|
| 1 | Змінити `ORCHESTRATOR_PROVIDER=inngest` | 10 секунд |
| 2 | Перезапустити Agent Service | 30 секунд |
| 3 | Pending Trigger.dev runs — завершаться або timeout | Автоматично |
| 4 | Верифікувати: новий run → Inngest | 1 хвилина |

**[DECISION]** Rollback не потребує зміни MinIO, Worker, Frontend, FastAPI — вони orchestrator-agnostic.

**[DECISION]** Дані в MinIO (`runs/`, `status.json`) записані Trigger.dev — залишаються валідними і після rollback. Формат ідентичний.

### Risks

| Ризик | Ймовірність | Вплив | Мітигація |
|-------|-------------|-------|-----------|
| In-flight Inngest runs під час cutover | Середня | Середній | Drain: зачекати завершення active runs перед cutover |
| Trigger.dev SDK bug у production | Низька | Високий | Rollback plan (10 секунд) |
| Cron schedules не перереєструвались | Низька | Середній | Startup verification: Agent Service перевіряє всі cron при старті |
| Missing events після cutover | Низька | Середній | Monitoring: алерт якщо scheduled run не виконався |

### Acceptance Criteria / DoD

- [ ] Agent Service працює з `ORCHESTRATOR_PROVIDER=triggerdev`
- [ ] Manual agent run: UI → Worker → Trigger.dev → Mastra → MinIO → UI (end-to-end)
- [ ] Cron agent run: Trigger.dev scheduled → run completed
- [ ] Error scenario: NLM unavailable → retry → recovery або failed
- [ ] Rollback test: переключити на inngest → працює
- [ ] No changes in Frontend, Worker routing, MinIO paths
- [ ] Monitoring dashboard accessible

---

## Phase 4 — Decommission Inngest

### Goals

1. Видалити Inngest SDK та залежності
2. Оновити canonical docs
3. Позначити Inngest як deprecated у документації
4. Очистити feature flags

### Changes Required

| Документ/компонент | Зміна | Тип |
|-------------------|-------|-----|
| **Agent Service** | Видалити `@inngest/sdk` залежність | IMPLEMENTATION |
| **Agent Service** | Видалити Inngest-specific код | IMPLEMENTATION |
| **Agent Service** | Видалити feature flag `ORCHESTRATOR_PROVIDER` (тепер завжди Trigger.dev) | IMPLEMENTATION |
| `ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` | Перейменувати або banner: "Замінено на TARGET_ORCHESTRATION_MODEL_TRIGGERDEV_V1.md" | DOC |
| `GLOSSARY.md` | Inngest → deprecated, Trigger.dev → canonical | DOC |
| `АРХІТЕКТУРНИЙ_АУДИТ_ТА_УЗГОДЖЕНІСТЬ_FINAL.md` | §2.3 → Trigger.dev | DOC |
| `INBOX_AND_RUN_LIFECYCLE_V1.md` | Inngest → "Orchestrator (Trigger.dev)" | DOC |
| `КОНТРАКТ_АГЕНТА_V1.md` | §1.2: Inngest → Trigger.dev | DOC |
| `INBOX_ТА_PROPOSAL_АРХІТЕКТУРА.md` | §2.4: Inngest → Trigger.dev | DOC |
| `LOVABLE_УЗГОДЖЕННЯ_З_RUNTIME_АРХІТЕКТУРОЮ.md` | §5: Inngest → Trigger.dev | DOC |
| `API_CONTRACTS_V1.md` | §0.4 error codes: "Inngest" → "orchestrator" | DOC |
| `DOCUMENTATION_INVENTORY.md` | Оновити статус ЦІЛЬОВОЇ_АРХІТЕКТУРИ | DOC |
| `INNGEST_DEPRECATION_AND_CLEANUP_PLAN.md` | Виконати план (Phase 4 trigger) | DOC |

### Як позначити deprecated

**[DECISION]** Файли з Inngest-specific назвами:

| Файл | Дія |
|------|-----|
| `ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` | Додати banner: `> ⚠️ DEPRECATED: orchestrator мігровано на Trigger.dev. Див. TARGET_ORCHESTRATION_MODEL_TRIGGERDEV_V1.md` |
| Решта docs | Замінити "Inngest" → "Orchestrator (Trigger.dev)" inline |

**[DECISION]** НЕ видаляти `ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` — він містить цінні архітектурні рішення. Позначити banner + redirect.

### Як прибрати старі концепти

| Концепт | Дія |
|---------|-----|
| "Inngest event bus" | → "Trigger.dev task triggers" |
| "Inngest durable execution" | → "Trigger.dev durable execution" |
| "Inngest step functions" | → "Trigger.dev task steps" |
| "Inngest cron triggers" | → "Trigger.dev scheduled tasks" |
| "Inngest Cloud / Dev Server" | → "Trigger.dev Cloud / self-hosted" |
| `POST /inngest` endpoint | → Trigger.dev worker endpoint |
| `inngest.send()` | → Orchestrator Adapter |

### Risks

| Ризик | Ймовірність | Вплив | Мітигація |
|-------|-------------|-------|-----------|
| Передчасне видалення Inngest до стабілізації Trigger.dev | Середня | Високий | Decommission ТІЛЬКИ після 2+ тижнів stable operation |
| Пропущена згадка Inngest у документах | Низька | Низький | Grep "Inngest" у docs/ — checklist |
| Rollback неможливий після видалення SDK | Середня | Високий | Keep Inngest SDK version у documentation для emergency re-install |

### Acceptance Criteria / DoD

- [ ] `@inngest/sdk` видалено з `package.json`
- [ ] Жоден `.ts`/`.js` файл не імпортує Inngest
- [ ] Feature flag `ORCHESTRATOR_PROVIDER` видалений
- [ ] `grep -ri "inngest" docs/` → тільки deprecated banners та historical notes
- [ ] `ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` має deprecation banner
- [ ] GLOSSARY.md оновлений
- [ ] Trigger.dev stable ≥2 тижні без rollback
- [ ] `npm run build` без помилок

---

## Зведена таблиця фаз

| Фаза | Назва | Тип | Тривалість (estimate) | Залежність |
|------|-------|-----|----------------------|------------|
| **0** | Pre-migration hardening | Docs-only | 1 день | — |
| **1** | Abstraction layer | Docs + verification | 2–3 дні | Phase 0 |
| **2** | Dual-run (optional) | Implementation | 3–5 днів | Phase 1 |
| **3** | Cutover | Implementation + ops | 1 день | Phase 1 (або 2) |
| **4** | Decommission Inngest | Cleanup | 1–2 дні | Phase 3 + 2 тижні stable |

**Загалом:** 8–12 днів (з Phase 2) або 5–7 днів (без Phase 2).

---

*Цей документ є покроковим планом міграції Inngest → Trigger.dev. Кожна фаза залишає систему у працездатному стані.*
