# Міграція Inngest → Trigger.dev: Інвентар та Impact Map

> Створено: 2026-02-15
> Автор: Головний архітектор системи
> Статус: Інвентаризація (DRY-RUN — без змін у коді/репозиторії)
> Мова: Українська (канонічна)
> Базується на: усіх канонічних документах docs/

---

## 0. Контекст та інваріанти

**ROLE:** Головний архітектор Garden Seedling, автор маніфесту.

**МЕТА:** Повний інвентар згадок та залежностей від Inngest у canonical docs для підготовки міграції на Trigger.dev.

**Canonical інваріанти (НЕ чіпати):**

| Інваріант | Статус |
|-----------|--------|
| Folder = Agent | **[FACT]** Не змінюється |
| MinIO = canonical source of truth | **[FACT]** Не змінюється |
| `_agent.md` = behavioral contract | **[FACT]** Не змінюється |
| Mastra = runtime інтерпретатор, не джерело істини | **[FACT]** Не змінюється |
| Humans approve = proposal gate | **[FACT]** Не змінюється |
| Frontend = projection layer | **[FACT]** Не змінюється |
| Worker (Gateway) = single entrypoint | **[FACT]** Не змінюється |

**[DECISION]** Міграція Inngest → Trigger.dev є **pure orchestrator swap**. Жоден інваріант не порушується. Змінюється лише реалізація orchestration layer.

---

## 1. Where Inngest Appears

### 1.1 Canonical Documents з прямими згадками Inngest

| # | Файл | Секція | Що саме Inngest гарантує | Кількість згадок |
|---|------|--------|--------------------------|------------------|
| 1 | `ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` | §2.3, §3, §4, §5, §7 | Durable execution, event-driven triggers, step-based workflows, concurrency control, cron, timeouts. **Головний документ** | ~40+ |
| 2 | `INBOX_AND_RUN_LIFECYCLE_V1.md` | §2.1–2.6 | Run state machine (`requested→queued→running→completed/failed`), status writer, step completion tracking | ~15 |
| 3 | `API_CONTRACTS_V1.md` | §0.4, Appendix A | Error code `UPSTREAM_UNAVAILABLE` (MinIO, Inngest), `502` upstream error | ~3 |
| 4 | `INBOX_ТА_PROPOSAL_АРХІТЕКТУРА.md` | §2.4, §5 | Agent run orchestration, Inngest callback як webhook source | ~10 |
| 5 | `КОНТРАКТ_АГЕНТА_V1.md` | §1.2, §4.3 | Runs/ записується Inngest + Mastra, error state transition | ~5 |
| 6 | `АРХІТЕКТУРНИЙ_АУДИТ_ТА_УЗГОДЖЕНІСТЬ_FINAL.md` | §2.3, §4.1, §4.4 | Orchestration authority, failure handling, runtime restart | ~10 |
| 7 | `LOVABLE_УЗГОДЖЕННЯ_З_RUNTIME_АРХІТЕКТУРОЮ.md` | §1.2, §2.3, §3.2, §5, §6 (Inv.6) | Frontend опаковує Inngest як "opaque runtime", events через Worker | ~8 |
| 8 | `АРХІТЕКТУРНА_БАЗА_СИСТЕМИ.md` | §4.2, §2 | "Inngest" у таблиці canonical sources (deprecated gh-aw); Mastra+Inngest як цільова архітектура | ~3 |
| 9 | `GLOSSARY.md` | Компоненти архітектури | Визначення терміну "Inngest" | ~2 |
| 10 | `DOCUMENTATION_INVENTORY.md` | §1 | Статус файлу ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md | ~3 |
| 11 | `FRONTEND_V1_MIGRATION_PLAN.md` | — | Немає прямих згадок Inngest (frontend opaque) | 0 |

### 1.2 Типи згадок

| Тип згадки | Приклади | Вплив міграції |
|-----------|----------|----------------|
| **Назва файлу** | `ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` | **[DECISION]** Перейменувати або залишити з banner |
| **Mermaid діаграми** | `subgraph "Orchestration — Inngest"` | **[DECISION]** Перемалювати |
| **Таблиці ролей** | "Inngest — система оркестрації" | **[DECISION]** Замінити на Trigger.dev |
| **Sequence діаграми** | `participant IG as Inngest` | **[DECISION]** Перемалювати |
| **Інваріанти/принципи** | "Inngest не містить бізнес-логіки" | **[DECISION]** Зберегти принцип, замінити vendor |
| **Error codes** | `UPSTREAM_UNAVAILABLE: Inngest недоступний` | **[DECISION]** Замінити на generic "orchestrator" |
| **Event names** | `agent/run.requested`, `agent/run.finished` | **[ASSUMPTION]** Trigger.dev може підтримати аналогічні events |
| **Deployment** | `POST /inngest (serve function)` | **[DECISION]** Замінити на Trigger.dev endpoint |
| **Глосарій** | Визначення "Inngest" | **[DECISION]** Оновити |

---

## 2. Responsibility Map

### 2.1 Capability mapping: Inngest → Trigger.dev

| Capability | Current Owner | Migration Target Owner | Notes |
|-----------|--------------|----------------------|-------|
| **Event-driven triggers** (`agent/run.requested`) | Inngest event bus | Trigger.dev trigger/event system | **[ASSUMPTION]** Trigger.dev підтримує custom event triggers |
| **Durable execution** (retry з останнього кроку) | Inngest durable engine | Trigger.dev durable execution | **[ASSUMPTION]** Trigger.dev має аналогічну durability guarantee |
| **Step-based workflows** (load→query→propose→persist) | Inngest step functions | Trigger.dev task steps | **[ASSUMPTION]** Trigger.dev підтримує step-based orchestration |
| **Concurrency control** (1 per agent) | Inngest native concurrency | Trigger.dev concurrency limits | **[ASSUMPTION]** Trigger.dev має per-trigger concurrency |
| **Cron triggers** (планові запуски) | Inngest cron | Trigger.dev scheduled triggers | **[ASSUMPTION]** Trigger.dev має cron scheduling |
| **Timeouts** (120с на крок) | Inngest step timeout | Trigger.dev task timeout | **[ASSUMPTION]** Trigger.dev має step-level timeouts |
| **Retries/backoff** | Inngest retry policy | Trigger.dev retry configuration | **[ASSUMPTION]** Trigger.dev має configurable retries |
| **Status writing** (status.json → MinIO) | Inngest step function wrapper | Trigger.dev task wrapper | **[DECISION]** Status writer = orchestrator wrapper (не Mastra) |
| **Run lifecycle states** (requested→queued→running→...) | Inngest state machine | Trigger.dev run states | **[ASSUMPTION]** Trigger.dev має аналогічні run states |
| **Idempotency** (correlationId) | Worker + Inngest event dedup | Worker + Trigger.dev idempotency | **[ASSUMPTION]** Trigger.dev підтримує idempotency keys |
| **Step logs** (проміжні результати) | Inngest step results | Trigger.dev step output | **[ASSUMPTION]** Trigger.dev зберігає step results |
| **Queue position** (позиція в черзі) | Inngest queue metrics | Trigger.dev queue info | **[ASSUMPTION]** Trigger.dev може повідомити позицію |
| **Event callback** (run.finished → Worker) | Inngest callback/webhook | Trigger.dev webhook/callback | **[ASSUMPTION]** Trigger.dev підтримує completion callbacks |
| **Dashboard/UI** (моніторинг) | Inngest Dashboard | Trigger.dev Dashboard | **[FACT]** Обидва мають web dashboards |

### 2.2 Components NOT affected by migration

| Компонент | Причина |
|-----------|---------|
| **MinIO** | Storage layer — orchestrator-agnostic |
| **Mastra** | Runtime — викликається orchestrator, але не залежить від vendor |
| **FastAPI** | Cognitive proxy — не знає про orchestrator |
| **Cloudflare Worker** | Gateway — делегує orchestrator, абстрагує його від frontend |
| **Frontend** | Projection layer — `Інваріант 6: Agent runtime is opaque` |
| **Cloudflare KV** | Auth/zones — не пов'язаний з orchestrator |
| **GitHub** | Content persistence — orchestrator-agnostic |

---

## 3. Non-Doc Impacts (зони ризику)

### 3.1 Runtime контракти, що можуть бути implicit tied to Inngest

| Зона ризику | Деталі | Серйозність |
|-------------|--------|-------------|
| **Event naming convention** | `agent/run.requested`, `agent/step.completed`, `agent/run.finished`, `inbox.item.created`, `proposal.created` — Inngest event naming format. Trigger.dev може мати інший формат | **[ASSUMPTION]** Середня — потрібно перевірити Trigger.dev event naming |
| **Inngest serve endpoint** | `POST /inngest` — специфічний endpoint для Inngest SDK. Trigger.dev має власний endpoint | **[FACT]** Потрібно замінити |
| **Inngest Cloud vs self-hosted** | Документація описує два варіанти. Trigger.dev також має cloud/self-hosted | **[ASSUMPTION]** Trigger.dev self-hosted доступний |
| **Inngest SDK API surface** | `inngest.send()`, `step.run()`, `step.sleep()` — API Inngest SDK. Trigger.dev має інший API | **[FACT]** Потрібно адаптер/wrapper |
| **Step function semantics** | Inngest step function записує step result, retry per-step. Trigger.dev може мати іншу семантику per-step retry | **[ASSUMPTION]** Потрібно верифікувати |
| **Concurrency key** | Inngest uses `concurrency.key` для per-agent limiting. Trigger.dev може мати інший механізм | **[ASSUMPTION]** Потрібно верифікувати |
| **Error code `UPSTREAM_UNAVAILABLE`** | API contract включає Inngest у список upstream. Замінити на generic | **[DECISION]** Тривіальна заміна |
| **Deployment topology** | `Agent Service (Node.js/TypeScript)` з Inngest SDK Client. Потрібно замінити на Trigger.dev SDK | **[FACT]** Архітектурно аналогічно |

### 3.2 Frontend зони ризику

| Зона | Деталі | Вплив |
|------|--------|-------|
| **Polling endpoints** | `GET /runs/{runId}/status` — джерело даних Worker → MinIO `status.json`. Inngest пише status.json. Trigger.dev буде писати ті ж файли | **НУЛЬОВИЙ** — frontend не знає хто пише |
| **Error codes** | `UPSTREAM_UNAVAILABLE` — generic, не Inngest-специфічний | **НУЛЬОВИЙ** — код вже абстрагований |
| **Run states** | `requested/queued/running/completed/failed` — визначені в API contract, не в Inngest | **НУЛЬОВИЙ** — frontend оперує абстракціями |

**[FACT]** Frontend повністю ізольований від orchestrator vendor завдяки `Інваріант 6: Agent runtime is opaque`.

---

## 4. Decision Framing

### 4.1 Що НЕ змінюємо (інваріанти)

| Інваріант | Гарантія |
|-----------|----------|
| Folder = Agent | `_agent.md` = маркер; MinIO paths незмінні |
| MinIO = source of truth | Runs, proposals, audit — все у MinIO |
| `_agent.md` = behavioral contract | Mastra читає з MinIO, не з orchestrator |
| Mastra = stateless interpreter | Не залежить від orchestrator vendor |
| Proposal lifecycle | Inbox → Proposal → Approval → Apply — orchestrator-agnostic |
| Frontend = projection | Не знає про orchestrator |
| Worker = single entrypoint | Worker абстрагує orchestrator від frontend |
| Status writer = orchestrator wrapper | **[DECISION]** Принцип зберігається: хто б не був orchestrator, він пише status.json |

### 4.2 Що змінюємо (orchestrator layer only)

| Зміна | Тип |
|-------|-----|
| SDK: `@inngest/sdk` → `@trigger.dev/sdk` | **[DECISION]** Implementation change |
| Event API: `inngest.send()` → Trigger.dev emit | **[DECISION]** Implementation change |
| Step API: `step.run()` → Trigger.dev step | **[DECISION]** Implementation change |
| Endpoint: `POST /inngest` → Trigger.dev webhook | **[DECISION]** Implementation change |
| Cron: Inngest cron → Trigger.dev scheduled triggers | **[DECISION]** Implementation change |
| Deployment: Inngest Cloud/self-hosted → Trigger.dev cloud/self-hosted | **[DECISION]** Infrastructure change |
| Documentation: "Inngest" → "Trigger.dev" (або "Orchestrator") | **[DECISION]** Doc change |
| Glossary: Оновити визначення | **[DECISION]** Doc change |
| Diagrams: Перемалювати Mermaid | **[DECISION]** Doc change |

### 4.3 Висновок інвентаризації

**[FACT]** Inngest згадується у **10 canonical документах** з різним ступенем залежності.

**[FACT]** Жодна згадка Inngest не стосується **бізнес-логіки** або **інваріантів**. Усі згадки — у контексті orchestration layer.

**[DECISION]** Міграція є **vendor swap** у чітко визначеному шарі (orchestration). Архітектурна цілісність зберігається.

**[ASSUMPTION]** Trigger.dev підтримує всі capability, що використовуються Inngest у цій системі (durable execution, step functions, cron, concurrency, timeouts, retries, callbacks). Це потребує верифікації перед реалізацією.

---

*Цей документ є інвентарем для міграції Inngest → Trigger.dev. Він не пропонує змін — лише фіксує поточний стан залежностей.*
