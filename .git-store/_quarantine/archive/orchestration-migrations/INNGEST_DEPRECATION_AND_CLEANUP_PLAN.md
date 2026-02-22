# Inngest Deprecation та Cleanup Plan

> Створено: 2026-02-15
> Автор: Головний архітектор системи
> Статус: Plan (DRY-RUN)
> Мова: Українська (канонічна)
> Базується на: MIGRATION_INNGEST_TO_TRIGGERDEV_INVENTORY.md, DOCUMENTATION_INVENTORY.md

---

## 0. Мета

Визначити для кожного документа, що містить Inngest-специфічні згадки:
- **REWRITE** — переписати секції з Inngest → Trigger.dev / Orchestrator
- **MOVE** — перенести в archive/
- **BANNER** — додати deprecation banner
- **KEEP** — залишити без змін
- **DELETE** — видалити

**[DECISION]** Canonical docs не повинні вимагати знання Inngest-специфічних термінів. Після cleanup, reader повинен розуміти архітектуру без історичного контексту Inngest.

---

## 1. Класифікація файлів

### 1.1 Category A: REWRITE (переписати секції)

| # | Файл | Секції для переписування | Обсяг змін |
|---|------|------------------------|------------|
| 1 | `INBOX_AND_RUN_LIFECYCLE_V1.md` | §2.1 state diagram (`Inngest прийняв event`), §2.2 (`Inngest (через Worker callback)`), §2.6 Status Writer | Мінімальний: замінити "Inngest" → "Orchestrator (Trigger.dev)" у ~5 місцях |
| 2 | `КОНТРАКТ_АГЕНТА_V1.md` | §1.2 (`Inngest + Mastra`), §4.3 (`runtime помилка`) | Мінімальний: ~3 заміни |
| 3 | `INBOX_ТА_PROPOSAL_АРХІТЕКТУРА.md` | §2.4 (`Mastra через Inngest`), §5 sequence diagrams | Середній: перемалювати 2 diagrams, ~8 замін |
| 4 | `АРХІТЕКТУРНИЙ_АУДИТ_ТА_УЗГОДЖЕНІСТЬ_FINAL.md` | §2.3 Orchestration authority, §4.1 failure handling, §4.4 runtime restart, event names | Середній: ~10 замін, переписати authority section |
| 5 | `LOVABLE_УЗГОДЖЕННЯ_З_RUNTIME_АРХІТЕКТУРОЮ.md` | §1.2 (data flow), §3.2 (sequence diagram), §5 (architecture diagram) | Середній: перемалювати 2 diagrams, ~5 замін |
| 6 | `API_CONTRACTS_V1.md` | §0.4 (502 Inngest), Appendix A (`UPSTREAM_UNAVAILABLE` description) | Мінімальний: ~2 заміни |
| 7 | `АРХІТЕКТУРНА_БАЗА_СИСТЕМИ.md` | §2 canonical sources table, §4.2 | Мінімальний: ~2 заміни |
| 8 | `GLOSSARY.md` | Термін "Inngest", "Mastra" (оновити контекст) | Мінімальний: оновити 2 рядки, додати 2 нових |
| 9 | `DOCUMENTATION_INVENTORY.md` | §1 inventory table | Мінімальний: оновити статус файлів |

### 1.2 Category B: MOVE to archive (перенести)

| # | Файл | Причина | Destination |
|---|------|---------|-------------|
| 1 | `ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` | **[DECISION]** НЕ переносити. Додати BANNER + redirect. Файл містить цінні архітектурні рішення (MinIO layout, Mastra roles, deployment), які не Inngest-специфічні. | BANNER (Category D) |

**[DECISION]** Жоден canonical doc не переноситься в archive. Усі docs проходять REWRITE або BANNER.

### 1.3 Category C: KEEP (без змін)

| # | Файл | Причина |
|---|------|---------|
| 1 | `MANIFESTO.md` | Не містить згадок Inngest |
| 2 | `PHILOSOPHY_EVERYTHING_AGENT.md` | Не містить згадок Inngest |
| 3 | `LANGUAGE_CANONICALIZATION.md` | Не містить згадок Inngest |
| 4 | `БЕЗПЕКА_СИСТЕМИ.md` | Не містить згадок Inngest |
| 5 | `DRAKON_ІНТЕГРАЦІЯ_ТА_МОДЕЛЬ_ВИКОНАННЯ_АГЕНТА.md` | Мінімальні згадки Inngest у контексті "Mastra + Inngest" — замінити inline |
| 6 | `PROPOSAL_SYSTEM_V1.md` | Не містить згадок Inngest |
| 7 | `FRONTEND_V1_MIGRATION_PLAN.md` | Не містить згадок Inngest (frontend opaque) |
| 8 | Усі `docs/drakon/*` | Не містять згадок Inngest |

### 1.4 Category D: BANNER (deprecation banner)

| # | Файл | Banner text |
|---|------|-------------|
| 1 | `ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` | `> ⚠️ DEPRECATED ORCHESTRATOR: Inngest мігровано на Trigger.dev (2026-02-15). Orchestrator-специфічні секції (§2.3, §3, §7) замінені TARGET_ORCHESTRATION_MODEL_TRIGGERDEV_V1.md. Решта секцій (MinIO, Mastra, FastAPI, Worker, Frontend) залишаються canonical.` |
| 2 | `АРХІТЕКТУРНИЙ_АУДИТ_ТА_УЗГОДЖЕНІСТЬ.md` (старий) | Вже позначений як DEPRECATED у DOCUMENTATION_INVENTORY |

### 1.5 Category E: DELETE

**[DECISION]** Жоден файл не видаляється. Inngest-specific content перетворюється на "Orchestrator" або отримує banner.

---

## 2. Правила заміни

### 2.1 Terminology mapping

| Inngest-specific термін | Заміна у canonical docs |
|------------------------|------------------------|
| "Inngest" (як vendor) | "Orchestrator (Trigger.dev)" |
| "Inngest" (як інтерфейс/шар) | "Orchestrator" |
| "Inngest event bus" | "Orchestrator event/trigger system" |
| "Inngest durable execution" | "Orchestrator durable execution" |
| "Inngest step functions" | "Orchestrator task steps" |
| "Inngest cron triggers" | "Orchestrator scheduled tasks" |
| "Inngest Cloud" | "Orchestrator cloud service" |
| "Inngest Dev Server" | "Orchestrator self-hosted" |
| `inngest.send()` | "Orchestrator emit event" |
| `step.run()` | "Orchestrator step execution" |
| `POST /inngest` | "Orchestrator endpoint" |
| "Inngest SDK Client" | "Orchestrator SDK Client" |
| `participant IG as Inngest` (Mermaid) | `participant ORC as Orchestrator` |
| `subgraph "Orchestration — Inngest"` | `subgraph "Orchestration — Trigger.dev"` |
| "Inngest callback" | "Orchestrator webhook/callback" |
| "Mastra + Inngest" (у назвах) | "Mastra + Orchestrator" або "Mastra + Trigger.dev" |

### 2.2 Правила контексту

| Контекст | Правило | Приклад |
|----------|---------|---------|
| **Принцип/інваріант** | Замінити vendor → generic "Orchestrator" | "Orchestrator не містить бізнес-логіки" |
| **Архітектурна діаграма** | Замінити box label → "Trigger.dev" | `subgraph "Orchestration — Trigger.dev"` |
| **Sequence diagram** | Замінити participant → "Orchestrator" або "Trigger.dev" | `participant TD as Trigger.dev` |
| **Таблиця ролей** | Замінити "Inngest" → "Orchestrator (Trigger.dev)" | "Orchestrator (Trigger.dev) — система оркестрації" |
| **Error codes** | Замінити "Inngest" → "orchestrator" | `UPSTREAM_UNAVAILABLE: orchestrator недоступний` |
| **Event names** | Зберегти as-is | `agent/run.requested` — це бізнес-event, не Inngest-specific |
| **Deployment** | Замінити повністю | "Trigger.dev Cloud або self-hosted" |
| **Historical notes** | Зберегти у banner/footnote | "Раніше: Inngest (до 2026-02-15)" |

### 2.3 Мінімальність правок

**[DECISION]** Зміни мають бути **мінімальними**:
- НЕ переписувати параграфи (лише заміна слова "Inngest")
- НЕ реструктурувати документи
- НЕ видаляти секції
- Зберегти markup/formatting
- Зберегти cross-references

---

## 3. Історичні згадки

### 3.1 Правило

**[DECISION]** Історичні згадки Inngest (у контексті "ми мігрували з Inngest") зберігаються як:

1. **Banner** на файлі ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md
2. **Deprecated entry** у GLOSSARY.md
3. **Footnote** у нових документах (де доречно):
   ```
   > Примітка: до 2026-02-15 orchestrator layer реалізовувався через Inngest.
   > Див. archive/ для Inngest-specific деталей.
   ```

### 3.2 Що НЕ архівувати

| Елемент | Причина |
|---------|---------|
| MinIO layout (з ЦІЛЬОВОЇ_АРХІТЕКТУРИ) | Не Inngest-specific |
| Mastra roles та обмеження | Не Inngest-specific |
| FastAPI integration | Не Inngest-specific |
| Frontend projection rules | Не Inngest-specific |
| Proposal lifecycle | Не Inngest-specific |
| Agent contract (`_agent.md`) | Не Inngest-specific |
| Worker gateway rules | Не Inngest-specific |

---

## 4. Execution Checklist

### Phase 0 (pre-migration)

- [ ] Оновити GLOSSARY.md: додати "Orchestrator", "Trigger.dev"; deprecate "Inngest"
- [ ] Оновити АРХІТЕКТУРНА_БАЗА_СИСТЕМИ.md: §2 canonical sources
- [ ] Оновити DOCUMENTATION_INVENTORY.md: нові файли

### Phase 4 (post-cutover)

- [ ] Додати banner на ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md
- [ ] REWRITE: INBOX_AND_RUN_LIFECYCLE_V1.md (~5 замін)
- [ ] REWRITE: КОНТРАКТ_АГЕНТА_V1.md (~3 заміни)
- [ ] REWRITE: INBOX_ТА_PROPOSAL_АРХІТЕКТУРА.md (~8 замін + 2 diagrams)
- [ ] REWRITE: АРХІТЕКТУРНИЙ_АУДИТ_ТА_УЗГОДЖЕНІСТЬ_FINAL.md (~10 замін)
- [ ] REWRITE: LOVABLE_УЗГОДЖЕННЯ_З_RUNTIME_АРХІТЕКТУРОЮ.md (~5 замін + 2 diagrams)
- [ ] REWRITE: API_CONTRACTS_V1.md (~2 заміни)
- [ ] REWRITE: DRAKON_ІНТЕГРАЦІЯ (~2 заміни inline)
- [ ] Verify: `grep -ri "inngest" docs/` → тільки banners, deprecated entries, historical notes
- [ ] Verify: жоден canonical doc не вимагає знання Inngest для розуміння архітектури

---

*Цей документ є планом decontamination canonical docs від Inngest-specific термінології після міграції на Trigger.dev.*
