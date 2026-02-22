# Архітектурний аудит та узгодженість — Trigger.dev Migration FINAL

> Створено: 2026-02-15
> Автор: Головний архітектор системи
> Статус: Фінальний аудит узгодженості після міграційної документації
> Мова: Українська (канонічна)
> Метод: Cross-document consistency audit
> Базується на: усіх канонічних документах + нові міграційні документи

---

## Перелік аудитованих документів

### Існуючі canonical

| Документ | Скорочення |
|----------|-----------|
| АРХІТЕКТУРНА_БАЗА_СИСТЕМИ.md | [БАЗА] |
| ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md | [ЦІЛЬОВА] |
| КОНТРАКТ_АГЕНТА_V1.md | [КОНТРАКТ] |
| INBOX_ТА_PROPOSAL_АРХІТЕКТУРА.md | [INBOX] |
| INBOX_AND_RUN_LIFECYCLE_V1.md | [LIFECYCLE] |
| PROPOSAL_SYSTEM_V1.md | [PROPOSAL] |
| LOVABLE_УЗГОДЖЕННЯ_З_RUNTIME_АРХІТЕКТУРОЮ.md | [FRONTEND] |
| API_CONTRACTS_V1.md | [API] |
| АРХІТЕКТУРНИЙ_АУДИТ_ТА_УЗГОДЖЕНІСТЬ_FINAL.md | [PREV_AUDIT] |
| GLOSSARY.md | [ГЛОСАРІЙ] |
| MANIFESTO.md | [МАНІФЕСТ] |

### Нові міграційні

| Документ | Скорочення |
|----------|-----------|
| MIGRATION_INNGEST_TO_TRIGGERDEV_INVENTORY.md | [ІНВЕНТАР] |
| TARGET_ORCHESTRATION_MODEL_TRIGGERDEV_V1.md | [TARGET] |
| MIGRATION_PLAN_INNGEST_TO_TRIGGERDEV_V1.md | [ПЛАН] |
| INNGEST_DEPRECATION_AND_CLEANUP_PLAN.md | [CLEANUP] |
| API_CONTRACTS_TRIGGERDEV_DELTA.md | [DELTA] |

---

## РОЗДІЛ 1 — Перевірка інваріантів

### Інваріант 1: Folder = Agent

**ПІДТВЕРДЖЕНО — НЕ ПОРУШЕНО**

Міграція orchestrator не стосується структури папок агентів. `_agent.md` залишається маркером. MinIO paths без змін.

Документи: [КОНТРАКТ] §1, [TARGET] §2.3, [ІНВЕНТАР] §4.1 — узгоджені.

---

### Інваріант 2: MinIO = canonical source of truth

**ПІДТВЕРДЖЕНО — НЕ ПОРУШЕНО**

[TARGET] §2.3: MinIO paths не змінюються. `status.json`, `manifest.json`, `steps/*.json` — ті ж schemas.
[DELTA] §1.3: API endpoints читають MinIO, не orchestrator.
[ІНВЕНТАР] §2.2: MinIO у списку "NOT affected by migration".

---

### Інваріант 3: `_agent.md` = behavioral contract

**ПІДТВЕРДЖЕНО — НЕ ПОРУШЕНО**

`_agent.md` читається Mastra (runtime), не orchestrator. Orchestrator swap не стосується behavioral contract.

---

### Інваріант 4: Mastra = runtime, не джерело істини

**ПІДТВЕРДЖЕНО — НЕ ПОРУШЕНО**

[TARGET] §1.3: Mastra роль ідентична в обох моделях. Mastra не залежить від orchestrator vendor.

---

### Інваріант 5: Proposal lifecycle = mutation gate

**ПІДТВЕРДЖЕНО — НЕ ПОРУШЕНО**

Proposal lifecycle визначений у [INBOX], [PROPOSAL], [LIFECYCLE]. Жоден з цих docs не залежить від orchestrator vendor. [DELTA] §1.4: proposal endpoints — NO CHANGE.

---

### Інваріант 6: Frontend = projection layer

**ПІДТВЕРДЖЕНО — НЕ ПОРУШЕНО**

[FRONTEND] Інваріант 6: "Agent runtime is opaque". [DELTA] §4: Vendor Opaqueness Verification — PASSED.

---

### Інваріант 7: Worker = single entrypoint

**ПІДТВЕРДЖЕНО — НЕ ПОРУШЕНО**

Worker делегує orchestrator, але API surface не змінюється. [DELTA] §1: усі endpoints — NO CHANGE.

---

## РОЗДІЛ 2 — Конфлікти між документами

### 2.1 [ЦІЛЬОВА] vs [TARGET]

| Аспект | [ЦІЛЬОВА] (Inngest) | [TARGET] (Trigger.dev) | Конфлікт? |
|--------|---------------------|----------------------|-----------|
| Orchestrator role | Inngest | Trigger.dev | **ОЧІКУВАНИЙ** — це мета міграції |
| MinIO paths | `agents/<slug>/runs/` | Ідентичні | **НІ** |
| Mastra role | Interpreter | Ідентична | **НІ** |
| Status writer | Inngest step function | Trigger.dev task step | **ОЧІКУВАНИЙ** — vendor swap |
| Event names | `agent/run.requested` | Ті ж бізнес-events | **НІ** |
| Deployment | Inngest Cloud/self-hosted | Trigger.dev Cloud/self-hosted | **ОЧІКУВАНИЙ** |
| Frontend flow | Identical | Identical | **НІ** |

**Вердикт:** Конфлікти між [ЦІЛЬОВА] та [TARGET] є **очікуваними** і **обмежені** orchestrator vendor box. Жодного архітектурного конфлікту.

**[DECISION]** Після Phase 4 (decommission): [ЦІЛЬОВА] отримує deprecation banner, [TARGET] стає canonical. До того — обидва документи valid (transitional period).

### 2.2 [LIFECYCLE] vs [TARGET]

| Аспект | [LIFECYCLE] | [TARGET] | Конфлікт? |
|--------|------------|----------|-----------|
| Run states | `requested→queued→running→completed\|failed` | Ідентичні | **НІ** |
| Status writer | "Inngest/backend" | "Trigger.dev task wrapper" | **ОЧІКУВАНИЙ** — vendor name |
| Polling | 5s interval | Те ж | **НІ** |
| State diagram | `participant IG as Inngest` | `participant TD as Trigger.dev` | **ОЧІКУВАНИЙ** — cosmetic |

**Вердикт:** Немає архітектурних конфліктів. Після Phase 4: [LIFECYCLE] оновлюється (REWRITE per [CLEANUP]).

### 2.3 [API] vs [DELTA]

**[DELTA] підтверджує: API_CONTRACTS_V1.md не потребує змін.** Єдина cosmetic зміна — опис `UPSTREAM_UNAVAILABLE`.

**Вердикт:** Немає конфліктів.

### 2.4 [ПЛАН] internal consistency

| Phase | Залежності | Узгоджено? |
|-------|-----------|------------|
| 0 → 1 | Phase 0 creates abstraction, Phase 1 uses it | **ТАК** |
| 1 → 2 | Phase 1 verifies capabilities, Phase 2 tests them | **ТАК** |
| 1 → 3 | Phase 1 sufficient for direct cutover (Phase 2 optional) | **ТАК** |
| 3 → 4 | Phase 3 cutover, Phase 4 cleanup after stability | **ТАК** |

**Вердикт:** План внутрішньо узгоджений.

### 2.5 [CLEANUP] vs [ІНВЕНТАР]

| Файл у [ІНВЕНТАР] | Класифікація у [CLEANUP] | Узгоджено? |
|-------------------|------------------------|------------|
| INBOX_AND_RUN_LIFECYCLE_V1.md (15 згадок) | REWRITE (~5 замін) | **ТАК** |
| КОНТРАКТ_АГЕНТА_V1.md (5 згадок) | REWRITE (~3 заміни) | **ТАК** |
| INBOX_ТА_PROPOSAL_АРХІТЕКТУРА.md (10 згадок) | REWRITE (~8 замін) | **ТАК** |
| ЦІЛЬОВА_АРХІТЕКТУРА (40+ згадок) | BANNER (не rewrite) | **ТАК** — banner + redirect на [TARGET] |
| GLOSSARY.md (2 згадки) | REWRITE (2 рядки) | **ТАК** |

**Вердикт:** [CLEANUP] правильно класифікує усі файли з [ІНВЕНТАР].

---

## РОЗДІЛ 3 — Missing Definitions

### 3.1 Failure handling

| Сценарій | Визначено? | Документ |
|----------|-----------|----------|
| Trigger.dev task crash → retry | **ТАК** | [TARGET] §4: max 3 retries, exponential backoff |
| Trigger.dev service unavailable | **ТАК** | [DELTA] §2.2: maps to `UPSTREAM_UNAVAILABLE` |
| Partial step write → recovery | **ТАК** | [TARGET] §3.3: step result ПЕРЕД status update |
| Total run timeout | **ТАК** | [TARGET] §4.1: 600s (10 хв) |

**Вердикт:** Failure handling визначено.

### 3.2 Concurrency

| Сценарій | Визначено? | Документ |
|----------|-----------|----------|
| Два runs одного агента | **ТАК** | [TARGET] §4.1: concurrency = 1 per agent |
| Global concurrency | **ТАК** | [TARGET] §4.1: max 5 concurrent runs |
| Queue position visibility | **ЧАСТКОВО** | [ІНВЕНТАР] §2.1: ASSUMPTION — Trigger.dev може повідомити позицію |

**Вердикт:** Concurrency визначено. Queue position — залежить від Trigger.dev API (потребує верифікації).

### 3.3 Recovery

| Сценарій | Визначено? | Документ |
|----------|-----------|----------|
| Orchestrator restart → in-flight runs | **ТАК** | [TARGET] §3.2: durable execution replay |
| Rollback Trigger.dev → Inngest | **ТАК** | [ПЛАН] Phase 3: env var switch, 10s rollback |
| MinIO data after rollback | **ТАК** | [ПЛАН] Phase 3: MinIO data orchestrator-agnostic |

**Вердикт:** Recovery визначено.

### 3.4 Versioning

| Аспект | Визначено? | Документ |
|--------|-----------|----------|
| Trigger.dev SDK version pinning | **НІ** | **[MISSING]** — потрібно зафіксувати мінімальну версію Trigger.dev v3 |
| Orchestrator Interface version | **НІ** | **[MISSING]** — [ПЛАН] Phase 1 створить ORCHESTRATOR_ADAPTER_INTERFACE.md, але versioning не описаний |

**Вердикт:** Versioning визначено **частково**. Рекомендація: додати мінімальну версію SDK у ORCHESTRATOR_ADAPTER_INTERFACE.md.

---

## РОЗДІЛ 4 — Ризики

| # | Ризик | Ймовірність | Вплив | Мітигація | Документ |
|---|-------|-------------|-------|-----------|----------|
| 1 | Trigger.dev не підтримує per-step retry | Низька | Високий | Верифікація у Phase 1 | [ІНВЕНТАР] ASSUMPTION |
| 2 | Queue position API відсутній у Trigger.dev | Середня | Низький | Показувати "У черзі" без номера позиції | [ІНВЕНТАР] ASSUMPTION |
| 3 | Trigger.dev self-hosted — складний deployment | Низька | Середній | Docker compose; спочатку cloud | [TARGET] §6.2 |
| 4 | Документи розсинхронізуються під час transitional period | Середня | Середній | Phase 0→4 послідовно; один author | [ПЛАН] |
| 5 | Inngest-specific event naming не маппиться на Trigger.dev | Низька | Середній | Events — бізнес-level, не vendor | [DELTA] |

---

## РОЗДІЛ 5 — Уточнення

### 5.1 ASSUMPTIONs що потребують верифікації

| # | ASSUMPTION | Де зафіксований | Як верифікувати | Пріоритет |
|---|-----------|-----------------|-----------------|-----------|
| 1 | Trigger.dev підтримує durable execution з per-step replay | [ІНВЕНТАР] §2.1 | Trigger.dev docs / POC | **P0** — блокує міграцію |
| 2 | Trigger.dev підтримує custom event triggers (HTTP) | [ІНВЕНТАР] §2.1 | Trigger.dev docs | **P0** |
| 3 | Trigger.dev підтримує per-task concurrency limits | [ІНВЕНТАР] §2.1 | Trigger.dev docs | **P0** |
| 4 | Trigger.dev підтримує cron scheduling | [ІНВЕНТАР] §2.1 | Trigger.dev docs | **P0** |
| 5 | Trigger.dev підтримує step-level timeouts | [ІНВЕНТАР] §2.1 | Trigger.dev docs | **P1** |
| 6 | Trigger.dev підтримує queue position query | [ІНВЕНТАР] §2.1 | Trigger.dev docs | **P2** — nice-to-have |
| 7 | Trigger.dev підтримує completion webhook/callback | [ІНВЕНТАР] §2.1 | Trigger.dev docs | **P1** |
| 8 | Trigger.dev v3 self-hosted via Docker | [TARGET] §6.2 | Trigger.dev docs | **P1** |

**[DECISION]** ASSUMPTIONs #1–4 (P0) блокують перехід до Phase 2/3. Мають бути верифіковані у Phase 1.

### 5.2 Open questions

| # | Питання | Відповідь | Документ |
|---|---------|----------|----------|
| 1 | Чи зберігати файл ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md після міграції? | **ТАК** — banner + redirect | [CLEANUP] §1.2 |
| 2 | Чи потрібна Phase 2 (dual-run)? | **Owner вирішує** — опціональна | [ПЛАН] Phase 2 |
| 3 | Яку версію Trigger.dev SDK використовувати? | **TBD** — v3 latest | [MISSING] |
| 4 | Cloud vs self-hosted для production? | **Owner вирішує** | [TARGET] §6.2 |

---

## РОЗДІЛ 6 — Фінальний вердикт

### ARCHITECTURE CONSISTENT — міграційна документація не порушує інваріантів

---

### Обґрунтування

1. **Інваріанти (7/7 підтверджено):** Жоден інваріант не порушений міграцією. Orchestrator layer правильно ізольований.

2. **Конфлікти (0 архітектурних):** Усі виявлені конфлікти між [ЦІЛЬОВА] та [TARGET] є **очікуваними** vendor-swap конфліктами, не архітектурними.

3. **API контракти (NO CHANGE):** [DELTA] підтверджує нульовий вплив на API layer. Frontend не потребує змін.

4. **Missing definitions (2):**
   - Trigger.dev SDK version — додати при реалізації
   - Orchestrator Interface version — додати у Phase 1

5. **ASSUMPTIONs (8):** Потребують верифікації у Phase 1. 4 з них — P0 (blocking).

6. **Ризики (5):** Всі з мітигаціями. Жоден не є show-stopper.

### Рівень готовності

| Рівень | Опис | Стан |
|--------|------|------|
| 1. Інвентар | Де Inngest, що міняти | ✅ [ІНВЕНТАР] |
| 2. Цільова модель | Як виглядає з Trigger.dev | ✅ [TARGET] |
| 3. План міграції | Покрокові фази | ✅ [ПЛАН] |
| 4. Cleanup план | Як очистити docs | ✅ [CLEANUP] |
| 5. API delta | Чи міняти контракти | ✅ [DELTA] — NO CHANGE |
| 6. Аудит | Узгодженість | ✅ Цей документ |

**Міграційна документація готова. Наступний крок: верифікація ASSUMPTIONs (Phase 1).**

---

*Цей документ є фінальним архітектурним аудитом міграції Inngest → Trigger.dev. Він підтверджує узгодженість міграційної документації з canonical архітектурою.*
