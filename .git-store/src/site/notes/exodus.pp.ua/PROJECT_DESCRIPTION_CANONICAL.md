---
{"tags":["domain:arch","status:canonical","format:spec"],"created":"2026-02-21","updated":"2026-02-21","tier":1,"title":"PROJECT DESCRIPTION CANONICAL","dg-publish":true,"dg-metatags":null,"dg-home":null,"permalink":"/exodus.pp.ua/PROJECT_DESCRIPTION_CANONICAL/","dgPassFrontmatter":true,"noteIcon":""}
---


# Garden Bloom — Canonical Project Description

> Створено: 2026-02-15
> Автор: Головний архітектор системи
> Статус: Канонічний
> Мова: English (canonical)

---

## 1. Executive Overview

Garden Bloom — це execution platform для автономних агентів і knowledge-centric workflows, побудована на storage-centric architecture, де всі зміни knowledge state контролюються через consent-based Proposal system, а behavioral logic визначається декларативно через DRAKON diagrams і Markdown-контракти.

Garden Bloom **НЕ є chatbot або AI-додатком.** Це операційна система для агентів, яка забезпечує:

- контрольоване виконання агентів
- повністю audit-able mutation knowledge state
- deterministic authority model
- vendor-agnostic orchestration
- safe autonomy для AI-агентів

Система забезпечує strict separation між:

- **behavioral intent** (contract)
- **execution** (runtime)
- **orchestration** (execution coordination)
- **authority** (storage)

---

## 2. Core Architectural Principles

### 2.1 Storage is the single source of truth

Єдиним canonical authority є object storage (MinIO).

У storage зберігаються:

- agent definitions (`_agent.md`)
- behavioral logic (`pseudocode.md`)
- drakon diagrams (`.drakon.json`)
- run artifacts (`runs/<runId>/`)
- proposals (`proposals/`)
- audit logs (`audit/`)
- system indexes

Runtime, orchestration і frontend можуть втратити весь свій стан без втрати knowledge state.

### 2.2 Execution layers are replaceable

Execution layers не є authoritative.

До них належать:

- Orchestration Layer
- Mastra runtime
- Gateway
- Frontend

Вони можуть бути замінені без зміни canonical knowledge state.

Це забезпечує vendor independence.

### 2.3 Proposal-based mutation model

Жоден компонент НЕ має права змінювати knowledge state напряму.

Будь-яка зміна відбувається через Proposal lifecycle:

```
proposed → pending → approved → applied | rejected | failed
```

Proposal system забезпечує:

- consent-based mutation
- auditability
- conflict safety
- deterministic change history

### 2.4 Behavioral logic is declarative

Behavior агентів визначається через:

- `_agent.md`
- `pseudocode.md`
- DRAKON diagrams

Runtime НЕ визначає behavior.

Runtime лише інтерпретує contract.

Це забезпечує separation between intent and execution.

---

## 3. System Architecture

Система складається з п'яти основних layers:

```
Frontend
    ↕
Gateway
    ↕
Orchestration Layer
    ↕
Runtime Layer
    ↕
Storage Layer
```

---

## 4. Frontend Layer

Frontend є presentation layer і control interface.

Він відповідає за:

- перегляд knowledge state
- відображення agent runs
- proposal approval / rejection
- створення user actions

Frontend НЕ має write authority над storage.

Frontend взаємодіє лише з Gateway.

---

## 5. Gateway Layer

Gateway є єдиною точкою входу для write operations.

Реалізований як stateless API layer (Cloudflare Worker).

Gateway відповідає за:

- authentication
- authorization
- validation
- proposal creation
- routing execution requests
- audit logging

Gateway НЕ зберігає canonical knowledge state.

Gateway НЕ виконує agent logic.

---

## 6. Orchestration Layer

Orchestration Layer відповідає за execution lifecycle.

Його відповідальність:

- scheduling execution
- retry handling
- concurrency control
- run lifecycle management

Canonical lifecycle:

```
requested → queued → running → completed | failed
```

Orchestration Layer НЕ є authoritative.

Він не інтерпретує behavioral logic.

Він лише координує execution.

Orchestration Layer є vendor-agnostic abstraction.

Може бути реалізований через:

- Trigger.dev
- Temporal
- BullMQ
- custom orchestrator

без зміни інших layers.

---

## 7. Runtime Layer (Mastra)

Mastra runtime є execution engine.

Його відповідальність:

- loading agent contract
- interpreting pseudocode через LLM
- executing tools
- generating proposals
- writing execution artifacts

Mastra НЕ має authority змінювати canonical knowledge state.

Mastra генерує proposals замість direct mutations.

---

## 8. Storage Layer (MinIO)

Storage є canonical authority.

Він зберігає:

- agent definitions
- execution artifacts
- proposals
- audit logs
- system indexes

Storage визначає system state.

Всі інші layers є consumers або producers через controlled interfaces.

---

## 9. Agent Model

Agent визначається через contract files:

- `_agent.md`
- `pseudocode.md`
- drakon diagram

Agent contract визначає:

- execution intent
- decision logic
- available tools
- behavioral flow

Runtime інтерпретує contract, але НЕ визначає його.

---

## 10. Execution Lifecycle

Execution починається через Gateway або Orchestration Layer.

Pipeline:

```
Trigger
  ↓
Orchestration Layer creates run
  ↓
Runtime loads contract
  ↓
Runtime executes logic
  ↓
Runtime generates artifacts
  ↓
Runtime generates proposals (if mutation required)
  ↓
Gateway applies approved proposals
  ↓
Storage updated
```

---

## 11. Proposal System

Proposal system є safety mechanism.

Proposal містить:

- mutation intent
- target path
- proposed content
- agent metadata
- audit information

Proposal може бути:

- approved
- rejected
- failed

Proposal approval є explicit consent mechanism.

---

## 12. Authority Model

Authority hierarchy:

| Layer | Role |
|-------|------|
| **Storage** | canonical authority |
| **Gateway** | write gatekeeper |
| **Orchestration** | execution coordinator |
| **Runtime** | contract interpreter |
| **Frontend** | presentation layer |

Жоден layer крім Gateway НЕ має write authority.

Жоден layer крім Storage НЕ є canonical authority.

---

## 13. Failure and Recovery Model

System є crash-resilient.

| Failure | Impact |
|---------|--------|
| Runtime crash | execution може бути retried; knowledge state не втрачається |
| Orchestrator crash | execution може бути replayed |
| Frontend crash | knowledge state не affected |
| Gateway crash | system state не corrupted |

Storage забезпечує deterministic recovery.

---

## 14. Vendor Independence

System є vendor-agnostic by design.

**Replaceable components:**

- Orchestration Layer
- Runtime Layer
- Gateway implementation

**Non-replaceable canonical component:**

- Storage Layer

---

## 15. Design Goals

Garden Bloom забезпечує:

- deterministic knowledge state
- controlled mutations через proposal system
- auditable execution history
- safe agent autonomy з explicit consent
- vendor independence на всіх execution layers
- declarative behavioral definition
- storage-centric authority model

---

## 16. Intended Use Cases

- autonomous knowledge agents
- controlled content mutation
- agent-driven workflows
- knowledge automation
- AI-assisted system maintenance

---

## 17. Architectural Classification

Garden Bloom є:

- agent execution platform
- knowledge operating system
- proposal-based mutation system
- storage-centric architecture
- vendor-agnostic orchestration platform

---

## 18. Summary

Garden Bloom є execution platform, де:

- behavior визначається declaratively через contracts і DRAKON diagrams
- execution orchestrated but not authoritative
- storage є єдиним canonical authority
- mutations controlled через consent-based proposal system
- architecture є vendor-agnostic на всіх replaceable layers

Це забезпечує safety, auditability, deterministic system state і safe autonomy для AI-агентів.

---

## Семантичні зв'язки

**Цей документ деталізує:**
- [[exodus.pp.ua/architecture/foundation/АРХІТЕКТУРНИЙ_КОРІНЬ\|АРХІТЕКТУРНИЙ_КОРІНЬ]] — executive overview для всіх 7 аксіом і 5 архітектурних ролей
- [[exodus.pp.ua/manifesto/МАНІФЕСТ\|МАНІФЕСТ]] — реалізація ідеологічних принципів у технічній архітектурі

**Цей документ залежить від:**
- [[exodus.pp.ua/architecture/foundation/АРХІТЕКТУРНИЙ_КОРІНЬ\|АРХІТЕКТУРНИЙ_КОРІНЬ]] — аксіоми A1–A7 як основа архітектурних рішень
- [[exodus.pp.ua/architecture/core/КАНОНІЧНА_АРХІТЕКТУРА_ВИКОНАННЯ\|КАНОНІЧНА_АРХІТЕКТУРА_ВИКОНАННЯ]] — деталізація execution layer (§6–§7)
- [[exodus.pp.ua/architecture/core/КОНТРАКТ_АГЕНТА_V1\|КОНТРАКТ_АГЕНТА_V1]] — визначення агентної моделі (§9)
- [[exodus.pp.ua/architecture/core/INBOX_ТА_PROPOSAL_АРХІТЕКТУРА\|INBOX_ТА_PROPOSAL_АРХІТЕКТУРА]] — Proposal system як safety mechanism (§11)
- [[exodus.pp.ua/architecture/core/КАНОНІЧНА_МОДЕЛЬ_АВТОРИТЕТУ_СХОВИЩА\|КАНОНІЧНА_МОДЕЛЬ_АВТОРИТЕТУ_СХОВИЩА]] — storage-centric authority model (§8, §12)

**Від цього документа залежать:**
- [[exodus.pp.ua/architecture/КАРТА_ГРАФУ\|КАРТА_ГРАФУ]] — використовує цей документ як Tier 1 overview вузол
