---
{"tags":["domain:meta","status:canonical","format:prompt"],"created":"2026-02-21","updated":"2026-02-21","title":"АУДІО ПРОМПТ NOTEBOOKLM","dg-publish":true,"dg-metatags":null,"dg-home":null,"isolated":"intentional","permalink":"/exodus.pp.ua/АУДІО_ПРОМПТ_NOTEBOOKLM/","dgPassFrontmatter":true,"noteIcon":""}
---


# NotebookLM Audio Review — Prompt

## Context

You are reviewing the complete architecture documentation of **Garden Bloom** — an execution platform for autonomous AI agents with storage-centric architecture. The documentation is in mixed Ukrainian/English. Generate the audio overview in **Ukrainian**.

---

## What This Project IS

Garden Bloom is an **operating system for AI agents**, not a chatbot. It provides:
- Controlled execution of autonomous agents
- Consent-based mutation of knowledge state
- Deterministic authority model
- Vendor-agnostic orchestration

---

## Key Accents for Audio Review

### 1. Storage-Centric Architecture (MOST IMPORTANT)

Emphasize that **MinIO object storage is the ONLY source of truth**. Everything else — runtime, orchestration, frontend — is replaceable. If any execution layer crashes, knowledge state survives. This is the fundamental architectural decision that defines the entire system.

### 2. Proposal System as Safety Mechanism

No component can mutate knowledge state directly. Every change goes through: `proposed → pending → approved → applied`. This is the consent-based mutation model. Explain WHY this matters for AI agent safety — agents cannot modify system state without explicit approval.

### 3. Agent Contract Model (Declarative, Not Imperative)

Agents are defined by contracts (`_agent.md`, `pseudocode.md`, DRAKON diagrams), NOT by code. Runtime interprets contracts but does NOT define behavior. This separation between intent and execution is critical. DRAKON diagrams provide visual, deterministic behavioral logic.

### 4. Five-Layer Architecture

Explain each layer's role and authority boundaries:
- **Storage** — canonical authority (the only one)
- **Gateway** — write gatekeeper (the only write entry point)
- **Orchestration** — execution coordination (replaceable, vendor-agnostic)
- **Runtime (Mastra)** — contract interpreter (not authoritative)
- **Frontend** — presentation only (no write access)

Stress that authority flows DOWN (storage → gateway → orchestration → runtime → frontend), never UP.

### 5. Vendor Independence

Orchestration Layer is explicitly designed as a replaceable abstraction. It can be Trigger.dev, Temporal, BullMQ, or custom — architecture remains unchanged. This is not accidental, it's a core design principle.

### 6. Crash Resilience

Walk through failure scenarios: runtime crash, orchestrator crash, frontend crash — in ALL cases knowledge state is preserved. Storage provides deterministic recovery. This is a direct consequence of storage-centric architecture.

### 7. Run Lifecycle

Explain the canonical run lifecycle: `requested → queued → running → completed | failed`. Orchestration manages this lifecycle but doesn't have authority over knowledge state.

---

## What to QUESTION / CHALLENGE in the Review

- Is the proposal system overhead justified for ALL mutations, or should some low-risk operations bypass it?
- How does the system handle proposal conflicts when multiple agents propose changes to the same knowledge object?
- What happens when the proposal queue grows large — is there a backpressure mechanism?
- DRAKON diagrams as behavioral contracts — how are they versioned and migrated?
- What is the concrete latency cost of the proposal lifecycle for time-sensitive agent actions?

---

## Tone

Technical but accessible. Imagine explaining this architecture to a senior engineer who has never seen the project. Be precise about authority boundaries and separation of concerns. Don't oversimplify — the audience understands distributed systems.

---

## Structure Suggestion

1. **Open** — what Garden Bloom is and why it exists (30 sec)
2. **Core insight** — storage as canonical authority, everything else replaceable (1 min)
3. **Walk through the five layers** — role, authority, boundaries (2-3 min)
4. **Proposal system deep dive** — why consent-based mutations matter for AI safety (1-2 min)
5. **Agent contract model** — declarative behavior, DRAKON diagrams (1 min)
6. **Failure model** — what crashes and what survives (1 min)
7. **Open questions and challenges** — what could be improved (1-2 min)


---

## Семантичні зв'язки

`isolated: intentional` — цей документ є standalone операційним промптом для NotebookLM audio overview. Не включається до навігаційного графу навмисно.

**Контекст використання:**
- Завантажити до NotebookLM разом з Tier 1 документами з [[exodus.pp.ua/ІНДЕКС\|ІНДЕКС]]
- Використовується для генерації audio overview системи Garden Bloom

---

*Standalone prompt. Не є частиною канонічного knowledge graph.*
