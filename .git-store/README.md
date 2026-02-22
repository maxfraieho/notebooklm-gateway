# Garden Bloom Frontend

## Overview

Garden Bloom Frontend is the presentation layer of the Garden Bloom execution platform.

It renders system state retrieved via Gateway API and provides user interfaces for:

- viewing notes
- viewing proposals
- approving or rejecting proposals
- interacting with agent-generated content
- viewing execution results

Frontend does NOT execute agents.
Frontend does NOT mutate canonical storage.

---

## Architectural Role

Frontend is a Projection Layer.

Responsibilities:

- render state from Gateway API
- submit user intents to Gateway
- display execution status
- display proposals
- collect approval decisions

Frontend never:

- writes to MinIO directly
- executes agents
- modifies canonical storage
- bypasses Gateway

Canonical reference:

docs/architecture/RUNTIME_ARCHITECTURE_CANONICAL.md

---

## Stack

- Vite
- React
- TypeScript
- TailwindCSS

Runtime dependencies:

- Gateway API
- Cloudflare Worker (Gateway)
- Canonical Storage (indirect via Gateway)

---

## Gateway contract

Frontend communicates exclusively via Gateway.

Reference:

docs/backend/API_CONTRACTS_V1.md

No direct storage access allowed.

---

## Repository structure

Important directories:

```
src/           — React application code
public/        — static assets and runtime libs
vendor/        — embedded runtime libraries (DRAKON widget)
docs/          — canonical architecture and API contracts
.github/       — CI/CD workflows
_collab/       — agent collaboration and migration artifacts
_quarantine/   — legacy and non-frontend code isolated from runtime
```

Frontend runtime depends ONLY on:

```
src/
public/
vendor/
docs/
```

---

## Development

Install:

```bash
npm install
```

Run:

```bash
npm run dev
```

Build:

```bash
npm run build
```

---

## Architectural invariants

Frontend is stateless.

All canonical state exists in storage layer accessed via Gateway.

Frontend must remain vendor-agnostic with respect to orchestration.

---

## Canonical architecture reference

docs/architecture/RUNTIME_ARCHITECTURE_INDEX.md
