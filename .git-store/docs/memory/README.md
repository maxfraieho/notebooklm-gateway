# Memory Subsystem — Garden Bloom

> DiffMem-inspired git-based differential memory for AI agents.

## 📁 Contents

| File | Description |
|------|-------------|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System architecture, layers, diagrams |
| [API_CONTRACT.md](./API_CONTRACT.md) | REST API specification (v1) |
| [prompts/](./prompts/) | Prompts for deploying backend |

## 📁 Prompts (for backend agents)

| File | Target Agent | Description |
|------|-------------|-------------|
| [01_REPLIT_MASTRA_SETUP.md](./prompts/01_REPLIT_MASTRA_SETUP.md) | Replit | Full Mastra + DiffMem backend setup |
| [02_CLOUDFLARE_WORKER_ROUTES.md](./prompts/02_CLOUDFLARE_WORKER_ROUTES.md) | CF Worker | Add /v1/memory/* routes to gateway |
| [03_MASTRA_AGENTS_CONFIG.md](./prompts/03_MASTRA_AGENTS_CONFIG.md) | Replit | Mastra agents: Writer + Searcher |

## 🏗️ Frontend Types

- `src/types/agentMemory.ts` — TypeScript interfaces for memory API

## 🚀 Quick Start

1. **Deploy backend** → Use prompt `01_REPLIT_MASTRA_SETUP.md` on Replit
2. **Configure gateway** → Use prompt `02_CLOUDFLARE_WORKER_ROUTES.md` on CF Worker
3. **Configure agents** → Use prompt `03_MASTRA_AGENTS_CONFIG.md` on Replit
4. **Frontend integration** → Types ready in `src/types/agentMemory.ts`

## 📊 Architecture Overview

```
Frontend (React) → Gateway (CF Worker) → Backend (Replit + Mastra)
                                              │
                                         DiffMem Adapter
                                              │
                                    Git Repo (Markdown files)
```

Key concepts from DiffMem:
- **Current-state focus**: Only current Markdown files are searched/indexed
- **Git history for depth**: Temporal reasoning via git diffs
- **4-level context**: basic → wide → deep → temporal
- **BM25 search**: Fast, explainable text retrieval
- **Mastra agents**: Writer (process transcripts) + Searcher (answer questions)
