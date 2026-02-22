# Memory Subsystem Architecture

> DiffMem-inspired git-based differential memory for Garden Bloom AI agents.

## Overview

The Memory Subsystem adapts [DiffMem](https://github.com/Growth-Kinetics/DiffMem) concepts into Garden Bloom's architecture. It provides AI agents with persistent, versioned, searchable memory stored as Markdown files in a git repository.

### Core Principles

1. **Current-State Focus** — Memory files store only the "now" view. Historical states live in git history, accessible on-demand.
2. **Differential Intelligence** — Git diffs track how memories evolve. Agents can ask "how has this changed?" without scanning full histories.
3. **Canonical Markdown** — Human-readable, tool-agnostic plaintext storage.
4. **4-Level Context Depth** — basic → wide → deep → temporal, progressively more context at higher token cost.

## System Layers

```
┌─────────────────────────────────────────────────────┐
│  Frontend (React)                                   │
│  useAgentMemory() hook → mcpGatewayClient.ts        │
├─────────────────────────────────────────────────────┤
│  Gateway (Cloudflare Worker)                        │
│  /v1/memory/* routes → proxy to Replit backend      │
├─────────────────────────────────────────────────────┤
│  Backend (Replit — Mastra + DiffMem Adapter)        │
│  ┌───────────────────────────────────────────────┐  │
│  │  Mastra Runtime                               │  │
│  │  ├── Memory Tools (read, write, search, diff) │  │
│  │  ├── Writer Agent (process transcripts)       │  │
│  │  ├── Searcher Agent (LLM-orchestrated search) │  │
│  │  └── Context Manager (depth-based assembly)   │  │
│  ├───────────────────────────────────────────────┤  │
│  │  DiffMem Adapter (TypeScript)                 │  │
│  │  ├── GitMemoryStore (isomorphic-git)          │  │
│  │  ├── BM25 Index (in-memory, rebuilt on init)  │  │
│  │  ├── Entity Manager (CRUD on .md files)       │  │
│  │  └── Diff Engine (git log/diff queries)       │  │
│  ├───────────────────────────────────────────────┤  │
│  │  Storage Layer                                │  │
│  │  ├── Git Repository (canonical store)         │  │
│  │  ├── GitHub Remote (sync + backup)            │  │
│  │  └── MinIO (optional blob storage)            │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Memory Repository Layout

```
memory-repo/
├── entities/
│   ├── people/
│   │   ├── alice.md          # Person entity
│   │   └── bob.md
│   ├── projects/
│   │   ├── garden-bloom.md   # Project entity
│   │   └── exodus.md
│   ├── concepts/
│   │   ├── agentic-garden.md # Concept entity
│   │   └── drakon.md
│   └── timelines/
│       ├── 2026-01.md        # Monthly timeline
│       └── 2026-02.md
├── sessions/
│   ├── session-001.md        # Raw session transcript
│   └── session-002.md
├── artifacts/
│   ├── summaries/
│   └── digests/
├── _index/
│   └── bm25_cache.json       # Optional BM25 index cache
└── _meta/
    └── config.yaml           # Memory repo configuration
```

### Entity File Format

```markdown
# Alice Johnson

<!-- ALWAYS_LOAD -->
## Core Facts
- Role: Product Manager at Acme Corp
- Relationship: Close colleague since 2024
- Key trait: Detail-oriented, prefers async communication
<!-- /ALWAYS_LOAD -->

## Interactions
### 2026-02-20
- Discussed garden-bloom roadmap
- Agreed on memory subsystem priority

## Context
- Works closely with Bob on frontend
- Prefers morning meetings
```

The `ALWAYS_LOAD` block is always included in basic/wide context, ensuring core facts are available without loading full files.

## Context Depth Model

| Depth | What's Loaded | Token Cost | Use Case |
|-------|--------------|-----------|----------|
| `basic` | ALWAYS_LOAD blocks from top entities | ~500-1K | Quick responses, small talk |
| `wide` | BM25/semantic search results + ALWAYS_LOAD | ~2-5K | Topic-specific queries |
| `deep` | Complete entity files | ~5-15K | Comprehensive analysis |
| `temporal` | Complete files + git history diffs | ~10-30K | "How has X changed?" questions |

## API Contract

See [API_CONTRACT.md](./API_CONTRACT.md) for full endpoint specifications.

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/memory/{userId}/context` | Get context for conversation |
| `POST` | `/v1/memory/{userId}/search` | BM25/semantic search |
| `POST` | `/v1/memory/{userId}/orchestrated-search` | LLM-orchestrated search |
| `POST` | `/v1/memory/{userId}/process-and-commit` | Process + commit memory |
| `POST` | `/v1/memory/{userId}/process-session` | Process (stage changes) |
| `POST` | `/v1/memory/{userId}/commit-session` | Commit staged changes |
| `GET`  | `/v1/memory/{userId}/entity/{entityId}` | Get entity content |
| `GET`  | `/v1/memory/{userId}/status` | Get repo status |
| `GET`  | `/v1/memory/{userId}/recent-timeline` | Get recent timeline |
| `POST` | `/v1/memory/{userId}/diff` | Get entity diffs |
| `POST` | `/v1/memory/{userId}/onboard` | Initialize user memory |
| `POST` | `/v1/memory/sync` | Sync with remote |

## Integration with Mastra

Mastra serves as the agent runtime orchestrator. The DiffMem adapter provides **tools** that Mastra agents can invoke:

```typescript
// Mastra tool definitions
const memoryTools = {
  read_memory: {
    description: "Read current state of a memory entity",
    parameters: { entityId: z.string() },
    execute: async ({ entityId }) => adapter.readEntity(entityId),
  },
  search_memory: {
    description: "Search across memory entities",
    parameters: { query: z.string(), k: z.number().default(5) },
    execute: async ({ query, k }) => adapter.search(query, k),
  },
  write_memory: {
    description: "Update a memory entity",
    parameters: { entityId: z.string(), content: z.string() },
    execute: async ({ entityId, content }) => adapter.updateEntity(entityId, content),
  },
  diff_memory: {
    description: "Get historical changes for an entity",
    parameters: { entityId: z.string(), depth: z.number().default(3) },
    execute: async ({ entityId, depth }) => adapter.getDiff(entityId, depth),
  },
  get_context: {
    description: "Assemble context for current conversation",
    parameters: { depth: z.enum(['basic', 'wide', 'deep', 'temporal']) },
    execute: async ({ depth }) => adapter.getContext(conversation, depth),
  },
};
```

## Sequence Diagrams

### Memory Read (Context Assembly)

```
Frontend           Gateway            Backend (Mastra)      DiffMem Adapter    Git Repo
   │                  │                    │                      │                │
   │ POST /context    │                    │                      │                │
   │─────────────────>│                    │                      │                │
   │                  │ proxy /v1/memory/* │                      │                │
   │                  │───────────────────>│                      │                │
   │                  │                    │ getContext(conv,depth)│                │
   │                  │                    │─────────────────────>│                │
   │                  │                    │                      │ git show HEAD  │
   │                  │                    │                      │───────────────>│
   │                  │                    │                      │ file contents  │
   │                  │                    │                      │<───────────────│
   │                  │                    │                      │ BM25 search    │
   │                  │                    │                      │ (in-memory)    │
   │                  │                    │ context + entities   │                │
   │                  │                    │<─────────────────────│                │
   │                  │ ContextResponse    │                      │                │
   │                  │<───────────────────│                      │                │
   │ context + meta   │                    │                      │                │
   │<─────────────────│                    │                      │                │
```

### Memory Write (Process & Commit)

```
Frontend           Gateway            Backend (Mastra)      DiffMem Adapter    Git Repo
   │                  │                    │                      │                │
   │ POST /process-   │                    │                      │                │
   │   and-commit     │                    │                      │                │
   │─────────────────>│                    │                      │                │
   │                  │ proxy              │                      │                │
   │                  │───────────────────>│                      │                │
   │                  │                    │ Writer Agent         │                │
   │                  │                    │ analyzes transcript  │                │
   │                  │                    │                      │                │
   │                  │                    │ createOrUpdate()     │                │
   │                  │                    │─────────────────────>│                │
   │                  │                    │                      │ write .md files│
   │                  │                    │                      │───────────────>│
   │                  │                    │                      │ git add + commit│
   │                  │                    │                      │───────────────>│
   │                  │                    │                      │ rebuild index  │
   │                  │                    │                      │                │
   │                  │                    │ ProcessResponse      │                │
   │                  │                    │<─────────────────────│                │
   │                  │ response           │                      │                │
   │                  │<───────────────────│                      │                │
   │ entities affected│                    │                      │                │
   │<─────────────────│                    │                      │                │
```

## Technology Stack

### Backend (Replit)
- **Runtime**: Node.js + TypeScript
- **Agent Framework**: [Mastra](https://mastra.ai/) — agent orchestration, tool execution
- **Git Operations**: `isomorphic-git` — pure JS git implementation (no native deps)
- **Search**: `wink-bm25-text-search` or custom BM25 — in-memory text search
- **LLM**: OpenRouter API (or direct Anthropic/OpenAI)
- **HTTP**: Fastify or Express — REST API server

### Gateway (Cloudflare Worker)
- Route prefix: `/v1/memory/*`
- Auth: Bearer token (SERVICE_TOKEN) for backend communication
- Proxy: Standard gateway proxy pattern (same as existing routes)

### Frontend (React)
- Types: `src/types/agentMemory.ts`
- API Client: Methods in `src/lib/api/mcpGatewayClient.ts`
- Hook: `src/hooks/useAgentMemory.ts` (Phase 3)

## Security

- All memory endpoints require owner authentication (Bearer token)
- Per-user isolation: each userId has its own git branch/directory
- Gateway validates tokens before proxying to backend
- No direct access to git repo from frontend
- Memory content is never cached on Cloudflare (passthrough proxy)

## Future Considerations

- **Vector embeddings**: Hybrid BM25 + cosine similarity search
- **Memory pruning**: Auto-archive low-relevance entities to branches
- **Multi-agent memory**: Shared memory spaces between agents
- **Streaming context**: SSE for real-time memory updates during agent runs
- **Garden integration**: Link memory entities to garden notes (bidirectional refs)
