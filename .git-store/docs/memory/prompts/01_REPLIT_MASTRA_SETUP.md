# Промт для Replit: Розгортання Mastra + DiffMem Backend

> Цей промт призначений для агента Replit, який розгортає серверну частину Memory Subsystem.

---

## Контекст

Ти — Replit агент. Твоя задача — створити Node.js/TypeScript бекенд для Memory Subsystem проєкту Garden Bloom.

Архітектура:
- **Mastra** — AI agent framework для TypeScript (https://mastra.ai/)
- **DiffMem-like** — git-based memory storage (Markdown файли + git history)
- **isomorphic-git** — pure JS git implementation (без native deps)
- **BM25 search** — in-memory text search по entity файлах
- **Fastify** — HTTP server для REST API

Документація API контракту: файл `docs/memory/API_CONTRACT.md` в репозиторії garden-bloom.

---

## Крок 1: Ініціалізація проєкту

```bash
npm init -y
npm install typescript @types/node tsx
npm install mastra @mastra/core
npm install isomorphic-git
npm install fastify @fastify/cors
npm install zod
npm install wink-bm25-text-search
npm install openai  # або @anthropic-ai/sdk
npx tsc --init
```

**tsconfig.json:**
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "esModuleInterop": true,
    "outDir": "dist",
    "rootDir": "src",
    "declaration": true,
    "resolveJsonModule": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"]
}
```

---

## Крок 2: Структура проєкту

```
src/
├── server.ts                 # Fastify HTTP server
├── config.ts                 # Environment config
├── routes/
│   └── memory.ts             # /v1/memory/* routes
├── memory/
│   ├── adapter.ts            # DiffMem adapter (main class)
│   ├── git-store.ts          # Git operations via isomorphic-git
│   ├── bm25-index.ts         # BM25 search index
│   ├── entity-manager.ts     # CRUD for memory entities
│   ├── context-manager.ts    # Context assembly (4 depths)
│   ├── diff-engine.ts        # Git diff/log queries
│   └── types.ts              # Internal types
├── agents/
│   ├── writer-agent.ts       # Mastra agent: processes transcripts
│   ├── searcher-agent.ts     # Mastra agent: orchestrated search
│   └── tools.ts              # Mastra tool definitions
└── utils/
    ├── markdown.ts           # Markdown parsing helpers
    └── tokens.ts             # Token counting
```

---

## Крок 3: Конфігурація (config.ts)

```typescript
import { z } from 'zod';

const ConfigSchema = z.object({
  PORT: z.coerce.number().default(3001),
  SERVICE_TOKEN: z.string().min(1),
  MEMORY_REPO_PATH: z.string().default('./memory-repo'),
  GITHUB_PAT: z.string().optional(),
  GITHUB_REPO: z.string().optional(), // owner/repo
  OPENROUTER_API_KEY: z.string().optional(),
  ANTHROPIC_API_KEY: z.string().optional(),
  LLM_MODEL: z.string().default('anthropic/claude-sonnet-4-20250514'),
  DEFAULT_USER_ID: z.string().default('garden-owner'),
  CORS_ORIGINS: z.string().default('*'),
});

export const config = ConfigSchema.parse(process.env);
```

**Replit Secrets потрібні:**
- `SERVICE_TOKEN` — той самий що в Cloudflare Worker
- `GITHUB_PAT` — для git push/pull (optional)
- `GITHUB_REPO` — e.g. `maxfraieho/garden-bloom-memory`
- `OPENROUTER_API_KEY` або `ANTHROPIC_API_KEY` — для LLM

---

## Крок 4: Git Store (git-store.ts)

Реалізуй клас `GitMemoryStore` використовуючи `isomorphic-git`:

```typescript
import git from 'isomorphic-git';
import fs from 'fs';
import path from 'path';

export class GitMemoryStore {
  constructor(private repoPath: string) {}

  async init(): Promise<void> {
    // git init або clone якщо GITHUB_REPO вказано
  }

  async readFile(filePath: string): Promise<string | null> {
    const fullPath = path.join(this.repoPath, filePath);
    try { return fs.readFileSync(fullPath, 'utf-8'); } catch { return null; }
  }

  async writeFile(filePath: string, content: string): Promise<void> {
    const fullPath = path.join(this.repoPath, filePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, 'utf-8');
  }

  async stageFile(filePath: string): Promise<void> {
    await git.add({ fs, dir: this.repoPath, filepath: filePath });
  }

  async commit(message: string): Promise<string> {
    const sha = await git.commit({
      fs, dir: this.repoPath,
      message,
      author: { name: 'garden-agent', email: 'agent@garden.local' },
    });
    return sha;
  }

  async log(filePath?: string, maxCount = 10): Promise<any[]> {
    return git.log({ fs, dir: this.repoPath, filepath: filePath, depth: maxCount });
  }

  async diff(commitSha1: string, commitSha2: string, filePath: string): Promise<string> {
    // Implement using git.readBlob for both commits, then compute unified diff
  }

  async listFiles(dirPath: string): Promise<string[]> {
    const fullPath = path.join(this.repoPath, dirPath);
    try {
      return fs.readdirSync(fullPath, { recursive: true })
        .filter(f => f.toString().endsWith('.md'))
        .map(f => path.join(dirPath, f.toString()));
    } catch { return []; }
  }

  async push(): Promise<void> {
    // git push if GITHUB_PAT + GITHUB_REPO configured
  }

  async pull(): Promise<void> {
    // git pull from remote
  }
}
```

---

## Крок 5: BM25 Index (bm25-index.ts)

```typescript
import BM25 from 'wink-bm25-text-search';

export class MemoryIndex {
  private engine: any;
  private documents: Map<string, { content: string; name: string; type: string }>;

  constructor() {
    this.engine = BM25();
    this.documents = new Map();
  }

  async buildFromFiles(gitStore: GitMemoryStore): Promise<void> {
    // Read all .md files from entities/
    // Parse frontmatter/headers for metadata
    // Add to BM25 index
    const files = await gitStore.listFiles('entities');
    this.engine.defineConfig({ fldWeights: { title: 2, body: 1 } });
    this.engine.definePrepTasks([/* tokenizer, stemmer */]);

    for (const file of files) {
      const content = await gitStore.readFile(file);
      if (!content) continue;
      const name = path.basename(file, '.md');
      const type = file.split('/')[1]; // entities/TYPE/name.md
      this.documents.set(file, { content, name, type });
      this.engine.addDoc({ title: name, body: content }, file);
    }
    this.engine.consolidate();
  }

  search(query: string, k = 10): Array<{ entityId: string; score: number; snippet: string }> {
    const results = this.engine.search(query, k);
    return results.map((r: any) => ({
      entityId: r[0].replace('entities/', '').replace('.md', ''),
      score: r[1],
      snippet: this.getSnippet(r[0], query),
    }));
  }

  private getSnippet(filePath: string, query: string): string {
    const doc = this.documents.get(filePath);
    if (!doc) return '';
    // Extract ~200 chars around first match
    const idx = doc.content.toLowerCase().indexOf(query.toLowerCase());
    if (idx === -1) return doc.content.slice(0, 200);
    const start = Math.max(0, idx - 100);
    return doc.content.slice(start, start + 200);
  }

  rebuild(): void {
    // Called after commits to refresh index
  }
}
```

---

## Крок 6: Context Manager (context-manager.ts)

```typescript
export class ContextManager {
  constructor(
    private gitStore: GitMemoryStore,
    private index: MemoryIndex,
  ) {}

  async getContext(
    conversation: Array<{ role: string; content: string }>,
    depth: 'basic' | 'wide' | 'deep' | 'temporal',
    options?: { entityTypes?: string[]; maxTokens?: number }
  ): Promise<{ context: string; entities: any[]; tokenCount: number }> {

    switch (depth) {
      case 'basic':
        return this.getBasicContext(options);
      case 'wide':
        return this.getWideContext(conversation, options);
      case 'deep':
        return this.getDeepContext(conversation, options);
      case 'temporal':
        return this.getTemporalContext(conversation, options);
    }
  }

  private async getBasicContext(options?: any) {
    // 1. List all entity files
    // 2. Extract ALWAYS_LOAD blocks
    // 3. Return concatenated blocks
  }

  private async getWideContext(conversation: any[], options?: any) {
    // 1. Extract query from conversation
    // 2. BM25 search
    // 3. Return search results + ALWAYS_LOAD blocks
  }

  private async getDeepContext(conversation: any[], options?: any) {
    // 1. BM25 search for relevant entities
    // 2. Read full file content for top matches
    // 3. Return full content
  }

  private async getTemporalContext(conversation: any[], options?: any) {
    // 1. Deep context +
    // 2. Git log for matched entities
    // 3. Include diffs in context
  }
}
```

---

## Крок 7: Mastra Agent Setup (agents/writer-agent.ts)

```typescript
import { Agent } from '@mastra/core';
import { memoryTools } from './tools';

export const writerAgent = new Agent({
  name: 'memory-writer',
  instructions: `You are a memory writer agent. Your task is to:
1. Analyze conversation transcripts or input text
2. Identify entities (people, projects, concepts, events)
3. Create or update Markdown memory files for each entity
4. Preserve existing information while adding new facts
5. Use ALWAYS_LOAD blocks for core facts that should always be in context
6. Organize information chronologically within entities
7. Create timeline entries for dated events

Rules:
- Never delete existing information unless explicitly corrected
- Add new information under appropriate headers
- Use ## headers for sections, ### for dated entries
- Keep ALWAYS_LOAD blocks concise (max 5-7 bullet points)
- Tag entities with relevant keywords`,
  model: {
    provider: 'ANTHROPIC',
    name: 'claude-sonnet-4-20250514',
  },
  tools: memoryTools,
});
```

---

## Крок 8: HTTP Routes (routes/memory.ts)

```typescript
import { FastifyInstance } from 'fastify';
import { DiffMemAdapter } from '../memory/adapter';

export function registerMemoryRoutes(app: FastifyInstance, adapter: DiffMemAdapter) {
  // Auth middleware
  app.addHook('preHandler', async (req, reply) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token !== config.SERVICE_TOKEN) {
      reply.code(401).send({ success: false, error: { code: 'UNAUTHORIZED' } });
    }
  });

  app.post('/v1/memory/:userId/context', async (req) => {
    const { conversation, depth, entityTypes, maxTokens } = req.body as any;
    return adapter.getContext(req.params.userId, conversation, depth, { entityTypes, maxTokens });
  });

  app.post('/v1/memory/:userId/search', async (req) => {
    const { query, k, entityTypes, method } = req.body as any;
    return adapter.search(req.params.userId, query, { k, entityTypes, method });
  });

  app.post('/v1/memory/:userId/process-and-commit', async (req) => {
    const { memoryInput, sessionId, sessionDate, autoCommit } = req.body as any;
    return adapter.processAndCommit(req.params.userId, memoryInput, sessionId, { sessionDate });
  });

  app.get('/v1/memory/:userId/status', async (req) => {
    return adapter.getStatus(req.params.userId);
  });

  app.get('/v1/memory/:userId/recent-timeline', async (req) => {
    const { daysBack, limit } = req.query as any;
    return adapter.getTimeline(req.params.userId, { daysBack, limit });
  });

  app.post('/v1/memory/:userId/diff', async (req) => {
    const { entityId, depth, since, until } = req.body as any;
    return adapter.getDiff(req.params.userId, entityId, { depth, since, until });
  });

  app.post('/v1/memory/:userId/onboard', async (req) => {
    const { userInfo, sessionId } = req.body as any;
    return adapter.onboard(req.params.userId, userInfo, sessionId);
  });

  app.post('/v1/memory/sync', async () => {
    return adapter.sync();
  });

  app.get('/v1/memory/health', async () => {
    return adapter.health();
  });
}
```

---

## Крок 9: Server Entry Point (server.ts)

```typescript
import Fastify from 'fastify';
import cors from '@fastify/cors';
import { config } from './config';
import { DiffMemAdapter } from './memory/adapter';
import { registerMemoryRoutes } from './routes/memory';

async function main() {
  const app = Fastify({ logger: true });
  await app.register(cors, { origin: config.CORS_ORIGINS });

  const adapter = new DiffMemAdapter(config.MEMORY_REPO_PATH);
  await adapter.init();

  registerMemoryRoutes(app, adapter);

  await app.listen({ port: config.PORT, host: '0.0.0.0' });
  console.log(`Memory backend running on port ${config.PORT}`);
}

main().catch(console.error);
```

---

## Крок 10: Тестування

```bash
# Health check
curl http://localhost:3001/v1/memory/health

# Onboard user
curl -X POST http://localhost:3001/v1/memory/garden-owner/onboard \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userInfo":"Garden owner, knowledge management enthusiast","sessionId":"onboard-1"}'

# Process and commit
curl -X POST http://localhost:3001/v1/memory/garden-owner/process-and-commit \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"memoryInput":"Today I started building the memory subsystem for garden-bloom.","sessionId":"s-001","sessionDate":"2026-02-22"}'

# Search
curl -X POST http://localhost:3001/v1/memory/garden-owner/search \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"memory subsystem","k":5}'

# Get context
curl -X POST http://localhost:3001/v1/memory/garden-owner/context \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"conversation":[{"role":"user","content":"What am I working on?"}],"depth":"wide"}'
```

---

## Replit Secrets

Встанови наступні секрети в Replit:

| Secret | Description | Required |
|--------|------------|----------|
| `SERVICE_TOKEN` | Auth token (same as CF Worker) | ✅ |
| `GITHUB_PAT` | GitHub Personal Access Token | ❌ (для sync) |
| `GITHUB_REPO` | e.g. `maxfraieho/garden-bloom-memory` | ❌ (для sync) |
| `ANTHROPIC_API_KEY` | Anthropic API key | ✅ (або OpenRouter) |
| `OPENROUTER_API_KEY` | OpenRouter API key | ❌ (альтернатива) |

---

## Replit .replit Config

```toml
run = "npx tsx src/server.ts"
entrypoint = "src/server.ts"

[nix]
channel = "stable-24_05"

[env]
PORT = "3001"
DEFAULT_USER_ID = "garden-owner"
MEMORY_REPO_PATH = "./memory-repo"
```
