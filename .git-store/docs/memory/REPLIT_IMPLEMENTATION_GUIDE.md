# Replit Backend — Implementation Guide

**Читай цей файл ПЕРШИМ, перед усіма іншими промтами.**

Цей документ — авторитетне доповнення до промтів Lovable:
- `01_REPLIT_MASTRA_SETUP.md` — структура проекту та базовий setup
- `03_MASTRA_AGENTS_CONFIG.md` — конфіг агентів та інструментів

Він заповнює gaps, вирішує суперечності та надає реальний код для критичних частин.

---

## 1. Контекст і місія

Ти розгортаєш **backend пам'яті агентної системи** для цифрового саду exodus.pp.ua.

### Що це таке

Git-репозиторій Markdown-файлів, який слугує довгостроковою пам'яттю AI-агентів.
Агенти читають контекст звідси перед відповіддю та записують нові сесії сюди після них.

### Три рівні системи

```
Frontend (React)           ← НЕ твоя зона
    ↓ HTTP Bearer token
Cloudflare Worker Gateway  ← НЕ твоя зона (налаштовано окремо)
    ↓ HTTP SERVICE_TOKEN
Replit Backend             ← ТВОя зона (цей промт)
    ├── Fastify server (src/server.ts)
    ├── Memory routes (/v1/memory/*)
    ├── DiffMem adapter (isomorphic-git + BM25)
    └── Mastra agents (Writer + Searcher)
```

### Що backend робить

1. **Зберігає сутності** (люди, проекти, концепції) як Markdown-файли у git-репозиторії
2. **Індексує** їх через BM25 для швидкого пошуку
3. **Збирає контекст** (4 рівні глибини) для AI-агентів перед відповіддю
4. **Обробляє транскрипти** через Writer Agent — автоматично витягує та зберігає сутності
5. **Відповідає на запити** через Searcher Agent з посиланнями на сутності

---

## 2. Авторитетні рішення (вирішені суперечності)

### 2.1 Назви токенів

| Компонент | Env var name | Значення |
|-----------|-------------|---------|
| Replit backend | `SERVICE_TOKEN` | Секретний рядок, наприклад `svc_abc123` |
| Cloudflare Worker | `NOTEBOOKLM_SERVICE_TOKEN` | **Те саме значення**, різна назва змінної |

Cloudflare надсилає `Authorization: Bearer <NOTEBOOKLM_SERVICE_TOKEN>` до Replit.
Replit перевіряє: `token === process.env.SERVICE_TOKEN`.

### 2.2 HTTP-сервер

Використовуй **Fastify** (не Express). Промт згадує обидва — Fastify правильний вибір.

```typescript
// src/server.ts
import Fastify from 'fastify';
import cors from '@fastify/cors';
```

### 2.3 LLM-модель

```typescript
// src/agents/writer-agent.ts та searcher-agent.ts
model: anthropic('claude-sonnet-4-5')
// НЕ 'claude-sonnet-4-20250514' — це застарілий alias
```

Через `@ai-sdk/anthropic`, не через `openai` SDK напряму.

### 2.4 GitHub sync — опціонально для MVP

Якщо `GITHUB_PAT` і `GITHUB_REPO` не задані — backend працює в local-only режимі.
`POST /v1/memory/sync` повертає `{ skipped: true, reason: 'no-github-config' }`.

### 2.5 Per-user ізоляція — директорії, не гілки

```
memory-repo/
└── users/
    └── garden-owner/      ← userId як назва директорії
        ├── entities/
        ├── sessions/
        └── artifacts/
```

Не окремі git-гілки (складніше). Один репозиторій, директорії на користувача.

---

## 3. Авторитетний список env variables

```bash
# Обов'язкові
PORT=3001
SERVICE_TOKEN=          # Обов'язково — той самий що у CF Worker

# Шляхи
MEMORY_REPO_PATH=./memory-repo   # Де зберігається git-репозиторій
DEFAULT_USER_ID=garden-owner     # Для MVP — один користувач

# LLM (одне з двох)
ANTHROPIC_API_KEY=      # Або
OPENROUTER_API_KEY=     # Якщо через OpenRouter

LLM_MODEL=claude-sonnet-4-5      # Модель для Mastra агентів

# GitHub sync (опціонально)
GITHUB_PAT=             # Personal access token
GITHUB_REPO=            # Наприклад: maxfraieho/garden-memory

# CORS
CORS_ORIGINS=https://garden-seedling.lovable.app,http://localhost:5173
```

Replit Secrets (через UI): `SERVICE_TOKEN`, `ANTHROPIC_API_KEY`, `GITHUB_PAT`.
Решта — через `.replit` або env defaults у коді.

---

## 4. Пакети — точний список

```json
{
  "dependencies": {
    "fastify": "^4.28.0",
    "@fastify/cors": "^9.0.0",
    "mastra": "^0.10.0",
    "@mastra/core": "^0.10.0",
    "@ai-sdk/anthropic": "^1.0.0",
    "isomorphic-git": "^1.27.0",
    "wink-bm25-text-search": "^2.4.0",
    "wink-nlp": "^2.3.0",
    "wink-eng-lite-web-model": "^1.5.0",
    "diff": "^7.0.0",
    "zod": "^3.23.0",
    "tiktoken": "^1.0.17"
  },
  "devDependencies": {
    "typescript": "^5.5.0",
    "@types/node": "^22.0.0",
    "@types/diff": "^5.2.0",
    "tsx": "^4.16.0"
  }
}
```

**Важливо:** `wink-bm25-text-search` потребує `wink-nlp` та `wink-eng-lite-web-model`.

---

## 5. Реалізація критичних частин

Ці частини відсутні або неповні в промтах Lovable. Реалізуй їх точно як описано.

### 5.1 ALWAYS_LOAD block parsing

```typescript
// src/utils/markdown.ts

export function extractAlwaysLoad(content: string): string {
  const match = content.match(/<!--\s*ALWAYS_LOAD\s*-->([\s\S]*?)<!--\s*\/ALWAYS_LOAD\s*-->/);
  return match ? match[1].trim() : '';
}

export function extractFrontmatter(content: string): Record<string, string> {
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return {};
  const result: Record<string, string> = {};
  for (const line of match[1].split('\n')) {
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      result[line.slice(0, colonIdx).trim()] = line.slice(colonIdx + 1).trim();
    }
  }
  return result;
}

export function parseEntityFromMarkdown(content: string) {
  const fm = extractFrontmatter(content);
  const alwaysLoad = extractAlwaysLoad(content);

  // Extract tags from content (lines starting with #tag or frontmatter tags field)
  const tagMatches = content.match(/#([a-zA-Z_\u0400-\u04FF]+)/g) || [];
  const tags = tagMatches.map(t => t.slice(1));

  return { frontmatter: fm, alwaysLoad, tags };
}
```

### 5.2 Git diff через isomorphic-git + diff

isomorphic-git **не має** вбудованого unified diff. Потрібен пакет `diff`.

```typescript
// src/memory/diff-engine.ts
import git from 'isomorphic-git';
import fs from 'fs';
import { createTwoFilesPatch } from 'diff';
import path from 'path';
import type { MemoryDiff } from '../types.js';

export async function getEntityDiffs(
  repoDir: string,
  filePath: string,
  depth = 1
): Promise<MemoryDiff[]> {
  const commits = await git.log({
    fs,
    dir: repoDir,
    ref: 'HEAD',
    depth: depth + 1,
  });

  const diffs: MemoryDiff[] = [];

  for (let i = 0; i < Math.min(depth, commits.length - 1); i++) {
    const newCommit = commits[i];
    const oldCommit = commits[i + 1];

    let oldContent = '';
    let newContent = '';

    try {
      const oldBlob = await git.readBlob({
        fs,
        dir: repoDir,
        oid: oldCommit.oid,
        filepath: filePath,
      });
      oldContent = new TextDecoder().decode(oldBlob.blob);
    } catch {
      // File didn't exist in this commit
    }

    try {
      const newBlob = await git.readBlob({
        fs,
        dir: repoDir,
        oid: newCommit.oid,
        filepath: filePath,
      });
      newContent = new TextDecoder().decode(newBlob.blob);
    } catch {
      // File deleted in this commit
    }

    const patch = createTwoFilesPatch(
      filePath,
      filePath,
      oldContent,
      newContent,
      oldCommit.oid.slice(0, 8),
      newCommit.oid.slice(0, 8)
    );

    const additions = (patch.match(/^\+[^+]/gm) || []).length;
    const deletions = (patch.match(/^-[^-]/gm) || []).length;

    diffs.push({
      commitSha: newCommit.oid,
      commitMessage: newCommit.commit.message.trim(),
      author: newCommit.commit.author.name,
      date: newCommit.commit.author.timestamp * 1000,
      diff: patch,
      additions,
      deletions,
    });
  }

  return diffs;
}
```

### 5.3 BM25 пошуковий індекс

```typescript
// src/memory/bm25-index.ts
import BM25 from 'wink-bm25-text-search';
import winkNLP from 'wink-nlp';
import model from 'wink-eng-lite-web-model';
import type { MemorySearchResult } from '../types.js';

const nlp = winkNLP(model);

type IndexDoc = {
  entityId: string;
  title: string;
  content: string;
  tags: string;
  entityType: string;
};

export class MemoryIndex {
  private engine: ReturnType<typeof BM25>;
  private docs = new Map<string, IndexDoc>();
  private consolidated = false;

  constructor() {
    this.engine = BM25();
    this.engine.defineConfig({
      fldWeights: { title: 5, tags: 3, entityType: 2, content: 1 },
    });
    this.engine.definePrepTasks([
      nlp.readDoc,
      its => its.tokens().filter(t => t.out(its.type) === 'word').out(),
      tokens => tokens.map((t: string) => t.toLowerCase()),
    ]);
  }

  addDocument(doc: IndexDoc): void {
    this.docs.set(doc.entityId, doc);
    this.consolidated = false;
  }

  removeDocument(entityId: string): void {
    this.docs.delete(entityId);
    this.consolidated = false;
  }

  // Rebuild from scratch (needed after remove)
  rebuild(): void {
    this.engine = BM25();
    this.engine.defineConfig({
      fldWeights: { title: 5, tags: 3, entityType: 2, content: 1 },
    });
    this.engine.definePrepTasks([
      nlp.readDoc,
      its => its.tokens().filter(t => t.out(its.type) === 'word').out(),
      tokens => tokens.map((t: string) => t.toLowerCase()),
    ]);
    for (const [id, doc] of this.docs) {
      this.engine.addDoc(doc, id);
    }
    this.engine.consolidate();
    this.consolidated = true;
  }

  consolidate(): void {
    if (!this.consolidated) {
      this.engine.consolidate();
      this.consolidated = true;
    }
  }

  search(query: string, k = 10): Array<{ entityId: string; score: number }> {
    this.consolidate();
    const results = this.engine.search(query);
    return results.slice(0, k).map((r: any) => ({
      entityId: r[0] as string,
      score: r[1] as number,
    }));
  }

  size(): number {
    return this.docs.size;
  }
}
```

### 5.4 Write lock (конкурентність)

```typescript
// src/utils/lock.ts
export class AsyncMutex {
  private locked = false;
  private queue: Array<() => void> = [];

  async acquire(): Promise<void> {
    if (!this.locked) {
      this.locked = true;
      return;
    }
    return new Promise(resolve => this.queue.push(resolve));
  }

  release(): void {
    const next = this.queue.shift();
    if (next) {
      next();
    } else {
      this.locked = false;
    }
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

// Один mutex для всіх git write operations
export const gitWriteLock = new AsyncMutex();
```

**Використовуй у всіх операціях запису:**
```typescript
// src/memory/git-store.ts
import { gitWriteLock } from '../utils/lock.js';

async commitChanges(message: string, userId: string): Promise<string> {
  return gitWriteLock.run(async () => {
    await git.add({ fs, dir: this.repoDir, filepath: '.' });
    return git.commit({
      fs,
      dir: this.repoDir,
      message,
      author: { name: 'MemoryAgent', email: 'agent@memory.local' },
    });
  });
}
```

### 5.5 Token counting

```typescript
// src/utils/tokens.ts
import { get_encoding } from 'tiktoken';

const encoder = get_encoding('cl100k_base'); // Claude/GPT-4 tokenizer

export function countTokens(text: string): number {
  return encoder.encode(text).length;
}

export function truncateToTokenLimit(text: string, maxTokens: number): string {
  const tokens = encoder.encode(text);
  if (tokens.length <= maxTokens) return text;
  // Decode truncated tokens back to string
  const truncated = encoder.decode(tokens.slice(0, maxTokens));
  return new TextDecoder().decode(truncated);
}
```

### 5.6 Auth middleware (Fastify)

```typescript
// src/routes/auth.ts
import type { FastifyRequest, FastifyReply } from 'fastify';
import { config } from '../config.js';

export async function requireServiceToken(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const auth = request.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    reply.status(401).send({ success: false, error: 'UNAUTHORIZED', message: 'Missing Bearer token' });
    return;
  }
  const token = auth.slice(7);
  if (token !== config.SERVICE_TOKEN) {
    reply.status(401).send({ success: false, error: 'UNAUTHORIZED', message: 'Invalid token' });
    return;
  }
}

// Реєстрація у server.ts:
fastify.addHook('preHandler', async (request, reply) => {
  if (request.url.startsWith('/v1/memory') && request.url !== '/v1/memory/health') {
    await requireServiceToken(request, reply);
  }
});
```

### 5.7 Mastra tool context injection

В промті Lovable `context` в tool handlers — це **Mastra tool input**, не глобальний об'єкт.

```typescript
// src/agents/tools.ts — правильний синтаксис Mastra v0.10+
import { createTool } from '@mastra/core';
import { z } from 'zod';

export const readMemoryTool = createTool({
  id: 'read-memory',
  description: 'Read a memory entity by its ID',
  inputSchema: z.object({
    entityId: z.string().describe('Entity ID, e.g. "people/alice"'),
  }),
  execute: async ({ context }) => {
    // context = { entityId: '...' } — це inputSchema fields
    const { entityId } = context;
    const entity = await memoryAdapter.readEntity(entityId);
    return entity ? { success: true, entity } : { success: false, error: 'NOT_FOUND' };
  },
});

// Як передати memoryAdapter в tools:
// Ін'єкція через closure — adapter ініціалізується один раз глобально

// src/memory/adapter.ts
export let memoryAdapter: DiffMemAdapter; // singleton
export function initAdapter(adapter: DiffMemAdapter) { memoryAdapter = adapter; }
```

### 5.8 Context assembly (4 depth levels)

```typescript
// src/memory/context-manager.ts
import { countTokens } from '../utils/tokens.js';
import { extractAlwaysLoad } from '../utils/markdown.js';
import type { ContextDepth, ContextResponse } from '../types.js';

export async function assembleContext(
  userId: string,
  conversation: Array<{ role: string; content: string }>,
  depth: ContextDepth,
  entityStore: EntityManager,
  index: MemoryIndex,
  diffEngine: typeof getEntityDiffs,
  maxTokens = 8000
): Promise<ContextResponse> {
  const query = conversation.map(m => m.content).join('\n');

  const parts: string[] = [];
  const included: ContextEntity[] = [];

  if (depth === 'basic') {
    // Top 5 entities by BM25, ALWAYS_LOAD blocks only
    const results = index.search(query, 5);
    for (const r of results) {
      const entity = await entityStore.read(userId, r.entityId);
      if (!entity) continue;
      const alwaysLoad = extractAlwaysLoad(entity.content);
      if (alwaysLoad) {
        parts.push(`## ${entity.name}\n${alwaysLoad}`);
        included.push({ entityId: r.entityId, name: entity.name, entityType: entity.entityType, relevance: r.score, fullContent: false, includesHistory: false });
      }
    }
  } else if (depth === 'wide') {
    // Top 10 entities, ALWAYS_LOAD + first paragraph
    const results = index.search(query, 10);
    for (const r of results) {
      const entity = await entityStore.read(userId, r.entityId);
      if (!entity) continue;
      const alwaysLoad = extractAlwaysLoad(entity.content);
      const firstPara = entity.content.split('\n\n')[0] || '';
      parts.push(`## ${entity.name}\n${alwaysLoad}\n\n${firstPara}`);
      included.push({ entityId: r.entityId, name: entity.name, entityType: entity.entityType, relevance: r.score, fullContent: false, includesHistory: false });
    }
  } else if (depth === 'deep') {
    // Top 5 entities, full content
    const results = index.search(query, 5);
    for (const r of results) {
      const entity = await entityStore.read(userId, r.entityId);
      if (!entity) continue;
      parts.push(`## ${entity.name}\n${entity.content}`);
      included.push({ entityId: r.entityId, name: entity.name, entityType: entity.entityType, relevance: r.score, fullContent: true, includesHistory: false });
    }
  } else if (depth === 'temporal') {
    // Top 3 entities, full content + git diffs
    const results = index.search(query, 3);
    for (const r of results) {
      const entity = await entityStore.read(userId, r.entityId);
      if (!entity) continue;
      const diffs = await diffEngine(entity.filePath, 3);
      const diffText = diffs.map(d => `### ${d.commitMessage} (${new Date(d.date).toISOString()})\n${d.diff}`).join('\n');
      parts.push(`## ${entity.name}\n${entity.content}\n\n### History\n${diffText}`);
      included.push({ entityId: r.entityId, name: entity.name, entityType: entity.entityType, relevance: r.score, fullContent: true, includesHistory: true });
    }
  }

  // Enforce token limit
  let context = parts.join('\n\n---\n\n');
  const tokenCount = countTokens(context);
  if (tokenCount > maxTokens) {
    context = truncateToTokenLimit(context, maxTokens);
  }

  return {
    success: true,
    context,
    entities: included,
    tokenCount: countTokens(context),
    depth,
  };
}
```

---

## 6. Структура файлів (авторитетна)

```
replit-memory-backend/
├── .replit
├── replit.nix
├── package.json
├── tsconfig.json
├── memory-repo/                  ← git init тут при першому запуску
│   └── users/
│       └── garden-owner/
│           ├── entities/
│           │   ├── people/
│           │   ├── projects/
│           │   ├── concepts/
│           │   └── timelines/
│           ├── sessions/
│           └── artifacts/
└── src/
    ├── server.ts                  ← Fastify entry point
    ├── config.ts                  ← Zod-validated config
    ├── mastra.ts                  ← Mastra instance
    ├── routes/
    │   ├── memory.ts              ← всі /v1/memory/* routes
    │   └── auth.ts                ← requireServiceToken middleware
    ├── memory/
    │   ├── adapter.ts             ← DiffMem facade (головний файл)
    │   ├── git-store.ts           ← isomorphic-git wrapper
    │   ├── bm25-index.ts          ← MemoryIndex class
    │   ├── entity-manager.ts      ← CRUD для .md файлів
    │   ├── context-manager.ts     ← 4-depth context assembly
    │   ├── diff-engine.ts         ← git diffs computation
    │   └── types.ts               ← internal types (відрізняються від API types)
    ├── agents/
    │   ├── writer-agent.ts
    │   ├── searcher-agent.ts
    │   └── tools.ts               ← Mastra tool definitions
    └── utils/
        ├── markdown.ts            ← ALWAYS_LOAD parsing, frontmatter
        ├── tokens.ts              ← tiktoken-based counting
        └── lock.ts                ← AsyncMutex
```

### tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "esModuleInterop": true
  },
  "include": ["src/**/*"]
}
```

### .replit

```toml
run = "npx tsx src/server.ts"
entrypoint = "src/server.ts"

[env]
PORT = "3001"
MEMORY_REPO_PATH = "./memory-repo"
DEFAULT_USER_ID = "garden-owner"
LLM_MODEL = "claude-sonnet-4-5"
CORS_ORIGINS = "https://garden-seedling.lovable.app,http://localhost:5173"
```

---

## 7. Git repo initialization

При першому запуску треба ініціалізувати git-репозиторій:

```typescript
// src/memory/git-store.ts

import git from 'isomorphic-git';
import fs from 'fs';
import path from 'path';

export class GitMemoryStore {
  constructor(private readonly repoDir: string) {}

  async init(): Promise<void> {
    const gitDir = path.join(this.repoDir, '.git');
    if (!fs.existsSync(gitDir)) {
      await git.init({ fs, dir: this.repoDir });
      // Initial commit
      fs.mkdirSync(path.join(this.repoDir, 'users'), { recursive: true });
      fs.writeFileSync(
        path.join(this.repoDir, 'README.md'),
        '# Agent Memory Repository\n\nGit-based memory store for AI agents.\n'
      );
      await git.add({ fs, dir: this.repoDir, filepath: '.' });
      await git.commit({
        fs,
        dir: this.repoDir,
        message: 'init: initialize memory repository',
        author: { name: 'MemoryAgent', email: 'agent@memory.local' },
      });
    }
  }

  async readFile(relativePath: string): Promise<string | null> {
    const fullPath = path.join(this.repoDir, relativePath);
    if (!fs.existsSync(fullPath)) return null;
    return fs.readFileSync(fullPath, 'utf-8');
  }

  async writeFile(relativePath: string, content: string): Promise<void> {
    const fullPath = path.join(this.repoDir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, 'utf-8');
    await git.add({ fs, dir: this.repoDir, filepath: relativePath });
  }

  async commit(message: string): Promise<string> {
    return gitWriteLock.run(() =>
      git.commit({
        fs,
        dir: this.repoDir,
        message,
        author: { name: 'MemoryAgent', email: 'agent@memory.local' },
      })
    );
  }

  async listFiles(directory: string): Promise<string[]> {
    const fullPath = path.join(this.repoDir, directory);
    if (!fs.existsSync(fullPath)) return [];
    return fs.readdirSync(fullPath, { recursive: true })
      .filter((f): f is string => typeof f === 'string' && f.endsWith('.md'))
      .map(f => path.join(directory, f));
  }

  async getLog(depth = 10): Promise<Array<{ oid: string; message: string; timestamp: number }>> {
    const commits = await git.log({ fs, dir: this.repoDir, ref: 'HEAD', depth });
    return commits.map(c => ({
      oid: c.oid,
      message: c.commit.message.trim(),
      timestamp: c.commit.author.timestamp * 1000,
    }));
  }
}
```

---

## 8. Onboarding endpoint — критичний перший крок

```typescript
// В routes/memory.ts

fastify.post('/v1/memory/:userId/onboard', {
  preHandler: requireServiceToken,
}, async (request, reply) => {
  const { userId } = request.params as { userId: string };
  const { userInfo, sessionId } = request.body as { userInfo: string; sessionId: string };

  // Створити директорії для користувача
  const userDir = path.join(config.MEMORY_REPO_PATH, 'users', userId);
  for (const dir of ['entities/people', 'entities/projects', 'entities/concepts', 'entities/timelines', 'sessions', 'artifacts']) {
    fs.mkdirSync(path.join(userDir, dir), { recursive: true });
  }

  // Створити index.md для користувача
  const indexContent = `# Memory Index — ${userId}\n\nInitialized: ${new Date().toISOString()}\n\n## User Info\n${userInfo}\n`;
  await gitStore.writeFile(`users/${userId}/index.md`, indexContent);
  const sha = await gitStore.commit(`init: onboard user ${userId}`);

  // Перебудувати BM25 індекс
  await index.rebuild();

  return reply.send({
    success: true,
    userId,
    sessionId,
    commitSha: sha,
    message: `User ${userId} onboarded`,
  });
});
```

---

## 9. Health endpoint — перший тест

```typescript
fastify.get('/v1/memory/health', async (request, reply) => {
  return reply.send({
    ok: true,
    gitReady: gitStore.isInitialized(),
    indexReady: index.size() >= 0,
    entityCount: index.size(),
    uptime: Math.floor(process.uptime()),
    version: '1.0.0',
  });
});
```

---

## 10. Порядок запуску (src/server.ts)

```typescript
import Fastify from 'fastify';
import cors from '@fastify/cors';
import path from 'path';
import { config } from './config.js';
import { GitMemoryStore } from './memory/git-store.js';
import { EntityManager } from './memory/entity-manager.js';
import { MemoryIndex } from './memory/bm25-index.js';
import { initAdapter } from './memory/adapter.js';
import { DiffMemAdapter } from './memory/adapter.js';
import { registerMemoryRoutes } from './routes/memory.js';

const fastify = Fastify({ logger: true });

async function start() {
  // 1. Register CORS
  await fastify.register(cors, {
    origin: config.CORS_ORIGINS.split(','),
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  });

  // 2. Initialize git store
  const gitStore = new GitMemoryStore(config.MEMORY_REPO_PATH);
  await gitStore.init();

  // 3. Initialize BM25 index
  const memoryIndex = new MemoryIndex();

  // 4. Initialize entity manager
  const entityManager = new EntityManager(gitStore);

  // 5. Build BM25 index from existing entities
  const allFiles = await gitStore.listFiles('users');
  for (const filePath of allFiles) {
    const content = await gitStore.readFile(filePath);
    if (!content) continue;
    const { tags } = parseEntityFromMarkdown(content);
    const entityId = filePath.replace(/^users\/[^/]+\/entities\//, '').replace('.md', '');
    const title = content.match(/^#\s+(.+)/m)?.[1] || entityId;
    memoryIndex.addDocument({ entityId, title, content, tags: tags.join(' '), entityType: 'unknown' });
  }
  memoryIndex.consolidate();

  // 6. Initialize DiffMem adapter (singleton)
  const adapter = new DiffMemAdapter(gitStore, entityManager, memoryIndex);
  initAdapter(adapter);

  // 7. Register routes
  await registerMemoryRoutes(fastify);

  // 8. Start server
  await fastify.listen({ port: config.PORT, host: '0.0.0.0' });
  console.log(`Memory backend running on port ${config.PORT}`);
}

start().catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});
```

---

## 11. Checklist верифікації

Виконай у такому порядку після деплою:

### Крок 1 — Health check (без токену)
```bash
curl https://your-replit-url.replit.app/v1/memory/health
# Очікувано: { "ok": true, "gitReady": true, "indexReady": true }
```

### Крок 2 — Onboarding (з токеном)
```bash
curl -X POST https://your-replit-url.replit.app/v1/memory/garden-owner/onboard \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userInfo":"Garden owner, curator of exodus.pp.ua knowledge garden","sessionId":"onboard-001"}'
# Очікувано: { "success": true, "commitSha": "abc123..." }
```

### Крок 3 — Write entity
```bash
curl -X POST https://your-replit-url.replit.app/v1/memory/garden-owner/process-and-commit \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"memoryInput":"Зустріч з Максом. Обговорювали архітектуру memory backend для exodus.pp.ua. Вирішили використати Mastra + isomorphic-git.","sessionId":"test-001","autoCommit":true}'
# Очікувано: { "success": true, "entitiesAffected": [...] }
```

### Крок 4 — Search
```bash
curl -X POST https://your-replit-url.replit.app/v1/memory/garden-owner/search \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"Mastra архітектура","k":5}'
# Очікувано: { "success": true, "results": [...] }
```

### Крок 5 — Context assembly
```bash
curl -X POST https://your-replit-url.replit.app/v1/memory/garden-owner/context \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"conversation":[{"role":"user","content":"Що ми вирішили щодо архітектури?"}],"depth":"basic"}'
# Очікувано: { "success": true, "context": "...", "tokenCount": 123 }
```

### Крок 6 — Orchestrated search (LLM)
```bash
curl -X POST https://your-replit-url.replit.app/v1/memory/garden-owner/orchestrated-search \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"conversation":[{"role":"user","content":"Розкажи про memory backend"}]}'
# Очікувано: { "success": true, "answer": "...", "sources": [...] }
```

---

## 12. Відомі обмеження MVP

| Обмеження | Опис | Коли вирішити |
|-----------|------|---------------|
| Single-user | `garden-owner` фіксований для MVP | До публічного релізу |
| In-memory BM25 | Перебудовується при рестарті (повільно при 1000+ сутностей) | Після 500+ сутностей |
| No vector search | Тільки BM25, без semantic embeddings | Фаза 2 |
| No GitHub sync | `GITHUB_PAT` опціональний, sync повертає skipped | Після MVP |
| Sequential writes | AsyncMutex — writes йдуть по черзі | Достатньо для MVP |
| No pagination | Search повертає топ K без offset | При масштабуванні |
| No rollback API | Немає endpoint для revert commit | Пізніше |

---

## 13. Якщо щось не працює

### Проблема: Mastra не знаходить модель
```typescript
// Перевір що є ANTHROPIC_API_KEY
// Та використовуй правильний import:
import { anthropic } from '@ai-sdk/anthropic';
// НЕ: import Anthropic from '@anthropic-ai/sdk'
```

### Проблема: isomorphic-git помилка `ENOENT`
```typescript
// Переконайся що MEMORY_REPO_PATH існує та ініціалізований:
fs.mkdirSync(config.MEMORY_REPO_PATH, { recursive: true });
await gitStore.init(); // треба викликати ПЕРШИМ
```

### Проблема: BM25 `Cannot add doc after consolidate`
```typescript
// Після додавання нового документа треба rebuild, не просто addDoc:
index.addDocument(doc);
index.rebuild(); // НЕ consolidate() після addDoc якщо вже consolidate() був
```

### Проблема: Timeout від Cloudflare
```typescript
// Backend повинен відповідати за < 25s (CF timeout = 30s)
// Для orchestrated-search встанови явний timeout на LLM виклику:
const result = await agent.generate(prompt, { maxSteps: 5 }); // обмеж кількість steps
```
