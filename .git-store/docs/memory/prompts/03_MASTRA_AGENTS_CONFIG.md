# Промт для Replit: Налаштування Mastra Agents

> Детальна конфігурація Mastra agents для Memory Subsystem.

---

## Встановлення Mastra

```bash
npm install mastra @mastra/core @mastra/memory
npm install @ai-sdk/anthropic  # або @ai-sdk/openai
```

---

## Mastra Config (src/mastra/index.ts)

```typescript
import { Mastra } from '@mastra/core';
import { writerAgent } from '../agents/writer-agent';
import { searcherAgent } from '../agents/searcher-agent';
import { memoryTools } from '../agents/tools';

export const mastra = new Mastra({
  agents: {
    'memory-writer': writerAgent,
    'memory-searcher': searcherAgent,
  },
});
```

---

## Memory Tools (src/agents/tools.ts)

Визначення інструментів які Mastra agents можуть викликати:

```typescript
import { createTool } from '@mastra/core';
import { z } from 'zod';
import type { DiffMemAdapter } from '../memory/adapter';

// Adapter instance буде ін'єктований при ініціалізації
let adapter: DiffMemAdapter;

export function initTools(adapterInstance: DiffMemAdapter) {
  adapter = adapterInstance;
}

export const readMemoryTool = createTool({
  id: 'read-memory',
  description: 'Read the current content of a memory entity by its ID (e.g., "people/alice", "projects/garden-bloom")',
  inputSchema: z.object({
    entityId: z.string().describe('Entity ID in format type/name'),
  }),
  execute: async ({ context }) => {
    const content = await adapter.readEntity('garden-owner', context.entityId);
    return content;
  },
});

export const writeMemoryTool = createTool({
  id: 'write-memory',
  description: 'Create or update a memory entity. Provide the full updated Markdown content.',
  inputSchema: z.object({
    entityId: z.string().describe('Entity ID in format type/name'),
    content: z.string().describe('Full Markdown content for the entity'),
    entityType: z.enum(['person', 'project', 'concept', 'timeline', 'session', 'artifact', 'note']),
  }),
  execute: async ({ context }) => {
    await adapter.writeEntity('garden-owner', context.entityId, context.content, context.entityType);
    return { success: true, entityId: context.entityId };
  },
});

export const searchMemoryTool = createTool({
  id: 'search-memory',
  description: 'Search across all memory entities using BM25 text search. Returns relevant snippets.',
  inputSchema: z.object({
    query: z.string().describe('Search query'),
    k: z.number().default(5).describe('Max results to return'),
  }),
  execute: async ({ context }) => {
    return adapter.search('garden-owner', context.query, { k: context.k });
  },
});

export const listEntitiesTool = createTool({
  id: 'list-entities',
  description: 'List all memory entities, optionally filtered by type',
  inputSchema: z.object({
    entityType: z.string().optional().describe('Filter by entity type'),
  }),
  execute: async ({ context }) => {
    return adapter.listEntities('garden-owner', context.entityType);
  },
});

export const diffMemoryTool = createTool({
  id: 'diff-memory',
  description: 'Get historical changes (git diffs) for a memory entity',
  inputSchema: z.object({
    entityId: z.string().describe('Entity ID to get diffs for'),
    depth: z.number().default(3).describe('Number of commits back'),
  }),
  execute: async ({ context }) => {
    return adapter.getDiff('garden-owner', context.entityId, { depth: context.depth });
  },
});

export const commitMemoryTool = createTool({
  id: 'commit-memory',
  description: 'Commit all staged changes to git with a descriptive message',
  inputSchema: z.object({
    message: z.string().describe('Git commit message describing the changes'),
  }),
  execute: async ({ context }) => {
    return adapter.commitChanges('garden-owner', context.message);
  },
});

export const memoryTools = {
  readMemoryTool,
  writeMemoryTool,
  searchMemoryTool,
  listEntitiesTool,
  diffMemoryTool,
  commitMemoryTool,
};
```

---

## Writer Agent (src/agents/writer-agent.ts)

```typescript
import { Agent } from '@mastra/core';
import { anthropic } from '@ai-sdk/anthropic';
import {
  readMemoryTool,
  writeMemoryTool,
  searchMemoryTool,
  listEntitiesTool,
  commitMemoryTool,
} from './tools';

export const writerAgent = new Agent({
  name: 'memory-writer',
  instructions: `You are a Memory Writer Agent for a digital garden knowledge management system.

## Your Role
You process conversation transcripts, notes, and raw text input to extract structured knowledge and store it as memory entities.

## Entity Types
- **person**: People the user interacts with (colleagues, friends, family)
- **project**: Projects, initiatives, or work items
- **concept**: Ideas, theories, methodologies, or knowledge areas
- **timeline**: Monthly or weekly activity logs
- **session**: Raw session transcripts (preserved as-is)
- **artifact**: Generated outputs (summaries, digests, essays)
- **note**: General notes that don't fit other categories

## Entity File Format
Each entity is a Markdown file with this structure:

\`\`\`markdown
# Entity Name

<!-- ALWAYS_LOAD -->
## Core Facts
- Key fact 1
- Key fact 2
- Key fact 3
<!-- /ALWAYS_LOAD -->

## Detailed Section
Content here...

## Interactions / History
### YYYY-MM-DD
- What happened on this date
\`\`\`

## Rules
1. **Never delete** existing information unless it's explicitly corrected
2. **ALWAYS_LOAD blocks** should contain only the 5-7 most important facts
3. **Date entries** go under ### headers with ISO date format
4. **Search before creating** — check if an entity already exists before making a new one
5. **Update, don't duplicate** — if an entity exists, update it with new info
6. **Preserve structure** — maintain existing headers and organization
7. **Extract entities** — identify people, projects, concepts from the input
8. **Cross-reference** — mention related entities by name for search discoverability
9. **Commit after changes** — always commit with a descriptive message

## Process
1. Read the input carefully
2. Search existing memory for related entities
3. Decide which entities to create or update
4. Write/update each entity
5. Commit all changes with a descriptive message`,
  model: anthropic('claude-sonnet-4-20250514'),
  tools: {
    readMemoryTool,
    writeMemoryTool,
    searchMemoryTool,
    listEntitiesTool,
    commitMemoryTool,
  },
});
```

---

## Searcher Agent (src/agents/searcher-agent.ts)

```typescript
import { Agent } from '@mastra/core';
import { anthropic } from '@ai-sdk/anthropic';
import {
  readMemoryTool,
  searchMemoryTool,
  listEntitiesTool,
  diffMemoryTool,
} from './tools';

export const searcherAgent = new Agent({
  name: 'memory-searcher',
  instructions: `You are a Memory Searcher Agent. Your role is to answer questions by searching through the memory store.

## Process
1. Analyze the user's question
2. Generate 1-3 focused search queries
3. Search memory for relevant entities
4. Read full content of the most relevant entities
5. Synthesize a comprehensive answer based on what you found
6. Cite your sources (entity names and relevant sections)

## Rules
- Always cite which entities you found information in
- If you can't find relevant information, say so honestly
- Use diff_memory when asked about changes over time
- Combine information from multiple entities when needed
- Don't make up information not found in memory`,
  model: anthropic('claude-sonnet-4-20250514'),
  tools: {
    readMemoryTool,
    searchMemoryTool,
    listEntitiesTool,
    diffMemoryTool,
  },
});
```

---

## Використання в Routes

```typescript
// In routes/memory.ts
import { mastra } from '../mastra';

app.post('/v1/memory/:userId/process-and-commit', async (req) => {
  const { memoryInput, sessionId, sessionDate } = req.body as any;
  
  const writerAgent = mastra.getAgent('memory-writer');
  
  const result = await writerAgent.generate(
    `Process this input and update memory accordingly.
    
Session ID: ${sessionId}
Date: ${sessionDate || new Date().toISOString().split('T')[0]}

Input:
${memoryInput}`,
  );

  // Parse agent's response to extract entities affected
  return {
    success: true,
    sessionId,
    entitiesAffected: result.toolCalls?.map(tc => ({
      entityId: tc.args?.entityId,
      action: 'updated',
      name: tc.args?.entityId?.split('/').pop(),
    })) || [],
    commitSha: result.text,
  };
});

app.post('/v1/memory/:userId/orchestrated-search', async (req) => {
  const { conversation } = req.body as any;
  
  const searcherAgent = mastra.getAgent('memory-searcher');
  const lastMessage = conversation[conversation.length - 1]?.content || '';
  
  const result = await searcherAgent.generate(lastMessage);
  
  return {
    success: true,
    answer: result.text,
    subQueries: [], // Extract from tool calls
    sources: result.toolCalls
      ?.filter(tc => tc.toolName === 'searchMemoryTool')
      .flatMap(tc => tc.result?.results || []) || [],
  };
});
```

---

## Тестування Agents

```bash
# Test writer agent
curl -X POST http://localhost:3001/v1/memory/garden-owner/process-and-commit \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "memoryInput": "Today I met with Alice to discuss the garden-bloom memory subsystem. We decided to use Mastra as the agent framework and isomorphic-git for git operations. Alice suggested adding BM25 search for fast retrieval.",
    "sessionId": "test-001",
    "sessionDate": "2026-02-22"
  }'

# Verify entities were created
curl http://localhost:3001/v1/memory/garden-owner/status \
  -H "Authorization: Bearer $SERVICE_TOKEN"

# Test searcher agent
curl -X POST http://localhost:3001/v1/memory/garden-owner/orchestrated-search \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "conversation": [
      {"role": "user", "content": "What did Alice suggest about the memory system?"}
    ]
  }'
```
