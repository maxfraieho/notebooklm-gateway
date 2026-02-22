import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import { getAdapter } from "../memory/adapter.js";

export const searchMemoryTool = createTool({
  id: "search-memory",
  description:
    "Search across memory entities using BM25 full-text search. Returns matching entities with relevance scores.",
  inputSchema: z.object({
    query: z.string().describe("Search query"),
    k: z.number().default(10).describe("Number of results to return"),
  }),
  execute: async (inputData) => {
    const adapter = getAdapter();
    const results = adapter.search(inputData.query, inputData.k);
    return { results };
  },
});

export const readMemoryTool = createTool({
  id: "read-memory",
  description:
    "Read the full content of a memory entity by its ID. Use after search to get complete content.",
  inputSchema: z.object({
    entityId: z
      .string()
      .describe('Entity ID, e.g. "machine-learning" or "project-alpha"'),
  }),
  execute: async (inputData) => {
    const adapter = getAdapter();
    const entity = adapter.getEntity(inputData.entityId);
    if (!entity)
      return { success: false, error: "NOT_FOUND", entityId: inputData.entityId };
    return { success: true, entity };
  },
});

export const writeMemoryTool = createTool({
  id: "write-memory",
  description:
    "Create or update a memory entity with new content. Always preserve existing facts — only ADD new information.",
  inputSchema: z.object({
    entityId: z.string().describe('Entity ID, e.g. "people/max"'),
    title: z.string().describe("Entity title"),
    content: z.string().describe("Full markdown content for the entity"),
    tags: z.array(z.string()).optional().describe("Tags for categorization"),
  }),
  execute: async (inputData) => {
    const adapter = getAdapter();
    const result = await adapter.write({
      id: inputData.entityId,
      title: inputData.title,
      content: inputData.content,
      tags: inputData.tags,
    });
    return {
      entityId: result.entity.id,
      title: result.entity.title,
      diff: {
        additions: result.diff.additions,
        deletions: result.diff.deletions,
      },
    };
  },
});

export const listEntitiesTool = createTool({
  id: "list-entities",
  description:
    "List all memory entities, optionally limited. Returns entity IDs, titles, and tags.",
  inputSchema: z.object({
    limit: z
      .number()
      .default(50)
      .describe("Maximum number of entities to list"),
  }),
  execute: async (inputData) => {
    const adapter = getAdapter();
    const entities = adapter.listEntities();
    return {
      entities: entities.slice(0, inputData.limit).map((e) => ({
        id: e.id,
        title: e.title,
        tags: e.tags,
      })),
      total: entities.length,
    };
  },
});

export const commitMemoryTool = createTool({
  id: "commit-memory",
  description:
    "Commit all staged memory changes to git with a descriptive message. Call once after all writes.",
  inputSchema: z.object({
    message: z
      .string()
      .describe("Commit message describing what was updated"),
  }),
  execute: async (inputData) => {
    const adapter = getAdapter();
    const result = await adapter.commit(inputData.message);
    return { commitSha: result.sha, message: result.message };
  },
});

export const getContextTool = createTool({
  id: "get-context",
  description:
    "Get graph context from an entity, traversing links and backlinks. Returns related entities forming a knowledge neighborhood.",
  inputSchema: z.object({
    entityId: z.string().describe("The root entity ID to build context from"),
    maxDepth: z.number().default(4).describe("Maximum traversal depth"),
    maxTokens: z
      .number()
      .default(8000)
      .describe("Maximum token budget for context"),
  }),
  execute: async (inputData) => {
    const adapter = getAdapter();
    const graph = adapter.getContext(
      inputData.entityId,
      inputData.maxDepth,
      inputData.maxTokens,
    );
    return {
      root: graph.root,
      totalTokens: graph.totalTokens,
      nodes: graph.nodes.map((n) => ({
        id: n.entity.id,
        title: n.entity.title,
        depth: n.depth,
        relevance: n.relevance,
        content: n.entity.content,
        tags: n.entity.tags,
      })),
    };
  },
});
