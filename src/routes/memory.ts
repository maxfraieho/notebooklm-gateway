import type { FastifyInstance } from "fastify";
import { memory } from "../memory/adapter.js";
import { mastra } from "../mastra.js";
import {
  flattenToolCalls,
  flattenToolResults,
  extractEntitiesFromToolCalls,
  extractCommitSha,
  extractSubQueries,
  extractSources,
} from "../agents/extract-results.js";

export async function memoryRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/memory/health", async () => {
    return {
      ok: true,
      initialized: memory.isInitialized,
      entityCount: memory.entityCount,
    };
  });

  app.post("/v1/memory/init", async () => {
    const result = await memory.init();
    return { ok: true, ...result };
  });

  app.post("/v1/memory/refresh", async () => {
    const result = await memory.refresh();
    return { ok: true, ...result };
  });

  app.get("/v1/memory/entities", async (request) => {
    const query = (request.query as any)?.q as string | undefined;
    const limit = parseInt((request.query as any)?.limit || "20", 10);

    if (query) {
      const results = memory.search(query, limit);
      return { results };
    }

    const entities = memory.listEntities();
    return {
      entities: entities.slice(0, limit).map((e) => ({
        id: e.id,
        title: e.title,
        tags: e.tags,
        updatedAt: e.updatedAt,
      })),
      total: entities.length,
    };
  });

  app.get("/v1/memory/entities/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const entity = memory.getEntity(id);
    if (!entity) {
      reply.code(404).send({ error: "Entity not found" });
      return;
    }
    return entity;
  });

  app.get("/v1/memory/context/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const { maxDepth, maxTokens } = request.query as {
      maxDepth?: string;
      maxTokens?: string;
    };

    const entity = memory.getEntity(id);
    if (!entity) {
      reply.code(404).send({ error: "Entity not found" });
      return;
    }

    const graph = memory.getContext(
      id,
      maxDepth ? parseInt(maxDepth, 10) : undefined,
      maxTokens ? parseInt(maxTokens, 10) : undefined,
    );
    return graph;
  });

  app.post("/v1/memory/context", async (request) => {
    const { query, maxDepth, maxTokens } = request.body as {
      query: string;
      maxDepth?: number;
      maxTokens?: number;
    };

    const graph = memory.getContextForQuery(query, maxDepth, maxTokens);
    return graph;
  });

  app.post("/v1/memory/entities", async (request) => {
    const body = request.body as {
      id: string;
      title: string;
      content: string;
      tags?: string[];
      aliases?: string[];
      meta?: Record<string, unknown>;
    };

    const result = await memory.write(body);
    return result;
  });

  app.put("/v1/memory/entities/:id", async (request) => {
    const { id } = request.params as { id: string };
    const body = request.body as {
      title: string;
      content: string;
      tags?: string[];
      aliases?: string[];
      meta?: Record<string, unknown>;
    };

    const result = await memory.write({ ...body, id });
    return result;
  });

  app.delete("/v1/memory/entities/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const deleted = await memory.delete(id);
    if (!deleted) {
      reply.code(404).send({ error: "Entity not found" });
      return;
    }
    return { ok: true };
  });

  app.post("/v1/memory/commit", async (request) => {
    const { message } = request.body as { message: string };
    const result = await memory.commit(message || "memory: update entities");
    return result;
  });

  app.get("/v1/memory/search", async (request) => {
    const { q, limit } = request.query as { q: string; limit?: string };
    if (!q) {
      return { results: [] };
    }
    const results = memory.search(q, limit ? parseInt(limit, 10) : 10);
    return { results };
  });

  app.post("/v1/memory/:userId/orchestrated-search", async (request, reply) => {
    if (!memory.isInitialized) {
      reply.code(409).send({
        error: "Memory not initialized. Call POST /v1/memory/init first.",
      });
      return;
    }

    const { userId } = request.params as { userId: string };
    const body = request.body as {
      conversation?: Array<{ role: string; content: string }>;
      query?: string;
      k?: number;
    };

    const lastMessage =
      body.query ??
      body.conversation?.findLast((m) => m.role === "user")?.content ??
      "";

    if (!lastMessage) {
      reply.code(400).send({ error: "query or conversation with user message is required" });
      return;
    }

    try {
      const searcherAgent = mastra.getAgent("memory-searcher");
      const result = await searcherAgent.generate(
        `Answer this question using the memory for user ${userId}: ${lastMessage}`,
        { maxSteps: 15 },
      );

      const toolCalls = flattenToolCalls(result.steps, result.toolCalls as any);
      const toolResults = flattenToolResults(result.steps, result.toolResults as any);

      return {
        success: true,
        answer: result.text,
        subQueries: extractSubQueries(toolCalls),
        sources: extractSources(toolResults),
      };
    } catch (err) {
      reply.code(500).send({
        error: "Agent execution failed",
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });

  app.post("/v1/memory/garden-owner/orchestrated-search", async (request, reply) => {
    if (!memory.isInitialized) {
      reply.code(409).send({
        error: "Memory not initialized. Call POST /v1/memory/init first.",
      });
      return;
    }

    const body = request.body as {
      conversation?: Array<{ role: string; content: string }>;
      query?: string;
    };

    const lastMessage =
      body.query ??
      body.conversation?.findLast((m) => m.role === "user")?.content ??
      "";

    if (!lastMessage) {
      reply.code(400).send({ error: "query or conversation with user message is required" });
      return;
    }

    try {
      const searcherAgent = mastra.getAgent("memory-searcher");
      const result = await searcherAgent.generate(
        `Answer this question using the memory for user garden-owner: ${lastMessage}`,
        { maxSteps: 15 },
      );

      const toolCalls = flattenToolCalls(result.steps, result.toolCalls as any);
      const toolResults = flattenToolResults(result.steps, result.toolResults as any);

      return {
        success: true,
        answer: result.text,
        subQueries: extractSubQueries(toolCalls),
        sources: extractSources(toolResults),
      };
    } catch (err) {
      reply.code(500).send({
        error: "Agent execution failed",
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });

  app.post("/v1/memory/:userId/process-transcript", async (request, reply) => {
    if (!memory.isInitialized) {
      reply.code(409).send({
        error: "Memory not initialized. Call POST /v1/memory/init first.",
      });
      return;
    }

    const { userId } = request.params as { userId: string };
    const body = request.body as {
      memoryInput?: string;
      text?: string;
      sessionId?: string;
      autoCommit?: boolean;
      instructions?: string;
    };

    const text = body.memoryInput || body.text || "";
    if (!text) {
      reply.code(400).send({ error: "memoryInput or text field is required" });
      return;
    }

    const sessionId = body.sessionId ?? `session-${Date.now()}`;

    try {
      const writerAgent = mastra.getAgent("memory-writer");
      const prompt = body.instructions
        ? `Process this conversation/input for user ${userId} (session: ${sessionId}).\n\nAdditional instructions: ${body.instructions}\n\nText:\n${text}`
        : `Process this conversation/input for user ${userId} (session: ${sessionId}):\n\n${text}`;

      const result = await writerAgent.generate(prompt, { maxSteps: 20 });

      const toolResults = flattenToolResults(result.steps, result.toolResults as any);

      return {
        success: true,
        sessionId,
        entitiesAffected: extractEntitiesFromToolCalls(toolResults),
        commitSha: extractCommitSha(toolResults),
      };
    } catch (err) {
      reply.code(500).send({
        error: "Agent execution failed",
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });

  app.post("/v1/memory/garden-owner/process-transcript", async (request, reply) => {
    if (!memory.isInitialized) {
      reply.code(409).send({
        error: "Memory not initialized. Call POST /v1/memory/init first.",
      });
      return;
    }

    const body = request.body as {
      memoryInput?: string;
      text?: string;
      sessionId?: string;
      autoCommit?: boolean;
      instructions?: string;
    };

    const text = body.memoryInput || body.text || "";
    if (!text) {
      reply.code(400).send({ error: "memoryInput or text field is required" });
      return;
    }

    const sessionId = body.sessionId ?? `session-${Date.now()}`;

    try {
      const writerAgent = mastra.getAgent("memory-writer");
      const prompt = body.instructions
        ? `Process this conversation/input for user garden-owner (session: ${sessionId}).\n\nAdditional instructions: ${body.instructions}\n\nText:\n${text}`
        : `Process this conversation/input for user garden-owner (session: ${sessionId}):\n\n${text}`;

      const result = await writerAgent.generate(prompt, { maxSteps: 20 });

      const toolResults = flattenToolResults(result.steps, result.toolResults as any);

      return {
        success: true,
        sessionId,
        entitiesAffected: extractEntitiesFromToolCalls(toolResults),
        commitSha: extractCommitSha(toolResults),
      };
    } catch (err) {
      reply.code(500).send({
        error: "Agent execution failed",
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });
}
