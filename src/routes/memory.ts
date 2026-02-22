import type { FastifyInstance } from "fastify";
import { memory } from "../memory/adapter.js";

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
}
