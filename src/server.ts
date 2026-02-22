import Fastify from "fastify";
import cors from "@fastify/cors";
import { config } from "./config.js";
import { authMiddleware } from "./routes/auth.js";
import { memoryRoutes } from "./routes/memory.js";
import { initTokenizer } from "./utils/tokens.js";
import { memory, setAdapter } from "./memory/adapter.js";
import { initIndex } from "./memory/bm25-index.js";

const app = Fastify({ logger: true });

setAdapter(memory);

await app.register(cors, { origin: true });

app.addHook("onRequest", async (request, reply) => {
  if (
    request.url === "/v1/memory/health" ||
    request.url === "/" ||
    request.url === "/health"
  ) {
    return;
  }
  if (request.url.startsWith("/v1/")) {
    await authMiddleware(request, reply);
  }
});

app.get("/", async () => {
  return {
    service: "memory-backend",
    version: "1.0.0",
    endpoints: [
      "GET  /health",
      "GET  /v1/memory/health",
      "POST /v1/memory/init",
      "POST /v1/memory/refresh",
      "GET  /v1/memory/entities",
      "GET  /v1/memory/entities/:id",
      "POST /v1/memory/entities",
      "PUT  /v1/memory/entities/:id",
      "DEL  /v1/memory/entities/:id",
      "GET  /v1/memory/context/:id",
      "POST /v1/memory/context",
      "GET  /v1/memory/search?q=...",
      "POST /v1/memory/commit",
      "POST /v1/memory/:userId/orchestrated-search",
      "POST /v1/memory/:userId/process-transcript",
      "POST /v1/memory/garden-owner/orchestrated-search",
      "POST /v1/memory/garden-owner/process-transcript",
    ],
  };
});

app.get("/health", async () => {
  return { ok: true };
});

await memoryRoutes(app);

await initTokenizer();
initIndex();

const start = async () => {
  try {
    await app.listen({ port: config.port, host: "0.0.0.0" });
    console.log(`Memory backend listening on port ${config.port}`);

    if (config.githubToken) {
      try {
        const result = await memory.init();
        console.log(
          `Memory auto-initialized: ${result.entityCount} entities loaded`,
        );
      } catch (err) {
        console.error("Memory auto-init failed (call POST /v1/memory/init manually):", err);
      }
    }
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();
