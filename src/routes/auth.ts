import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { config } from "../config.js";

export async function authMiddleware(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const auth = request.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    reply.code(401).send({ error: "Missing or invalid Authorization header" });
    return;
  }
  const token = auth.slice(7);
  if (token !== config.serviceToken) {
    reply.code(403).send({ error: "Invalid service token" });
    return;
  }
}

export function registerAuthHook(app: FastifyInstance, prefix: string): void {
  app.addHook("onRequest", async (request, reply) => {
    if (request.url.startsWith(prefix)) {
      await authMiddleware(request, reply);
    }
  });
}
