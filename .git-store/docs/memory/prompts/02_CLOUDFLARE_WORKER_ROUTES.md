# Промт для Cloudflare Worker: Memory API Routes

> Додати `/v1/memory/*` routes до існуючого Cloudflare Worker gateway.

---

## Контекст

Існуючий Cloudflare Worker (`garden-mcp-server`) вже проксірує запити до Replit backend для `/v1/git/*`, `/v1/notes/*`, `/v1/drakon/*` та інших маршрутів.

Потрібно додати маршрути для Memory API, що проксіруються до **окремого** Replit backend (Memory Service) або до того ж самого backend (залежно від деплою).

---

## Нові маршрути

Додай у Worker `handleRequest` або router:

```typescript
// Memory API routes — proxy to memory backend
if (url.pathname.startsWith('/v1/memory')) {
  return proxyToMemoryBackend(request, env);
}
```

## Proxy Function

```typescript
async function proxyToMemoryBackend(request: Request, env: Env): Promise<Response> {
  const memoryBackendUrl = env.MEMORY_BACKEND_URL; // Replit URL
  if (!memoryBackendUrl) {
    return jsonResponse({ success: false, error: { code: 'SERVER_ERROR', message: 'Memory backend not configured' } }, 503);
  }

  // Validate owner auth (same as other v1/* routes)
  const authResult = await validateOwnerAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse({ success: false, error: { code: 'UNAUTHORIZED' } }, 401);
  }

  // Proxy request to memory backend
  const targetUrl = new URL(request.url);
  targetUrl.hostname = new URL(memoryBackendUrl).hostname;
  targetUrl.port = new URL(memoryBackendUrl).port;
  targetUrl.protocol = new URL(memoryBackendUrl).protocol;

  const headers = new Headers(request.headers);
  headers.set('Authorization', `Bearer ${env.NOTEBOOKLM_SERVICE_TOKEN}`);
  headers.set('X-Correlation-Id', request.headers.get('X-Correlation-Id') || crypto.randomUUID());

  const proxyRequest = new Request(targetUrl.toString(), {
    method: request.method,
    headers,
    body: request.method !== 'GET' ? request.body : undefined,
  });

  try {
    const response = await fetch(proxyRequest);
    // Forward response with CORS headers
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders,
    });
  } catch (err) {
    return jsonResponse({
      success: false,
      error: { code: 'UPSTREAM_UNAVAILABLE', message: 'Memory backend unreachable' }
    }, 503);
  }
}
```

## Нова Environment Variable

Додай у `wrangler.toml`:

```toml
[vars]
MEMORY_BACKEND_URL = "https://memory-service.replit.app"
```

Або в KV/secrets якщо URL динамічний:

```bash
wrangler secret put MEMORY_BACKEND_URL
```

## Health Check Route

Додай до Worker health endpoint інформацію про memory backend:

```typescript
// In /health handler
const memoryHealth = await checkMemoryBackendHealth(env);
return jsonResponse({
  ok: true,
  services: {
    gateway: 'ok',
    backend: backendStatus,
    memory: memoryHealth ? 'ok' : 'unreachable',
  }
});
```

## CORS

Memory API endpoints потребують тих самих CORS headers що й решта API:

```typescript
// Already handled by existing CORS middleware
// No additional CORS config needed
```

## Тестування

```bash
# Health check через gateway
curl https://garden-mcp-server.maxfraieho.workers.dev/v1/memory/health

# Search через gateway
curl -X POST https://garden-mcp-server.maxfraieho.workers.dev/v1/memory/garden-owner/search \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"test","k":5}'
```
