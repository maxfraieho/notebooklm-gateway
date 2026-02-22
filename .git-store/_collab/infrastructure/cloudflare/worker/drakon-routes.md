# Cloudflare Worker: DRAKON Routes

**Дата:** 2026-02-07

---

## Нові routes для проксі до Replit backend

Додати до `index.js` наступні routes:

### 1. POST `/v1/drakon/commit`

Проксі до Replit backend для створення/оновлення DRAKON-діаграм.

```javascript
// In router section, add:
if (path === '/v1/drakon/commit' && method === 'POST') {
  return proxyToReplit(request, env, '/v1/drakon/commit');
}
```

### 2. DELETE `/v1/drakon/:folderSlug/:diagramId`

Проксі для видалення діаграм.

```javascript
// Pattern: /v1/drakon/{folderSlug}/{diagramId}
const drakonDeleteMatch = path.match(/^\/v1\/drakon\/([^\/]+)\/([^\/]+)$/);
if (drakonDeleteMatch && method === 'DELETE') {
  const [, folderSlug, diagramId] = drakonDeleteMatch;
  return proxyToReplit(request, env, `/v1/drakon/${folderSlug}/${diagramId}`);
}
```

---

## Повний приклад інтеграції

У секції routes у `index.js`:

```javascript
// ============================================
// DRAKON Diagrams Routes (proxy to Replit)
// ============================================

// Create/Update diagram
if (path === '/v1/drakon/commit' && method === 'POST') {
  // Requires owner auth - forward token to Replit
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) {
    return jsonResponse({ success: false, error: 'AUTH_REQUIRED' }, 401);
  }
  
  return fetch(`${env.REPLIT_BACKEND_URL}/v1/drakon/commit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': authHeader,
    },
    body: request.body,
  });
}

// Delete diagram
const drakonDeleteMatch = path.match(/^\/v1\/drakon\/([^\/]+)\/([^\/]+)$/);
if (drakonDeleteMatch && method === 'DELETE') {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) {
    return jsonResponse({ success: false, error: 'AUTH_REQUIRED' }, 401);
  }
  
  const [, folderSlug, diagramId] = drakonDeleteMatch;
  return fetch(`${env.REPLIT_BACKEND_URL}/v1/drakon/${encodeURIComponent(folderSlug)}/${encodeURIComponent(diagramId)}`, {
    method: 'DELETE',
    headers: {
      'Authorization': authHeader,
    },
  });
}
```

---

## Environment Variables

Переконатися що в Worker є:
- `REPLIT_BACKEND_URL` або використовувати існуючий URL бекенду

---

## Тестування

```bash
# Test commit (через Worker)
curl -X POST https://garden-mcp.exodus.pp.ua/v1/drakon/commit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"diagramId":"test","diagram":{},"isNew":true}'

# Очікуваний результат: 200 OK з JSON response
```
