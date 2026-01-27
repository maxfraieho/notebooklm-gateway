# Виправлення Cloudflare Worker для NotebookLM Chat

## Проблема 1: Неправильне ім'я поля (КРИТИЧНО)

**Файл:** `index.js`  
**Рядок:** ~439

### Було (неправильно):
```javascript
const chatRes = await fetchNotebookLM(env, '/v1/chat', {
  method: 'POST',
  body: JSON.stringify({
    notebook_url: notebookUrl,  // ❌ НЕПРАВИЛЬНО - snake_case
    message,
    kind,
    history,
  }),
});
```

### Стало (правильно):
```javascript
const chatRes = await fetchNotebookLM(env, '/v1/chat', {
  method: 'POST',
  body: JSON.stringify({
    notebookUrl: notebookUrl,  // ✅ ПРАВИЛЬНО - camelCase
    message,
    kind,
    history,
  }),
});
```

---

## Проблема 2: Таймаут занадто короткий

**Файл:** `index.js`  
**Рядок:** ~361

Chat запити можуть тривати до 90 секунд. Потрібно збільшити таймаут для chat.

### Варіант A: Додати змінну оточення
Додай в Cloudflare Worker Settings → Variables:
```
NOTEBOOKLM_TIMEOUT_MS = 120000
```

### Варіант B: Передати таймаут в функцію (рекомендовано)

Змінити функцію `fetchNotebookLM` щоб приймала опціональний `timeoutMs`:

```javascript
async function fetchNotebookLM(env, path, init = {}, customTimeoutMs = null) {
  const baseUrl = (env.NOTEBOOKLM_BASE_URL || 'https://notebooklm-gateway.replit.app').replace(/\/$/, '');
  const timeoutMs = customTimeoutMs || Number.parseInt(env.NOTEBOOKLM_TIMEOUT_MS, 10) || 15000;
  // ... решта коду без змін
}
```

І в `handleNotebookLMChat` передати 120000ms:

```javascript
const chatRes = await fetchNotebookLM(env, '/v1/chat', {
  method: 'POST',
  body: JSON.stringify({
    notebookUrl: notebookUrl,
    message,
    kind,
    history,
  }),
}, 120000);  // 120 секунд для chat
```

---

## Повний виправлений код handleNotebookLMChat

```javascript
async function handleNotebookLMChat(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400, undefined, 'INVALID_JSON');
  }

  const notebookUrl = typeof body?.notebookUrl === 'string' ? body.notebookUrl.trim() : '';
  const message = typeof body?.message === 'string' ? body.message.trim() : '';
  const kind = typeof body?.kind === 'string' ? body.kind : 'answer';
  const history = Array.isArray(body?.history) ? body.history : [];

  if (!notebookUrl) return errorResponse('notebookUrl is required', 400, body, 'NOTEBOOKLM_CHAT_INVALID');
  if (!message) return errorResponse('message is required', 400, body, 'NOTEBOOKLM_CHAT_INVALID');

  // Використовуємо збільшений таймаут для chat (120 секунд)
  const chatTimeoutMs = 120000;
  
  const baseUrl = (env.NOTEBOOKLM_BASE_URL || 'https://notebooklm-gateway.replit.app').replace(/\/$/, '');
  const url = `${baseUrl}/v1/chat`;

  const headers = new Headers();
  headers.set('Content-Type', 'application/json');
  if (env.NOTEBOOKLM_SERVICE_TOKEN) {
    headers.set('Authorization', `Bearer ${env.NOTEBOOKLM_SERVICE_TOKEN}`);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort('timeout'), chatTimeoutMs);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        notebookUrl: notebookUrl,  // ✅ camelCase
        message,
        kind,
        history,
      }),
      signal: controller.signal,
    });

    const contentType = res.headers.get('content-type') || '';
    const data = contentType.includes('application/json')
      ? await res.json().catch(() => null)
      : await res.text().catch(() => null);

    if (!res.ok) {
      return errorResponse(
        data?.error?.message || data?.error || data?.detail || 'NotebookLM chat failed',
        res.status || 502,
        data,
        'NOTEBOOKLM_CHAT_FAILED'
      );
    }

    return jsonResponse({ success: true, ...data });
  } catch (err) {
    const isTimeout = err?.name === 'AbortError' || err === 'timeout';
    return errorResponse(
      isTimeout ? `Chat timeout after ${chatTimeoutMs / 1000}s` : `Chat failed: ${err?.message || String(err)}`,
      isTimeout ? 504 : 502,
      undefined,
      isTimeout ? 'NOTEBOOKLM_CHAT_TIMEOUT' : 'NOTEBOOKLM_CHAT_FAILED'
    );
  } finally {
    clearTimeout(timeoutId);
  }
}
```

---

## Після внесення змін

1. Збережи файл `index.js`
2. Виконай `wrangler deploy` або задеплой через Cloudflare Dashboard
3. Протестуй chat в UI
