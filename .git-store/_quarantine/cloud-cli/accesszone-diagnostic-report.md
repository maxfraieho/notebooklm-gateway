# AccessZone Diagnostic Report

**Date:** 2025-01-15
**Analyst:** Claude (Cloud CLI Agent)
**Status:** [DIAGNOSIS COMPLETE]

---

## Executive Summary

AccessZone не працює через **три критичні проблеми в index.js**:
1. **handleZonesList** повертає stub замість реального списку зон
2. **handleZonesCreate** не генерує та не повертає `accessCode`, який очікує frontend
3. **Відсутній механізм індексації** зон для отримання списку

Зони фактично зберігаються в KV, але система не може їх знайти через відсутність індексу.

---

## Findings

### Finding 1: handleZonesList є stub implementation
- **Severity:** CRITICAL
- **Location:** `infrastructure/cloudflare/worker/index.js:731-736`
- **Description:** Endpoint `/zones/list` завжди повертає фіксоване повідомлення замість списку зон
- **Evidence:**
```javascript
async function handleZonesList(env) {
  return jsonResponse({
    success: true,
    message: 'Implement zone index for listing'
  });
}
```
- **Impact:** Frontend отримує `undefined` для `data.zones` (useAccessZones.ts:62), список зон завжди порожній

### Finding 2: accessCode не генерується при створенні зони
- **Severity:** CRITICAL
- **Location:** `infrastructure/cloudflare/worker/index.js:694-724`
- **Description:** handleZonesCreate не генерує та не повертає accessCode у відповіді
- **Evidence:**
```javascript
// Worker response (index.js:717-723)
return jsonResponse({
  success: true,
  zoneId,
  zoneUrl: `https://${host.replace('garden-mcp-server', 'exodus')}/zone/${zoneId}`,
  expiresAt,
  noteCount: notes.length,
  // ❌ accessCode відсутній!
});

// Frontend очікує (useAccessZones.ts:115)
accessCode: data.accessCode, // → undefined
```
- **Impact:** Frontend не може створити повний URL для доступу до зони

### Finding 3: Відсутній індекс зон
- **Severity:** HIGH
- **Location:** `infrastructure/cloudflare/worker/index.js:694-724`
- **Description:** При створенні зони не оновлюється індекс для подальшого листингу
- **Evidence:**
```javascript
// Зона зберігається
await env.KV.put(
  `zone:${zoneId}`,
  JSON.stringify(zone),
  { expirationTtl: ttlMinutes * 60 }
);

// ❌ Індекс НЕ оновлюється:
// await env.KV.put('zones:index', ...)
```
- **Impact:** Неможливо отримати список всіх зон без сканування всього KV namespace

### Finding 4: API контракт не співпадає між frontend та backend
- **Severity:** MEDIUM
- **Location:**
  - Frontend: `src/hooks/useAccessZones.ts:88-96`
  - Backend: `infrastructure/cloudflare/worker/index.js:695`
- **Description:** Frontend передає додаткові поля, які backend ігнорує
- **Evidence:**

**Frontend передає:**
```javascript
{
  name: params.name,           // ❌ ігнорується
  description: params.description, // ❌ ігнорується
  folders: params.folders,     // ❌ ігнорується (прийшло як allowedPaths)
  noteCount: params.noteCount, // ❌ ігнорується (генерується з notes.length)
  accessType: params.accessType, // ❌ ігнорується
  ttlMinutes: params.ttlMinutes, // ✅ використовується
  notes: params.notes,         // ✅ використовується
}
```

**Backend приймає:**
```javascript
const { allowedPaths, ttlMinutes, notes } = body;
// name, description, accessType - відсутні
```

- **Impact:** Втрачається інформація про назву зони, опис, тип доступу

### Finding 5: KV операції виглядають коректно
- **Severity:** N/A (не проблема)
- **Location:** `infrastructure/cloudflare/worker/index.js:711-714, 651, 675`
- **Description:** KV keys consistency, TTL, async/await - все правильно
- **Evidence:**
```javascript
// Create використовує
await env.KV.put(`zone:${zoneId}`, JSON.stringify(zone), { expirationTtl: ttlMinutes * 60 });

// Validate використовує
const zoneData = await env.KV.get(`zone:${zoneId}`);

// Notes використовує
const zoneData = await env.KV.get(`zone:${zoneId}`);

// ✅ Ключі співпадають, await присутній, TTL в секундах (правильно для KV API)
```

---

## Root Cause Analysis

### Чому AccessZone не працює?

**Проблема №1: Stub implementation handleZonesList**

Коли frontend викликає `GET /zones/list`, він очікує:
```javascript
{ success: true, zones: [...] }
```

Але отримує:
```javascript
{ success: true, message: 'Implement zone index for listing' }
```

Результат: `data.zones` → `undefined` → `setZones(undefined || [])` → завжди порожній список

**Проблема №2: Відсутній accessCode**

AccessZone потребує код доступу для публічного перегляду. Frontend намагається створити URL:
```javascript
webUrl: `${APP_BASE_URL}/zone/${data.zoneId}?code=${data.accessCode}`
```

Але `data.accessCode` → `undefined`, тому URL неповний і доступ не працює.

**Проблема №3: Немає індексу**

Cloudflare KV не підтримує сканування всіх ключів. Для листингу потрібен окремий індекс:
```javascript
// Поточна структура
zone:abc123 → { zoneId: 'abc123', ... }
zone:def456 → { zoneId: 'def456', ... }

// Немає способу отримати список всіх zone:* ключів!
```

Потрібен індекс:
```javascript
zones:index → ['abc123', 'def456', ...]
```

**Проблема №4: API контракт**

Frontend та backend мають різні очікування щодо структури даних. Це призводить до втрати метаданих (name, description, accessType), які потім неможливо відновити.

---

## Recommendations

### Must Fix (Critical)

#### 1. Імплементувати handleZonesList

**Файл:** `infrastructure/cloudflare/worker/index.js:731-736`

**Замінити:**
```javascript
async function handleZonesList(env) {
  return jsonResponse({
    success: true,
    message: 'Implement zone index for listing'
  });
}
```

**На:**
```javascript
async function handleZonesList(env) {
  const indexData = await env.KV.get('zones:index');

  if (!indexData) {
    return jsonResponse({ success: true, zones: [] });
  }

  const zoneIds = JSON.parse(indexData);

  // Отримуємо деталі кожної зони
  const zones = await Promise.all(
    zoneIds.map(async (zoneId) => {
      const zoneData = await env.KV.get(`zone:${zoneId}`);
      if (!zoneData) return null;

      const zone = JSON.parse(zoneData);

      // Фільтруємо expired зони
      if (new Date(zone.expiresAt) < new Date()) {
        return null;
      }

      return {
        id: zone.zoneId,
        name: zone.name,
        description: zone.description,
        folders: zone.allowedPaths,
        noteCount: zone.noteCount,
        accessType: zone.accessType,
        createdAt: new Date(zone.createdAt).getTime(),
        expiresAt: new Date(zone.expiresAt).getTime(),
        accessCode: zone.accessCode,
      };
    })
  );

  // Видаляємо null (expired/deleted зони)
  const validZones = zones.filter(z => z !== null);

  return jsonResponse({ success: true, zones: validZones });
}
```

#### 2. Генерувати та повертати accessCode

**Файл:** `infrastructure/cloudflare/worker/index.js:694-724`

**Додати після рядка 698 (генерація zoneId):**
```javascript
const zoneId = crypto.randomUUID().slice(0, 8);
const accessCode = `ACCESS-${crypto.randomUUID().slice(0, 8).toUpperCase()}`; // ДОДАТИ
```

**Додати accessCode у об'єкт zone (після рядка 700):**
```javascript
const zone = {
  zoneId,
  accessCode,        // ДОДАТИ
  allowedPaths,
  notes,
  noteCount: notes.length,
  expiresAt,
  createdAt: new Date().toISOString(),
  createdBy: 'owner',
};
```

**Додати accessCode у відповідь (рядок 717-723):**
```javascript
return jsonResponse({
  success: true,
  zoneId,
  accessCode,        // ДОДАТИ
  zoneUrl: `https://${host.replace('garden-mcp-server', 'exodus')}/zone/${zoneId}`,
  expiresAt,
  noteCount: notes.length,
});
```

#### 3. Оновлювати індекс при створенні зони

**Файл:** `infrastructure/cloudflare/worker/index.js:711-714`

**Після `await env.KV.put(...)` додати:**
```javascript
await env.KV.put(
  `zone:${zoneId}`,
  JSON.stringify(zone),
  { expirationTtl: ttlMinutes * 60 }
);

// ДОДАТИ: Оновлення індексу
const indexData = await env.KV.get('zones:index');
const zoneIndex = indexData ? JSON.parse(indexData) : [];
zoneIndex.push(zoneId);
await env.KV.put('zones:index', JSON.stringify(zoneIndex));
```

**⚠️ Важливо:** Також потрібно видаляти з індексу при `handleZonesDelete`:

**Файл:** `infrastructure/cloudflare/worker/index.js:726-729`

**Замінити:**
```javascript
async function handleZonesDelete(zoneId, env) {
  await env.KV.delete(`zone:${zoneId}`);
  return jsonResponse({ success: true });
}
```

**На:**
```javascript
async function handleZonesDelete(zoneId, env) {
  await env.KV.delete(`zone:${zoneId}`);

  // Видалити з індексу
  const indexData = await env.KV.get('zones:index');
  if (indexData) {
    const zoneIndex = JSON.parse(indexData);
    const updatedIndex = zoneIndex.filter(id => id !== zoneId);
    await env.KV.put('zones:index', JSON.stringify(updatedIndex));
  }

  return jsonResponse({ success: true });
}
```

### Should Fix (Important)

#### 4. Узгодити API контракт

**Файл:** `infrastructure/cloudflare/worker/index.js:695`

**Замінити:**
```javascript
const { allowedPaths, ttlMinutes, notes } = body;
```

**На:**
```javascript
const { name, description, allowedPaths, ttlMinutes, notes, accessType } = body;
```

**Додати поля у об'єкт zone:**
```javascript
const zone = {
  zoneId,
  accessCode,
  name,              // ДОДАТИ
  description,       // ДОДАТИ
  accessType,        // ДОДАТИ
  allowedPaths,
  notes,
  noteCount: notes.length,
  expiresAt,
  createdAt: new Date().toISOString(),
  createdBy: 'owner',
};
```

**Оновити frontend для передачі allowedPaths:**

**Файл:** `src/hooks/useAccessZones.ts:88-96`

**Замінити:**
```javascript
body: JSON.stringify({
  name: params.name,
  description: params.description,
  folders: params.folders,  // змінити на allowedPaths
  noteCount: params.noteCount,
  accessType: params.accessType,
  ttlMinutes: params.ttlMinutes,
  notes: params.notes,
}),
```

**На:**
```javascript
body: JSON.stringify({
  name: params.name,
  description: params.description,
  allowedPaths: params.folders,  // змінити
  accessType: params.accessType,
  ttlMinutes: params.ttlMinutes,
  notes: params.notes,
}),
```

### Nice to Have

#### 5. Періодична очистка expired зон з індексу

Створити окрему функцію для очистки:
```javascript
async function cleanupExpiredZones(env) {
  const indexData = await env.KV.get('zones:index');
  if (!indexData) return;

  const zoneIds = JSON.parse(indexData);
  const validZoneIds = [];

  for (const zoneId of zoneIds) {
    const zoneData = await env.KV.get(`zone:${zoneId}`);
    if (zoneData) {
      const zone = JSON.parse(zoneData);
      if (new Date(zone.expiresAt) > new Date()) {
        validZoneIds.push(zoneId);
      }
    }
  }

  await env.KV.put('zones:index', JSON.stringify(validZoneIds));
}
```

Викликати при `handleZonesList` або через Cron Trigger.

#### 6. Додати валідацію вхідних даних

```javascript
async function handleZonesCreate(request, env, host) {
  const body = await request.json();
  const { name, description, allowedPaths, ttlMinutes, notes, accessType } = body;

  // Валідація
  if (!name || typeof name !== 'string') {
    return errorResponse('Invalid name', 400);
  }

  if (!Array.isArray(allowedPaths) || allowedPaths.length === 0) {
    return errorResponse('Invalid allowedPaths', 400);
  }

  if (!Array.isArray(notes) || notes.length === 0) {
    return errorResponse('Invalid notes', 400);
  }

  if (!ttlMinutes || ttlMinutes < 1 || ttlMinutes > 43200) {
    return errorResponse('Invalid ttlMinutes (1-43200)', 400);
  }

  if (!['web', 'mcp', 'both'].includes(accessType)) {
    return errorResponse('Invalid accessType', 400);
  }

  // ... решта коду
}
```

---

## Verification Steps

### 1. Після імплементації фіксів, створити зону:

```bash
TOKEN="your-owner-token"

curl -X POST https://garden-mcp.exodus.pp.ua/zones/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Zone",
    "description": "Diagnostic test",
    "allowedPaths": ["/test"],
    "ttlMinutes": 60,
    "accessType": "both",
    "notes": [
      {
        "slug": "test/note1",
        "title": "Test Note",
        "content": "Test content",
        "tags": ["test"]
      }
    ]
  }'
```

**Очікуваний результат:**
```json
{
  "success": true,
  "zoneId": "abc12345",
  "accessCode": "ACCESS-XYZ78901",
  "zoneUrl": "https://exodus.pp.ua/zone/abc12345",
  "expiresAt": "2025-01-15T19:48:00.000Z",
  "noteCount": 1
}
```

### 2. Перевірити список зон:

```bash
curl https://garden-mcp.exodus.pp.ua/zones/list \
  -H "Authorization: Bearer $TOKEN"
```

**Очікуваний результат:**
```json
{
  "success": true,
  "zones": [
    {
      "id": "abc12345",
      "name": "Test Zone",
      "description": "Diagnostic test",
      "folders": ["/test"],
      "noteCount": 1,
      "accessType": "both",
      "createdAt": 1736964480000,
      "expiresAt": 1736968080000,
      "accessCode": "ACCESS-XYZ78901"
    }
  ]
}
```

### 3. Валідувати зону:

```bash
curl https://garden-mcp.exodus.pp.ua/zones/validate/abc12345
```

**Очікуваний результат:**
```json
{
  "success": true,
  "zone": {
    "zoneId": "abc12345",
    "allowedPaths": ["/test"],
    "expiresAt": "2025-01-15T19:48:00.000Z",
    "noteCount": 1
  }
}
```

### 4. Отримати нотатки зони:

```bash
curl https://garden-mcp.exodus.pp.ua/zones/abc12345/notes
```

**Očекуваний результат:**
```json
{
  "success": true,
  "notes": [
    {
      "slug": "test/note1",
      "title": "Test Note",
      "content": "Test content",
      "tags": ["test"]
    }
  ],
  "expiresAt": "2025-01-15T19:48:00.000Z"
}
```

### 5. Видалити зону:

```bash
curl -X DELETE https://garden-mcp.exodus.pp.ua/zones/abc12345 \
  -H "Authorization: Bearer $TOKEN"
```

**Очікуваний результат:**
```json
{
  "success": true
}
```

### 6. Перевірити, що зона видалена з індексу:

```bash
curl https://garden-mcp.exodus.pp.ua/zones/list \
  -H "Authorization: Bearer $TOKEN"
```

**Очікуваний результат:**
```json
{
  "success": true,
  "zones": []
}
```

---

## Files Analyzed

1. `infrastructure/cloudflare/worker/index.js` - Worker implementation
2. `infrastructure/cloudflare/worker/accessZone.md` - AccessZone documentation
3. `src/hooks/useAccessZones.ts` - Frontend hook
4. `agents/chatgpt/accesszone-diagnostic-task.md` - Task specification

---

## Summary of Changes Required

| File | Function | Change | Priority |
|------|----------|--------|----------|
| index.js | handleZonesList | Імплементувати реальний листинг з індексу | CRITICAL |
| index.js | handleZonesCreate | Генерувати та повертати accessCode | CRITICAL |
| index.js | handleZonesCreate | Оновлювати zones:index при створенні | CRITICAL |
| index.js | handleZonesDelete | Видаляти з zones:index при видаленні | CRITICAL |
| index.js | handleZonesCreate | Приймати name, description, accessType | HIGH |
| useAccessZones.ts | createZone | Передавати allowedPaths замість folders | HIGH |
| index.js | handleZonesCreate | Додати валідацію вхідних даних | MEDIUM |
| index.js | cleanupExpiredZones | Створити функцію очистки індексу | LOW |

---

## Next Steps

1. **Lovable Agent:** Отримує цей звіт → імплементує всі Must Fix та Should Fix зміни
2. **Comet Agent:** Деплоїть оновлений Worker через Cloudflare Dashboard
3. **Cloud CLI Agent:** Виконує Verification Steps через curl команди, підтверджує, що всі endpoints працюють

---

## Notes

- KV операції (put/get, TTL, await) працюють правильно - це **не** джерело проблеми
- Структура ключів `zone:${zoneId}` консистентна між create/validate/notes - це **не** джерело проблеми
- Проблема виключно в **неповній імплементації** handleZonesList, відсутності accessCode та індексу
- Після виправлення цих трьох речей AccessZone має працювати стабільно

---

**End of Report**
