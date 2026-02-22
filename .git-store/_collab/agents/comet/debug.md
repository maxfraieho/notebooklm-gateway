# Comet: Debug AccessZone

## Проблема

AccessZone створюється (200 OK), але:
- Не з'являється в списку
- Не валідується
- Доступ не працює

## Діагностика

### 1. Перевірити створення зони

```bash
# Спочатку логін
curl -X POST https://garden-mcp.exodus.pp.ua/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password":"YOUR_PASSWORD"}' \
  | jq '.token'

# Зберегти токен
TOKEN="eyJ..."

# Створити зону
curl -X POST https://garden-mcp.exodus.pp.ua/zones/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Test Zone",
    "noteIds": ["test-note"],
    "expiresIn": 3600000
  }'
```

**Очікувана відповідь:**
```json
{
  "zoneId": "zone_abc123",
  "accessCode": "ZONE-XXXX-YYYY",
  "expiresAt": "..."
}
```

### 2. Перевірити список зон

```bash
curl https://garden-mcp.exodus.pp.ua/zones/list \
  -H "Authorization: Bearer $TOKEN"
```

**Проблемна відповідь:**
```json
[]  // Порожній масив - зона не збереглась!
```

### 3. Перевірити валідацію

```bash
curl https://garden-mcp.exodus.pp.ua/zones/validate/zone_abc123?code=ZONE-XXXX-YYYY
```

**Проблемна відповідь:**
```json
{
  "valid": false,
  "error": "Zone not found"
}
```

## Можливі причини

### A. KV не прив'язаний

**Перевірка:**
```
Dashboard → Workers → garden-mcp-server → Settings → KV Namespace Bindings
```

**Має бути:**
```
Variable name: KV
Namespace: MCP_SESSIONS
```

### B. Помилка в коді збереження

**Перевірити в index.js:**
```javascript
// Має бути
await env.KV.put(`zone:${zoneId}`, JSON.stringify(zoneData));

// Перевірити що env.KV існує
if (!env.KV) {
  console.error('KV not bound!');
}
```

### C. Немає індексу для listing

**Перевірити в index.js:**
```javascript
// При створенні зони має оновлюватись індекс
const index = await env.KV.get('zones:index', 'json') || [];
index.push(zoneId);
await env.KV.put('zones:index', JSON.stringify(index));
```

### D. TTL видаляє дані

**Перевірити:**
```javascript
// Якщо використовується expirationTtl
await env.KV.put(key, value, { expirationTtl: seconds });

// Переконатись що TTL достатній
```

## DevTools перевірка

### Network tab

1. Відкрити DevTools (F12)
2. Network tab
3. Виконати створення зони через UI
4. Перевірити:
   - Request payload
   - Response status
   - Response body

### Console

Шукати помилки:
```
[Error] KV binding not found
[Error] Failed to save zone
```

## Виправлення

### Quick Fix: Додати логування

В `index.js` додати:
```javascript
// В handler /zones/create
console.log('Creating zone:', JSON.stringify(body));
console.log('KV available:', !!env.KV);

// Після збереження
const saved = await env.KV.get(`zone:${zoneId}`);
console.log('Zone saved:', !!saved);
```

### Перевірити логи

```
Dashboard → Workers → garden-mcp-server → Logs → Real-time
```

## Звіт

Після діагностики записати результати в:
```
cloud-cli/analysis-notes.md
```

Формат:
```markdown
## AccessZone Debug - [Date]

### Findings
- KV binding: OK/MISSING
- Zone creation: SUCCESS/FAIL
- Index update: YES/NO

### Root cause
...

### Recommended fix
...
```
