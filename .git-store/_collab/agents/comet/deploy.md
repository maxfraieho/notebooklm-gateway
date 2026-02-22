# Comet: Deploy Cloudflare Worker

## Передумови

- Доступ до [Cloudflare Dashboard](https://dash.cloudflare.com)
- Worker `garden-mcp-server` вже створений
- KV namespace `MCP_SESSIONS` прив'язаний

## Кроки деплою

### 1. Відкрити Dashboard

```
URL: https://dash.cloudflare.com
```

### 2. Навігація

```
Workers & Pages → garden-mcp-server → Quick Edit
```

### 3. Вставити код

1. Виділити весь код в редакторі (Ctrl+A)
2. Видалити (Delete)
3. Вставити новий код з `infrastructure/cloudflare/worker/index.js` (Ctrl+V)

### 4. Зберегти

```
Click: "Save and Deploy" (синя кнопка)
```

### 5. Перевірити Environment Variables

```
Settings → Variables

Required:
- JWT_SECRET: [set]
- MINIO_ENDPOINT: https://apiminio.exodus.pp.ua
- MINIO_BUCKET: mcpstorage
- MINIO_ACCESS_KEY: [set]
- MINIO_SECRET_KEY: [set]
```

### 6. Перевірити KV Bindings

```
Settings → KV Namespace Bindings

Required:
- Variable name: KV
- KV namespace: MCP_SESSIONS
```

## Верифікація

### Health Check

```bash
curl https://garden-mcp.exodus.pp.ua/health
```

**Очікувана відповідь:**
```json
{
  "status": "ok",
  "version": "3.0",
  "timestamp": "...",
  "features": {
    "auth": true,
    "mcp": true,
    "zones": true,
    "minio": true
  }
}
```

### Auth Status

```bash
curl -X POST https://garden-mcp.exodus.pp.ua/auth/status
```

**Очікувана відповідь:**
```json
{
  "initialized": true,
  "message": "Owner password is set"
}
```

## Troubleshooting

### "Worker not found"

- Перевірити URL воркера
- Перевірити DNS routing

### "KV binding error"

- Settings → KV Namespace Bindings
- Перевірити що binding name = `KV`

### "Environment variable missing"

- Settings → Variables
- Додати відсутню змінну

## Чекліст після деплою

- [ ] `/health` повертає 200
- [ ] `features.zones` = true
- [ ] `/auth/status` працює
- [ ] KV binding активний
