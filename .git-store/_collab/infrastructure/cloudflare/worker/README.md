# Garden MCP Cloudflare Worker

## Призначення

Цей worker забезпечує:
- Аутентифікацію власника (Owner Auth)
- Управління MCP сесіями
- Управління Access Zones
- MCP JSON-RPC endpoint
- SSE транспорт для real-time комунікації

## Деплоймент

**Метод:** GitHub Actions (автоматичний)

### Автоматичний деплой

При пуші в `main` гілку з змінами в `infrastructure/cloudflare/worker/**`:
1. GitHub Action запускається автоматично
2. Wrangler деплоїть worker до Cloudflare

### Налаштування (одноразово)

1. Додати GitHub Secrets:
   - `CLOUDFLARE_API_TOKEN` - API токен з правами Workers
   - `CLOUDFLARE_ACCOUNT_ID` - ID акаунту Cloudflare

2. Оновити `wrangler.toml`:
   - Замінити `YOUR_KV_NAMESPACE_ID` на реальний ID з Cloudflare Dashboard

### Ручний деплой

```bash
cd infrastructure/cloudflare/worker
wrangler deploy
```

### Legacy метод (Quick Edit)

1. Відкрити [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Workers & Pages → `garden-mcp-server`
3. Quick Edit
4. Вставити код з `index.js`
5. Save and Deploy

## Environment Variables

| Variable | Опис |
|----------|------|
| `JWT_SECRET` | Секрет для підпису JWT токенів |
| `MINIO_ENDPOINT` | URL MinIO API (e.g. `https://apiminio.exodus.pp.ua`) |
| `MINIO_BUCKET` | Назва bucket (e.g. `mcpstorage`) |
| `MINIO_ACCESS_KEY` | Access key MinIO |
| `MINIO_SECRET_KEY` | Secret key MinIO |

## KV Bindings

| Binding Name | Namespace |
|--------------|-----------|
| `KV` | `MCP_SESSIONS` |

## Endpoints

### Public
- `GET /health` - Health check
- `POST /auth/status` - Check owner initialization
- `POST /auth/setup` - One-time password setup
- `POST /auth/login` - Owner login → JWT
- `POST /auth/refresh` - Refresh JWT
- `POST /auth/validate` - Validate JWT

### Owner-Protected (JWT required)
- `POST /sessions/create` - Create MCP session
- `POST /sessions/revoke` - Delete session
- `GET /sessions/list` - List sessions

### Zones
- `POST /zones/create` - Create access zone
- `DELETE /zones/:zoneId` - Delete zone
- `GET /zones/list` - List zones
- `GET /zones/validate/:zoneId` - Validate zone access
- `GET /zones/:zoneId/notes` - Get zone notes

### MCP
- `POST /mcp?session=<id>` - MCP JSON-RPC
- `GET /sse?session=<id>` - SSE transport

## Пов'язані документи

- [AccessZone Logic](./accessZone.md)
- [Auth Model](./auth.md)
- [Comet Deploy Guide](../../../agents/comet/deploy.md)
