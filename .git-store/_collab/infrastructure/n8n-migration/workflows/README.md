# n8n Workflows

Цей каталог містить n8n workflows для бізнес-логіки Garden API.

---

## Deployment Status (2026-02-02)

### Phase 2: Zones Management

| Workflow | n8n ID | Status | Webhook URL |
|----------|--------|--------|-------------|
| Garden - Zones Create | `HgdX7OIRzOHPz473` | ⏸️ Inactive | `POST /webhook/zones-create` |
| Garden - Zones Delete | `xDXU1njw8g9b6ba0` | ⏸️ Inactive | `POST /webhook/zones-delete` |

**Production URLs (after activation):**
```
POST https://n8n.exodus.pp.ua/webhook/zones-create
POST https://n8n.exodus.pp.ua/webhook/zones-delete
```

### Pending Phases

- [ ] Phase 3: Storage (MinIO upload/delete)
- [ ] Phase 4: NotebookLM (create/import/retry)
- [ ] Phase 5: Verification (API_MAP.md cross-reference)

---

## Redis Setup (Docker - Same Host as n8n)

### Option A: Redis in Same Docker Network

Якщо n8n працює в Docker, Redis має бути в тій же мережі.

**1. Перевірити мережу n8n:**
```bash
docker inspect garden-n8n | jq '.[0].NetworkSettings.Networks'
# Або
docker network ls
```

**2. Запустити Redis в тій же мережі:**
```bash
# Якщо мережа називається n8n-migration_garden-network:
docker run -d \
  --name garden-redis \
  --network n8n-migration_garden-network \
  --restart unless-stopped \
  -v redis-data:/data \
  redis:7-alpine \
  redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru

# Перевірити
docker exec garden-redis redis-cli ping
# Має відповісти: PONG
```

**3. Налаштувати credentials в n8n:**
- n8n UI → Settings → Credentials → Add Credential
- Type: **Redis**
- Host: `garden-redis` (ім'я контейнера, НЕ localhost)
- Port: `6379`
- Password: (залишити порожнім якщо без пароля)

### Option B: Redis вже запущений через docker-compose

Якщо використовуєте `docker-compose.yml` з цього репозиторію:

```bash
cd infrastructure/n8n-migration
docker-compose up -d redis
```

**Credentials в n8n:**
- Host: `redis` (service name з docker-compose)
- Port: `6379`

### Option C: Зовнішній Redis (VPS/Cloud)

```bash
# Host: IP або домен Redis сервера
# Port: 6379
# Password: ваш пароль
# TLS: увімкнути якщо потрібно
```

---

## Assign Credentials to Workflows

Після створення Redis credential:

1. Відкрити workflow в n8n UI
2. Клікнути на кожен **Redis node**
3. В полі "Credential to connect with" вибрати створений credential
4. Save workflow
5. Activate workflow (toggle вверху)

### Workflows що потребують Redis:

**Garden - Zones Create** (ID: HgdX7OIRzOHPz473):
- "Save Zone to Redis" node
- "Get Zones Index" node
- "Save Index" node

**Garden - Zones Delete** (ID: xDXU1njw8g9b6ba0):
- "Delete" node

---

## Імпорт workflows (альтернативний метод)

Якщо workflows ще не створені через API:

1. Відкрийте n8n UI: https://n8n.exodus.pp.ua
2. Перейдіть до Settings → Import
3. Виберіть JSON файл workflow
4. Активуйте workflow

## Список workflows

| Файл | Webhook URL | Опис |
|------|-------------|------|
| `zones-create.json` | `/webhook/zones-create` | Створення access zone з MinIO upload |
| `zones-delete.json` | `/webhook/zones-delete` | Видалення zone з MinIO cleanup |
| `minio-upload.json` | `/webhook/minio-upload` | Upload файлів до MinIO |
| `notebooklm-create.json` | `/webhook/notebooklm-create` | Створення NotebookLM notebook |

---

## Credentials Summary

Потрібно налаштувати в n8n:

### Redis (REQUIRED for Phase 2)
- Type: Redis
- Host: `garden-redis` або `redis` (container name)
- Port: 6379
- Password: (якщо встановлений)

### HTTP Request (MinIO) - Phase 3
- Credentials не потрібні - використовується AWS Signature V4 в Code node

### HTTP Request (NotebookLM) - Phase 4
- Type: Header Auth
- Name: Authorization
- Value: Bearer {NOTEBOOKLM_SERVICE_TOKEN}

---

## Структура workflow

```
Webhook Trigger
    ↓
Code Node (Prepare data)
    ↓
Redis Node (Read/Write)
    ↓
HTTP Request (MinIO/NotebookLM)
    ↓
Code Node (Format response)
    ↓
Respond to Webhook
```

## Debugging

1. Увімкніть "Save Execution Progress" у Settings
2. Перегляньте Executions для помилок
3. Використовуйте Console.log в Code nodes

## Environment Variables

В n8n Settings → Variables:

```
MINIO_ENDPOINT=https://apiminio.exodus.pp.ua
MINIO_BUCKET=garden-notes
MINIO_ACCESS_KEY=...
MINIO_SECRET_KEY=...
NOTEBOOKLM_BASE_URL=https://notebooklm-gateway.replit.app
```

---

## Verification Commands

```bash
# Check workflow exists via API
curl -s "https://n8n.exodus.pp.ua/api/v1/workflows/HgdX7OIRzOHPz473" \
  -H "X-N8N-API-KEY: <your-api-key>" | jq '{name, active}'

# Test webhook (after activation)
curl -X POST "https://n8n.exodus.pp.ua/webhook/zones-create" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Zone","folders":["test"]}'
```
