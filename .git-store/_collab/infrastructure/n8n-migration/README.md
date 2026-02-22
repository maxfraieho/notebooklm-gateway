# Garden API Migration: Cloudflare Workers → n8n

## Огляд

Цей пакет містить повну міграцію API-шару з Cloudflare Workers на n8n + Node.js Adapter.

**Ціль:** Замінити Cloudflare Workers на n8n без поломки фронтенду.

**Результат:** API-контракт повністю збережений - фронтенд змінює лише base URL.

---

## Архітектура

```
┌─────────────────┐     ┌────────────────────┐     ┌─────────────────┐
│    Frontend     │────▶│  Node.js Adapter   │────▶│      n8n        │
│  (unchanged)    │     │  (Express)         │     │   Workflows     │
└─────────────────┘     └────────────────────┘     └─────────────────┘
        │                       │                         │
        │                       │ JWT, CORS, SSE          │ Business logic
        │                       ▼                         ▼
        │               ┌─────────────────┐     ┌─────────────────┐
        │               │     Redis       │     │  NotebookLM     │
        │               │  (KV storage)   │     │   Backend       │
        │               └─────────────────┘     └─────────────────┘
        │                                               │
        │                                               ▼
        │                                       ┌─────────────────┐
        └──────────────────────────────────────▶│     MinIO       │
                                                │  (S3 storage)   │
                                                └─────────────────┘
```

### Чому Node.js Adapter?

n8n не підтримує:
- **SSE streaming** (`/sse` endpoint)
- **Stateful MCP** (`/mcp` JSON-RPC)
- **JWT криптографію** (HMAC-SHA256)
- **CORS preflight** (OPTIONS requests)

Node.js Adapter вирішує ці проблеми та проксює бізнес-логіку до n8n.

### Чому Redis замість Cloudflare KV?

- Cloudflare KV - пропрієтарний, прив'язаний до Workers
- Redis - універсальний, швидкий, підтримує TTL
- Легко мігрувати дані через JSON export/import

---

## Структура файлів

```
n8n-migration/
├── README.md                    # Цей файл
├── API_MAP.md                   # Повна карта всіх endpoints
├── adapter/
│   ├── server.js                # Node.js Express adapter
│   ├── package.json             # Dependencies
│   ├── .env.example             # Environment template
│   └── Dockerfile               # Container build
├── workflows/
│   ├── zones-create.json        # n8n workflow: create zone
│   ├── zones-delete.json        # n8n workflow: delete zone
│   ├── minio-upload.json        # n8n workflow: upload to MinIO
│   └── README.md                # Workflow import instructions
├── redis/
│   ├── docker-compose.yml       # Redis container
│   └── migrate-kv.js            # Script to migrate from CF KV
├── frontend/
│   └── config-changes.md        # Frontend changes needed
└── testing/
    ├── test-endpoints.sh        # curl test script
    └── expected-responses.json  # Expected API responses
```

---

## Швидкий старт

### 1. Запустити Redis

```bash
cd redis/
docker-compose up -d
```

### 2. Встановити залежності адаптера

```bash
cd adapter/
npm install
cp .env.example .env
# Заповнити .env своїми значеннями
```

### 3. Імпортувати n8n workflows

```bash
# В n8n UI: Settings → Import → вибрати JSON з workflows/
```

### 4. Запустити адаптер

```bash
cd adapter/
npm start
# Сервер на http://localhost:3001
```

### 5. Оновити фронтенд

```bash
# В .env.local фронтенду:
VITE_API_URL=http://localhost:3001
```

### 6. Тестування

```bash
cd testing/
chmod +x test-endpoints.sh
./test-endpoints.sh
```

---

## Міграція даних з Cloudflare KV

### Експорт з Cloudflare

```bash
# Встановити wrangler CLI
npm install -g wrangler
wrangler login

# Експорт всіх ключів
wrangler kv:key list --namespace-id=YOUR_NAMESPACE_ID > kv-keys.json

# Для кожного ключа отримати значення
# (скрипт redis/migrate-kv.js автоматизує це)
```

### Імпорт в Redis

```bash
cd redis/
node migrate-kv.js
```

---

## Production Deployment

### Option A: Docker Compose (рекомендовано)

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Option B: Kubernetes

```bash
kubectl apply -f k8s/
```

### Option C: PM2 (VPS)

```bash
pm2 start adapter/server.js --name garden-api
pm2 save
```

---

## Порівняння: До і Після

| Аспект | Cloudflare Workers | n8n + Adapter |
|--------|-------------------|---------------|
| Runtime | Edge (CF) | Node.js + n8n |
| KV Storage | Cloudflare KV | Redis |
| Latency | ~10-50ms | ~20-100ms |
| Cost | $5/month (paid) | Self-hosted |
| Flexibility | Limited | High |
| Debugging | Difficult | Easy |
| Vendor Lock | Yes | No |

---

## Troubleshooting

### Redis connection refused

```bash
# Перевірити чи Redis запущений
docker ps | grep redis
redis-cli ping
```

### n8n workflow not triggered

```bash
# Перевірити URL webhook в n8n
# Має бути: http://localhost:5678/webhook/zones-create
```

### JWT validation fails

```bash
# Перевірити JWT_SECRET в .env
# Має бути однаковий для adapter і при генерації токенів
```

### CORS errors in browser

```bash
# Adapter вже налаштований на Access-Control-Allow-Origin: *
# Якщо проблема - перевірити чи немає proxy перед adapter
```

---

## API Compatibility

Всі 28 endpoints зберігають повну сумісність:

- ✅ Однакові URL paths
- ✅ Однакові HTTP methods
- ✅ Однакові request/response JSON shapes
- ✅ Однакові status codes
- ✅ Однакові CORS headers
- ✅ Однакові error formats

Фронтенд потребує лише зміни `API_BASE_URL`.

---

## Автор

Міграція виконана Claude Code для проекту Garden Bloom.

Дата: 2026-02-02
