# Comet: Deployment Checklist

## Pre-Deploy

- [ ] Код worker оновлений в `infrastructure/cloudflare/worker/index.js`
- [ ] Немає syntax errors
- [ ] Немає hardcoded secrets

## Deploy

- [ ] Відкрито Cloudflare Dashboard
- [ ] Знайдено worker `garden-mcp-server`
- [ ] Відкрито Quick Edit
- [ ] Код вставлений
- [ ] Натиснуто "Save and Deploy"
- [ ] Deploy successful (зелена галочка)

## Environment Variables

- [ ] `JWT_SECRET` встановлено
- [ ] `MINIO_ENDPOINT` встановлено
- [ ] `MINIO_BUCKET` встановлено
- [ ] `MINIO_ACCESS_KEY` встановлено
- [ ] `MINIO_SECRET_KEY` встановлено

## KV Bindings

- [ ] Binding `KV` прив'язаний до `MCP_SESSIONS`

## Verification

### Health Check
```bash
curl https://garden-mcp.exodus.pp.ua/health
```
- [ ] Status 200
- [ ] `status: "ok"`
- [ ] `version: "3.0"`
- [ ] `features.zones: true`

### Auth Status
```bash
curl -X POST https://garden-mcp.exodus.pp.ua/auth/status
```
- [ ] Status 200
- [ ] `initialized: true`

### Zone Creation (Optional)
```bash
# Get token first
TOKEN=$(curl -s -X POST https://garden-mcp.exodus.pp.ua/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password":"YOUR_PASSWORD"}' | jq -r '.token')

# Create zone
curl -X POST https://garden-mcp.exodus.pp.ua/zones/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Test","noteIds":["test"],"expiresIn":3600000}'
```
- [ ] Zone created
- [ ] Zone appears in list
- [ ] Zone validates correctly

## Post-Deploy

- [ ] Результати записані в `cloud-cli/analysis-notes.md`
- [ ] Lovable повідомлено про результат
- [ ] Якщо помилки - створено issue

## Rollback (якщо потрібно)

1. Dashboard → Workers → garden-mcp-server
2. Deployments tab
3. Вибрати попередню версію
4. "Rollback to this deployment"

## Контакти

- Проблеми з Worker: див. `debug.md`
- Проблеми з UI: Lovable agent
- Архітектурні питання: ChatGPT agent
