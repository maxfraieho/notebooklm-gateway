# 🌱 Digital Garden (Sweet Brain Share Hub) — AGENT HANDOFF

> Цей документ — «передача зміни» для наступного Lovable агента/акаунта.
> Мета: швидко відновити контекст, зрозуміти актуальний стан, не зламати інтеграції, та продовжити розробку.

**Останнє оновлення:** 2026-02-07

---

## 0) TL;DR (що це за проєкт)

Це **Digital Garden** (веб-застосунок на Lovable/React) для перегляду та навігації по markdown-нотатках з:

- wiki-посиланнями (`[[...]]`), тегами, пошуком, графами звʼязків;
- **Owner Mode** (власник/адмін): логін, налаштування, керування зонами доступу;
- **Access Zones**: гостьовий/делегований доступ до підмножини нотаток по коду + строк дії;
- інтеграціями через **Cloudflare Worker gateway** (зовнішній бекенд): auth/zones/sessions/MCP;
- окремою фічею **NotebookLM Chat** (через worker → Replit backend);
- **DRAKON Editor**: візуальний редактор алгоритмічних схем з Git-автоматизацією.

Проєкт дотримується підходу **Agentic Triad Pipeline**:
- *Lovable* — фронтенд/UI інтеграція
- *Comet* — інфра/деплой (Cloudflare Worker, n8n і т.д.)
- *Claude/Replit* — бекенд/автоматизація/безпека (у межах того, що живе поза Lovable)

---

## 1) Архітектура (актуальна)

### Frontend (цей репозиторій, Lovable)
- **React 18 + Vite + TypeScript + Tailwind + shadcn/ui**
- **React Router**: `src/App.tsx`
- **React Query** для серверного стану
- Контент — markdown файли під `src/site/notes/**`
- **DRAKON діаграми** — JSON файли під `src/site/notes/**/diagrams/*.drakon.json`

### Backend gateway (поза Lovable)
**Cloudflare Worker** — єдиний «вхід» для фронтенда:
- Owner Auth (setup/login/validate/refresh)
- Access Zones (create/list/validate/notes)
- MCP sessions (create/list/revoke) + JSON-RPC + SSE
- NotebookLM proxy (`/notebooklm/*`) до Replit backend
- **DRAKON Git automation** (`/v1/drakon/commit`, `/v1/drakon/:folderSlug/:diagramId`)

### Replit Backend
FastAPI сервіс для:
- NotebookLM gateway: `https://notebooklm-gateway-1.replit.app`
- Git automation (GitHub commits): `/v1/git/commit`, `/v1/git/delete`, `/v1/git/status`
- DRAKON endpoints: `/v1/drakon/commit`, `/v1/drakon/{folderSlug}/{diagramId}`

---

## 2) Важливі URL та маршрути

### Gateway URLs (Cloudflare Worker)
**Основний (CNAME):** `https://garden-mcp.exodus.pp.ua`
**Fallback (workers.dev):** `https://garden-mcp-server.maxfraieho.workers.dev`

### Ключові сторінки фронтенду
| Route | Опис |
|-------|------|
| `/` | Головна сторінка garden |
| `/notes/:slug` | Перегляд нотатки |
| `/editor` | Редактор нотаток (Owner only) |
| `/drakon` | **DRAKON Editor** (Owner only) |
| `/tags`, `/tags/:tag` | Теги |
| `/graph` | Граф звʼязків |
| `/files` | Файловий браузер |
| `/zone/:zoneId` | Гостьовий перегляд зони |
| `/chat` | Chat UI (NotebookLM) |
| `/admin/diagnostics` | Адмін-діагностика |

### Циклічна навігація в хедері
`Home` → `Files` → `Chat` → `Graph` → `New Note` → `DRAKON Editor` → `Home`

---

## 3) ENV/Secrets

### Frontend (.env у Lovable settings)
```env
VITE_MCP_GATEWAY_URL=https://garden-mcp.exodus.pp.ua
```

### Cloudflare Worker (Variables/Secrets)
| Key | Опис |
|-----|------|
| `JWT_SECRET` | Для Owner Auth |
| `MINIO_ENDPOINT`, `MINIO_BUCKET`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` | Storage |
| `NOTEBOOKLM_BASE_URL` | `https://notebooklm-gateway-1.replit.app` |
| `NOTEBOOKLM_SERVICE_TOKEN` | Bearer token для Replit |
| `REPLIT_BACKEND_URL` | URL Replit backend для Git operations |
| `REPLIT_SERVICE_TOKEN` | Token: `garden-nlm-service-2026-a7f3b9c1e5d2` |

---

## 4) Ключові модулі/файли

### Роутинг/Providers
- `src/App.tsx` — всі роути

### Owner Auth
- `src/hooks/useOwnerAuth.tsx`
- UI: `OwnerSetupWizard`, `OwnerLoginDialog`, `OwnerModeIndicator`, `OwnerSettingsDialog`

### Access Zones
- `src/hooks/useAccessZones.ts`
- UI: `AccessZonesManager`, `ZoneCreationDialog`, `ZoneQRDialog`, `AccessZonesWall`

### DRAKON Editor
- `src/pages/DrakonPage.tsx` — головна сторінка редактора
- `src/components/garden/DrakonEditor.tsx` — wrapper для drakonwidget
- `src/components/garden/DrakonViewer.tsx` — readonly viewer
- `src/components/garden/DrakonDiagramBlock.tsx` — блок в нотатках
- `src/hooks/useDrakonDiagram.ts` — завантаження/збереження
- `src/lib/drakon/*` — adapter, types, theme
- `vendor/drakonwidget/` — бібліотека drakonwidget
- `public/libs/drakonwidget.js` — UMD bundle

### API Client
- `src/lib/api/mcpGatewayClient.ts` — всі API calls до gateway
  - `commitDrakonDiagram()` — збереження діаграми
  - `deleteDrakonDiagram()` — видалення діаграми

### Нотатки/рендеринг
- `src/lib/notes/noteLoader.ts` — завантаження markdown
- `src/lib/notes/wikilinkParser.ts` — парсинг `[[wikilinks]]`
- `src/components/garden/NoteRenderer.tsx` — рендеринг контенту

### Локалізація
- `src/lib/i18n/*` — uk/en/fr/de/it
- `src/hooks/useLocale.tsx`

---

## 5) DRAKON Integration Details

### Формат файлів
```
src/site/notes/{folderSlug}/diagrams/{diagramId}.drakon.json
```
Приклад: `src/site/notes/test-drakon/diagrams/demo.drakon.json`

### API Endpoints (через Gateway → Replit)
```
POST /v1/drakon/commit
Body: { folderSlug, diagramId, diagram, name, isNew }
Response: { success, sha, url, path }

DELETE /v1/drakon/{folderSlug}/{diagramId}
Response: { success, sha, path }
```

### Авторизація
- Bearer token: `garden-nlm-service-2026-a7f3b9c1e5d2`
- Owner auth перевіряється на рівні Worker

---

## 6) Поточний стан (що працює)

### ✅ Працює
- Перегляд нотаток, теги, графи, пошук
- Owner initialization/login flow
- CRUD для Access Zones
- MCP sessions інтеграція
- NotebookLM Chat через gateway
- **DRAKON Editor** — створення, редагування, збереження діаграм
- Git automation для нотаток та діаграм
- Циклічна навігація в хедері

### 🔍 Перевірити після переносу
1. ENV `VITE_MCP_GATEWAY_URL` в новому Lovable проєкті
2. CORS/origin allowlist у worker — додати нові домени
3. Owner auth status: `/admin/diagnostics`
4. DRAKON Editor: `/drakon?id=test&new=true`

---

## 7) Відомі особливості

### DRAKON Widget
- Використовує глобальний `window.DrakonWidget`
- Завантажується через `<script>` з `/libs/drakonwidget.js`
- Theme adapter: `src/lib/drakon/themeAdapter.ts`

### Git Automation Flow
```
Frontend → Cloudflare Worker → Replit Backend → GitHub API
                                      ↓
                              PostgreSQL (config)
```

---

## 8) Мінімальний чеклист для нового агента

1. ✅ Перевірити що app відкривається без runtime errors
2. ✅ Відкрити `/admin/diagnostics` → пройтись по checks
3. ✅ Перевірити циклічну навігацію в хедері
4. ✅ Відкрити `/drakon` — має показати форму створення діаграми
5. ✅ Перевірити що зміна UI не ламає access model
6. ✅ Якщо торкаємось текстів — оновити всі локалі

---

## 9) Перспективні напрями

### Найближчі
1. Інтеграція DRAKON в редактор нотаток (кнопка вставки)
2. Список існуючих діаграм на `/drakon`
3. Preview діаграм в нотатках

### Стратегічні
1. Task Queue API через Worker
2. Agent roles (Archivist/Tech Writer/Architect)
3. Збереження результатів агентів як draft-notes
