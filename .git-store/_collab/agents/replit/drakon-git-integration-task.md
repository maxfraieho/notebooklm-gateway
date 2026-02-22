# 🎯 Завдання для Replit Agent: DRAKON Diagrams Git Integration

**Дата:** 2026-02-07
**Контекст:** Digital Garden (garden-bloom) потребує збереження DRAKON-діаграм через Git API

---

## TL;DR

Додати новий endpoint `/v1/drakon/commit` для збереження DRAKON-діаграм у GitHub репозиторій за аналогією з існуючим `/v1/notes/commit`.

---

## Контекст

Проєкт вже має працюючу Git-автоматизацію для markdown-нотаток:
- `POST /v1/git/commit` — комітить файл у GitHub
- `POST /v1/notes/commit` — wrapper для комітування нотаток
- `DELETE /v1/notes/:slug` — видалення нотаток

Тепер потрібно аналогічну підтримку для DRAKON-діаграм (JSON файли).

---

## Структура файлів діаграм

```
src/site/notes/
├── exodus.pp.ua/
│   ├── article-name.md
│   └── diagrams/
│       ├── process-flow.drakon.json
│       └── decision-tree.drakon.json
├── violin.pp.ua/
│   ├── ...
│   └── diagrams/
│       └── setup-guide.drakon.json
└── standalone-diagrams/           # діаграми без прив'язки до нотатки
    └── diagrams/
        └── architecture.drakon.json
```

**Формат файлу** (`*.drakon.json`):
```json
{
  "version": "1.0",
  "id": "process-flow",
  "name": "Process Flow Diagram",
  "createdAt": "2026-02-07T10:00:00Z",
  "updatedAt": "2026-02-07T10:30:00Z",
  "diagram": {
    "name": "Process Flow",
    "access": "read",
    "items": {
      "1": { "type": "end" },
      "2": { "type": "branch", "branchId": 0, "one": "3" },
      "3": { "type": "action", "content": "Початок", "one": "1" }
    }
  }
}
```

---

## Необхідні Endpoints

### 1. POST `/v1/drakon/commit`

**Request body:**
```typescript
interface DrakonCommitRequest {
  /** Папка нотатки або standalone шлях (e.g., 'exodus.pp.ua/article-name' або 'standalone-diagrams') */
  folderSlug?: string;
  /** ID діаграми (filename без розширення) */
  diagramId: string;
  /** Повний JSON об'єкт діаграми (StoredDrakonDiagram) */
  diagram: object;
  /** Людино-зрозуміла назва для commit message */
  name?: string;
  /** Чи це нова діаграма */
  isNew?: boolean;
}
```

**Response:**
```typescript
interface DrakonCommitResponse {
  success: boolean;
  sha?: string;      // commit SHA
  url?: string;      // GitHub file URL
  path?: string;     // шлях у репо
  error?: string;
}
```

**Логіка:**
1. Якщо `folderSlug` вказано:
   - Шлях: `src/site/notes/{folderSlug}/diagrams/{diagramId}.drakon.json`
2. Якщо `folderSlug` не вказано:
   - Шлях: `src/site/notes/diagrams/{diagramId}.drakon.json` (root diagrams)
3. Серіалізувати `diagram` як JSON з форматуванням (2 spaces indent)
4. Використати існуючий `POST /v1/git/commit` для збереження
5. Commit message: `chore(drakon): ${isNew ? 'create' : 'update'} ${name || diagramId}`

### 2. DELETE `/v1/drakon/:folderSlug/:diagramId`

**Логіка:**
1. Побудувати шлях до файлу
2. Використати існуючу логіку видалення файлів
3. Commit message: `chore(drakon): delete ${diagramId}`

**Response:**
```typescript
interface DrakonDeleteResponse {
  success: boolean;
  sha?: string;
  path?: string;
  error?: string;
}
```

---

## Приклад використання

### Створення нової діаграми
```bash
curl -X POST https://notebooklm-gateway-1.replit.app/v1/drakon/commit \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "folderSlug": "exodus.pp.ua/Опис UX",
    "diagramId": "user-flow",
    "diagram": {
      "version": "1.0",
      "id": "user-flow",
      "name": "User Flow",
      "createdAt": "2026-02-07T10:00:00Z",
      "updatedAt": "2026-02-07T10:00:00Z",
      "diagram": { "name": "User Flow", "access": "read", "items": {...} }
    },
    "name": "User Flow",
    "isNew": true
  }'
```

### Видалення діаграми
```bash
curl -X DELETE "https://notebooklm-gateway-1.replit.app/v1/drakon/exodus.pp.ua%2F%D0%9E%D0%BF%D0%B8%D1%81%20UX/user-flow" \
  -H "Authorization: Bearer $OWNER_TOKEN"
```

---

## Інтеграція з існуючим кодом

Судячи з `/v1/notes/commit`, потрібно:

1. **Новий route handler** у FastAPI/Express (залежно від стеку):
   ```python
   @app.post("/v1/drakon/commit")
   async def commit_drakon(request: DrakonCommitRequest, auth: OwnerAuth = Depends()):
       # 1. Validate diagramId (alphanumeric + dashes)
       # 2. Build file path
       # 3. Serialize diagram to JSON
       # 4. Call existing git commit logic
       # 5. Return response
   ```

2. **Reuse** існуючих утиліт:
   - Git commit функції
   - Auth middleware
   - Error handling

---

## Валідація

- `diagramId`: тільки `[a-zA-Z0-9_-]+`
- `folderSlug`: URL-encoded шлях (може містити кирилицю, слеші)
- `diagram`: має бути валідний JSON object

---

## Тестування

Після реалізації:
1. Створити тестову діаграму через API
2. Перевірити commit у GitHub
3. Перевірити що Lovable підтягує зміни

---

## Пов'язані файли

- **Frontend API client:** `src/lib/api/mcpGatewayClient.ts` (вже оновлено)
- **Frontend hook:** `src/hooks/useDrakonDiagram.ts` (вже створено)
- **Editor UI:** `src/components/garden/DrakonEditor.tsx` (вже створено)
- **Cloudflare Worker:** потрібно додати proxy route `/v1/drakon/*`

---

## Очікуваний результат

Після виконання:
1. ✅ Можливість зберігати нові DRAKON-діаграми через UI
2. ✅ Можливість редагувати існуючі діаграми
3. ✅ Діаграми комітяться у GitHub репозиторій
4. ✅ Структура файлів відповідає специфікації
