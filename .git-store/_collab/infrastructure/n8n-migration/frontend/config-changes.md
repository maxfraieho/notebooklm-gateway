# Frontend Configuration Changes

## Мінімальні зміни

Фронтенд потребує лише зміни **base URL** для API.

---

## Крок 1: Знайти поточну конфігурацію

```bash
# Пошук API URL в коді
grep -r "garden-mcp-server" src/
grep -r "VITE_API" src/
grep -r "API_URL" src/
grep -r "apiUrl" src/
grep -r "baseUrl" src/
```

Можливі місця:
- `src/lib/config.ts`
- `src/lib/api.ts`
- `src/services/api.ts`
- `.env`
- `.env.local`
- `.env.production`

---

## Крок 2: Оновити .env файли

### .env.local (development)
```bash
# ДО:
VITE_API_URL=https://garden-mcp-server.YOUR-ACCOUNT.workers.dev

# ПІСЛЯ:
VITE_API_URL=http://localhost:3001
```

### .env.production
```bash
# ДО:
VITE_API_URL=https://garden-mcp-server.YOUR-ACCOUNT.workers.dev

# ПІСЛЯ:
VITE_API_URL=https://api.exodus.pp.ua
```

---

## Крок 3: Оновити config.ts (якщо hardcoded)

### src/lib/config.ts

```typescript
// ДО:
export const API_BASE_URL = 'https://garden-mcp-server.YOUR-ACCOUNT.workers.dev';

// ПІСЛЯ:
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://api.exodus.pp.ua';
```

---

## Крок 4: Перевірити API клієнт

### src/lib/api.ts або src/services/api.ts

```typescript
// Перевірте що використовується правильна змінна
import { API_BASE_URL } from './config';

// АБО напряму:
const API_BASE_URL = import.meta.env.VITE_API_URL;

// Функція fetch повинна використовувати цю змінну:
export async function apiRequest(path: string, options?: RequestInit) {
  const url = `${API_BASE_URL}${path}`;
  // ...
}
```

---

## Що НЕ потрібно змінювати

- ✅ Формат request/response - **однаковий**
- ✅ HTTP методи - **однакові**
- ✅ URL paths - **однакові**
- ✅ Headers - **однакові**
- ✅ Error handling - **однаковий**
- ✅ CORS - **налаштований в adapter**

---

## Перевірка

### 1. Build

```bash
npm run build
# Має пройти без помилок
```

### 2. Dev server

```bash
npm run dev
# Відкрити в браузері
```

### 3. Network tab

- Відкрити DevTools → Network
- Перевірити що API calls йдуть на новий URL
- Перевірити що responses правильні

### 4. Console

- Не має бути CORS помилок
- Не має бути 404/500 помилок

---

## Rollback

Якщо щось не працює:

```bash
# Повернути старий URL
VITE_API_URL=https://garden-mcp-server.YOUR-ACCOUNT.workers.dev npm run dev
```

---

## Production Deployment

### Option A: Environment Variables

```bash
# Vercel
vercel env add VITE_API_URL production
# Enter: https://api.exodus.pp.ua

# Netlify
netlify env:set VITE_API_URL https://api.exodus.pp.ua
```

### Option B: Build-time

```bash
VITE_API_URL=https://api.exodus.pp.ua npm run build
```

---

## Troubleshooting

### CORS errors

```
Access to fetch at 'https://api.exodus.pp.ua/...' from origin 'https://exodus.pp.ua'
has been blocked by CORS policy
```

**Рішення:** Перевірте що adapter запущений і CORS middleware працює.

### 401 Unauthorized

**Рішення:** Токен міг expired. Виконайте re-login.

### 502 Bad Gateway

**Рішення:** Adapter не може з'єднатися з Redis або NotebookLM backend.

### Network Error

**Рішення:** Adapter не запущений або неправильний URL.
