# Authentication & Access Model

## Модель доступу

### Рівні доступу

```
┌─────────────────────────────────────────────────┐
│                   PUBLIC                        │
│  /health, /auth/status, /auth/login             │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│              ACCESS GATE                        │
│  Сайт закритий без:                            │
│  - Master Code (адміністратор)                 │
│  - Zone Access Code (гість)                    │
└─────────────────────────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│   OWNER MODE    │     │   ZONE ACCESS   │
│   (Master Code) │     │   (Guest Code)  │
│                 │     │                 │
│ - Full access   │     │ - Limited notes │
│ - Create zones  │     │ - Read only     │
│ - Manage MCP    │     │ - Time limited  │
└─────────────────┘     └─────────────────┘
```

## Master Code (Owner)

### Первинне налаштування

```javascript
POST /auth/setup
Body: { "password": "your-secure-password" }

// Зберігається як hash в KV
// Одноразова операція
```

### Логін

```javascript
POST /auth/login
Body: { "password": "your-secure-password" }

Response: {
  "token": "eyJ...",
  "expiresAt": "2024-01-15T12:00:00Z"
}
```

### JWT структура

```javascript
{
  "sub": "owner",
  "iat": 1705312800,
  "exp": 1705399200  // 24 години
}
```

## Zone Access Code

### Формат коду

```
ZONE-XXXX-YYYY
│    │    │
│    │    └── Random suffix
│    └─────── Zone identifier
└──────────── Prefix
```

### Валідація

```javascript
GET /zones/validate/:zoneId?code=ZONE-XXXX-YYYY

Response: {
  "valid": true,
  "zone": {
    "id": "zone_abc",
    "name": "Guest Access",
    "noteIds": [...],
    "expiresAt": "..."
  }
}
```

## Global Access Gate (TODO)

### Архітектура

```
User Request
     │
     ▼
┌─────────────┐
│  Cloudflare │
│   Worker    │
└─────────────┘
     │
     ├── Has valid session cookie? ──► Allow
     │
     ├── Has master code? ──► Create session ──► Allow
     │
     ├── Has zone code? ──► Create limited session ──► Allow
     │
     └── No code ──► Show "Access Required" page
```

### Frontend компонент (TODO)

```tsx
// src/components/garden/AccessGate.tsx
const AccessGate = ({ children }) => {
  const { hasAccess, isLoading } = useAccessValidation();
  
  if (isLoading) return <LoadingSpinner />;
  if (!hasAccess) return <AccessRequiredPage />;
  
  return children;
};
```

### Cookies/Storage

```javascript
// Session cookie (httpOnly, secure)
garden_session: "encrypted_session_id"

// LocalStorage fallback
garden_access_token: "zone_abc:ZONE-XXXX-YYYY"
```

## Безпека

### Правила

1. ❌ НІКОЛИ не хардкодити master password
2. ❌ НІКОЛИ не логувати токени
3. ✅ Завжди хешувати паролі (SHA-256)
4. ✅ Завжди валідувати JWT signature
5. ✅ Завжди перевіряти expiration
6. ✅ Використовувати httpOnly cookies

### Environment Variables

```
JWT_SECRET=<random-256-bit-string>
```

**Генерація:**
```bash
openssl rand -hex 32
```
