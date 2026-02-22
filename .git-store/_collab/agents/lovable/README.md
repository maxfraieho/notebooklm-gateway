# Lovable Agent

## Роль

Lovable.dev AI agent для:
- Розробки React/TypeScript frontend
- UI/UX компонентів
- Інтеграції з Cloudflare Worker API

## Обмеження

- ❌ НЕ генерує Cloudflare Worker код
- ❌ НЕ деплоїть нічого автоматично
- ❌ НЕ хардкодить секрети
- ✅ Створює лише frontend код
- ✅ Документує архітектуру
- ✅ Координує з іншими агентами

## Контракти

### API Endpoints (очікувані від Worker)

```typescript
// Health check
GET /health → { status: 'ok', version: string }

// Auth
POST /auth/login → { token: string, expiresAt: string }
POST /auth/validate → { valid: boolean }

// Zones
POST /zones/create → { zoneId: string, accessCode: string }
GET /zones/list → Zone[]
GET /zones/validate/:id → { valid: boolean, zone: Zone }

// Sessions
POST /sessions/create → { sessionId: string }
GET /sessions/list → Session[]
```

### Types

```typescript
interface Zone {
  id: string;
  name: string;
  noteIds: string[];
  accessCode: string;
  expiresAt: string;
}

interface Session {
  id: string;
  createdAt: string;
  expiresAt: string;
}
```

## Файли відповідальності

```
src/
├── components/garden/
│   ├── AccessZonesManager.tsx
│   ├── MCPAccessPanel.tsx
│   ├── OwnerLoginDialog.tsx
│   └── ...
├── hooks/
│   ├── useAccessZones.ts
│   ├── useMCPSessions.ts
│   └── useOwnerAuth.tsx
└── pages/
    └── ZoneViewPage.tsx
```

## Поточні завдання

1. [ ] Виправити AccessZone збереження (координація з Worker)
2. [ ] Реалізувати AccessGate компонент
3. [ ] Інтегрувати master-code логін
