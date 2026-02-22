# Завдання для Claude (Cloud CLI Agent)

> **Файл:** `agents/chatgpt/accesszone-diagnostic-task.md`
> **Версія:** 1.0
> **Дата:** 2025-01-15

---

## Роль

Ти — аналітичний AI-агент (Claude), що працює через Cloud CLI у локальній мережі з доступом до інтернету. Твоя задача — провести технічну діагностику системи доступу AccessZone у проєкті Digital Garden на базі Cloudflare Worker.

---

## Початкові умови

- Репозиторій містить актуальну структуру, згенеровану Lovable.dev
- Код Cloudflare Worker вже наявний у файлі: `infrastructure/cloudflare/worker/index.js`
- Деплой здійснюється вручну через Cloudflare Dashboard (не через Wrangler)
- Ти **НЕ** деплоїш код, **НЕ** змінюєш акаунт Cloudflare
- Ти працюєш локально з репозиторієм

---

## Крок 1. Отримання коду

Виконай:

```bash
# 1. Синхронізація репозиторію
git pull origin main

# 2. Перегляд коду Cloudflare Worker (ОСНОВНИЙ ФАЙЛ ДЛЯ АНАЛІЗУ)
cat infrastructure/cloudflare/worker/index.js

# 3. Перегляд документації AccessZone
cat infrastructure/cloudflare/worker/accessZone.md

# 4. Перегляд frontend hook (для порівняння API контракту)
cat src/hooks/useAccessZones.ts
```

Переконайся, що в репозиторії присутня така структура (мінімум):

```
infrastructure/cloudflare/worker/
├── index.js
├── accessZone.md
├── auth.md
├── README.md

agents/
├── lovable/
├── chatgpt/
├── comet/

cloud-cli/
├── README.md
├── analysis-notes.md

docs/
├── architecture.md
├── access-model.md
├── security.md
```

---

## Крок 2. Аналіз Cloudflare Worker

Уважно проаналізуй **тільки логіку, без виконання**:

### Файл: `infrastructure/cloudflare/worker/index.js`

Дослідити:

| Аспект | Що перевірити |
|--------|---------------|
| **Створення AccessZone** | Як викликається `handleZonesCreate()` |
| **Збереження** | KV key pattern: `zone:${zoneId}` |
| **Отримання списку** | Як працює `handleZonesList()` |
| **Валідація** | Як працює `handleZonesValidate()` |
| **TTL / expiration** | Чи правильно передається `expirationTtl` |
| **Key consistency** | Чи збігаються keys при `put` і `get` |

### Критичні точки для аналізу

```javascript
// Створення зони (handleZonesCreate)
await env.KV.put(
  `zone:${zoneId}`,
  JSON.stringify(zone),
  { expirationTtl: ttlMinutes * 60 }
);

// Валідація зони (handleZonesValidate)
const zoneData = await env.KV.get(`zone:${zoneId}`);

// Список зон (handleZonesList)
// Наразі: return jsonResponse({ success: true, message: 'Implement zone index for listing' });
```

---

## Крок 3. Фокус проблеми

### Вихідна проблема

> AccessZone створюється, але:
> - ❌ Не з'являється в списку
> - ❌ Не зберігається стабільно
> - ❌ Доступ по ній не працює

### Можливі причини (дослідити кожну)

| # | Гіпотеза | Як перевірити |
|---|----------|---------------|
| 1 | Помилка namespace/prefix у KV | Порівняти key при `put` vs `get` |
| 2 | Неправильне використання `expirationTtl` | Перевірити одиниці (секунди vs мілісекунди) |
| 3 | Створення зони без фактичного `await` | Шукати missing await |
| 4 | Різні формати `zoneId` / `accessCode` | Порівняти генерацію і використання |
| 5 | Логіка працює лише в пам'яті Worker | Перевірити чи є KV.put |
| 6 | Race condition | Перевірити async flow |
| 7 | Неузгодженість між endpoints | Frontend очікує X, backend повертає Y |
| 8 | Відсутній index для listing | `handleZonesList` — stub |

---

## Крок 4. Документація та висновки

Сформуй письмовий звіт з такими секціями:

### 4.1. Короткий діагноз

> У чому коренева причина проблеми AccessZone?

### 4.2. Технічний розбір

> Які саме місця в коді призводять до проблеми?
> Чому зона "зникає" або недоступна?

### 4.3. Рекомендації

> Мінімальні зміни для виправлення:
> - Що **змінити**
> - Що **додати**
> - Що **прибрати**
> 
> Без переписування архітектури!

### 4.4. Перевірочний чекліст

```bash
# 1. Створити зону
curl -X POST https://garden-mcp.exodus.pp.ua/zones/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"allowedPaths":["/test"],"ttlMinutes":60,"notes":[]}'

# 2. Перевірити список
curl https://garden-mcp.exodus.pp.ua/zones/list \
  -H "Authorization: Bearer $TOKEN"

# 3. Валідувати зону
curl https://garden-mcp.exodus.pp.ua/zones/validate/{zoneId}

# 4. Отримати нотатки зони
curl https://garden-mcp.exodus.pp.ua/zones/{zoneId}/notes
```

---

## Крок 5. Формат результату

Результат оформи як **Markdown**, який можна:

1. Вставити в `cloud-cli/analysis-notes.md`
2. Передати ChatGPT / Lovable для реалізації фіксу

### Шаблон звіту

```markdown
# AccessZone Diagnostic Report

**Date:** YYYY-MM-DD
**Analyst:** Claude (Cloud CLI Agent)
**Status:** [DIAGNOSIS COMPLETE]

## Executive Summary
[1-2 речення про root cause]

## Findings

### Finding 1: [Назва]
- **Severity:** High/Medium/Low
- **Location:** `file:line`
- **Description:** ...
- **Evidence:** ...

### Finding 2: ...

## Root Cause Analysis
[Детальний опис чому AccessZone не працює]

## Recommendations

### Must Fix (Critical)
1. ...

### Should Fix (Important)
1. ...

### Nice to Have
1. ...

## Verification Steps
1. ...
2. ...

## Files Analyzed
- infrastructure/cloudflare/worker/index.js
- src/hooks/useAccessZones.ts
- ...
```

---

## Обмеження

| ❌ Заборонено | ✅ Дозволено |
|---------------|--------------|
| Змінювати код | Читати і аналізувати код |
| Генерувати нові файли | Писати звіт у Markdown |
| Виконувати HTTP-запити | Аналізувати endpoint логіку |
| "Фантазувати" поведінку | Робити висновки з коду |
| Деплоїти | Документувати знахідки |

**Працюй як:** Code Auditor / Systems Diagnostician

---

## Очікуваний результат

Після твоєї роботи має бути **однозначно зрозуміло**:

1. ✅ Чому AccessZone не працює зараз
2. ✅ Що саме потрібно змінити, щоб вона працювала стабільно
3. ✅ Які частини системи НЕ є причиною проблеми

---

## Наступні кроки після діагностики

| Агент | Дія |
|-------|-----|
| **Lovable** | Отримує звіт → імплементує фікс у Worker коді |
| **Comet** | Деплоїть оновлений Worker через Cloudflare Dashboard |
| **Cloud CLI** | Верифікує фікс через curl команди |

---

## Посилання

- Worker код: `infrastructure/cloudflare/worker/index.js`
- AccessZone опис: `infrastructure/cloudflare/worker/accessZone.md`
- Frontend hook: `src/hooks/useAccessZones.ts`
- Comet deploy guide: `agents/comet/deploy.md`
- Comet debug guide: `agents/comet/debug.md`
