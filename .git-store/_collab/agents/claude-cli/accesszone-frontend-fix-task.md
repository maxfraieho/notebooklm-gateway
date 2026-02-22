# AccessZone Frontend & Integration Fix Task

**Шлях до файлу:** `agents/claude-cli/accesszone-frontend-fix-task.md`

---

## Мета

Провести аналіз та імплементацію виправлень у frontend та інтеграційному шарі системи доступу, щоб:

1. Дані AccessZone (Web URL, MCP URL, accessCode, QR) були **постійно доступні власнику** після створення зони.

2. Головний сайт був **повністю закритий за замовчуванням** і доступний **тільки**:
   * за master-кодом адміністратора, або
   * за валідним AccessZone URL / QR.

3. Сторінки зон **реально відкривались і відображали контент**, а не зависали на loading state.

---

## Context

* AccessZone backend **виправлений** (Cloudflare Worker):
  * зони зберігаються,
  * з'являються у списку,
  * мають `accessCode`,
  * коректно видаляються.

* UI вже показує:
  * список зон,
  * TTL,
  * кількість папок/нотаток.

* **Нові проблеми (після фіксів)**:
  1. ❌ Дані доступу (Web URL, MCP URL, QR, accessCode) доступні **лише в момент створення**, після закриття модалки — **втрачаються**.
  2. ❌ Будь-хто може зайти на головну сторінку сайту без коду.
  3. ❌ Перехід за AccessZone URL або QR:
     * показує loading ~1 секунду,
     * потім рендериться **порожня сторінка** (white screen).

---

## Крок 0. Отримання коду для аналізу

Виконай наступні команди для отримання контексту:

```bash
# Frontend routing та layout
cat src/App.tsx
cat src/pages/Index.tsx
cat src/pages/ZoneViewPage.tsx

# AccessZone компоненти
cat src/components/garden/AccessZonesManager.tsx
cat src/components/garden/ZoneQRDialog.tsx
cat src/components/garden/ZoneNoteRenderer.tsx

# Hooks для доступу
cat src/hooks/useAccessZones.ts
cat src/hooks/useZoneValidation.ts
cat src/hooks/useOwnerAuth.tsx

# Cloudflare Worker (для референсу API)
cat infrastructure/cloudflare/worker/index.js
```

---

## Observed Problems (to diagnose)

### Problem A — Access Data Loss (Owner UX)

* AccessZoneCard показує:
  * назву,
  * TTL,
  * папки,
* але **НЕ надає повторний доступ до**:
  * Web URL,
  * MCP URL,
  * QR,
  * accessCode.

* Це **критично для власника** (неможливо повторно поділитись доступом).

### Problem B — Missing Global Access Gate

* Головна сторінка сайту доступна без перевірки.
* Вимога: **NO ACCESS → NO CONTENT**
* Має існувати єдиний Access Gate:
  * поле введення коду (admin / zone),
  * або автоматичний доступ через валідний zone URL.

### Problem C — Zone Page Blank Screen

* URL типу:
  ```
  https://exodus.pp.ua/zone/:zoneId?code=ACCESS-XXXX
  ```
* Симптом:
  * короткий loading,
  * далі порожній екран.
* Ймовірні причини:
  * access validation hook не переходить у `hasAccess=true`,
  * router не рендерить children,
  * відсутній fallback UI при denied/expired,
  * mismatch між API response та frontend expectations.

---

## Constraints

* ❌ Не змінювати backend API (Worker) без крайньої необхідності
* ❌ Не ламати існуючий UI
* ❌ Не хардкодити секрети
* ❌ Не робити публічний доступ
* ✅ Всі виправлення — у frontend та access-flow
* ✅ AccessZone URL + QR мають працювати без додаткових дій користувача

---

## Required Tasks

### Task 1 — Persistent AccessZone Owner Controls

#### Аналіз
* Перевірити `AccessZonesManager.tsx`, `ZoneQRDialog.tsx`, `useAccessZones.ts`
* Визначити, де втрачається `accessCode` та URLs

#### Імплементація
* Для **кожної зони** у списку:
  * додати кнопки:
    * **Web URL** (copy)
    * **MCP URL** (copy)
    * **QR** (show dialog)
    * **Copy Access Code**
* Дані беруться **з API `/zones/list`**, не з локального state creation.
* QR-код має **генеруватись повторно**, не тільки при create.

---

### Task 2 — Global Access Gate (Critical Security Fix)

#### Аналіз
* Перевірити `App.tsx` routing та root layout
* Виявити, де зараз дозволяється доступ без перевірки

#### Імплементація
* Додати **Global Access Guard**:
  * якщо **немає валідної сесії / зони**:
    * показувати лише сторінку:
      * опис сервісу
      * поле введення коду
* Дозволені сценарії:
  1. Admin вводить master-код → повний доступ
  2. Користувач заходить за `/zone/:id?code=...` → доступ до зони
* Усі інші маршрути — заблоковані

---

### Task 3 — Fix Zone Page Rendering (Blank Screen Bug)

#### Аналіз
* Пройти шлях:
  ```
  /zone/:zoneId → useZoneValidation → router → content
  ```
* Знайти, де зникає рендер

#### Імплементація
* Гарантувати 3 стани:
  1. `isLoading === true` → spinner + message
  2. `hasAccess === false` → Access Denied UI
  3. `hasAccess === true` → **реальний контент**
* Заборонено залишати порожній екран.

---

## Expected Output

Після аналізу створити звіт:

1. **Діагностика A / B / C** — що саме викликає проблему
2. **Запропоновані рішення** — конкретні зміни у файлах
3. **План імплементації**:
   * Persistent owner access data
   * Global access gate
   * Correct zone rendering
4. **Зміни у файлах** — список файлів та що змінено

---

## Acceptance Criteria

* ✅ Власник **у будь-який момент** може:
  * скопіювати Web URL
  * показати QR
  * поділитись доступом
* ✅ Головна сторінка **НЕ відкривається без доступу**
* ✅ Zone URL / QR **відкриває контент**, не порожній екран
* ✅ Немає regression у MCP-доступі

---

## Out of Scope

* Редизайн UI
* Зміни Worker API
* SEO / public preview
* Cron / cleanup

---

## Файли для аналізу (повний список)

| Категорія | Файли |
|-----------|-------|
| Routing | `src/App.tsx` |
| Pages | `src/pages/Index.tsx`, `src/pages/ZoneViewPage.tsx` |
| Components | `src/components/garden/AccessZonesManager.tsx`, `src/components/garden/ZoneQRDialog.tsx`, `src/components/garden/ZoneNoteRenderer.tsx` |
| Hooks | `src/hooks/useAccessZones.ts`, `src/hooks/useZoneValidation.ts`, `src/hooks/useOwnerAuth.tsx` |
| Backend (ref) | `infrastructure/cloudflare/worker/index.js` |
