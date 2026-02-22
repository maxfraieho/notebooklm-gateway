# ChatGPT Agent

## Роль

AI-агент для:
- Код ревʼю
- Архітектурного аналізу
- Рекомендацій та best practices
- Дебагу складних проблем

## Робочий процес

### 1. Отримання контексту

```bash
# Cloud CLI виконує
git pull origin main
```

### 2. Аналіз коду

ChatGPT аналізує:
- `infrastructure/cloudflare/worker/` - Worker код
- `src/hooks/` - Frontend логіка
- `docs/` - Архітектура

### 3. Звіт

Результати записуються в:
- `cloud-cli/analysis-notes.md`

## Поточні задачі

### AccessZone Debug

**Проблема:** Zone створюється але не зберігається

**Файли для аналізу:**
1. `infrastructure/cloudflare/worker/index.js` - Worker handler
2. `infrastructure/cloudflare/worker/accessZone.md` - Опис проблеми
3. `src/hooks/useAccessZones.ts` - Frontend hook

**Питання для аналізу:**
1. Чи правильно викликається `env.KV.put()`?
2. Чи є index для listing?
3. Чи повертається помилка при створенні?

### Security Review

**Файли:**
- `infrastructure/cloudflare/worker/auth.md`
- `docs/security.md`

**Перевірити:**
1. JWT implementation
2. Password hashing
3. CORS policy
4. Rate limiting

## Формат звіту

```markdown
# Analysis Report - [Date]

## Summary
...

## Findings
1. **Issue:** ...
   **Severity:** High/Medium/Low
   **Recommendation:** ...

## Code Changes
\`\`\`javascript
// Before
...
// After
...
\`\`\`
```
