# Cloud CLI

## Призначення

Локальний CLI інструмент для:
- Синхронізації з репозиторієм (`git pull`)
- AI-аналізу коду
- Генерації рекомендацій

## Робочий процес

### 1. Синхронізація

```bash
cd /path/to/garden-project
git pull origin main
```

### 2. Аналіз

```bash
# Перегляд worker коду
cat infrastructure/cloudflare/worker/index.js

# Перегляд frontend hooks
cat src/hooks/useAccessZones.ts

# Перегляд проблем
cat infrastructure/cloudflare/worker/accessZone.md
```

### 3. Запис результатів

```bash
# Відкрити notes
nano cloud-cli/analysis-notes.md

# Додати аналіз
# Зберегти

# Commit
git add cloud-cli/analysis-notes.md
git commit -m "Add analysis: AccessZone debug findings"
git push
```

## Інтеграція з AI

### ChatGPT

1. Скопіювати код з репо
2. Надати контекст з `accessZone.md`
3. Запитати аналіз
4. Записати результат в `analysis-notes.md`

### Claude / Other

Аналогічний процес

## Структура analysis-notes.md

```markdown
# Analysis Notes

## [Date] - [Topic]

### Context
...

### Findings
...

### Recommendations
...

### Code Changes
...
```

## Корисні команди

```bash
# Знайти всі TODO
grep -r "TODO" src/

# Знайти всі API calls
grep -r "fetch(" src/hooks/

# Перевірити типи
npx tsc --noEmit
```
