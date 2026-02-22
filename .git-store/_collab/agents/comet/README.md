# Comet Browser Agent (Perplexity)

## Роль

Browser-based AI агент для:
- Деплою через Cloudflare Dashboard
- Ручного тестування endpoints
- Візуальної перевірки UI

## Інструкції

- [deploy.md](./deploy.md) - Як деплоїти Worker
- [debug.md](./debug.md) - Як дебажити AccessZone
- [checklist.md](./checklist.md) - Чекліст перевірки

## Можливості

✅ Може робити:
- Відкривати Cloudflare Dashboard
- Копіювати/вставляти код
- Натискати кнопки (Save, Deploy)
- Відкривати DevTools
- Виконувати curl команди

❌ НЕ може робити:
- Запускати CLI команди (wrangler)
- Редагувати файли локально
- Виконувати git операції

## Координація

### З Lovable

1. Lovable оновлює `infrastructure/cloudflare/worker/index.js`
2. Comet деплоїть через Dashboard
3. Comet перевіряє `/health`
4. Comet повідомляє результат

### З Cloud CLI

1. Cloud CLI робить `git pull`
2. Cloud CLI аналізує код
3. Cloud CLI записує в `analysis-notes.md`
4. Comet перевіряє рекомендації в production
