# 🔧 Replit Backend: Налаштування для garden-seedling

**Мета**: Оновити змінні середовища для роботи з новим репозиторієм.

---

## Оновити Replit Secrets

Зміни в секретах Replit проєкту `notebooklm-gateway-1`:

| Variable | Нове значення | Опис |
|----------|---------------|------|
| `GITHUB_REPO` | `maxfraieho/garden-seedling` | ⚠️ ЗМІНИТИ з `project-genesis` |
| `GITHUB_BRANCH` | `main` | Без змін |
| `SERVICE_TOKEN` | `garden-nlm-service-2026-a7f3b9c1e5d2` | Без змін |
| `GITHUB_PAT` | `ghp_...` | Перевірити що має доступ до нового репо |

---

## Перевірка доступу GitHub PAT

GitHub PAT повинен мати доступ до `maxfraieho/garden-seedling`:

1. Відкрий https://github.com/settings/tokens
2. Знайди токен що використовується
3. Перевір що він має права на новий репозиторій:
   - `repo` — Full control
   - `workflow` — якщо потрібно тригерити Actions

**Якщо PAT старий** — створи новий Classic PAT з правами на `garden-seedling`.

---

## Тест після оновлення

```bash
# 1. Health check
curl https://notebooklm-gateway-1.replit.app/health

# 2. Git status — перевірка доступу до нового репо
curl -H "Authorization: Bearer garden-nlm-service-2026-a7f3b9c1e5d2" \
  "https://notebooklm-gateway-1.replit.app/v1/git/status?path=README.md"

# Очікувана відповідь: {"exists": true, "sha": "..."}
```

---

## Checklist

- [ ] Оновити `GITHUB_REPO` → `maxfraieho/garden-seedling`
- [ ] Перевірити що PAT має доступ до нового репо
- [ ] Перезапустити Replit сервіс
- [ ] Протестувати `/v1/git/status`
- [ ] Протестувати DRAKON commit з фронтенду
