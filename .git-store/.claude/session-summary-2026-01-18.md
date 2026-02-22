# Claude-Mem Debug Session Summary

**Дата:** 2026-01-18, 07:45
**Проект:** garden-bloom
**Мета:** Налаштувати claude-mem persistent memory

---

## Проблема

Claude Code не пам'ятає контекст між сесіями. Claude-mem плагін встановлений, worker працює, але hooks не спрацьовують.

## Root Cause (ЗНАЙДЕНО)

**Плагін не був правильно зареєстрований:**

1. `~/.claude/plugins/installed_plugins.json` був порожній (`"plugins": {}`)
2. `thedotmack` marketplace не був в `known_marketplaces.json`
3. Файл `.orphaned_at` позначав плагін як осиротілий

**Результат:** Claude Code бачив `enabledPlugins: {"claude-mem@thedotmack": true}` в settings, але плагін не був в реєстрі встановлених → hooks не завантажувались.

## Виправлення (ЗАСТОСОВАНО)

### 1. Додано marketplace в known_marketplaces.json

```json
"thedotmack": {
  "source": {
    "source": "github",
    "repo": "thedotmack/claude-mem"
  },
  "installLocation": "/home/vokov/.claude/plugins/marketplaces/thedotmack",
  "lastUpdated": "2026-01-18T07:40:00.000Z"
}
```

### 2. Зареєстровано плагін в installed_plugins.json

```json
{
  "version": 2,
  "plugins": {
    "claude-mem@thedotmack": {
      "name": "claude-mem",
      "version": "9.0.5",
      "marketplace": "thedotmack",
      "installPath": "/home/vokov/.claude/plugins/cache/thedotmack/claude-mem/9.0.5",
      "installedAt": "2026-01-18T07:40:00.000Z",
      "enabled": true
    }
  }
}
```

### 3. Видалено .orphaned_at маркер

```bash
rm ~/.claude/plugins/cache/thedotmack/claude-mem/9.0.5/.orphaned_at
```

---

## Тест пам'яті

**Секретне слово:** `BANANA-ROCKET-2026`

**Питання для перевірки:** "Пам'ятаєш секретне слово?"

**Очікувана відповідь:** BANANA-ROCKET-2026

---

## Діагностичні команди

### Перевірка worker статусу
```bash
ps aux | grep -E "bun.*worker|claude-mem" | grep -v grep
curl -s http://127.0.0.1:37777/api/health | python3 -m json.tool
```

### Перевірка observations в базі
```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('/home/vokov/.claude-mem/claude-mem.db')
c = conn.cursor()
c.execute('SELECT id, type, project, created_at FROM observations ORDER BY created_at DESC LIMIT 5')
for row in c.fetchall():
    print(row)
conn.close()
"
```

### Перевірка логів worker
```bash
tail -30 /home/vokov/.claude-mem/logs/claude-mem-2026-01-18.log
```

### Перевірка конфігурації плагінів
```bash
cat ~/.claude/plugins/installed_plugins.json
cat ~/.claude/plugins/known_marketplaces.json
ls -la ~/.claude/plugins/cache/thedotmack/claude-mem/9.0.5/.orphaned_at 2>&1
```

---

## Структура claude-mem

- **Worker:** bun script на порту 37777
- **База:** `~/.claude-mem/claude-mem.db` (SQLite)
- **Логи:** `~/.claude-mem/logs/`
- **Hooks:** `~/.claude/plugins/cache/thedotmack/claude-mem/9.0.5/hooks/hooks.json`

### Hook events:
- `SessionStart` → завантаження контексту
- `UserPromptSubmit` → ініціалізація сесії
- `PostToolUse` → запис observations
- `Stop` → створення summary

---

## Якщо не спрацює

1. Перевірити чи hooks.json завантажується Claude Code
2. Перевірити логи worker на помилки
3. Можливо потрібно додати hooks вручну в `~/.claude/settings.json` замість через плагін систему
4. Альтернатива: використати user-level hooks замість plugin hooks

---

## Файли змінені в цій сесії

- `~/.claude/plugins/known_marketplaces.json` - додано thedotmack
- `~/.claude/plugins/installed_plugins.json` - зареєстровано плагін
- `~/.claude/plugins/cache/thedotmack/claude-mem/9.0.5/.orphaned_at` - ВИДАЛЕНО
- `/home/vokov/projects/garden-bloom/.claude-mem-test.txt` - тестовий файл (з попередньої сесії)
- `/home/vokov/projects/garden-bloom/.claude-mem-test-2.txt` - тестовий файл
