# GH-AW Deprecation Notice

> **Статус:** DEPRECATED
> **Дата депрекації:** 2026-02-15
> **Замінено на:** Mastra + Inngest

---

## Що таке gh-aw

**gh-aw** (GitHub Agentic Workflows) — це Go-based розширення GitHub CLI, розроблене GitHub, що дозволяло писати агентні воркфлоу природною мовою у Markdown файлах та виконувати їх як GitHub Actions.

### Ключові концепції gh-aw

| Концепт | Опис |
|---------|------|
| **Workflow** | Markdown файл з YAML frontmatter (конфігурація) + Markdown body (логіка) |
| **Safe Outputs** | Механізм безпечного виведення результатів без write permissions |
| **Safe Inputs** | Механізм безпечного введення даних у workflow |
| **IssueOps** | Паттерн автоматизації через GitHub Issues |
| **DailyOps** | Паттерн щоденних інкрементальних змін через cron |
| **ChatOps** | Паттерн автоматизації через коментарі |
| **Frontmatter** | YAML конфігурація: triggers, permissions, tools, engines |
| **MCP Gateway** | Інтеграція з Model Context Protocol серверами |

---

## Коли використовувалось

gh-aw використовувався у проєкті Garden Seedling як **референсна модель** для визначення формату агентів та оркестрації. Конкретно:

- **Формат агентів:** YAML frontmatter + Markdown body як універсальний формат опису агентів
- **Execution model:** GitHub Actions як runtime для виконання воркфлоу
- **Patterns:** IssueOps, DailyOps, ChatOps, LabelOps та інші operational patterns
- **Security model:** Safe Outputs/Inputs для ізоляції дозволів
- **Documentation:** Starlight-based сайт документації (`docs/src/content/docs/`)

gh-aw був **клонований як референсний репозиторій** у директорію `gh-aw/` і слугував специфікацією, а не production runtime.

---

## Чому замінено

| Обмеження gh-aw | Вплив на проєкт |
|-----------------|-----------------|
| **GitHub-залежність** | Прив'язка до GitHub Actions як єдиного runtime |
| **Cold start** | GitHub Actions мають значний час старту |
| **Відсутність MinIO інтеграції** | gh-aw не підтримує MinIO як canonical storage |
| **Обмежена оркестрація** | Немає native fan-out, retry, saga patterns |
| **Відсутність event-driven архітектури** | Немає native підтримки event bus |
| **Vendor lock-in** | Залежність від GitHub infrastructure |

---

## Чим замінено

### Canonical Runtime Stack (з 2026-02-15)

| Компонент | Роль | Замінює з gh-aw |
|-----------|------|-----------------|
| **Mastra** | Agent interpreter — парсить `_agent.md`, виконує логіку агентів | gh-aw CLI + workflow compilation |
| **Inngest** | Orchestration — event-driven scheduling, retry, fan-out, saga | GitHub Actions cron/triggers |
| **MinIO** | Source of truth — canonical storage для zones, agents, knowledge | GitHub repository storage |
| **FastAPI Worker** | API gateway — REST/SSE endpoints для frontend | gh-aw safe-outputs/inputs |
| **Lovable** | Projection layer — React frontend, відображення стану системи | (не було еквіваленту) |

### Mapping концептів

| gh-aw концепт | Нова форма |
|---------------|------------|
| `.md` workflow файл | `_agent.md` (КОНТРАКТ_АГЕНТА_V1) |
| YAML frontmatter | YAML frontmatter `_agent.md` з `tools[]`, `triggers[]` |
| Safe Outputs | FastAPI endpoints + Inngest event results |
| Safe Inputs | Mastra tools з `tools[]` у `_agent.md` |
| GitHub Actions triggers | Inngest events + cron functions |
| IssueOps/DailyOps patterns | Inngest scheduled/event-driven functions |
| MCP Gateway | Cloudflare Worker gateway |
| Workflow compilation (.lock.yml) | Mastra runtime interpretation (no compilation) |

---

## Документація

### Де знаходяться gh-aw артефакти

| Локація | Зміст |
|---------|-------|
| `docs/deprecated/gh-aw/` | Переміщені gh-aw специфічні документи |
| `docs/deprecated/legacy-en/` | Англомовна legacy документація |
| `docs/src/content/docs/` | Starlight site — **GH-AW_ARTIFACT**, не canonical |
| `docs/migration/ПЛАН_МІГРАЦІЇ_GH_AW_НА_MASTRA_INNGEST.md` | План міграції (canonical) |

### Canonical документація поточної архітектури

| Документ | Зміст |
|----------|-------|
| `docs/architecture/АРХІТЕКТУРНА_БАЗА_СИСТЕМИ.md` | Фундаментальна архітектура |
| `docs/architecture/ЦІЛЬОВА_АРХІТЕКТУРА_MASTRA_INNGEST.md` | Цільова архітектура Mastra + Inngest |
| `docs/architecture/КОНТРАКТ_АГЕНТА_V1.md` | Специфікація формату `_agent.md` |
| `docs/manifesto/MANIFESTO.md` | Маніфест проєкту (оновлений) |

---

## Інваріант

**Жоден canonical документ проєкту не повинен описувати gh-aw як активний execution layer.**

Допустимі згадки gh-aw:
- Як historical reference з позначкою `DEPRECATED`
- У документі міграції (`ПЛАН_МІГРАЦІЇ_GH_AW_НА_MASTRA_INNGEST.md`)
- У deprecation notice (цей документ)

Недопустимі згадки gh-aw:
- Як поточний runtime або execution layer
- Як інструкція до інсталяції чи використання
- Як частина поточної архітектури

---

*Цей документ є частиною Phase 4 (Decommission gh-aw) плану міграції.*
