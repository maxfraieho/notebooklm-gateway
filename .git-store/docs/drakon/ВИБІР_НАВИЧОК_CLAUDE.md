---
tags:
  - domain:drakon
  - status:draft
  - format:guide
created: 2026-02-21
updated: 2026-02-21
tier: 2
title: "ВИБІР НАВИЧОК CLAUDE"
dg-publish: true
dg-metatags:
dg-home:
---

# CLAUDE_SKILLS_SELECTION_UA — Аналіз Claude Skills та їх вибір для інтеграції

**Дата:** 2026-02-07
**Проєкт:** garden-bloom

---

## 1. Повний аналіз папки `.claude/`

### Структура

```
.claude/
├── CLAUDE.md                          # Головна конфігурація проєкту
├── README.md                          # Документація з використання
├── AI_AGENT_QUICK_START.md            # Швидкий старт для AI-агентів
├── GARDEN_AGENT_INTEGRATION.md        # Інтеграція Garden Agent Service
├── INTEGRATION_SUMMARY.md             # Підсумок інтеграцій
├── session-summary-2026-01-18.md      # Журнал сесії
├── commands/                          # Slash-команди
│   ├── CLAUDE.md                      # claude-mem контекст
│   ├── audit.md                       # /audit — аудит безпеки та якості
│   ├── component.md                   # /component — створення компонентів
│   ├── debug.md                       # /debug — систематичний дебаг
│   ├── plan.md                        # /plan — планування фіч
│   └── review.md                      # /review — code review
└── skills/                            # Спеціалізовані агенти
    ├── component-builder.md           # Агент для створення React компонентів
    ├── react-debugger.md              # Агент для дебагу React проблем
    └── react-planner.md               # Агент для планування архітектури
```

---

## 2. РЕАЛЬНО ДОСТУПНІ CLAUDE SKILLS

### 2.1. Skills (Спеціалізовані агенти)

#### A. `component-builder` (React Component Builder Agent)
- **Тип:** agent skill
- **Опис:** Спеціалізований агент для створення React компонентів з TypeScript та shadcn-ui
- **Експертиза:**
  - TypeScript типізація (generics, utility types, inference)
  - React functional components + hooks
  - shadcn-ui інтеграція з class-variance-authority
  - Tailwind CSS (utility-first, responsive, cn())
- **Процес:** Requirements → Interface Design → Dependencies → Structure → Implementation → Quality Check
- **Контрольний список:** Types, React correctness, Styling, Performance, Code style

#### B. `react-debugger` (React Debugger Agent)
- **Тип:** agent skill
- **Опис:** Спеціалізований агент для дебагу React + TypeScript + Vite проблем
- **Спеціалізація:**
  - TypeScript помилки (types, interfaces, module resolution)
  - React помилки (hooks, re-renders, memory leaks)
  - Vite помилки (imports, builds, HMR)
  - Runtime помилки (network, React Query, forms)
  - CSS/стилізація проблеми
- **Метод:** Gather → Classify → Analyze → Hypotheses (3+) → Test → Fix → Verify
- **Принцип:** DOING/EXPECT/RESULT блоки для кожної дії

#### C. `react-planner` (React Feature Planner Agent)
- **Тип:** agent skill
- **Опис:** Спеціалізований агент для планування React фіч та архітектури
- **Процес:** Requirements → Exploration → Technical Design → File Structure → Implementation Plan → Risks & Questions
- **Вихідні:** Детальний технічний план, TODO список, питання, рекомендації
- **Принцип:** НЕ починати імплементацію без погодження плану

### 2.2. Commands (Slash-команди)

| Команда | Опис | Пов'язаний skill |
|---------|------|------------------|
| `/audit` | Комплексний аудит безпеки та якості коду | — (самостійний) |
| `/component` | Створення нового React компонента з TypeScript | component-builder |
| `/debug` | Систематичний дебаг проблем | react-debugger |
| `/plan` | Планування нової фічі або рефакторингу | react-planner |
| `/review` | Code review перед комітом | — (самостійний) |

### 2.3. Конфігурація та протоколи (з CLAUDE.md)

| Протокол | Опис |
|----------|------|
| **Inspector Role** | Senior Engineering Inspector — AUDIT → FIX → PROTECT |
| **Ownership Protocol** | Lovable = UI/JSX; Claude = Logic/Types/Security |
| **Merge Protocol** | feature/ai-dev → audit/claude → main |
| **Claude-Mem Policy** | Decisions, Bug Patterns, Rules, Implementation Patterns |
| **MCP Configuration** | Filesystem, Git, Postgres servers |
| **Security Checklist** | RLS, secrets, XSS, Zod validation, JWT |
| **Priority System** | Type Safety > Security > React > Performance > Consistency |

---

## 3. SELECTED CLAUDE SKILLS FOR THIS TASK

### 3.1. Вибрані skills та обґрунтування

#### Skill 1: `react-planner` — ОСНОВНИЙ
**Релевантність:** ВИСОКА (9/10)
**Обґрунтування:**
- Задача DRAKON інтеграції — це класична задача планування нової фічі
- Skill надає повний процес: Requirements → Exploration → Design → File Structure → Plan → Risks
- Включає шаблони для Component Design, Data Flow, State Management, Routing
- Визначає фази (Foundation → Core → Integration & Polish) — що ідеально для MVP → Beta → Prod

**Підзадачі, де буде використаний:**
1. Визначення архітектури інтеграції (embedded vs iframe vs web component)
2. Проектування файлової структури нових файлів
3. Планування фаз впровадження (MVP → Beta → Production)
4. Визначення ризиків та невідомих

#### Skill 2: `component-builder` — КЛЮЧОВИЙ
**Релевантність:** ВИСОКА (9/10)
**Обґрунтування:**
- Потрібно створити 3-5 нових React компонентів (DrakonViewer, DrakonEditor, DrakonDiagramBlock тощо)
- Skill забезпечує правильну TypeScript типізацію (критично для strict-typed проєкту)
- Включає shadcn-ui integration patterns (додаток побудований на shadcn)
- Контрольний список якості відповідає priorities проєкту (Type Safety > Security > React > Performance)

**Підзадачі, де буде використаний:**
1. Створення `DrakonViewer.tsx` — read-only рендеринг діаграми
2. Створення `DrakonEditor.tsx` — редагування діаграми
3. Створення `DrakonDiagramBlock.tsx` — markdown block компонент
4. Створення TypeScript інтерфейсів для DRAKON API
5. Створення хука `useDrakonDiagram.ts`

#### Skill 3: `react-debugger` — ДОПОМІЖНИЙ
**Релевантність:** СЕРЕДНЯ (7/10)
**Обґрунтування:**
- DRAKON widget — це vanilla JS бібліотека, що монтується в DOM
- Високий ризик проблем: React lifecycle vs DOM manipulation
- Memory leaks при unmount (canvas, event listeners)
- TypeScript type conflicts (no types in drakonwidget.js)
- CSS isolation issues (global styles від drakonwidget)

**Підзадачі, де буде використаний:**
1. Діагностика проблем з React lifecycle vs DRAKON DOM mount
2. Memory leak detection при unmount компонента
3. CSS conflict resolution між Tailwind та DRAKON styles
4. TypeScript inference issues з untyped DRAKON API

#### Command 4: `/audit` — ФІНАЛЬНА ПЕРЕВІРКА
**Релевантність:** ВИСОКА (8/10)
**Обґрунтування:**
- Після інтеграції обов'язкова перевірка Type Safety, Security, Performance
- Аудит нових компонентів на відповідність architecture правилам
- Перевірка XSS ризиків (DRAKON може рендерити HTML контент)
- Bundle size impact analysis

**Підзадачі, де буде використаний:**
1. Аудит DrakonViewer на XSS vulnerabilities
2. Перевірка type safety всіх нових інтерфейсів
3. Performance audit (lazy loading, bundle size)
4. Перевірка consistency зі стилем проєкту

#### Command 5: `/review` — ПЕРЕД КОЖНИМ КОМІТОМ
**Релевантність:** СЕРЕДНЯ (7/10)
**Обґрунтування:**
- Ownership Protocol вимагає Claude review перед merge
- Кожна фаза інтеграції має проходити через /review
- Перевірка TypeScript, React best practices, styling, forms

### 3.2. Skills, що НЕ підходять

| Skill/Command | Причина виключення |
|---------------|-------------------|
| `/component` (command) | Занадто спрощений; `component-builder` skill дає більше контролю |
| `/debug` (command) | Буде використаний непрямо через `react-debugger` skill |

---

## 4. Матриця: Skills ↔ Фази інтеграції

| Фаза | react-planner | component-builder | react-debugger | /audit | /review |
|------|:---:|:---:|:---:|:---:|:---:|
| 1. Архітектура | ★★★ | — | — | — | — |
| 2. Adapter/Types | ★ | ★★★ | ★ | — | — |
| 3. DrakonViewer | — | ★★★ | ★★ | — | ★ |
| 4. Markdown Plugin | ★ | ★★ | ★★ | — | ★ |
| 5. DrakonEditor | — | ★★★ | ★★ | — | ★ |
| 6. i18n | — | ★ | — | — | ★ |
| 7. Фінальний аудит | — | — | ★ | ★★★ | ★★★ |

---

## 5. Рекомендований workflow використання Skills

```
1. /plan (react-planner skill)
   → Деталізувати вимоги
   → Визначити компоненти та файли
   → Створити phased implementation plan

2. component-builder skill (для кожного компонента)
   → Requirements → Interface → Dependencies → Structure → Implementation
   → Quality checklist після кожного компонента

3. react-debugger skill (при проблемах)
   → Gather → Classify → Analyze → Hypotheses → Test → Fix → Verify
   → DOING/EXPECT/RESULT для кожної дії

4. /review (після кожної фази)
   → TypeScript check
   → React best practices
   → Styling consistency
   → Form validation

5. /audit (фінально)
   → Type Safety audit
   → Security review (XSS від DRAKON content)
   → Performance analysis
   → Consistency check
```

---

## 6. Висновок

Проєкт garden-bloom має **3 спеціалізовані agent skills** та **5 slash commands** у папці `.claude/`. Для задачі інтеграції DRAKON widget підібрано **всі 3 skills + 2 commands** з чітким розподілом по фазах роботи. Цей набір повністю покриває весь цикл: від планування архітектури до фінального аудиту.


---

## Семантичні зв'язки

**Цей документ є частиною:**
- [[DRAKON_ІНТЕГРАЦІЯ_ТА_МОДЕЛЬ_ВИКОНАННЯ_АГЕНТА]] — технічний контекст інтеграції

**Цей документ залежить від:**
- [[DRAKON_ІНТЕГРАЦІЯ_ТА_МОДЕЛЬ_ВИКОНАННЯ_АГЕНТА]] — загальна специфікація DRAKON runtime
- [[СТРАТЕГІЯ_ІНТЕГРАЦІЇ]] — стратегічний контекст вибору підходів

**Від цього документа залежають:**
- [[СТРАТЕГІЯ_ІНТЕГРАЦІЇ]] — використовує вибрані навички для реалізації

---

*Цей документ визначає вибір Claude skills для реалізації DRAKON інтеграції.*
