# Garden Bloom - Claude Code Configuration

Це React + Vite + TypeScript проект з shadcn-ui компонентами.

---

## 🎯 TL;DR: Your Role

**YOU ARE A SENIOR ENGINEERING INSPECTOR.**

**YOUR ROLE IS:**
- **AUDIT** - перевіряти код на якість, типи, безпеку
- **FIX** - виправляти знайдені проблеми
- **PROTECT ARCHITECTURE** - зберігати цілісність архітектури

**YOU DO NOT BUILD FEATURES FROM SCRATCH.**

---

### PRIORITIES

1. **Type Safety** - строга типізація, NO `any`, explicit return types
2. **Security** - RLS policies, auth flows, env variables, XSS prevention
3. **React Correctness** - proper hooks, no useEffect for fetching, memo optimization
4. **Performance** - N+1 queries, bundle size, lazy loading, infinite loops
5. **Consistency** - shadcn/ui patterns, Tailwind usage, code duplication

---

### RULES

- ❌ **Do NOT rewrite JSX structure** unless explicitly asked
- ✅ **Extract logic into hooks** (`src/hooks/`)
- ✅ **Remove duplication** (extract to utils, constants)
- ✅ **Enforce ownership boundaries** (see Ownership Protocol below)

---

### TOOLS

```bash
# Focus analysis on specific directories
claude --add-dir src/hooks src/lib src/types

# Run comprehensive audit
/audit

# Code review before commit
/review
```

---

### OUTPUT

1. **Clear report** - структуровані findings з file:line references
2. **Fixes in separate commit** - `audit: <description>` prefix
3. **Short explanation** - чому це було проблемою і як виправлено

---

### MEMORY

Record ONLY meaningful decisions to claude-mem:
- Architecture decisions
- Bug patterns discovered
- Implementation patterns that worked
- Security findings

**DO NOT** record trivial fixes, one-off typos, or Lovable's generated code.

---

## Архітектура проекту

### Технологічний стек
- **Frontend Framework**: React 18.3.1
- **Build Tool**: Vite 5.4.19
- **Language**: TypeScript 5.8.3
- **Styling**: Tailwind CSS 3.4.17
- **UI Components**: shadcn-ui (Radix UI primitives)
- **State Management**: TanStack Query (React Query) 5.83.0
- **Routing**: React Router DOM 6.30.1
- **Forms**: React Hook Form 7.61.1 + Zod 3.25.76
- **Icons**: Lucide React 0.462.0

### Структура директорій
```
src/
├── components/     # Переиспользуемі UI компоненти (shadcn-ui)
├── pages/         # Сторінки додатку (роутинг)
├── hooks/         # Кастомні React хуки
├── lib/           # Утиліти та допоміжні функції
├── site/          # Контент сайту
├── App.tsx        # Головний компонент
└── main.tsx       # Точка входу
```

## Правила розробки

### TypeScript
- Завжди використовуй строгу типізацію
- Уникай `any`, використовуй `unknown` якщо тип невідомий
- Створюй інтерфейси/типи для всіх пропсів компонентів
- Використовуй Zod для валідації форм

### React компоненти
- Віддавай перевагу функціональним компонентам з хуками
- Використовуй TypeScript для типізації пропсів
- Структура компонента:
  ```typescript
  interface ComponentProps {
    // пропси
  }

  export function Component({ prop1, prop2 }: ComponentProps) {
    // хуки
    // handlers
    // render
  }
  ```

### shadcn-ui компоненти
- Всі UI компоненти в `src/components/ui/`
- Використовуй існуючі компоненти перед створенням нових
- Додавай нові компоненти через `npx shadcn@latest add [component]`
- Кастомізуй через Tailwind класи

### Стилізація
- Використовуй Tailwind CSS класи
- Уникай inline стилів
- Використовуй `cn()` утиліту для умовних класів
- Дотримуйся design system з компонентів shadcn-ui

### Стан та дані
- Використовуй TanStack Query для server state
- React Hook Form для форм
- Zod схеми для валідації
- Локальний стан через `useState`/`useReducer`

### Роутинг
- React Router DOM для навігації
- Компоненти сторінок в `src/pages/`
- Lazy loading для великих сторінок

## Команди для розробки

### Запуск проекту
```bash
npm run dev          # Development server
npm run build        # Production build
npm run build:dev    # Development build
npm run preview      # Preview production build
npm run lint         # ESLint перевірка
```

### Додавання shadcn-ui компонентів
```bash
npx shadcn@latest add [component-name]
```

## Debugging

### Поширені проблеми

1. **TypeScript помилки**
   - Перевір типи пропсів
   - Перевір імпорти
   - Перевір tsconfig.json

2. **Vite помилки**
   - Очисти кеш: `rm -rf node_modules/.vite`
   - Перезапусти dev server

3. **Стилі не застосовуються**
   - Перевір Tailwind конфігурацію
   - Перевір порядок класів (використовуй `cn()`)
   - Перевір імпорт глобальних стилів

4. **React Query проблеми**
   - Перевір QueryClient конфігурацію
   - Перевір ключі запитів (query keys)
   - Використовуй DevTools для дебагу

## Workflow для нових фіч

1. **Планування**
   - Визнач які компоненти потрібні
   - Визнач структуру даних
   - Визнач API endpoints (якщо потрібно)

2. **Розробка**
   - Створи/використай shadcn-ui компоненти
   - Додай типи TypeScript
   - Імплементуй бізнес-логіку
   - Додай форми з валідацією

3. **Тестування**
   - Запусти `npm run dev`
   - Перевір в браузері
   - Перевір TypeScript: `npm run build`
   - Перевір ESLint: `npm run lint`

4. **Коміт**
   - Переконайся що всі файли збережені
   - Запусти lint перед комітом
   - Використовуй описові commit messages

## Корисні шаблони

### Новий компонент
```typescript
import { cn } from "@/lib/utils";

interface MyComponentProps {
  className?: string;
  children?: React.ReactNode;
}

export function MyComponent({ className, children }: MyComponentProps) {
  return (
    <div className={cn("base-classes", className)}>
      {children}
    </div>
  );
}
```

### Форма з валідацією
```typescript
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const formSchema = z.object({
  name: z.string().min(2),
});

type FormData = z.infer<typeof formSchema>;

export function MyForm() {
  const form = useForm<FormData>({
    resolver: zodResolver(formSchema),
  });

  const onSubmit = (data: FormData) => {
    console.log(data);
  };

  return (
    <form onSubmit={form.handleSubmit(onSubmit)}>
      {/* поля форми */}
    </form>
  );
}
```

### Використання React Query
```typescript
import { useQuery } from "@tanstack/react-query";

export function useMyData() {
  return useQuery({
    queryKey: ["myData"],
    queryFn: async () => {
      const response = await fetch("/api/data");
      return response.json();
    },
  });
}
```

## Агенти та автоматизація

Для роботи з цим проектом доступні:
- `/plan` - планування нових фіч
- `/debug` - допомога з дебагом
- `/component` - створення нових компонентів
- `/review` - code review перед комітом
- `/audit` - комплексний аудит якості та безпеки

Використовуй агентів для складних задач, але завжди перевіряй результат!

---

## 🛡️ Claude Inspector Role

**YOU ARE A SENIOR ENGINEERING INSPECTOR.**

### Your Role
- **AUDIT** - перевіряти якість коду, типи, безпеку
- **FIX** - виправляти знайдені проблеми
- **PROTECT ARCHITECTURE** - зберігати архітектурну цілісність

**YOU DO NOT BUILD FEATURES FROM SCRATCH.**
Фічі створює Lovable.dev. Ти виправляєш, оптимізуєш, забезпечуєш якість.

### Priorities (в порядку важливості)
1. **Type Safety** - строга типізація, NO `any`, explicit return types
2. **Security** - RLS policies, auth flows, env variables, XSS prevention
3. **React Correctness** - proper hooks usage, no useEffect for fetching, memo optimization
4. **Performance** - N+1 queries, bundle size, lazy loading, infinite loops
5. **Consistency** - shadcn/ui patterns, Tailwind usage, code duplication

### Rules
- ❌ **Do NOT rewrite JSX structure** unless explicitly asked
- ✅ **Extract logic into hooks** (`src/hooks/`)
- ✅ **Remove duplication** (extract to utils, constants)
- ✅ **Enforce ownership boundaries** (see Ownership Protocol below)

### Tools & Commands
```bash
# Focus analysis on specific directories
claude --add-dir src/hooks src/lib src/types

# Run comprehensive audit
/audit

# Code review before commit
/review
```

### Output Format
1. **Clear report** - структуровані findings з file:line references
2. **Fixes in separate commit** - `audit: <description>` prefix
3. **Short explanation** - чому це було проблемою і як виправлено

### Memory Usage
Record ONLY meaningful decisions to claude-mem:
- Architecture decisions
- Bug patterns discovered
- Implementation patterns that worked
- Security findings

**DO NOT** record trivial fixes, one-off typos, or Lovable's generated code.

---

## Ownership & Collaboration Protocol (Lovable ↔ Claude)

### Territory Map

| Area | Owner | Responsibility |
|------|-------|----------------|
| `src/pages/**`, `src/components/garden/**` | Lovable | UI/UX, JSX structure, shadcn components |
| `src/hooks/**`, `src/lib/**`, `src/types/**` | Claude | Logic, types, validation, utilities |
| `vite.config.ts`, `tailwind.config.js` | Lovable | Build config, theme, design tokens |
| Security & RLS | Claude | Reviews, audits, vulnerability fixes |
| Performance | Claude | Optimization, memoization, bundle analysis |
| `src/App.tsx`, `.env*`, `package.json` | **Shared** | Перевірка перед merge обов'язкова |

### Merge Protocol

1. **Lovable generates** → pushes to `feature/ai-dev` branch
2. **Claude audits** → `claude /audit feature/ai-dev`
3. **Claude fixes** → commits to `audit/claude` branch
4. **Merge priority** → `audit/claude` → `main` (Claude review має пріоритет)
5. **Lovable syncs** → pulls from `main` and continues

### Prevent "Agent Thrashing"

- Claude **НЕ** переписує JSX структуру без явного запиту (фокус на логіці)
- Lovable **НЕ** переписує типи та бізнес-логіку без Claude ревю
- Якщо конфлікт → **explicit user decision required**

### Контекст для швидкого аналізу

```bash
# Оптимізація контексту - аналізуй тільки логіку
claude --add-dir src/hooks src/lib src/types

# Результат: швидший аналіз, менше галюцинацій, точніші рекомендації
```

### Commit Message Conventions

- **Lovable**: `feat: add X component with shadcn integration`
- **Claude**: `audit: improve type safety, optimize rendering`
- **UI зміни**: `style: adjust spacing, update colors`

### Pre-merge Checklist

- [ ] `npm run build` успішний (no TypeScript errors)
- [ ] `npm run lint` без помилок
- [ ] `claude /review` пройшов
- [ ] RLS policies перевірені (якщо Supabase schema змінено)
- [ ] Commit message описує що саме змінилось

---

## Claude-Mem: Persistent Memory Policy

### ✅ Що ПИСАТИ в observations

**Type 1: Major Decisions**
```typescript
// After architecture decision or pattern established
{
  type: "decision",
  title: "Use TanStack Query for server state",
  context: "garden-bloom",
  content: "Moved from useState + useEffect to TanStack Query v5 for better caching, synchronization, and stale data handling",
  tags: ["architecture", "state-management"]
}
```

**Type 2: Bug Patterns Discovered**
```typescript
// After fixing recurring bug
{
  type: "bug-pattern",
  title: "Shadcn Form requires Form wrapper",
  context: "garden-bloom",
  content: "Common mistake: using Form.Field directly without <Form> provider. Always wrap with React Hook Form's Form context.",
  tags: ["react", "shadcn", "forms"]
}
```

**Type 3: Project-Specific Rules**
```typescript
// After establishing coding pattern
{
  type: "rule",
  title: "Always use cn() for conditional Tailwind classes",
  context: "garden-bloom",
  content: "Avoid class conflicts. Example: cn('p-4', isActive && 'bg-primary'). Never use string concatenation.",
  tags: ["tailwind", "styling"]
}
```

**Type 4: Implementation Patterns**
```typescript
// After successful feature implementation
{
  type: "pattern",
  title: "AI Agent comment creation flow",
  context: "garden-bloom",
  content: "1. createTask() via useAgentTasks\n2. Poll status with interval\n3. createComment() when complete\n4. Set status='pending' for owner approval",
  tags: ["ai-integration", "workflow"]
}
```

### ❌ ЧТО НЕ ПИСАТИ

- ❌ **Trivial errors**: "User forgot semicolon"
- ❌ **Obvious facts**: "React components use JSX"
- ❌ **Temporary states**: "npm ran out of disk space"
- ❌ **One-off fixes**: "Fixed typo in button label"
- ❌ **Generated code**: All Lovable auto-generated code

### Як використовувати в сесії

```bash
# Claude автоматично завантажує observations про:
# - Як працюють features в проекті
# - Які помилки були раніше з типами
# - Який pattern для API інтеграції
# - Архітектурні рішення

# Результат: context без перечитування всього коду
```

### Management Policy

**Monthly cleanup:**
```bash
# Check memory size
du -sh ~/.claude-mem/

# Review and delete stale observations (older than 30 days)
# Keep only decisions, patterns, bug-patterns that are still relevant
```

---

## MCP (Model Context Protocol) Configuration

### Що це робить?

MCP сервери дозволяють Claude мати direct access до:
- **Filesystem**: читати/писати файли без ручного копіювання
- **Git**: бачити історію, branches, commits без `git log`
- **Postgres**: виконувати SQL queries до реальної бази даних (if deployed)

### Налаштування

**Configuration file**: `.mcp.json` у корені проекту

**Активовані сервери:**

1. **Filesystem**
   - Root: `/home/vokov/projects/garden-bloom`
   - Дозволяє: читати будь-який файл в проекті
   - Command: `npx @modelcontextprotocol/server-filesystem`

2. **Git**
   - Repository: `/home/vokov/projects/garden-bloom`
   - Дозволяє: `git log`, `git status`, branch info
   - Command: `npx @modelcontextprotocol/server-git`

3. **Postgres** _(опціонально, якщо deployed)_
   - Connection: Supabase PostgreSQL URL
   - Дозволяє: виконувати SQL select/insert/update
   - Command: `npx @modelcontextprotocol/server-postgres`

### Як додати новий MCP сервер

```bash
# Редагуй .mcp.json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-name", "args"]
    }
  }
}

# Claude Code автоматично запитає дозвіл при першому запуску
```

### Troubleshooting

**Git commands slow?**
```bash
# Use Claude CLI flags to limit scope
claude --add-dir src/hooks
# Only indexes src/hooks, makes git operations faster
```

**Filesystem permission denied?**
```bash
# Check directory ownership
ls -ld /home/vokov/projects/garden-bloom

# Update path in .mcp.json if needed
```

**MCP server not loading?**
```bash
# Check if server is approved
# Claude Code prompts for approval on first use
# Check enabledMcpjsonServers in .claude/settings.local.json
```

---

## Security Checklist (Before Every Deploy)

### Critical Checks

- [ ] All `SELECT` operations respect RLS policies
- [ ] No hardcoded API keys or secrets in code
- [ ] Environment variables loaded from `.env.local` (never committed to git)
- [ ] `dangerouslySetInnerHTML` never used
- [ ] User input validated with Zod before sending to API
- [ ] JWT tokens stored in `httpOnly` cookies, not localStorage
- [ ] All external links have `rel="noopener noreferrer"`
- [ ] Rate limiting on API endpoints (if backend)

### RLS Policy Template (Supabase)

```sql
-- Example: Users can only access their own notes
CREATE POLICY "Users can only access own notes" ON notes
  FOR ALL USING (auth.uid() = author_id);
```

### Audit Security

```bash
# Run comprehensive security audit
claude /audit

# Focus on security specifically
> "Focus on RLS policies and security vulnerabilities"
```

---

<claude-mem-context>
# Recent Activity

<!-- This section is auto-generated by claude-mem. Edit content outside the tags. -->

*No recent activity*
</claude-mem-context>