# Lovable Agent: Інтеграція редактора нотаток

## Контекст проекту

**Garden-bloom** — веб-додаток "цифрового саду" для нотаток на стеку:
- React 18.3 + Vite 5.4 + TypeScript 5.8
- Tailwind CSS 3.4 + shadcn/ui (Radix primitives)
- TanStack Query 5.83 для серверного стану
- React Router DOM 6.30 для навігації
- React Hook Form 7.61 + Zod для форм

---

## Поточна архітектура

### Сторінки (`src/pages/`)
| Сторінка | Шлях | Опис |
|----------|------|------|
| `Index.tsx` | `/` | Головна: knowledge map, recent notes, tag cloud |
| `NotePage.tsx` | `/notes/:slug` | Перегляд нотатки з коментарями, backlinks, графом |
| `GraphPage.tsx` | `/graph` | Глобальний граф зв'язків |
| `ChatPage.tsx` | `/chat` | NotebookLM інтеграція |
| `FilesPage.tsx` | `/files` | Дерево папок/файлів |
| `TagsIndex.tsx` | `/tags` | Перегляд тегів |

### Навігація (`src/components/garden/`)
**GardenHeader.tsx** — sticky header з:
- Циклічним перемикачем екранів: `Home → Files → Chat → Graph → Home`
- SearchBar, OwnerModeIndicator, LanguageSwitcher, ThemeToggle
- Прямі посилання на Chat та Graph

**Sidebar.tsx** — бокова панель:
- Desktop: fixed 64px ліворуч
- Mobile: overlay toggle
- Рекурсивне дерево папок

### Ключові хуки (`src/hooks/`)
```typescript
// Дані нотаток та зв'язків
useBacklinks(slug)      // зворотні посилання на нотатку
useOutboundLinks(slug)  // вихідні посилання
useLocalGraph(slug)     // локальний граф нотатки
useLinkStats(slug)      // статистика зв'язків

// Теги
useAllTags()            // всі теги
useNotesByTag(tag)      // нотатки за тегом
useTagStats()           // статистика тегів

// Пошук
useSearch()             // live search з результатами

// Коментарі та анотації
useComments(articleSlug)     // CRUD для коментарів
useAnnotations(articleSlug)  // text highlight → comment

// Авторизація та UI
useOwnerAuth()          // токен, auth стан
useLocale()             // i18n
useTextSelection()      // виділення тексту
useSearchHighlight()    // підсвітка пошуку
```

### Завантаження нотаток (`src/lib/notes/`)
**noteLoader.ts** — центральний модуль:
```typescript
// Завантажує markdown з /src/site/notes/*.md
import.meta.glob('/src/site/notes/**/*.md', { query: '?raw' })

// Інтерфейс нотатки
interface Note {
  slug: string;           // URL-encoded шлях
  title: string;          // з frontmatter або імені файлу
  content: string;        // markdown без frontmatter
  frontmatter: NoteFrontmatter;
  rawContent: string;     // повний markdown
}

// Ключові функції
getAllNotes()           // всі нотатки
getNoteBySlug(slug)     // нотатка за slug
getPublishedNotes()     // опубліковані (dg-publish: true)
```

**Пов'язані модулі:**
- `linkGraph.ts` — будує граф [[wikilinks]]
- `tagResolver.ts` — індексує теги
- `searchResolver.ts` — повнотекстовий пошук
- `wikilinkParser.ts` — парсить `[[target|alias]]`

### API клієнт (`src/lib/api/mcpGatewayClient.ts`)
```typescript
// Gateway до Cloudflare Worker
const API_BASE = 'https://garden-mcp-server.maxfraieho.workers.dev'

// Endpoints:
POST /comments             // створення коментаря
GET  /comments/:articleSlug // коментарі нотатки
PATCH /comments/:id        // оновлення статусу
DELETE /comments/:id       // видалення

GET/POST/DELETE /annotations/*  // анотації
POST /zones                     // створення зони доступу
GET  /chats                     // історія чатів
```

### UI компоненти (`src/components/`)
**garden/**
- `NoteLayout.tsx` — layout для нотатки (metadata + content + backlinks + graph + comments)
- `NoteRenderer.tsx` — рендеринг Markdown з [[wikilinks]] та search highlight
- `NoteCard.tsx` — картка нотатки для списків
- `AnnotationLayer.tsx` — wrapper для text selection
- `AnnotationPopup.tsx` — popup для коментування виділеного
- `CommentSection.tsx`, `CommentForm.tsx`, `CommentItem.tsx` — коментарі
- `BacklinksSection.tsx` — зворотні посилання
- `LocalGraphView.tsx`, `GlobalGraphView.tsx` — візуалізація графа
- `WikiLink.tsx` — компонент [[посилання]]
- `TagLink.tsx`, `TagCloud.tsx` — теги
- `SearchBar.tsx` — глобальний пошук

**ui/** — shadcn компоненти:
- `Button`, `Input`, `Textarea`, `Dialog`, `Tooltip`
- `Card`, `Tabs`, `DropdownMenu`, `ScrollArea`
- `Form` (React Hook Form integration)
- `Toast` via `use-toast.ts`

---

## Завдання: Інтеграція редактора

Створи функціональний редактор нотаток на основі патерна Notemod (add_editor/index.html), але повністю переписаний на React з інтеграцією в екосистему garden-bloom.

### 1. EditorPage — нова сторінка (`src/pages/EditorPage.tsx`)

**Маршрути:**
- `/notes/:slug/edit` — редагування існуючої нотатки
- `/notes/new` — створення нової нотатки

**Структура компонента:**
```tsx
import { useParams, useNavigate } from 'react-router-dom'
import { getNoteBySlug } from '@/lib/notes/noteLoader'
import { useLocale } from '@/hooks/useLocale'
import { NoteEditor } from '@/components/garden/NoteEditor'

export function EditorPage() {
  const { slug } = useParams<{ slug: string }>()
  const navigate = useNavigate()
  const { t } = useLocale()

  // Якщо slug є — завантажуємо існуючу нотатку
  // Якщо немає — режим створення нової
  const isNewNote = !slug || slug === 'new'
  const note = isNewNote ? null : getNoteBySlug(slug)

  // Обробка збереження через mcpGatewayClient
  // Після успішного збереження — redirect до /notes/:newSlug
}
```

**Вимоги:**
- [ ] Завантаження rawContent існуючої нотатки
- [ ] Ініціалізація пустої нотатки для нового файлу
- [ ] Збереження через mcpGatewayClient (POST /notes endpoint — можливо потрібно додати)
- [ ] Toast notifications на успіх/помилку через `use-toast.ts`
- [ ] Redirect після збереження на сторінку нотатки

### 2. NoteEditor — компонент редактора (`src/components/garden/NoteEditor.tsx`)

**Функціональність (на базі Notemod):**

```tsx
interface NoteEditorProps {
  initialContent?: string       // Markdown з frontmatter
  initialTitle?: string
  onSave: (data: { title: string; content: string; tags: string[] }) => Promise<void>
  onCancel?: () => void
}
```

**UI структура:**
```tsx
<div className="flex flex-col h-full">
  {/* Toolbar */}
  <EditorToolbar
    onBold={() => formatDoc('bold')}
    onItalic={() => formatDoc('italic')}
    onHeading1={() => formatDoc('formatBlock', '<h1>')}
    onHeading2={() => formatDoc('formatBlock', '<h2>')}
    onLink={handleLinkInsert}
    onWikilink={handleWikilinkInsert}
    onTable={handleTableInsert}
    onCode={() => formatDoc('formatBlock', '<pre>')}
  />

  {/* Split view: Editor | Preview */}
  <div className="flex flex-1 gap-4">
    {/* Contenteditable or Textarea */}
    <div className="flex-1">
      <Textarea
        value={content}
        onChange={handleContentChange}
        className="font-mono h-full resize-none"
        placeholder={t('editor.placeholder')}
      />
    </div>

    {/* Live preview */}
    <div className="flex-1 overflow-auto">
      <NoteRenderer content={content} />
    </div>
  </div>

  {/* Footer: Tags, Save/Cancel */}
  <EditorFooter
    tags={tags}
    onTagsChange={setTags}
    onSave={handleSave}
    onCancel={onCancel}
    isSaving={isSaving}
  />
</div>
```

**Ключові features:**
- [ ] **Markdown editing** — textarea з моноширинним шрифтом
- [ ] **Live preview** — використовуй існуючий `NoteRenderer.tsx`
- [ ] **Toolbar** — форматування (bold, italic, headings, code, link, [[wikilink]], table)
- [ ] **Wikilink autocomplete** — при введенні `[[` показуй dropdown з існуючими нотатками
- [ ] **Tag editor** — input для тегів (використай useAllTags для autocomplete)
- [ ] **Frontmatter handling** — парсинг/серіалізація YAML frontmatter
- [ ] **Auto-save** — debounced save до localStorage (draft recovery)
- [ ] **Keyboard shortcuts** — Ctrl+S save, Ctrl+B bold, Ctrl+I italic

### 3. Інтеграція в навігацію

**GardenHeader.tsx** — додай "Editor" в циклічний перемикач:
```tsx
// Поточний цикл: Home → Files → Chat → Graph → Home
// Новий цикл:   Home → Files → Chat → Graph → Editor → Home

// Або: окрема кнопка "New Note" (PenSquare icon)
<Button variant="ghost" size="icon" asChild>
  <Link to="/notes/new">
    <PenSquare className="h-5 w-5" />
    <span className="sr-only">{t('editor.newNote')}</span>
  </Link>
</Button>
```

**NoteCard.tsx** — додай кнопку "Edit":
```tsx
<DropdownMenu>
  <DropdownMenuItem asChild>
    <Link to={`/notes/${note.slug}/edit`}>
      <Pencil className="mr-2 h-4 w-4" />
      {t('common.edit')}
    </Link>
  </DropdownMenuItem>
</DropdownMenu>
```

**NotePage.tsx** — кнопка редагування в header нотатки:
```tsx
// Тільки для owner mode (useOwnerAuth().isOwner)
{isOwner && (
  <Button variant="outline" size="sm" asChild>
    <Link to={`/notes/${slug}/edit`}>
      <Pencil className="mr-2 h-4 w-4" />
      {t('common.edit')}
    </Link>
  </Button>
)}
```

### 4. Інтеграція з FilesPage (дерево файлів)

**FilesPage.tsx** — кнопка "Нова нотатка":
```tsx
<div className="flex justify-between items-center mb-4">
  <h1>{t('files.title')}</h1>
  <Button asChild>
    <Link to="/notes/new">
      <Plus className="mr-2 h-4 w-4" />
      {t('editor.newNote')}
    </Link>
  </Button>
</div>
```

**FolderTree component** — context menu з "Create note here":
```tsx
// При створенні в конкретній папці, передай folder path
<Link to={`/notes/new?folder=${encodeURIComponent(folderPath)}`}>
  {t('editor.newNoteHere')}
</Link>
```

### 5. Нові хуки

**useNoteEditor.ts** — логіка редактора:
```typescript
export function useNoteEditor(slug?: string) {
  const [content, setContent] = useState('')
  const [title, setTitle] = useState('')
  const [tags, setTags] = useState<string[]>([])
  const [isDirty, setIsDirty] = useState(false)
  const [isSaving, setIsSaving] = useState(false)

  // Завантаження існуючої нотатки
  useEffect(() => {
    if (slug) {
      const note = getNoteBySlug(slug)
      if (note) {
        setContent(note.rawContent)
        setTitle(note.title)
        setTags(note.frontmatter.tags || [])
      }
    }
  }, [slug])

  // Auto-save draft до localStorage
  const draftKey = `note-draft-${slug || 'new'}`
  useEffect(() => {
    if (isDirty) {
      localStorage.setItem(draftKey, JSON.stringify({ content, title, tags }))
    }
  }, [content, title, tags, isDirty])

  // Відновлення draft
  useEffect(() => {
    const draft = localStorage.getItem(draftKey)
    if (draft) {
      // Show toast: "Unsaved draft found. Restore?"
    }
  }, [])

  // Save function
  const save = async () => {
    setIsSaving(true)
    try {
      // Serialize to markdown with frontmatter
      const markdown = serializeNote({ title, content, tags })
      // POST to API (mcpGatewayClient)
      await saveNote(slug, markdown)
      localStorage.removeItem(draftKey)
      setIsDirty(false)
    } finally {
      setIsSaving(false)
    }
  }

  return { content, setContent, title, setTitle, tags, setTags, isDirty, isSaving, save }
}
```

**useWikilinkSuggestions.ts** — autocomplete для [[wikilinks]]:
```typescript
export function useWikilinkSuggestions(query: string) {
  const allNotes = useMemo(() => getAllNotes(), [])

  const suggestions = useMemo(() => {
    if (!query) return []
    const q = query.toLowerCase()
    return allNotes
      .filter(note => note.title.toLowerCase().includes(q) || note.slug.includes(q))
      .slice(0, 10)
      .map(note => ({ title: note.title, slug: note.slug }))
  }, [query, allNotes])

  return suggestions
}
```

### 6. Утиліти (`src/lib/notes/`)

**noteSerializer.ts** — серіалізація нотатки в Markdown:
```typescript
export function serializeNote(data: {
  title: string
  content: string
  tags: string[]
  created?: string
  updated?: string
}): string {
  const frontmatter = {
    title: data.title,
    tags: data.tags,
    created: data.created || new Date().toISOString(),
    updated: new Date().toISOString(),
    'dg-publish': true
  }

  return `---
${yaml.stringify(frontmatter)}---

${data.content}`
}
```

**noteSaver.ts** — збереження через API:
```typescript
export async function saveNote(slug: string | null, content: string): Promise<string> {
  const response = await mcpGatewayClient.post('/notes', {
    slug,  // null = create new
    content
  })
  return response.slug  // повертає slug збереженої нотатки
}
```

### 7. Оновлення App.tsx — додай маршрути

```tsx
<Routes>
  {/* Existing routes */}
  <Route path="/" element={<Index />} />
  <Route path="/notes/:slug" element={<NotePage />} />
  <Route path="/graph" element={<GraphPage />} />
  <Route path="/chat" element={<ChatPage />} />
  <Route path="/files" element={<FilesPage />} />
  <Route path="/tags" element={<TagsIndex />} />

  {/* New editor routes */}
  <Route path="/notes/new" element={<EditorPage />} />
  <Route path="/notes/:slug/edit" element={<EditorPage />} />
</Routes>
```

### 8. i18n — додай переклади

**Розшир useLocale для editor strings:**
```typescript
const editorTranslations = {
  en: {
    'editor.newNote': 'New Note',
    'editor.editNote': 'Edit Note',
    'editor.placeholder': 'Start writing...',
    'editor.save': 'Save',
    'editor.cancel': 'Cancel',
    'editor.saving': 'Saving...',
    'editor.saved': 'Saved successfully',
    'editor.error': 'Failed to save',
    'editor.draftFound': 'Unsaved draft found',
    'editor.restoreDraft': 'Restore',
    'editor.discardDraft': 'Discard',
    'editor.toolbar.bold': 'Bold',
    'editor.toolbar.italic': 'Italic',
    'editor.toolbar.heading1': 'Heading 1',
    'editor.toolbar.heading2': 'Heading 2',
    'editor.toolbar.link': 'Insert Link',
    'editor.toolbar.wikilink': 'Insert Wikilink',
    'editor.toolbar.table': 'Insert Table',
    'editor.toolbar.code': 'Code Block',
  },
  uk: {
    'editor.newNote': 'Нова нотатка',
    'editor.editNote': 'Редагувати',
    'editor.placeholder': 'Почніть писати...',
    'editor.save': 'Зберегти',
    'editor.cancel': 'Скасувати',
    'editor.saving': 'Збереження...',
    'editor.saved': 'Успішно збережено',
    'editor.error': 'Помилка збереження',
    'editor.draftFound': 'Знайдено незбережений чернетку',
    'editor.restoreDraft': 'Відновити',
    'editor.discardDraft': 'Відхилити',
    // ... toolbar translations
  }
}
```

---

## Компоненти shadcn/ui для використання

```bash
# Якщо не встановлені, додай:
npx shadcn@latest add textarea
npx shadcn@latest add tabs
npx shadcn@latest add command  # для autocomplete
npx shadcn@latest add popover  # для dropdown suggestions
```

**Використовуй існуючі:**
- `Button` — save, cancel, toolbar actions
- `Input` — title field
- `Textarea` — markdown editor
- `Dialog` — confirm discard unsaved changes
- `Tooltip` — toolbar hints
- `DropdownMenu` — note card actions
- `Card` — editor container
- `ScrollArea` — preview panel
- `Tabs` — edit/preview toggle (mobile)
- `Command` + `Popover` — wikilink autocomplete

---

## Критичні обмеження

1. **НЕ використовуй contenteditable** — це складно з React. Використовуй `<Textarea>` з Markdown синтаксисом.

2. **НЕ копіюй CSS з Notemod** — все стилізуй через Tailwind classes.

3. **НЕ використовуй localStorage напряму** — тільки для drafts. Основне збереження через API.

4. **НЕ додавай нові npm пакети** без крайньої необхідності. Використовуй те, що вже є:
   - `react-markdown` (вже в проекті через NoteRenderer)
   - `js-yaml` (для frontmatter parsing)
   - Якщо потрібен code editor — розглянь `@uiw/react-textarea-code-editor` (легкий)

5. **ОБОВ'ЯЗКОВО** використовуй TypeScript з explicit types для всіх props та return values.

6. **ОБОВ'ЯЗКОВО** дотримуйся існуючих патернів:
   - Хуки в `src/hooks/`
   - Утиліти в `src/lib/`
   - Компоненти в `src/components/garden/`
   - UI примітиви в `src/components/ui/`

---

## Очікуваний результат

Після виконання:
1. ✅ Новий маршрут `/notes/new` для створення нотатки
2. ✅ Маршрут `/notes/:slug/edit` для редагування
3. ✅ Повноцінний Markdown редактор з live preview
4. ✅ Toolbar з форматуванням та [[wikilink]] autocomplete
5. ✅ Кнопки "New Note" та "Edit" в UI
6. ✅ Auto-save drafts
7. ✅ Інтеграція з існуючими хуками (useComments, useAnnotations, useTags)
8. ✅ i18n підтримка
9. ✅ Responsивний дизайн (mobile-friendly)
10. ✅ Keyboard shortcuts

---

## Порядок реалізації (рекомендований)

1. **Фаза 1: Базовий редактор**
   - EditorPage.tsx з простим Textarea
   - NoteEditor.tsx без toolbar
   - Маршрути в App.tsx
   - Базове збереження (console.log)

2. **Фаза 2: Preview та toolbar**
   - Split view: editor | NoteRenderer
   - EditorToolbar з базовими кнопками
   - Keyboard shortcuts

3. **Фаза 3: Autocomplete та meta**
   - useWikilinkSuggestions hook
   - Tag editor
   - Frontmatter handling

4. **Фаза 4: Інтеграція**
   - Кнопки в GardenHeader, NoteCard, FilesPage
   - Auto-save drafts
   - Toast notifications
   - Owner mode check

5. **Фаза 5: Polish**
   - i18n strings
   - Mobile responsiveness
   - Error handling
   - Confirmation dialogs
