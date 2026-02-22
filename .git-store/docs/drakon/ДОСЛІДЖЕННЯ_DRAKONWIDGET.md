---
tags:
  - domain:drakon
  - status:draft
  - format:research
  - feature:logic
created: 2026-02-21
updated: 2026-02-21
tier: 2
title: "ДОСЛІДЖЕННЯ DRAKONWIDGET"
dg-publish: true
dg-metatags:
dg-home:
---

# DRAKONWIDGET_RESEARCH_UA — Повний технічний аналіз DrakonWidget

**Дата:** 2026-02-07
**Бібліотека:** drakonwidget v1.4.4 (npm) / v1.4.7 (README)
**Автор бібліотеки:** Stepan Mitkin
**Ліцензія:** Unlicense (повна свобода використання)
**Репозиторій:** https://github.com/maxfraieho/drakonwidget (форк від stepan-mitkin/drakonwidget)

---

## 1. Загальний опис

DrakonWidget — JavaScript віджет для **перегляду та редагування** DRAKON-діаграм (блок-схем алгоритмів).

DRAKON (Дружній Російський Алгоритмічний мова, Який Обеспечує Наглядність) — візуальна мова програмування, розроблена для космічної програми "Буран".

---

## 2. Архітектура бібліотеки

### 2.1. Файлова структура

```
drakonwidget/
├── package.json          # v1.4.4, main: "index.js" (не існує!)
├── README.md             # Повна документація API
├── LICENSE               # Unlicense
├── index.html            # Demo page
├── libs/
│   ├── drakonwidget.js   # ГОЛОВНИЙ ФАЙЛ (~1.4 MB, plain JS)
│   ├── simplewidgets.js  # UI utilities (popups, menus, etc.)
│   ├── mousetrap.min.js  # Keyboard shortcuts library
│   └── rounded.js        # Rounded corners helpers
├── js/
│   ├── main.js           # Demo app logic
│   ├── examples.js       # Sample diagrams (JSON)
│   └── themes.js         # Color themes
├── styles/
│   ├── main.css          # Demo styles
│   └── reset.css         # CSS reset
├── images/               # Icons та зображення
└── dtsrc/
    └── drakon_widget.zip # Source code archive
```

### 2.2. Формат модулів

| Характеристика | Значення |
|---------------|---------|
| **Формат** | **IIFE** (Immediately Invoked Function Expression), НЕ ESM/CJS/UMD |
| **Entry point** | Глобальна функція `createDrakonWidget()` |
| **Залежності** | **НУЛЬ** — повністю автономний |
| **Розмір** | ~1.4 MB (неmінімізований, development) |
| **TypeScript типи** | **ВІДСУТНІ** — потрібно створити `.d.ts` |
| **npm package** | `"main": "index.js"` — але файл `index.js` НЕ ІСНУЄ! |

### КРИТИЧНЕ СПОСТЕРЕЖЕННЯ
Файл `package.json` вказує `"main": "index.js"`, але такого файлу в репозиторії немає. Реальний entry point — `libs/drakonwidget.js`. Це означає, що `npm install` + `import` не працюватимуть без адаптації.

---

## 3. API бібліотеки

### 3.1. Ініціалізація

```javascript
// 1. Створити інстанс
var drakon = createDrakonWidget()

// 2. Створити конфігурацію
var config = {
  startEditContent: myEditFunction,    // REQUIRED
  showContextMenu: myMenuFunction,     // REQUIRED
  canSelect: true,                      // дозволити редагування
  canvasIcons: false,                   // DOM або Canvas рендеринг
  textFormat: 'markdown',              // plain | markdown | html
  theme: { ... }                        // кольорова тема
}

// 3. Рендеринг
var widgetElement = drakon.render(width, height, config)
document.getElementById('container').appendChild(widgetElement)

// 4. Завантажити діаграму
var sender = { pushEdit: fn, stop: fn }
drakon.setDiagram(diagramId, diagramData, sender)
```

### 3.2. Ключові методи

| Метод | Опис | Повертає |
|-------|------|---------|
| `render(w, h, config)` | Створює DOM-елемент віджета | HTMLElement |
| `redraw()` | Перемальовує діаграму | void |
| `setDiagram(id, data, sender)` | Завантажує діаграму | Promise<string[]> |
| `exportJson()` | Експортує діаграму як JSON | string |
| `exportCanvas(zoom)` | Експортує як Canvas (тільки canvasIcons=true) | HTMLCanvasElement |
| `setContent(id, content)` | Встановлює контент елемента | string[] |
| `setZoom(level)` | Встановлює масштаб | void |
| `getZoom()` | Отримує масштаб | integer |
| `showItem(id)` | Прокрутити до елемента | void |
| `undo()` / `redo()` | Скасувати/повторити | Promise |

### 3.3. Callbacks (config)

| Callback | Required | Опис |
|----------|----------|------|
| `startEditContent(item, isReadonly)` | ДА | Редагування контенту елемента |
| `showContextMenu(left, top, items)` | ДА | Контекстне меню |
| `startEditLink(item, isReadonly)` | Ні | Редагування посилання |
| `startEditSecondary(item, isReadonly)` | Ні | Вторинний контент |
| `startEditStyle(ids, oldStyle, x, y, accepted)` | Ні | Стиль елементів |
| `onSelectionChanged(items)` | Ні | Зміна виділення |
| `onZoomChanged(zoom)` | Ні | Зміна масштабу |
| `translate(text)` | Ні | Переклад UI |

### 3.4. Формат даних діаграми

```typescript
interface DrakonDiagram {
  name: string;           // Назва діаграми
  access: 'read' | 'write';  // Режим доступу
  params?: string;        // Параметри (newline-separated)
  style?: string;         // JSON-string стилю
  items: Record<string, DrakonItem>;  // Елементи
}

interface DrakonItem {
  type: string;           // action, question, branch, end, etc.
  content?: string;       // Текст елемента
  secondary?: string;     // Вторинний текст
  link?: string;          // Посилання
  one?: string;           // ID наступного елемента (вниз)
  two?: string;           // ID наступного елемента (вправо)
  side?: string;          // ID бічного елемента
  flag1?: number;         // Yes/No орієнтація (для Question)
  branchId?: number;      // Порядок гілки (для Branch)
  margin?: number;        // Додатковий відступ
  style?: string;         // JSON-string стилю елемента
}
```

**Типи елементів:** action, question, select, case, foreach, branch, insertion, comment, parblock, par, timer, pause, duration, shelf, process, input, output, ctrlstart, ctrlend, drakon-image, header, end, address

### 3.5. EditSender — система збереження змін

```typescript
interface EditSender {
  pushEdit(edit: DrakonEdit): void;  // Зберегти зміни
  stop(): void;                       // Зупинити
}

interface DrakonEdit {
  id: string;                         // ID діаграми
  changes: DrakonChange[];            // Масив змін
}

interface DrakonChange {
  id?: string;                        // ID елемента
  op: 'insert' | 'update' | 'delete'; // Операція
  fields?: Record<string, unknown>;    // Поля для зміни
}
```

### 3.6. Theming

```typescript
interface DrakonTheme {
  background?: string;      // Фон діаграми (#74a8fc default)
  backText?: string;        // Колір Yes/No лейблів
  borderWidth?: number;     // Ширина бордера
  color?: string;           // Колір тексту
  iconBack?: string;        // Фон іконок
  iconBorder?: string;      // Бордер іконок
  lineWidth?: number;       // Ширина ліній
  lines?: string;           // Колір ліній
  shadowBlur?: number;      // Розмиття тіні
  shadowColor?: string;     // Колір тіні
  scrollBar?: string;       // Колір скроллбару
  icons?: Record<string, Partial<DrakonTheme>>; // Per-icon themes
}
```

---

## 4. Залежності та середовище

| Залежність | Тип | Розмір | Потрібна? |
|-----------|-----|--------|-----------|
| **drakonwidget.js** | Core | 1.4 MB | ДА |
| simplewidgets.js | Demo UI | 69 KB | НІ (замінити shadcn-ui) |
| mousetrap.min.js | Keyboard | 5 KB | ОПЦІОНАЛЬНО |
| rounded.js | Rendering | 3 KB | НІ (для demo) |

### DOM залежності
- **window** — використовується для розмірів та event listeners
- **document** — створює DOM елементи (div, canvas)
- **Canvas 2D API** — основний рендеринг (при canvasIcons=true)
- **localStorage** — НЕ використовується
- **navigator** — НЕ використовується

### CSS залежності
- `main.css` (demo) — НЕ потрібен для інтеграції
- `reset.css` — НЕ потрібен (у garden-bloom є свій)
- Внутрішні inline стилі — встановлюються через JS

---

## 5. Integration Feasibility Report

### Варіант A: Direct Integration (РЕКОМЕНДОВАНО)

**Опис:** Імпорт drakonwidget.js напряму, обгортка React компонентом з useRef + useEffect

```
Плюси:
+ Повний контроль над lifecycle
+ Найкращий performance
+ Доступ до всіх API методів
+ Можливість кастомізації theme під garden-bloom
+ Мінімальний bundle overhead

Мінуси:
- Потрібен TypeScript declaration file (.d.ts)
- Ручне управління DOM mount/unmount
- CSS ізоляція потрібна вручну
- Великий файл (1.4 MB) потребує code splitting

Ризики:
- Memory leaks при неправильному cleanup
- Event listener conflicts з React
- Canvas rendering vs React re-renders
```

**Оцінка складності:** СЕРЕДНЯ
**Рекомендація:** ДЛЯ MVP

### Варіант B: IFrame Integration

**Опис:** Завантажити DRAKON widget в iframe, комунікація через postMessage

```
Плюси:
+ Повна CSS/JS ізоляція
+ Простота реалізації
+ Жодних конфліктів з React

Мінуси:
- Performance overhead (окремий browsing context)
- Складна комунікація (postMessage API)
- Не можна стилізувати під garden-bloom theme
- Складний responsive design
- Проблеми з accessibility

Ризики:
- Cross-origin issues при деплоі
- Складнощі з keyboard shortcuts
```

**Оцінка складності:** НИЗЬКА
**Рекомендація:** ДЛЯ ПРОТОТИПУ (але не для production)

### Варіант C: Web Component

**Опис:** Обгорнути DRAKON widget у Custom Element, використати в React

```
Плюси:
+ Shadow DOM для CSS ізоляції
+ Standard-based підхід
+ Можна reuse в інших проєктах

Мінуси:
- Складність створення Web Component обгортки
- React + Custom Elements має нюанси (event handling)
- Додатковий рівень абстракції
- Shadow DOM ускладнює дебаг

Ризики:
- Browser compatibility (minor)
- Event propagation issues
```

**Оцінка складності:** ВИСОКА
**Рекомендація:** ДЛЯ PRODUCTION (якщо потрібна повна ізоляція)

### Варіант D: Мікрофронтенд (Module Federation)

**Опис:** Окремий Vite build для DRAKON, підключення через Module Federation

```
Плюси:
+ Повна ізоляція builds
+ Можна деплоїти окремо
+ Code splitting з коробки

Мінуси:
- Надмірна складність для одного віджета
- Vite Module Federation ще unstable
- Окремий деплой та CI/CD
- Overhead для користувача (завантаження окремого bundle)

Ризики:
- Vite Module Federation breaking changes
- Складність rollback
```

**Оцінка складності:** ДУЖЕ ВИСОКА
**Рекомендація:** OVERENGINEERING — НЕ рекомендовано

---

## 6. Рекомендований підхід: Direct Integration з Lazy Loading

### Стратегія

1. **Скопіювати `drakonwidget.js`** до `public/libs/drakonwidget.js`
2. **Створити TypeScript declaration** `src/types/drakonwidget.d.ts`
3. **Динамічний імпорт** через `<script>` tag або `import()` wrapper
4. **React wrapper** з `useRef` + `useEffect` для mount/unmount
5. **CSS scoping** через контейнер з `isolation: isolate` та scoped reset

### Адаптер для завантаження

```typescript
// src/lib/drakon/loader.ts
let widgetPromise: Promise<typeof createDrakonWidget> | null = null;

export function loadDrakonWidget(): Promise<typeof createDrakonWidget> {
  if (widgetPromise) return widgetPromise;

  widgetPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = '/libs/drakonwidget.js';
    script.onload = () => resolve(window.createDrakonWidget);
    script.onerror = reject;
    document.head.appendChild(script);
  });

  return widgetPromise;
}
```

---

## 7. Ризики та мітигація

| Ризик | Severity | Мітигація |
|-------|----------|-----------|
| Memory leaks при React unmount | HIGH | Строгий cleanup в useEffect return |
| CSS конфлікти з Tailwind | MEDIUM | Container з CSS isolation + scoped reset |
| 1.4 MB bundle size | MEDIUM | Lazy loading + dynamic import |
| Відсутність TypeScript types | LOW | Створити .d.ts файл |
| Canvas resize при responsive | MEDIUM | ResizeObserver + debounce redraw |
| Event conflicts (keyboard) | LOW | Mousetrap scoping або focus-based |
| XSS через diagram content | HIGH | Sanitize content перед рендерингом |
| No SSR support | NONE | Garden-bloom — SPA, SSR не потрібен |

---

## 8. Висновок

DrakonWidget — зріла, стабільна бібліотека з нульовими залежностями та відкритою ліцензією. Основні виклики інтеграції: великий розмір файлу, відсутність TypeScript типів та ESM модулів, потреба в CSS ізоляції.

**Рекомендований варіант: Direct Integration з lazy loading та React wrapper.**


---

## Семантичні зв'язки

**Цей документ є частиною:**
- [[DRAKON_ІНТЕГРАЦІЯ_ТА_МОДЕЛЬ_ВИКОНАННЯ_АГЕНТА]] — технічний фундамент інтеграції

**Цей документ залежить від:**
- [[DRAKON_ІНТЕГРАЦІЯ_ТА_МОДЕЛЬ_ВИКОНАННЯ_АГЕНТА]] — специфікує що треба інтегрувати

**Від цього документа залежають:**
- [[СТРАТЕГІЯ_ІНТЕГРАЦІЇ]] — стратегія базується на цьому дослідженні
- [[АНАЛІЗ_ПРОЕКТУ]] — аналіз використовує результати дослідження

---

*Цей документ містить технічне дослідження DrakonWidget для інтеграції у Garden Bloom.*
