# DrakonWidget Integration

## Purpose

This module provides integration with the DrakonWidget library for rendering DRAKON flowchart diagrams within markdown notes.

## Files

- `adapter.ts` — Dynamic script loader + createWidget wrapper (singleton pattern)
- `themeAdapter.ts` — Maps garden-bloom dark/light theme to DrakonWidget theme colors
- `types.ts` — StoredDrakonDiagram, DrakonBlockParams, parseDrakonDirective helper

## Usage

DRAKON diagrams are embedded in markdown using the directive syntax:

```markdown
:::drakon id="diagram-name" height="400" mode="view":::
```

The diagram JSON file must exist at:
`/site/notes/{noteSlug}/diagrams/{id}.drakon.json`

## Architecture

1. `NoteRenderer.tsx` detects `:::drakon:::` blocks and transforms them to markers
2. `DrakonDiagramBlock.tsx` loads the diagram JSON and lazy-loads `DrakonViewer`
3. `DrakonViewer.tsx` initializes the widget with proper theme and renders to canvas
4. `drakonwidget.js` is loaded dynamically from `/libs/` (not bundled)

## TypeScript Types

Full API declarations are in `src/types/drakonwidget.d.ts`.

## CSS Isolation

The `.drakon-container` class provides CSS isolation to prevent Tailwind resets from affecting the widget's internal styles. See `src/index.css`.
