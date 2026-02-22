// Mock notes data - Content source abstraction layer
// In production, this would be replaced with Supabase or API calls

import type { Note } from './types';

const mockNotesData: Record<string, { content: string; frontmatter: Record<string, unknown> }> = {
  'welcome': {
    frontmatter: {
      title: 'Welcome to the Digital Garden',
      created: '2024-01-15',
      updated: '2024-03-20',
      tags: ['meta', 'introduction'],
    },
    content: `
# Welcome to the Digital Garden

This is a **living collection of notes**, ideas, and thoughts that grow and evolve over time.

## What is a Digital Garden?

Unlike a traditional blog with polished, finished articles, a digital garden is a space for:

- **Seedlings** — raw ideas, just planted
- **Budding notes** — developing thoughts with some structure
- **Evergreen notes** — mature ideas, well-connected

## Navigation

You can navigate between notes using internal links like [[evergreen-notes]] or explore the concept of [[wikilinks-explained|wikilinks]].

> "A garden is never finished. It's a living thing that changes and grows." — Unknown

## Getting Started

Check out these foundational notes:

1. [[evergreen-notes]] — The core concept
2. [[wikilinks-explained|How wikilinks work]]
3. [[nonexistent-note|A broken link example]]

---

*This garden is tended with care. New notes are added regularly.*
`
  },
  'evergreen-notes': {
    frontmatter: {
      title: 'Evergreen Notes',
      created: '2024-01-20',
      updated: '2024-02-15',
      tags: ['methodology', 'writing', 'knowledge-management'],
    },
    content: `
# Evergreen Notes

Evergreen notes are written and organized to **develop, evolve, and accumulate** over time, across projects.

## Core Principles

### 1. Atomic Ideas

Each note should capture **one idea** completely. This makes notes easier to connect and remix.

### 2. Concept-Oriented

Notes should be organized around concepts, not sources or projects.

### 3. Densely Linked

The power of evergreen notes comes from their connections. See [[wikilinks-explained]] for how to create links.

## Benefits

- **Compound interest** for your knowledge
- Forces you to **think clearly**
- Creates a personal knowledge graph

## Related Notes

- [[welcome|Back to Welcome]]
- [[wikilinks-explained|Wikilinks Explained]]

---

*Reference: Inspired by Andy Matuschak's work on evergreen notes.*
`
  },
  'wikilinks-explained': {
    frontmatter: {
      title: 'Understanding Wikilinks',
      created: '2024-02-01',
      tags: ['syntax', 'linking'],
    },
    content: `
# Understanding Wikilinks

Wikilinks are the **connective tissue** of a digital garden. They create pathways between ideas.

## Syntax

There are two forms:

### Basic Link
\`[[note-slug]]\` — Links to a note using its slug

Example: [[evergreen-notes]]

### Aliased Link
\`[[note-slug|Display Text]]\` — Links with custom display text

Example: [[welcome|Return to the garden entrance]]

## Broken Links

When a note doesn't exist, the link should still render but appear differently. Try this: [[this-note-does-not-exist|A missing note]]

Broken links are actually useful — they show you **what you haven't written yet**.

## Best Practices

1. Link liberally as you write
2. Use aliases for readability
3. Don't fear broken links
4. Let connections emerge naturally

---

*See also: [[evergreen-notes]]*
`
  }
};

// Content source abstraction
export function getAllNotes(): Note[] {
  return Object.entries(mockNotesData).map(([slug, data]) => ({
    slug,
    title: (data.frontmatter.title as string) || slug,
    content: data.content.trim(),
    frontmatter: data.frontmatter,
    rawContent: data.content,
  }));
}

export function getNoteBySlug(slug: string): Note | null {
  const normalizedSlug = slug.toLowerCase().trim();
  const data = mockNotesData[normalizedSlug];
  
  if (!data) return null;
  
  return {
    slug: normalizedSlug,
    title: (data.frontmatter.title as string) || normalizedSlug,
    content: data.content.trim(),
    frontmatter: data.frontmatter,
    rawContent: data.content,
  };
}

export function noteExists(slug: string): boolean {
  return slug.toLowerCase().trim() in mockNotesData;
}

export function getAllSlugs(): string[] {
  return Object.keys(mockNotesData);
}
