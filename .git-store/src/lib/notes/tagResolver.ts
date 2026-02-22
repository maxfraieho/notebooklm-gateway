// Tag resolution and aggregation for Digital Garden notes
import { Note } from './types';
import { getAllNotes } from './noteLoader';

export interface TagInfo {
  tag: string;
  noteCount: number;
}

export interface TaggedNote {
  slug: string;
  title: string;
  updated?: string;
}

/**
 * Get all unique tags from published notes
 * Respects visibility rules (excludes dg_publish: false)
 */
export function getAllTags(): TagInfo[] {
  const notes = getAllNotes();
  const tagCounts = new Map<string, number>();

  notes.forEach((note) => {
    // Respect visibility: skip unpublished notes
    if (note.frontmatter.dg_publish === false) {
      return;
    }

    const tags = note.frontmatter.tags || [];
    tags.forEach((tag) => {
      const normalizedTag = tag.toLowerCase().trim();
      tagCounts.set(normalizedTag, (tagCounts.get(normalizedTag) || 0) + 1);
    });
  });

  return Array.from(tagCounts.entries())
    .map(([tag, noteCount]) => ({ tag, noteCount }))
    .sort((a, b) => a.tag.localeCompare(b.tag));
}

/**
 * Get all notes that have a specific tag
 * Respects visibility rules (excludes dg_publish: false)
 */
export function getNotesByTag(tag: string): TaggedNote[] {
  const notes = getAllNotes();
  const normalizedSearchTag = tag.toLowerCase().trim();

  return notes
    .filter((note) => {
      // Respect visibility: skip unpublished notes
      if (note.frontmatter.dg_publish === false) {
        return false;
      }

      const noteTags = note.frontmatter.tags || [];
      return noteTags.some(
        (t) => t.toLowerCase().trim() === normalizedSearchTag
      );
    })
    .map((note) => ({
      slug: note.slug,
      title: note.title,
      updated: note.frontmatter.updated,
    }))
    .sort((a, b) => a.title.localeCompare(b.title));
}

/**
 * Check if a tag exists (has at least one published note)
 */
export function tagExists(tag: string): boolean {
  return getNotesByTag(tag).length > 0;
}

/**
 * Get tags for a specific note
 */
export function getTagsForNote(note: Note): string[] {
  return (note.frontmatter.tags || []).map((t) => t.toLowerCase().trim());
}
