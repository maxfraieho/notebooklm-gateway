// Runtime search resolver for Digital Garden notes
// Performs case-insensitive, partial substring matching

import type { Note } from './types';
import { getAllNotes } from './noteLoader';

export interface SearchResult {
  slug: string;
  title: string;
  excerpt: string;
}

/**
 * Search notes by query string
 * Matches against title and raw content (case-insensitive, partial match)
 * Respects visibility rules (excludes dg_publish: false)
 * 
 * @param query - The search query string
 * @param maxExcerptLength - Maximum length of content excerpt (default: 150)
 * @returns Array of matching notes with excerpts
 */
export function searchNotes(query: string, maxExcerptLength = 150): SearchResult[] {
  const normalizedQuery = query.toLowerCase().trim();
  
  // Empty query returns no results
  if (!normalizedQuery) {
    return [];
  }
  
  const notes = getAllNotes();
  const results: SearchResult[] = [];
  
  for (const note of notes) {
    // Respect visibility: skip unpublished notes
    if (note.frontmatter.dg_publish === false) {
      continue;
    }
    
    const titleMatch = note.title.toLowerCase().includes(normalizedQuery);
    const contentMatch = note.content.toLowerCase().includes(normalizedQuery);
    
    if (titleMatch || contentMatch) {
      results.push({
        slug: note.slug,
        title: note.title,
        excerpt: generateExcerpt(note.content, maxExcerptLength),
      });
    }
  }
  
  // Sort: title matches first, then alphabetically
  return results.sort((a, b) => {
    const aTitle = a.title.toLowerCase().includes(normalizedQuery);
    const bTitle = b.title.toLowerCase().includes(normalizedQuery);
    
    if (aTitle && !bTitle) return -1;
    if (!aTitle && bTitle) return 1;
    return a.title.localeCompare(b.title);
  });
}

/**
 * Generate a clean excerpt from markdown content
 */
function generateExcerpt(content: string, maxLength: number): string {
  // Strip markdown syntax for cleaner excerpt
  const plainText = content
    // Remove headers
    .replace(/^#{1,6}\s+/gm, '')
    // Remove bold/italic
    .replace(/\*{1,2}([^*]+)\*{1,2}/g, '$1')
    .replace(/_{1,2}([^_]+)_{1,2}/g, '$1')
    // Remove wikilinks, keep display text or target
    .replace(/\[\[([^\]|]+)\|([^\]]+)\]\]/g, '$2')
    .replace(/\[\[([^\]]+)\]\]/g, '$1')
    // Remove regular links, keep text
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    // Remove blockquotes
    .replace(/^>\s+/gm, '')
    // Remove horizontal rules
    .replace(/^---+$/gm, '')
    // Remove code blocks
    .replace(/```[\s\S]*?```/g, '')
    .replace(/`([^`]+)`/g, '$1')
    // Collapse whitespace
    .replace(/\s+/g, ' ')
    .trim();
  
  if (plainText.length <= maxLength) {
    return plainText;
  }
  
  // Truncate at word boundary
  const truncated = plainText.slice(0, maxLength);
  const lastSpace = truncated.lastIndexOf(' ');
  
  return (lastSpace > 0 ? truncated.slice(0, lastSpace) : truncated) + '…';
}

/**
 * Get total count of searchable notes
 */
export function getSearchableNoteCount(): number {
  return getAllNotes().filter(note => note.frontmatter.dg_publish !== false).length;
}
