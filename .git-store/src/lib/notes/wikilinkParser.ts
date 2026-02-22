// Wikilink parsing utilities for Obsidian-style [[links]]

import type { NoteLink } from './types';
import { noteExists } from './noteLoader';

// Regex to match [[target]] or [[target|alias]]
const WIKILINK_REGEX = /\[\[([^\]]+)\]\]/g;

/**
 * Strip fenced and inline code blocks before wikilink extraction.
 * Matches graphContract.ts / check-graph.py contract §2.1.
 */
function stripCodeBlocks(text: string): string {
  let result = text.replace(/```[\s\S]*?```/g, '');
  result = result.replace(/`[^`\n]+`/g, '');
  return result;
}

export interface ParsedWikilink {
  fullMatch: string;
  target: string;
  alias: string | null;
  exists: boolean;
}

/**
 * Parse inner wikilink content into target and alias.
 * Handles: [[target]], [[target|alias]], [[path\|alias]]
 */
function parseInner(inner: string): { target: string; alias: string | null } {
  if (inner.includes('\\|')) {
    // Backslash-pipe: [[exodus.pp.ua/path/FILE\|ALIAS]]
    const [pathPart, aliasPart] = inner.split('\\|', 2);
    const stem = pathPart.includes('/')
      ? pathPart.split('/').pop() || pathPart
      : pathPart;
    return { target: stem.trim(), alias: aliasPart?.trim() || null };
  }
  if (inner.includes('|')) {
    // Clean alias: [[target|alias]]
    const [targetPart, aliasPart] = inner.split('|', 2);
    return { target: targetPart.trim(), alias: aliasPart?.trim() || null };
  }
  // Simple: [[target]]
  return { target: inner.trim(), alias: null };
}

/**
 * Parse all wikilinks from a markdown string
 */
export function parseWikilinks(content: string): ParsedWikilink[] {
  const body = stripCodeBlocks(content);
  const links: ParsedWikilink[] = [];
  let match: RegExpExecArray | null;

  WIKILINK_REGEX.lastIndex = 0;

  while ((match = WIKILINK_REGEX.exec(body)) !== null) {
    const { target, alias } = parseInner(match[1]);
    const slug = slugify(target);

    links.push({
      fullMatch: match[0],
      target: slug,
      alias,
      exists: noteExists(slug),
    });
  }

  return links;
}

/**
 * Convert a wikilink target to a slug matching noteLoader's pathToSlug format.
 * Wikilink targets can be:
 *   - Full paths: "exodus.pp.ua/architecture/ARCHITECTURE_ROOT"
 *   - Short names: "ARCHITECTURE_ROOT"
 * The noteLoader stores slugs as encodeURIComponent of the file path (without .md).
 * So we just trim and encodeURIComponent the target as-is.
 */
export function slugify(text: string): string {
  const trimmed = text.trim();
  // If it looks like a path (contains /), encode the whole path
  if (trimmed.includes('/')) {
    return encodeURIComponent(trimmed);
  }
  // Short name — try to match as-is (encoded)
  return encodeURIComponent(trimmed);
}

/**
 * Transform markdown content, replacing wikilinks with placeholder tokens
 * that will be handled by the React component
 */
export function transformWikilinks(content: string): string {
  const body = stripCodeBlocks(content);
  return body.replace(WIKILINK_REGEX, (fullMatch, inner) => {
    const { target, alias } = parseInner(inner);
    const slug = slugify(target);
    const displayText = alias || target;
    const exists = noteExists(slug);
    
    // Format: %%WIKILINK:slug:displayText:exists%%
    return `%%WIKILINK:${slug}:${displayText}:${exists}%%`;
  });
}

/**
 * Parse a wikilink marker back to its components
 */
export function parseWikilinkMarker(marker: string): ParsedWikilink | null {
  const regex = /%%WIKILINK:([^:]+):([^:]+):(true|false)%%/;
  const match = marker.match(regex);
  
  if (!match) return null;
  
  return {
    fullMatch: marker,
    target: match[1],
    alias: match[2],
    exists: match[3] === 'true',
  };
}
