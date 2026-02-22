// Runtime note loader for Digital Garden
// Loads real Markdown files from src/site/notes

import type { Note, NoteFrontmatter } from './types';

// Import all markdown files from src/site/notes
// Use a getter function to always get fresh modules
function getNoteModules(): Record<string, string> {
  return import.meta.glob('/src/site/notes/**/*.md', { 
    query: '?raw', 
    import: 'default',
    eager: true 
  }) as Record<string, string>;
}

interface ParsedFrontmatter extends NoteFrontmatter {
  'dg-publish'?: boolean;
  'dg-home'?: boolean;
  permalink?: string;
}

interface FolderInfo {
  name: string;
  path: string;
  notes: { slug: string; title: string; isHome: boolean }[];
  subfolders: FolderInfo[];
}

// Parse frontmatter from markdown content (JSON or YAML style)
function parseFrontmatter(content: string): { frontmatter: ParsedFrontmatter; body: string } {
  const frontmatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/);
  
  if (!frontmatterMatch) {
    return { frontmatter: {}, body: content };
  }
  
  const frontmatterStr = frontmatterMatch[1].trim();
  const body = frontmatterMatch[2];
  
  // Try parsing as JSON first (Obsidian Digital Garden plugin format)
  try {
    const parsed = JSON.parse(frontmatterStr);
    return { frontmatter: parsed, body };
  } catch {
    // Fall back to YAML-style parsing
    const frontmatter: ParsedFrontmatter = {};
    const lines = frontmatterStr.split('\n');
    
    for (const line of lines) {
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        const key = line.slice(0, colonIndex).trim();
        let value: unknown = line.slice(colonIndex + 1).trim();
        
        // Parse boolean/null values
        if (value === 'true') value = true;
        else if (value === 'false') value = false;
        else if (value === 'null') value = null;
        // Parse arrays (simple format: [item1, item2])
        else if (typeof value === 'string' && value.startsWith('[') && value.endsWith(']')) {
          try {
            value = JSON.parse(value);
          } catch {
            // Keep as string if parse fails
          }
        }
        // Remove quotes
        else if (typeof value === 'string' && value.startsWith('"') && value.endsWith('"')) {
          value = value.slice(1, -1);
        }
        
        (frontmatter as Record<string, unknown>)[key] = value;
      }
    }
    
    return { frontmatter, body };
  }
}

// Generate slug from file path
function pathToSlug(filePath: string): string {
  // Remove /src/site/notes/ prefix and .md suffix
  const cleanPath = filePath
    .replace('/src/site/notes/', '')
    .replace('.md', '');
  
  // URL-encode the path to handle Cyrillic and special characters
  return encodeURIComponent(cleanPath);
}

// Get folder path from file path
function getFolderPath(filePath: string): string {
  const cleanPath = filePath.replace('/src/site/notes/', '').replace('.md', '');
  const lastSlash = cleanPath.lastIndexOf('/');
  return lastSlash > 0 ? cleanPath.slice(0, lastSlash) : '';
}

// Build notes from imported modules
let notesCache: Note[] | null = null;
let homeNoteSlug: string | null = null;
let notesCacheSignature: string | null = null;

function quickHash(input: string): number {
  // Fast, low-collision-ish hash for change detection (samples content)
  let hash = 2166136261;
  const step = 97;
  for (let i = 0; i < input.length; i += step) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  hash ^= input.length;
  return hash >>> 0;
}

function computeModulesSignature(modules: Record<string, string>): string {
  const entries = Object.entries(modules);
  return entries
    .map(([filePath, raw]) => `${filePath}:${quickHash(raw)}`)
    .join('|');
}

function buildNotesCache(): Note[] {
  const noteModules = getNoteModules();
  const signature = computeModulesSignature(noteModules);

  // If markdown changed (HMR / edit / add / delete), rebuild cache
  if (notesCache && notesCacheSignature === signature) return notesCache;

  const notes: Note[] = [];
  homeNoteSlug = null;

  for (const [filePath, rawContent] of Object.entries(noteModules)) {
    const { frontmatter, body } = parseFrontmatter(rawContent);

    // Respect dg-publish visibility
    if (frontmatter['dg-publish'] === false) {
      continue;
    }

    const slug = pathToSlug(filePath);
    const title = frontmatter.title || filePath.split('/').pop()?.replace('.md', '') || slug;

    // Track home note
    if (frontmatter['dg-home'] === true) {
      homeNoteSlug = slug;
    }

    // Normalize frontmatter keys for internal use
    const normalizedFrontmatter: NoteFrontmatter = {
      ...frontmatter,
      dg_publish: frontmatter['dg-publish'],
      tags: frontmatter.tags || [],
    };

    notes.push({
      slug,
      title,
      content: body.trim(),
      frontmatter: normalizedFrontmatter,
      rawContent,
    });
  }

  notesCache = notes;
  notesCacheSignature = signature;
  return notes;
}

// Public API

export function getAllNotes(): Note[] {
  return buildNotesCache();
}

export function getNoteBySlug(slug: string): Note | null {
  const notes = buildNotesCache();

  const decodedSlug = decodeURIComponent(slug);
  const normalize = (s: string) => s.trim().replace(/\.+$/, '');

  const decodedNormalized = normalize(decodedSlug);
  const encodedNormalized = encodeURIComponent(decodedNormalized);

  const candidates = new Set([slug, decodedSlug, encodedNormalized, decodedNormalized]);

  // Try exact match first (including decoded comparisons)
  let note = notes.find((n) => {
    const nDecoded = decodeURIComponent(n.slug);
    return candidates.has(n.slug) || candidates.has(nDecoded);
  });

  // Try case-insensitive match
  if (!note) {
    const candidateLower = Array.from(candidates).map((c) => c.toLowerCase());
    note = notes.find((n) => {
      const nDecodedLower = decodeURIComponent(n.slug).toLowerCase();
      const nSlugLower = n.slug.toLowerCase();
      return candidateLower.includes(nSlugLower) || candidateLower.includes(nDecodedLower);
    });
  }

  // Fallback: match by filename (last path segment) for short wikilinks
  // e.g. [[ARCHITECTURE_ROOT]] should match exodus.pp.ua/architecture/ARCHITECTURE_ROOT
  if (!note) {
    const searchName = decodedNormalized.toLowerCase();
    note = notes.find((n) => {
      const decoded = decodeURIComponent(n.slug);
      const filename = decoded.split('/').pop() || decoded;
      return filename.toLowerCase() === searchName;
    });
  }

  return note || null;
}

export function noteExists(slug: string): boolean {
  return getNoteBySlug(slug) !== null;
}

export function getAllSlugs(): string[] {
  return buildNotesCache().map(n => n.slug);
}

export function getHomeNote(): Note | null {
  buildNotesCache();
  return homeNoteSlug ? getNoteBySlug(homeNoteSlug) : null;
}

export function getHomeNoteSlug(): string | null {
  buildNotesCache();
  return homeNoteSlug;
}

// Folder navigation structure
export function getFolderStructure(): FolderInfo[] {
  const notes = buildNotesCache();
  const folderMap = new Map<string, FolderInfo>();
  
  // Build folder structure
  for (const note of notes) {
    const decodedSlug = decodeURIComponent(note.slug);
    const parts = decodedSlug.split('/');
    
    // Build path progressively
    let currentPath = '';
    let parentFolder: FolderInfo | null = null;
    
    for (let i = 0; i < parts.length - 1; i++) {
      const folderName = parts[i];
      const newPath = currentPath ? `${currentPath}/${folderName}` : folderName;
      
      if (!folderMap.has(newPath)) {
        const folderInfo: FolderInfo = {
          name: folderName,
          path: newPath,
          notes: [],
          subfolders: [],
        };
        folderMap.set(newPath, folderInfo);
        
        // Add to parent
        if (parentFolder) {
          if (!parentFolder.subfolders.find(f => f.path === newPath)) {
            parentFolder.subfolders.push(folderInfo);
          }
        }
      }
      
      parentFolder = folderMap.get(newPath)!;
      currentPath = newPath;
    }
    
    // Add note to its folder
    if (parentFolder) {
      const isHome = note.frontmatter['dg-home'] === true || 
                     (note.frontmatter as ParsedFrontmatter)['dg-home'] === true;
      parentFolder.notes.push({
        slug: note.slug,
        title: note.title,
        isHome,
      });
    }
  }
  
  // Get root folders only
  const rootFolders: FolderInfo[] = [];
  for (const [path, folder] of folderMap) {
    if (!path.includes('/')) {
      rootFolders.push(folder);
    }
  }
  
  return rootFolders.sort((a, b) => a.name.localeCompare(b.name));
}

// Invalidate cache (useful for hot reloading)
export function invalidateNotesCache(): void {
  notesCache = null;
  homeNoteSlug = null;
}
