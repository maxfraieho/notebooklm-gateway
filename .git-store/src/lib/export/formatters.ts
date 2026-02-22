// Export formatters for AI context export

import type { Note } from '@/lib/notes/types';
import type { CommentExportOptions } from '@/lib/comments/types';

export interface ExportOptions {
  includeMetadata: boolean;
  includeContent: boolean;
  commentOptions?: CommentExportOptions;
}

// Format notes as Markdown with YAML frontmatter (best for Claude, ChatGPT)
export function formatMarkdown(notes: Note[], options: ExportOptions): string {
  return notes
    .map((note) => {
      const lines: string[] = ['---'];
      
      lines.push(`title: "${note.title}"`);
      
      if (options.includeMetadata) {
        if (note.frontmatter.created) {
          lines.push(`created: ${note.frontmatter.created}`);
        }
        if (note.frontmatter.updated) {
          lines.push(`updated: ${note.frontmatter.updated}`);
        }
        if (note.frontmatter.tags && note.frontmatter.tags.length > 0) {
          lines.push(`tags: [${note.frontmatter.tags.join(', ')}]`);
        }
        // Decode slug to show readable folder path
        const decodedSlug = decodeURIComponent(note.slug);
        const folderPath = decodedSlug.includes('/') 
          ? decodedSlug.substring(0, decodedSlug.lastIndexOf('/'))
          : '';
        if (folderPath) {
          lines.push(`folder: "${folderPath}"`);
        }
      }
      
      // Add comment options to frontmatter if enabled
      if (options.commentOptions) {
        const commentFlags: string[] = [];
        if (options.commentOptions.includeApproved) commentFlags.push('approved');
        if (options.commentOptions.includeMerged) commentFlags.push('merged');
        if (options.commentOptions.includeAnnotations) commentFlags.push('annotations');
        if (commentFlags.length > 0) {
          lines.push(`include_comments: [${commentFlags.join(', ')}]`);
        }
      }
      
      lines.push('---');
      lines.push('');
      
      if (options.includeContent) {
        lines.push(note.content);
        
        // Placeholder for comments section (will be populated by backend/MCP)
        if (options.commentOptions && (options.commentOptions.includeApproved || options.commentOptions.includeMerged)) {
          lines.push('');
          lines.push('<!-- COMMENTS_PLACEHOLDER: Comments will be fetched from API during MCP export -->');
        }
      } else {
        lines.push(`# ${note.title}`);
      }
      
      return lines.join('\n');
    })
    .join('\n\n---\n\n');
}

// Format notes as structured JSON (for API integrations)
export function formatJSON(notes: Note[], options: ExportOptions): string {
  const exportData = {
    export_metadata: {
      exported_at: new Date().toISOString(),
      total_notes: notes.length,
      format_version: '1.0',
      include_comments: options.commentOptions ? {
        approved: options.commentOptions.includeApproved,
        merged: options.commentOptions.includeMerged,
        annotations: options.commentOptions.includeAnnotations,
      } : null,
    },
    notes: notes.map((note) => {
      const decodedSlug = decodeURIComponent(note.slug);
      const folderPath = decodedSlug.includes('/') 
        ? decodedSlug.substring(0, decodedSlug.lastIndexOf('/'))
        : '';
      
      const noteData: Record<string, unknown> = {
        id: note.slug,
        title: note.title,
      };
      
      if (options.includeContent) {
        noteData.content = note.content;
      }
      
      if (options.includeMetadata) {
        noteData.tags = note.frontmatter.tags || [];
        noteData.created = note.frontmatter.created || null;
        noteData.updated = note.frontmatter.updated || null;
        noteData.folder = folderPath || null;
      }
      
      // Placeholder for comments (will be populated by backend/MCP)
      if (options.commentOptions) {
        noteData.comments = []; // Will be fetched from API
        noteData.annotations = []; // Will be fetched from API
      }
      
      return noteData;
    }),
  };
  
  return JSON.stringify(exportData, null, 2);
}

// Format notes as JSON Lines (for batch processing, fine-tuning)
export function formatJSONL(notes: Note[], options: ExportOptions): string {
  return notes
    .map((note) => {
      const decodedSlug = decodeURIComponent(note.slug);
      const folderPath = decodedSlug.includes('/') 
        ? decodedSlug.substring(0, decodedSlug.lastIndexOf('/'))
        : '';
      
      const noteData: Record<string, unknown> = {
        id: note.slug,
        title: note.title,
      };
      
      if (options.includeContent) {
        noteData.content = note.content;
      }
      
      if (options.includeMetadata) {
        noteData.tags = note.frontmatter.tags || [];
        noteData.folder = folderPath || null;
      }
      
      return JSON.stringify(noteData);
    })
    .join('\n');
}

export type ExportFormat = 'markdown' | 'json' | 'jsonl';

export function formatNotes(notes: Note[], format: ExportFormat, options: ExportOptions): string {
  switch (format) {
    case 'markdown':
      return formatMarkdown(notes, options);
    case 'json':
      return formatJSON(notes, options);
    case 'jsonl':
      return formatJSONL(notes, options);
    default:
      return formatMarkdown(notes, options);
  }
}

export function getFileExtension(format: ExportFormat): string {
  switch (format) {
    case 'markdown':
      return 'md';
    case 'json':
      return 'json';
    case 'jsonl':
      return 'jsonl';
    default:
      return 'txt';
  }
}

export function getMimeType(format: ExportFormat): string {
  switch (format) {
    case 'markdown':
      return 'text/markdown';
    case 'json':
      return 'application/json';
    case 'jsonl':
      return 'application/jsonl';
    default:
      return 'text/plain';
  }
}
