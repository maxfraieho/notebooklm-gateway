// React hooks for tag data consumption
import { useMemo } from 'react';
import {
  getAllTags,
  getNotesByTag,
  tagExists,
  TagInfo,
  TaggedNote,
} from '@/lib/notes/tagResolver';

/**
 * Hook to get all unique tags with note counts
 */
export function useAllTags(): TagInfo[] {
  return useMemo(() => getAllTags(), []);
}

/**
 * Hook to get all notes for a specific tag
 */
export function useNotesByTag(tag: string): TaggedNote[] {
  return useMemo(() => getNotesByTag(tag), [tag]);
}

/**
 * Hook to check if a tag exists
 */
export function useTagExists(tag: string): boolean {
  return useMemo(() => tagExists(tag), [tag]);
}

/**
 * Hook to get tag statistics
 */
export function useTagStats(): { totalTags: number; mostUsedTag: TagInfo | null } {
  return useMemo(() => {
    const tags = getAllTags();
    const mostUsedTag = tags.reduce<TagInfo | null>(
      (max, tag) => (!max || tag.noteCount > max.noteCount ? tag : max),
      null
    );
    return {
      totalTags: tags.length,
      mostUsedTag,
    };
  }, []);
}
