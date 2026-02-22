// React hooks for search functionality
import { useState, useMemo, useCallback } from 'react';
import { searchNotes, SearchResult, getSearchableNoteCount } from '@/lib/notes/searchResolver';

/**
 * Hook for searching notes with debounced query
 */
export function useSearch() {
  const [query, setQuery] = useState('');
  
  const results = useMemo<SearchResult[]>(() => {
    return searchNotes(query);
  }, [query]);
  
  const clearSearch = useCallback(() => {
    setQuery('');
  }, []);
  
  return {
    query,
    setQuery,
    results,
    clearSearch,
    hasResults: results.length > 0,
    isSearching: query.trim().length > 0,
  };
}

/**
 * Hook for getting searchable note count
 */
export function useSearchableNoteCount(): number {
  return useMemo(() => getSearchableNoteCount(), []);
}
