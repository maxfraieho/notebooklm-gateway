// React hook for accessing backlinks and local graph data

import { useMemo } from 'react';
import { getBacklinks, getLocalGraph, getOutboundLinks } from '@/lib/notes/linkGraph';
import type { Backlink, LocalGraph } from '@/lib/notes/linkGraph';

/**
 * Hook to get backlinks for a note
 * Returns memoized list of notes that link to the given note
 */
export function useBacklinks(noteSlug: string): Backlink[] {
  return useMemo(() => {
    return getBacklinks(noteSlug);
  }, [noteSlug]);
}

/**
 * Hook to get outbound links for a note
 * Returns memoized list of note slugs that the given note links to
 */
export function useOutboundLinks(noteSlug: string): string[] {
  return useMemo(() => {
    return getOutboundLinks(noteSlug);
  }, [noteSlug]);
}

/**
 * Hook to get the local graph data for a note
 * Returns memoized graph structure with center, outbound, and inbound nodes
 */
export function useLocalGraph(noteSlug: string): LocalGraph | null {
  return useMemo(() => {
    return getLocalGraph(noteSlug);
  }, [noteSlug]);
}

/**
 * Hook to get link statistics for a note
 */
export function useLinkStats(noteSlug: string): {
  outboundCount: number;
  inboundCount: number;
  totalConnections: number;
} {
  return useMemo(() => {
    const outbound = getOutboundLinks(noteSlug);
    const backlinks = getBacklinks(noteSlug);
    
    return {
      outboundCount: outbound.length,
      inboundCount: backlinks.length,
      totalConnections: outbound.length + backlinks.length,
    };
  }, [noteSlug]);
}
