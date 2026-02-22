// Link relationship resolver and graph data model
// Uses graphContract.ts as single source-of-truth for parsing/resolution

import type { Note } from './types';
import { getAllNotes, noteExists, getNoteBySlug } from './noteLoader';
import {
  buildGraphFromNotes,
  GRAPH_CONTRACT_VERSION,
  type GraphSnapshot,
  type SnapshotNode,
  type SnapshotEdge,
  type GraphDiagnostics,
} from './graphContract';

// ── Re-export types for consumers ──

export interface GraphNode {
  slug: string;
  title: string;
  exists: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  type?: 'structural' | 'semantic' | 'navigational';
  weight?: number;
  importance?: number;
  defaultVisible?: boolean;
}

export interface LocalGraph {
  center: GraphNode;
  outbound: GraphNode[];
  inbound: GraphNode[];
  edges: GraphEdge[];
}

export interface Backlink {
  slug: string;
  title: string;
}

// ── Snapshot loading ──

let cachedSnapshot: GraphSnapshot | null = null;

/**
 * Try to load graph.snapshot.json from public/
 * Falls back to client-parse if not available
 */
async function tryLoadSnapshot(): Promise<GraphSnapshot | null> {
  try {
    const resp = await fetch('/graph.snapshot.json');
    if (!resp.ok) return null;
    const data = await resp.json() as GraphSnapshot;
    // Validate contract version
    if (data.contractVersion !== GRAPH_CONTRACT_VERSION) {
      console.warn(`[graph] Snapshot version mismatch: ${data.contractVersion} vs ${GRAPH_CONTRACT_VERSION}, falling back to client-parse`);
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

/**
 * Get the graph snapshot — snapshot if available, otherwise client-parse
 */
function getSnapshot(): GraphSnapshot {
  if (!cachedSnapshot) {
    cachedSnapshot = buildGraphFromNotes();
  }
  return cachedSnapshot;
}

/**
 * Initialize snapshot (try loading from file, fallback to client-parse)
 * Call this once on app startup
 */
export async function initGraphSnapshot(): Promise<GraphSnapshot> {
  const snapshot = await tryLoadSnapshot();
  if (snapshot) {
    cachedSnapshot = snapshot;
    console.info(`[graph] Using snapshot (${snapshot.diagnostics.totalNodes} nodes, ${snapshot.diagnostics.totalEdges} edges)`);
  } else {
    cachedSnapshot = buildGraphFromNotes();
    console.info(`[graph] Client-parse (${cachedSnapshot.diagnostics.totalNodes} nodes, ${cachedSnapshot.diagnostics.totalEdges} edges)`);
  }
  return cachedSnapshot;
}

// ── Cache invalidation ──

export function invalidateLinkCache(): void {
  cachedSnapshot = null;
}

// ── Public API ──

export function getOutboundLinks(noteSlug: string): string[] {
  const snapshot = getSnapshot();
  return snapshot.edges
    .filter(e => e.source === noteSlug)
    .map(e => e.target);
}

export function getBacklinks(noteSlug: string): Backlink[] {
  const snapshot = getSnapshot();
  const inboundSlugs = snapshot.edges
    .filter(e => e.target === noteSlug)
    .map(e => e.source);
  
  const nodeMap = new Map(snapshot.nodes.map(n => [n.slug, n]));
  
  return inboundSlugs
    .map(slug => {
      const node = nodeMap.get(slug);
      if (!node) return null;
      return { slug: node.slug, title: node.title };
    })
    .filter((b): b is Backlink => b !== null);
}

export function getLocalGraph(noteSlug: string): LocalGraph | null {
  const snapshot = getSnapshot();
  const nodeMap = new Map(snapshot.nodes.map(n => [n.slug, n]));
  const centerNode = nodeMap.get(noteSlug);
  
  if (!centerNode) return null;
  
  const center: GraphNode = {
    slug: centerNode.slug,
    title: centerNode.title,
    exists: true,
  };
  
  // Outbound
  const outboundSlugs = snapshot.edges
    .filter(e => e.source === noteSlug)
    .map(e => e.target);
  
  const outbound: GraphNode[] = outboundSlugs.map(slug => {
    const node = nodeMap.get(slug);
    return {
      slug,
      title: node?.title || slug,
      exists: !!node,
    };
  });
  
  // Inbound
  const inboundSlugs = snapshot.edges
    .filter(e => e.target === noteSlug)
    .map(e => e.source);
  
  const inbound: GraphNode[] = inboundSlugs
    .map(slug => {
      const node = nodeMap.get(slug);
      if (!node) return null;
      return { slug, title: node.title, exists: true };
    })
    .filter((n): n is GraphNode => n !== null);
  
  const edges: GraphEdge[] = [
    ...outboundSlugs.map(target => ({ source: noteSlug, target })),
    ...inbound.map(node => ({ source: node.slug, target: noteSlug })),
  ];
  
  return { center, outbound, inbound, edges };
}

export function getFullGraph(): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const snapshot = getSnapshot();
  
  const nodes: GraphNode[] = snapshot.nodes.map(n => ({
    slug: n.slug,
    title: n.title,
    exists: n.exists,
  }));
  
  const edges: GraphEdge[] = snapshot.edges.map(e => ({
    source: e.source,
    target: e.target,
    type: e.type,
    weight: e.weight,
    importance: e.importance,
    defaultVisible: e.defaultVisible,
  }));
  
  return { nodes, edges };
}

/**
 * Get diagnostics for the debug panel
 */
export function getGraphDiagnostics(): GraphDiagnostics & { source: string; contractVersion: string } {
  const snapshot = getSnapshot();
  return {
    ...snapshot.diagnostics,
    source: snapshot.source,
    contractVersion: snapshot.contractVersion,
  };
}
