/**
 * Graph Parser Contract v1.1
 *
 * This module implements the SAME graph-building contract as scripts/check-graph.py.
 * It is the single source-of-truth for how the frontend constructs the knowledge graph.
 *
 * Contract summary (matching check-graph.py):
 *
 * 1. NODES: All .md files in src/site/notes/** with dg-publish !== false
 * 2. WIKILINK EXTRACTION: Regex [^\]|#\\] — excludes \, /, # from targets
 * 3. RESOLUTION: stem-based, case-insensitive (filename without extension)
 *    - Exact stem match (case-insensitive)
 *    - If target contains /, extract last segment as stem
 * 4. EDGES: directed (source slug → target slug), deduplicated per source
 * 5. EXCLUSIONS: links with \| (backslash-pipe) are invalid/skipped
 * 6. CODE BLOCKS: fenced (```) and inline (`) code is stripped before parsing
 *
 * @see docs/GRAPH_CONTRACT.md
 */

import type { Note } from './types';
import { getAllNotes } from './noteLoader';

// ── Contract version ──
/** Must match scripts/check-graph.py and public/graph.snapshot.json */
export const GRAPH_CONTRACT_VERSION = '1.1';

// ── Types ──

export interface GraphSnapshot {
  contractVersion: string;
  source: 'snapshot' | 'client-parse';
  generatedAt: string;
  nodes: SnapshotNode[];
  edges: SnapshotEdge[];
  diagnostics: GraphDiagnostics;
}

export interface SnapshotNode {
  slug: string;
  title: string;
  stem: string; // lowercase filename without extension
  exists: boolean;
}

export type EdgeType = 'structural' | 'semantic' | 'navigational';

export interface SnapshotEdge {
  source: string; // slug
  target: string; // slug
  type?: EdgeType;        // Phase 1: heuristic classification
  weight?: number;        // 0–1, default 1
  importance?: number;    // derived score for UX filtering
  defaultVisible?: boolean; // false → hidden until user expands
}

export interface GraphStats {
  avgDegree: number;
  maxDegree: number;
  density: number;           // edges / (nodes*(nodes-1))
  clusteringCoefficient: number;
  hubs: Array<{ slug: string; degree: number; zScore: number }>;
  leaves: string[];          // degree ≤ 1
  components: number;
  largestComponentRatio: number;
  edgeTypeCounts: Record<EdgeType, number>;
}

export interface ResolutionResult {
  resolved: boolean;
  slug?: string;
  step: 'exact-encoded' | 'exact-decoded' | 'case-insensitive-encoded' | 'case-insensitive-decoded' | 'stem-fallback' | 'unresolved';
}

/** Convenience alias for the step union in ResolutionResult */
export type ResolutionStep = ResolutionResult['step'];

export interface GraphDiagnostics {
  totalNodes: number;
  totalEdges: number;
  unresolvedLinks: UnresolvedLink[];
  malformedLinks: MalformedLink[];
  stats?: GraphStats;
}

export interface UnresolvedLink {
  sourceSlug: string;
  sourceTitle: string;
  targetText: string; // raw wikilink text
}

export interface MalformedLink {
  sourceSlug: string;
  sourceTitle: string;
  raw: string;
  reason: 'backslash-pipe' | 'backslash-in-target';
}

// ── Python snapshot file format (public/graph.snapshot.json) ──────────────────

/**
 * Shape of public/graph.snapshot.json as written by:
 *   python3 scripts/check-graph.py --generate-snapshot
 *
 * Snake_case fields match the Python JSON output directly.
 * Distinct from the runtime GraphSnapshot (which uses camelCase + diagnostics).
 */
export interface PythonGraphSnapshot {
  contract_version: string;
  generated: string; // ISO 8601
  node_count: number;
  edge_count: number;
  nodes: Array<{ slug: string; title: string }>;
  edges: Array<{
    source: string;
    target: string;
    type?: EdgeType;
    weight?: number;
    importance?: number | null;
    defaultVisible?: boolean | null;
  }>;
}

/**
 * Full density report from:
 *   python3 scripts/check-graph.py --stats
 *
 * Distinct from the lightweight runtime GraphStats — this is the complete
 * Python-computed output with full degree distributions and topology metrics.
 */
export interface PythonGraphStats {
  contract_version: string;
  timestamp: string;
  source: string;
  node_count: number;
  edge_count: number;
  avg_out_degree: number;
  avg_in_degree: number;
  avg_total_degree: number;
  degree_mean: number;
  degree_stddev: number;
  hub_threshold: number;
  degree_distribution: Record<string, number>;
  in_degree_distribution: Record<string, number>;
  out_degree_distribution: Record<string, number>;
  hubs: Array<{ slug: string; stem: string; title: string; total_degree: number; in_degree: number; out_degree: number; z_score: number }>;
  hub_count: number;
  leaves: Array<{ slug: string; stem: string; title: string; total_degree: number }>;
  leaf_count: number;
  clustering_coefficient: number;
  weak_component_count: number;
  strong_component_count: number;
  largest_weak_component_pct: number;
  redundant_neighborhoods: Array<{ source: string; target: string; jaccard: number; shared_targets: number; union_targets: number }>;
  redundant_neighborhood_count: number;
}

// ── Snapshot utilities ────────────────────────────────────────────────────────

/** True if the Python snapshot version matches current contract. */
export function isPythonSnapshotCompatible(snapshot: PythonGraphSnapshot): boolean {
  return snapshot.contract_version === GRAPH_CONTRACT_VERSION;
}

/** Derive stem from a slug: last path segment, decoded, lowercased. */
export function stemFromSlug(slug: string): string {
  const decoded = decodeURIComponent(slug);
  return (decoded.split('/').pop() ?? decoded).toLowerCase();
}

/** Absent/undefined defaultVisible → true (backward-compatible default). */
export function edgeIsDefaultVisible(edge: SnapshotEdge): boolean {
  return edge.defaultVisible !== false;
}

/** Safe edge type with fallback for unclassified edges. */
export function edgeTypeOrDefault(edge: SnapshotEdge): EdgeType {
  return edge.type ?? 'navigational';
}

// ── Code block stripping (matches check-graph.py: strip_code_blocks) ──

function stripCodeBlocks(text: string): string {
  // Remove fenced code blocks (``` ... ```)
  let result = text.replace(/```[\s\S]*?```/g, '');
  // Remove inline code (`...`)
  result = result.replace(/`[^`\n]+`/g, '');
  return result;
}

// ── Wikilink extraction ──

/**
 * Combined regex that handles BOTH formats:
 * 1. Clean: [[target]] or [[target|alias]]
 * 2. Backslash-pipe (Obsidian DG plugin): [[path\|alias]]
 *
 * Pattern: [[anything-except-]]] — we parse the inner content manually
 * to correctly handle both | and \| separators.
 */
const ALL_WIKILINKS_RE = /\[\[([^\]]+)\]\]/g;

export interface ExtractedLink {
  target: string; // resolved target text (stem-ready)
}

/**
 * Extract wikilinks from markdown content, stripping code blocks first.
 * Handles both clean [[target|alias]] and backslash-pipe [[path\|alias]] formats.
 *
 * Resolution strategy (matching check-graph.py smoke test):
 * - [[target]] → target as-is
 * - [[target|alias]] → target (before |)
 * - [[path\|alias]] → last segment of path (stem extraction)
 */
export function extractWikilinks(content: string): ExtractedLink[] {
  const body = stripCodeBlocks(content);
  const links: ExtractedLink[] = [];

  ALL_WIKILINKS_RE.lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = ALL_WIKILINKS_RE.exec(body)) !== null) {
    const inner = match[1].trim();
    if (inner.length === 0) continue;

    let target: string;

    if (inner.includes('\\|')) {
      // Backslash-pipe format: [[exodus.pp.ua/path/FILE\|ALIAS]]
      // Extract the path part (before \|), then take last segment as stem
      const pathPart = inner.split('\\|')[0].trim();
      target = pathPart.includes('/')
        ? pathPart.split('/').pop() || pathPart
        : pathPart;
    } else if (inner.includes('|')) {
      // Clean alias format: [[target|alias]]
      target = inner.split('|')[0].trim();
    } else {
      // Simple: [[target]]
      target = inner;
    }

    // Skip targets with # (section links)
    if (target.includes('#')) continue;

    if (target.length > 0) {
      links.push({ target });
    }
  }

  return links;
}

/**
 * Detect malformed links (backslash-pipe format) for diagnostics.
 * Now that we handle \| in extractWikilinks, these are "handled but noteworthy".
 */
export function detectMalformedLinks(content: string): string[] {
  const body = stripCodeBlocks(content);
  const results: string[] = [];
  const re = /\[\[([^\]]+\\[|][^\]]*)\]\]/g;

  let match: RegExpExecArray | null;
  while ((match = re.exec(body)) !== null) {
    results.push(match[1]);
  }

  return results;
}

// ── Stem resolution (matches check-graph.py: stem_map logic) ──

/**
 * Extract stem from a wikilink target.
 * If target contains /, take the last segment (matching JS fallback in check-graph.py).
 * Always lowercase for comparison.
 */
export function extractStem(target: string): string {
  let stem = target.trim();
  // If path, take last segment (matches check-graph.py line 121)
  if (stem.includes('/')) {
    stem = stem.split('/').pop() || stem;
  }
  return stem.toLowerCase();
}

/**
 * Build a stem→slug map from all notes (matches check-graph.py: stem_map).
 * First note wins for duplicate stems (same as check-graph.py).
 */
export function buildStemMap(notes: Note[]): Map<string, string> {
  const stemMap = new Map<string, string>();

  for (const note of notes) {
    const decoded = decodeURIComponent(note.slug);
    // Extract filename from path
    const filename = decoded.split('/').pop() || decoded;
    // Remove .md if present (shouldn't be, but safety)
    const stem = filename.replace(/\.md$/i, '').toLowerCase();

    if (!stemMap.has(stem)) {
      stemMap.set(stem, note.slug);
    }
  }

  return stemMap;
}

// ── Full graph builder (client-parse mode) ──

/**
 * Build the complete graph snapshot from loaded notes.
 * This implements the same logic as check-graph.py's run_smoke_test().
 */
export function buildGraphFromNotes(): GraphSnapshot {
  const allNotes = getAllNotes();

  // Filter visible notes (dg_publish !== false)
  const visibleNotes = allNotes.filter(n => n.frontmatter.dg_publish !== false);

  // Build stem map for resolution
  const stemMap = buildStemMap(visibleNotes);

  const nodes: SnapshotNode[] = visibleNotes.map(note => {
    const decoded = decodeURIComponent(note.slug);
    const filename = decoded.split('/').pop() || decoded;
    return {
      slug: note.slug,
      title: note.title,
      stem: filename.replace(/\.md$/i, '').toLowerCase(),
      exists: true,
    };
  });

  const edges: SnapshotEdge[] = [];
  const unresolvedLinks: UnresolvedLink[] = [];
  const malformedLinks: MalformedLink[] = [];

  // Strip frontmatter before parsing (matches check-graph.py)
  const FRONTMATTER_RE = /^---\s*\n[\s\S]*?\n---\s*\n/;

  for (const note of visibleNotes) {
    const fmMatch = note.rawContent.match(FRONTMATTER_RE);
    const body = fmMatch ? note.rawContent.slice(fmMatch[0].length) : note.content;

    // Extract canonical links
    const links = extractWikilinks(body);
    const seenTargets = new Set<string>();

    for (const link of links) {
      const stem = extractStem(link.target);
      const targetSlug = stemMap.get(stem);

      if (targetSlug && targetSlug !== note.slug && !seenTargets.has(targetSlug)) {
        seenTargets.add(targetSlug);
        edges.push({ source: note.slug, target: targetSlug });
      } else if (!targetSlug) {
        unresolvedLinks.push({
          sourceSlug: note.slug,
          sourceTitle: note.title,
          targetText: link.target,
        });
      }
    }

    // Detect malformed links
    const malformed = detectMalformedLinks(body);
    for (const raw of malformed) {
      malformedLinks.push({
        sourceSlug: note.slug,
        sourceTitle: note.title,
        raw,
        reason: raw.includes('\\|') ? 'backslash-pipe' : 'backslash-in-target',
      });
    }
  }

  return {
    contractVersion: GRAPH_CONTRACT_VERSION,
    source: 'client-parse',
    generatedAt: new Date().toISOString(),
    nodes,
    edges,
    diagnostics: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      unresolvedLinks,
      malformedLinks,
    },
  };
}
