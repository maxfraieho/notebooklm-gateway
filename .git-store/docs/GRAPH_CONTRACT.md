# GRAPH CONTRACT

**Version**: `GRAPH_CONTRACT_VERSION = "1.1"`
**Status**: Authoritative specification
**Last updated**: 2026-02-22

This document is the single source of truth for all graph-related behavior
in this knowledge garden. Both the Python CI scripts (`scripts/`) and the
TypeScript frontend (`src/lib/notes/`) are derived implementations of this
contract. Any divergence between implementations is a bug.

---

## Table of Contents

1. [Node Scope](#1-node-scope)
2. [Wikilink Extraction](#2-wikilink-extraction)
3. [Resolution Algorithm](#3-resolution-algorithm)
4. [Edge Model](#4-edge-model)
5. [Snapshot Format](#5-snapshot-format)
6. [Edge Semantics (Phase Model)](#6-edge-semantics-phase-model)
7. [Density Metrics](#7-density-metrics)
8. [Versioning and Evolution](#8-versioning-and-evolution)
9. [Implementation Compliance Checklist](#9-implementation-compliance-checklist)

---

## 1. Node Scope

### 1.1 Qualifying Files

A file qualifies as a graph node if and only if **all** of the following hold:

| Criterion | Requirement |
|-----------|-------------|
| Location | Under `src/site/notes/` (recursive) |
| Extension | `.md` |
| Frontmatter `dg-publish` | Not explicitly `false` (missing key = published) |
| Not in skip dirs | Not under `_quarantine/` or `.git/` |

Files where `dg-publish: false` in frontmatter are **excluded** from all graph
computations. Their links are not counted. They do not appear as nodes or targets.

### 1.2 Slug Derivation

The canonical **slug** for a node is:

```
slug = encodeURIComponent(relative_path_without_extension)
```

Where `relative_path_without_extension` is the file path relative to
`src/site/notes/`, with the `.md` suffix stripped.

**Examples:**

| File path | Relative path | Slug |
|-----------|---------------|------|
| `src/site/notes/exodus.pp.ua/architecture/ARCH_ROOT.md` | `exodus.pp.ua/architecture/ARCH_ROOT` | `exodus.pp.ua%2Farchitecture%2FARCH_ROOT` |
| `src/site/notes/Індекс.md` | `Індекс` | `%D0%86%D0%BD%D0%B4%D0%B5%D0%BA%D1%81` |
| `src/site/notes/README.md` | `README` | `README` |

**Unicode requirement**: `encodeURIComponent` (JavaScript semantics) MUST be
used. Python implementations MUST replicate this behavior using
`urllib.parse.quote(path, safe='')`.

### 1.3 Stem Derivation

The **stem** is the slug's final path segment, decoded and lowercased:

```
stem = decodeURIComponent(slug).split('/').pop().lower()
```

The stem is used as the fallback key in the resolution algorithm (§3).

---

## 2. Wikilink Extraction

### 2.1 Pre-processing: Code Block Stripping

Before extracting wikilinks, ALL content inside code regions MUST be removed:

1. **Fenced code blocks**: `` ``` ... ``` `` (including language tag, multiline)
2. **Inline code**: `` `...` `` (single backtick, non-newline span)

Wikilinks found inside code regions are **not** links. They are examples,
documentation, or templates. Both Python and TypeScript MUST strip these
regions before running the wikilink regex.

> **Known divergence as of 2026-02-22**: TypeScript `wikilinkParser.ts` does
> NOT strip code blocks. This is a compliance gap. Fix tracked separately.

### 2.2 Frontmatter Stripping

Wikilinks in the YAML frontmatter block (`--- ... ---`) are not content links
and MUST be excluded from extraction. Strip the frontmatter block before
applying the wikilink regex.

### 2.3 Canonical Wikilink Regex

```
\[\[([^\]|#\\]+?)(?:\|([^\]]+))?\]\]
```

Capture groups:
- Group 1: **target** — the link target (required)
- Group 2: **alias** — display text (optional)

**Excluded from target capture** (characters that terminate group 1):
- `]` — link terminator
- `|` — alias separator
- `#` — anchor/heading separator (anchors are ignored)
- `\` — backslash (indicates Obsidian plugin format artifact, normalized separately)

The `?` after `+` makes the match non-greedy (required for correctness in
files with multiple links on one line).

### 2.4 Post-extraction Normalization

After regex extraction, the raw target string MUST be:

1. `.strip()` — remove leading/trailing whitespace
2. Split on `/` to get path segments; if multiple segments, the **stem**
   (last segment) is used for resolution fallback
3. NOT further modified (no lowercase at this stage — the resolution
   algorithm handles case-insensitivity)

### 2.5 Anchor Handling

Wikilinks with heading anchors — `[[target#heading]]` — are treated as links
to the **target file only**. The `#heading` part is discarded. The regex in
§2.3 handles this by excluding `#` from group 1.

### 2.6 Backslash-Pipe Links

Links of the form `[[path\|alias]]` are the Obsidian Digital Garden plugin's
table-escaped format. These MUST be normalized before graph extraction:

- **In `src/site/notes/`**: `[[path\|alias]]` → `[[alias]]`
  (the alias IS the display target; the path is the plugin-generated route)
- **In `docs/`**: `[[TARGET\|alias]]` → `[[TARGET]]`
  (the left side IS the canonical target; the alias is a Markdown table escape)

Run `scripts/normalize-wikilinks.py` to normalize before any graph analysis.

---

## 3. Resolution Algorithm

Resolution maps a raw wikilink target string to a canonical node slug.
The algorithm is **deterministic** and applied in strict order. The first
match wins.

### 3.1 Input Preparation

Given raw target `T` (post §2.4 normalization):

```
decoded_T  = T                          # already a plain string, not encoded
encoded_T  = encodeURIComponent(T)      # e.g. "exodus.pp.ua/FOO" → "exodus.pp.ua%2FFOO"
stem_T     = T.split('/').pop().lower() # last segment, lowercase
```

### 3.2 Resolution Steps

| Step | Match Condition | Winner |
|------|----------------|--------|
| 1 — Exact encoded | `node.slug == encoded_T` | node |
| 2 — Exact decoded | `decodeURIComponent(node.slug) == decoded_T` | node |
| 3 — Case-insensitive encoded | `node.slug.lower() == encoded_T.lower()` | node |
| 4 — Case-insensitive decoded | `decodeURIComponent(node.slug).lower() == decoded_T.lower()` | node |
| 5 — Stem fallback | `stem(node.slug) == stem_T` | first match |
| FAIL | No match at any step | unresolved |

**Stem fallback note**: When multiple nodes share the same stem (e.g., two
files named `README.md` in different directories), step 5 returns the
**first** alphabetically sorted match. This is deterministic but ambiguous;
such conflicts SHOULD be flagged in the integrity report.

### 3.3 Unresolved Links

An unresolved link is **not** an error in the graph model — it is a dangling
reference. The integrity checker (I-S2) reports these separately. They are
excluded from the edge set.

---

## 4. Edge Model

### 4.1 Properties

| Property | Value |
|----------|-------|
| Directed | Yes |
| Self-loops | **Forbidden** (source ≠ target) |
| Duplicate edges | **Forbidden** (one directed edge per ordered pair) |
| Multiedges | Not supported |
| Weight | Optional, default `1.0` |

### 4.2 Edge Deduplication

After resolving all wikilinks in a source note, deduplicate:

```python
target_slugs = list(dict.fromkeys(resolved_slugs))  # preserve order, remove dupes
```

One source note can produce at most one directed edge to any given target.
Multiple wikilinks in the same note pointing to the same target collapse to
one edge.

### 4.3 Edge Scope

Only edges where **both** source and target are qualifying nodes (§1.1)
are included in the graph. Edges to unresolved or unpublished targets are
excluded.

### 4.4 Snapshot Structure

The canonical on-disk snapshot is stored at `public/graph.snapshot.json`.

```json
{
  "contract_version": "1.1",
  "generated": "2026-02-22T00:00:00Z",
  "node_count": 53,
  "edge_count": 296,
  "nodes": [
    {
      "slug": "exodus.pp.ua%2Farchitecture%2FARCH_ROOT",
      "title": "Architecture Root"
    }
  ],
  "edges": [
    {
      "source": "exodus.pp.ua%2Farchitecture%2FARCH_ROOT",
      "target": "exodus.pp.ua%2Farchitecture%2FBACKEND",
      "type": "structural",
      "weight": 1.0,
      "importance": null,
      "defaultVisible": true
    }
  ]
}
```

**Field semantics:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `contract_version` | string | yes | Matches `GRAPH_CONTRACT_VERSION` |
| `generated` | ISO 8601 string | yes | Generation timestamp |
| `node_count` | integer | yes | Redundant count for quick sanity check |
| `edge_count` | integer | yes | Redundant count for quick sanity check |
| `nodes[].slug` | string | yes | URL-encoded canonical slug |
| `nodes[].title` | string | yes | Human-readable title from frontmatter |
| `edges[].source` | string | yes | Slug of source node |
| `edges[].target` | string | yes | Slug of target node |
| `edges[].type` | enum\|null | no | See §6 |
| `edges[].weight` | float\|null | no | Default `1.0` |
| `edges[].importance` | float\|null | no | 0.0–1.0, null = unclassified |
| `edges[].defaultVisible` | bool\|null | no | null = implementation default |

---

## 5. Snapshot Format

### 5.1 File Location

```
public/graph.snapshot.json
```

This path is chosen so that:
- The Vite dev server and production build serve it statically at `/graph.snapshot.json`
- Python scripts can read/write it from `ROOT / "public" / "graph.snapshot.json"`
- No build step is required to make it available to the browser

### 5.2 Generation

Generate (or regenerate) the snapshot using:

```bash
python3 scripts/check-graph.py --generate-snapshot
```

This writes the current Python-derived graph to `public/graph.snapshot.json`.

### 5.3 Verification

```bash
python3 scripts/check-graph.py --verify-snapshot
```

Reads `public/graph.snapshot.json` and compares it against the Python-derived
graph. Reports:

- Nodes in snapshot but not in Python graph (stale nodes)
- Nodes in Python graph but not in snapshot (missing from snapshot)
- Edges in snapshot but not in Python graph (stale edges)
- Edges in Python graph but not in snapshot (missing from snapshot)

A divergence count > 0 indicates the snapshot is stale and should be regenerated.

### 5.4 Backward Compatibility

When the snapshot `contract_version` field is absent or older than the current
`GRAPH_CONTRACT_VERSION`:

- Readers MUST still load the snapshot (do not reject old versions)
- Readers SHOULD emit a warning noting the version mismatch
- The `--verify-snapshot` flag SHOULD report the version difference

New optional fields added to the snapshot format are backward compatible by
definition. Required fields MUST NOT be removed without a major version bump.

---

## 6. Edge Semantics (Phase Model)

Edge classification enables progressive visual filtering without reducing the
total graph. Classification is **additive** — unclassified edges default to
full visibility. No author burden is introduced in Phase 1.

### 6.1 Edge Types

| Type | Meaning | Heuristic Signal |
|------|---------|------------------|
| `structural` | Architectural dependency; core to navigation | Source or target is a map/index/root file (e.g. `КАРТА_СИСТЕМИ`, `ІНДЕКС`) |
| `semantic` | Conceptual relation; same topic cluster | Source and target share ≥2 tags OR are in the same directory |
| `navigational` | Cross-topic reference; browsing convenience | All other resolved edges |

### 6.2 Classification Criteria (Phase 1 — Heuristic)

```
if source_stem ∈ MAP_FILES or target_stem ∈ MAP_FILES:
    type = "structural"
elif shared_tags(source, target) ≥ 2 or same_directory(source, target):
    type = "semantic"
else:
    type = "navigational"
```

Where `MAP_FILES = {"карта_системи", "карта_графу", "індекс"}`.

### 6.3 Phase Roadmap

| Phase | Mechanism | Author Burden |
|-------|-----------|---------------|
| 1 — Heuristic | Automated classification at snapshot generation time | None |
| 2 — Frontmatter annotation | Author adds `link-type: structural` in frontmatter | Per-note, opt-in |
| 3 — Context-aware inference | LLM or semantic similarity assigns types | None (automated) |

Phase 1 is fully automated. Authors need not modify any files.
Phase 2 frontmatter annotations override Phase 1 heuristics.

### 6.4 Backward Compatibility

The `type` field in the snapshot is optional. Consumers that do not understand
edge types MUST treat all edges as fully visible (same behavior as before
classification was introduced).

A frontend filter that hides `navigational` edges MUST always provide a
"Show all" toggle that restores the full snapshot data.

### 6.5 TypeScript Interface

```typescript
// GRAPH_CONTRACT_VERSION = "1.1"

export type EdgeType = 'structural' | 'semantic' | 'navigational';

export interface SnapshotNode {
  slug: string;
  title: string;
}

export interface SnapshotEdge {
  source: string;
  target: string;
  type?: EdgeType;
  weight?: number;          // default 1.0
  importance?: number;      // 0.0–1.0
  defaultVisible?: boolean; // null/undefined = true
}

export interface GraphSnapshot {
  contract_version: string;
  generated: string;        // ISO 8601
  node_count: number;
  edge_count: number;
  nodes: SnapshotNode[];
  edges: SnapshotEdge[];
}
```

---

## 7. Density Metrics

Metrics are **observational only**. No automatic pruning or threshold
enforcement is performed. Metrics are produced by:

```bash
python3 scripts/check-graph.py --stats
```

Output is JSON to stdout.

### 7.1 Metric Definitions

| Metric | Definition |
|--------|-----------|
| `node_count` | Number of qualifying published nodes |
| `edge_count` | Number of resolved directed edges |
| `avg_out_degree` | `edge_count / node_count` |
| `avg_in_degree` | Same value (conservation of flow) |
| `avg_total_degree` | `2 * edge_count / node_count` |
| `degree_distribution` | Map of `{total_degree: node_count}` |
| `in_degree_distribution` | Map of `{in_degree: node_count}` |
| `out_degree_distribution` | Map of `{out_degree: node_count}` |
| `hubs` | Nodes with total degree > mean + 2σ |
| `leaves` | Nodes with total degree ≤ 1 |
| `clustering_coefficient` | Mean local undirected clustering coefficient |
| `weak_component_count` | Connected components ignoring edge direction |
| `strong_component_count` | Strongly connected components (Kosaraju) |
| `largest_weak_component_pct` | % of nodes in largest weak component |
| `redundant_neighborhoods` | Edges where Jaccard(out(u), out(v)) > 0.7 |

### 7.2 Output Schema

```json
{
  "contract_version": "1.1",
  "timestamp": "2026-02-22T00:00:00Z",
  "source": "src/site/notes",
  "node_count": 53,
  "edge_count": 296,
  "avg_out_degree": 5.58,
  "avg_in_degree": 5.58,
  "avg_total_degree": 11.17,
  "degree_distribution": {"0": 0, "5": 4, "11": 7},
  "in_degree_distribution": {"2": 5, "6": 8},
  "out_degree_distribution": {"3": 6, "8": 4},
  "hubs": [
    {"slug": "exodus.pp.ua%2FКАРТА_СИСТЕМИ", "stem": "карта_системи", "total_degree": 34, "z_score": 3.1}
  ],
  "leaves": [
    {"slug": "exodus.pp.ua%2FNOTE_X", "stem": "note_x", "total_degree": 1}
  ],
  "clustering_coefficient": 0.42,
  "weak_component_count": 1,
  "strong_component_count": 12,
  "largest_weak_component_pct": 100.0,
  "redundant_neighborhoods": [
    {
      "source": "exodus.pp.ua%2FКАРТА_СИСТЕМИ",
      "target": "exodus.pp.ua%2FARCH_ROOT",
      "jaccard": 0.82,
      "shared_targets": 9,
      "union_targets": 11
    }
  ]
}
```

### 7.3 Governance Interpretation

The metrics are intended for architectural visibility. Suggested readings:

| Signal | Implication |
|--------|-------------|
| Hub z-score > 3 | Node is load-bearing; consider splitting or documenting explicitly |
| Leaf count > 10% | Graph may have poorly connected periphery |
| Clustering > 0.6 | High local clustering; content may be over-compartmentalized |
| Weak components > 1 | Graph is disconnected; intentional isolation or oversight? |
| Redundant neighborhoods > 5 | Multiple "shortcut" edges; review if they add navigation value |

These are **advisory**, not thresholds. Authors make decisions; metrics inform them.

---

## 8. Versioning and Evolution

### 8.1 Current Version

```
GRAPH_CONTRACT_VERSION = "1.1"
```

This version string MUST appear in:
- This document (header)
- `src/lib/notes/graphContract.ts` (as exported constant)
- Every generated `public/graph.snapshot.json`
- `--stats` output JSON

### 8.2 Version Bump Rules

| Change type | Version bump |
|-------------|-------------|
| New optional snapshot field | Patch (1.1 → 1.2) |
| New required snapshot field | Minor (1.1 → 2.0) |
| Change to resolution algorithm | Minor (1.1 → 2.0) |
| Change to node scope rules | Minor (1.1 → 2.0) |
| Change to edge model (directedness, self-loops) | Major (1.1 → 2.0) |

### 8.3 Cross-implementation Sync Protocol

When this document changes:

1. Update `GRAPH_CONTRACT_VERSION` here and in `graphContract.ts`
2. Update Python implementation in `scripts/check-graph.py`
3. Update TypeScript implementation if affected
4. Regenerate `public/graph.snapshot.json` via `--generate-snapshot`
5. Run `--verify-snapshot` to confirm consistency
6. Run `python3 scripts/check-graph.py` to confirm CI passes

---

## 9. Implementation Compliance Checklist

For each implementation (Python and TypeScript), verify:

- [ ] Node scope: only `dg-publish !== false` files included
- [ ] Slugs use `encodeURIComponent` semantics (URI percent-encoding)
- [ ] Code blocks stripped before link extraction
- [ ] Frontmatter stripped before link extraction
- [ ] Wikilink regex matches §2.3 exactly
- [ ] Anchor (`#`) segments discarded
- [ ] Backslash-pipe links normalized before extraction
- [ ] Resolution follows §3.2 steps in strict order
- [ ] No self-loop edges produced
- [ ] Duplicate edges deduplicated per source note
- [ ] Snapshot `contract_version` matches `GRAPH_CONTRACT_VERSION`

---

*This contract is enforced by `scripts/check-graph.py --verify-snapshot` in CI.*
