#!/usr/bin/env python3
"""
check-graph.py — Knowledge graph integrity check for docs/

Enforces:
  - I-S1: every doc has "## Семантичні зв'язки" (or isolated:intentional)
  - I-S3/I-S6: every doc has ≥1 inbound wiki-link (or isolated:intentional)
  - I-S5: every doc has ≥2 outbound wiki-links (or isolated:intentional)
  - I-S2: no dangling wiki-links (links to non-existent files)
  - I-S8: no backslash-pipe [[target\|alias]] format (parser-breaking)
  - SMOKE: site graph has ≥50 resolved edges (graph-render smoke test)

Usage:
  python3 scripts/check-graph.py [--verbose] [--ci] [--no-smoke]
  python3 scripts/check-graph.py --stats
  python3 scripts/check-graph.py --verify-snapshot
  python3 scripts/check-graph.py --generate-snapshot

Exit codes:
  0 — clean graph
  1 — violations found
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
SITE_NOTES_DIR = ROOT / "src" / "site" / "notes"
SNAPSHOT_PATH = ROOT / "public" / "graph.snapshot.json"

# Contract version — must match GRAPH_CONTRACT_VERSION in graphContract.ts
GRAPH_CONTRACT_VERSION = "1.1"

# Minimum resolved edges required for graph smoke test (I-SMOKE-1)
SMOKE_MIN_EDGES = 50

SKIP_DIR_NAMES: set[str] = {"_quarantine", ".git"}
SKIP_FILE_NAMES: set[str] = {"CLAUDE.md"}

# Files that are exempt from outbound-link minimum (they ARE the maps)
EXEMPT_FROM_OUTBOUND = {"КАРТА_СИСТЕМИ", "КАРТА_ГРАФУ", "ІНДЕКС", "АУДІО_ПРОМПТ_NOTEBOOKLM"}

# Known valid references to external docs (agents/, future docs, etc.) — not in docs/
EXTERNAL_REFS: set[str] = {
    # Integrity agents (live in agents/ folder, not docs/)
    "graph-linter", "semantic-guard", "content-router", "tag-auditor",
    # Template placeholders in governance docs (examples, not real links)
    "somedoc", "wiki-links", "wiki-link", "targetname", "відповідний вузол",
}

# Hub classification: map/index files (stem, lowercase)
MAP_FILE_STEMS: set[str] = {"карта_системи", "карта_графу", "індекс"}


# ---------------------------------------------------------------------------
# Shared text utilities
# ---------------------------------------------------------------------------

def strip_code_blocks(text: str) -> str:
    """Remove fenced code blocks and inline code to avoid false-positive link detection."""
    text = re.sub(r"```[\s\S]*?```", "", text)
    text = re.sub(r"`[^`\n]+`", "", text)
    return text


def strip_frontmatter(text: str) -> str:
    """Remove YAML frontmatter block (--- ... ---)."""
    m = re.match(r"^---\s*\n[\s\S]*?\n---\s*\n", text)
    return text[m.end():] if m else text


def find_backslash_pipe_links(text: str) -> list[str]:
    """Return all [[target\|alias]] links in text (excluding code blocks)."""
    searchable = strip_code_blocks(text)
    raw = re.findall(r"\[\[([^\]]+)\]\]", searchable)
    return [lk for lk in raw if "\\|" in lk]


# ---------------------------------------------------------------------------
# docs/ integrity checks (unchanged)
# ---------------------------------------------------------------------------

def is_excluded(path: Path) -> bool:
    if path.name in SKIP_FILE_NAMES:
        return True
    return any(part in SKIP_DIR_NAMES for part in path.parts)


def parse_metadata(text: str) -> dict:
    searchable = strip_code_blocks(text)
    meta = {
        "is_isolated": "isolated: intentional" in text,
        "has_semantic_links": any(
            s in text for s in ["## Семантичні зв'язки", "## ЗВ'ЯЗКИ", "## ЗВ\\'ЯЗКИ"]
        ),
        # Extract links only from non-code text; skip links with backslash or spaces (template artifacts)
        "outlinks": [
            lk for lk in re.findall(r"\[\[([^\]|#]+?)(?:\|[^\]]+)?\]\]", searchable)
            if "\\" not in lk and "/" not in lk
        ],
        # I-S8: detect backslash-pipe links (Obsidian plugin format, breaks JS parser)
        "backslash_pipe_links": find_backslash_pipe_links(searchable),
    }
    return meta


# ---------------------------------------------------------------------------
# Site notes graph (src/site/notes/) — used by smoke test, --stats, --verify-snapshot
# ---------------------------------------------------------------------------

def _path_to_slug(p: Path) -> str:
    """Convert a site note path to its canonical slug (encodeURIComponent semantics)."""
    relative = p.relative_to(SITE_NOTES_DIR).with_suffix("")
    return quote(str(relative).replace("\\", "/"), safe="")


def _parse_title(text: str) -> str:
    """Extract title from frontmatter, or return empty string."""
    m = re.match(r"^---\s*\n([\s\S]*?)\n---\s*\n", text)
    if not m:
        return ""
    fm = m.group(1)
    # Try JSON frontmatter first
    try:
        data = json.loads(fm)
        return data.get("title", "") or ""
    except (json.JSONDecodeError, ValueError):
        pass
    # YAML-style: find "title:" line
    for line in fm.splitlines():
        if line.startswith("title:"):
            value = line[6:].strip().strip('"').strip("'")
            return value
    return ""


def _is_published(text: str) -> bool:
    """Return False only if dg-publish is explicitly false."""
    m = re.match(r"^---\s*\n([\s\S]*?)\n---\s*\n", text)
    if not m:
        return True
    fm = m.group(1)
    try:
        data = json.loads(fm)
        return data.get("dg-publish", True) is not False
    except (json.JSONDecodeError, ValueError):
        pass
    for line in fm.splitlines():
        if re.match(r"dg-publish\s*:\s*false", line.strip(), re.IGNORECASE):
            return False
    return True


# Canonical link extraction regex (per contract §2.3)
_CANONICAL_LINK_RE = re.compile(r"\[\[([^\]|#\\]+?)\]\]")


def build_site_graph() -> tuple[dict[str, dict], list[tuple[str, str]]]:
    """
    Build the directed graph from src/site/notes/.

    Returns:
        nodes: dict slug → {slug, stem, title}
        edges: list of (source_slug, target_slug)
    """
    if not SITE_NOTES_DIR.is_dir():
        return {}, []

    files = list(SITE_NOTES_DIR.rglob("*.md"))

    # Build node map
    nodes: dict[str, dict] = {}
    stem_to_slug: dict[str, str] = {}  # stem → first-match slug (for fallback resolution)

    for p in sorted(files):
        if any(part in SKIP_DIR_NAMES for part in p.parts):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if not _is_published(text):
            continue
        slug = _path_to_slug(p)
        stem = unquote(slug).split("/")[-1].lower()
        title = _parse_title(text) or p.stem
        nodes[slug] = {"slug": slug, "stem": stem, "title": title}
        if stem not in stem_to_slug:
            stem_to_slug[stem] = slug

    # Build outbound link map and resolve edges
    edges: list[tuple[str, str]] = []

    for p in sorted(files):
        if any(part in SKIP_DIR_NAMES for part in p.parts):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if not _is_published(text):
            continue

        source_slug = _path_to_slug(p)
        if source_slug not in nodes:
            continue

        body = strip_frontmatter(text)
        body = strip_code_blocks(body)

        seen_targets: set[str] = set()
        for m in _CANONICAL_LINK_RE.finditer(body):
            raw_target = m.group(1).strip()
            if not raw_target:
                continue

            # Resolution: exact encoded → exact decoded → case-insensitive → stem fallback
            resolved: str | None = None

            # Try exact encoded
            encoded = quote(raw_target, safe="")
            if encoded in nodes:
                resolved = encoded
            # Try exact decoded path (as-is, re-encoded)
            if resolved is None:
                for candidate in [quote(raw_target, safe=""), raw_target]:
                    if candidate in nodes:
                        resolved = candidate
                        break
            # Try case-insensitive
            if resolved is None:
                lower_encoded = encoded.lower()
                for slug in nodes:
                    if slug.lower() == lower_encoded or unquote(slug).lower() == raw_target.lower():
                        resolved = slug
                        break
            # Stem fallback (last path segment)
            if resolved is None:
                stem_candidate = raw_target.split("/")[-1].lower()
                resolved = stem_to_slug.get(stem_candidate)

            if resolved is None or resolved == source_slug:
                continue  # unresolved or self-loop

            if resolved not in seen_targets:
                seen_targets.add(resolved)
                edges.append((source_slug, resolved))

    return nodes, edges


# ---------------------------------------------------------------------------
# Smoke test (unchanged behaviour, now delegates to build_site_graph)
# ---------------------------------------------------------------------------

def run_smoke_test() -> tuple[int, str]:
    """
    Smoke test: count resolved edges in src/site/notes/.
    Returns (edge_count, status_message).
    """
    if not SITE_NOTES_DIR.is_dir():
        return -1, f"SKIP — {SITE_NOTES_DIR} not found"

    _, edges = build_site_graph()
    resolved = len(edges)
    status = "OK" if resolved >= SMOKE_MIN_EDGES else "FAIL"
    return resolved, f"{status} — {resolved} resolved edges (min {SMOKE_MIN_EDGES})"


# ---------------------------------------------------------------------------
# Stats computation
# ---------------------------------------------------------------------------

def _build_adjacency(nodes: dict, edges: list[tuple[str, str]]) -> tuple[dict, dict]:
    """Build out-adjacency and in-adjacency sets."""
    adj_out: dict[str, set[str]] = {s: set() for s in nodes}
    adj_in: dict[str, set[str]] = {s: set() for s in nodes}
    for src, tgt in edges:
        if src in adj_out:
            adj_out[src].add(tgt)
        if tgt in adj_in:
            adj_in[tgt].add(src)
    return adj_out, adj_in


def _clustering_coefficient(nodes: dict, adj_out: dict, adj_in: dict) -> float:
    """Mean local clustering coefficient (undirected approximation)."""
    coefficients: list[float] = []
    for node in nodes:
        neighbors = (adj_out.get(node, set()) | adj_in.get(node, set())) - {node}
        k = len(neighbors)
        if k < 2:
            coefficients.append(0.0)
            continue
        neighbor_list = sorted(neighbors)
        triangles = 0
        for i in range(k):
            for j in range(i + 1, k):
                u, v = neighbor_list[i], neighbor_list[j]
                if v in adj_out.get(u, set()) or u in adj_out.get(v, set()):
                    triangles += 1
        coefficients.append(2 * triangles / (k * (k - 1)))
    return round(sum(coefficients) / len(coefficients), 4) if coefficients else 0.0


def _weak_components(nodes: dict, adj_out: dict, adj_in: dict) -> list[set[str]]:
    """Weakly connected components (undirected BFS)."""
    adj_undirected: dict[str, set[str]] = {s: set() for s in nodes}
    for node in nodes:
        for neighbor in adj_out.get(node, set()):
            adj_undirected[node].add(neighbor)
            if neighbor in adj_undirected:
                adj_undirected[neighbor].add(node)

    visited: set[str] = set()
    components: list[set[str]] = []
    for start in nodes:
        if start in visited:
            continue
        component: set[str] = set()
        stack = [start]
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            component.add(node)
            for neighbor in adj_undirected.get(node, set()):
                if neighbor not in visited:
                    stack.append(neighbor)
        components.append(component)
    return components


def _strong_components(nodes: dict, adj_out: dict) -> list[set[str]]:
    """Strongly connected components via Kosaraju's algorithm."""
    visited: set[str] = set()
    finish_order: list[str] = []

    def dfs1(start: str) -> None:
        stack: list[tuple[str, iter]] = [(start, iter(adj_out.get(start, set())))]
        while stack:
            node, it = stack[-1]
            if node not in visited:
                visited.add(node)
            try:
                neighbor = next(it)
                if neighbor not in visited:
                    stack.append((neighbor, iter(adj_out.get(neighbor, set()))))
            except StopIteration:
                finish_order.append(node)
                stack.pop()

    for node in nodes:
        if node not in visited:
            dfs1(node)

    # Build reverse graph (adj_in is already available but we rebuild for clarity)
    adj_rev: dict[str, set[str]] = {s: set() for s in nodes}
    for node in nodes:
        for target in adj_out.get(node, set()):
            if target in adj_rev:
                adj_rev[target].add(node)

    visited2: set[str] = set()
    sccs: list[set[str]] = []

    def dfs2(start: str, component: set[str]) -> None:
        stack = [start]
        while stack:
            node = stack.pop()
            if node in visited2:
                continue
            visited2.add(node)
            component.add(node)
            for neighbor in adj_rev.get(node, set()):
                if neighbor not in visited2:
                    stack.append(neighbor)

    for node in reversed(finish_order):
        if node not in visited2:
            scc: set[str] = set()
            dfs2(node, scc)
            sccs.append(scc)

    return sccs


def _redundant_neighborhoods(
    adj_out: dict, edges: list[tuple[str, str]], threshold: float = 0.7
) -> list[dict]:
    """Edges where Jaccard(out(source), out(target)) > threshold."""
    result: list[dict] = []
    for source, target in edges:
        out_source = adj_out.get(source, set()) - {target}
        out_target = adj_out.get(target, set())
        if not out_source or not out_target:
            continue
        intersection = out_source & out_target
        union = out_source | out_target
        if not union:
            continue
        jaccard = len(intersection) / len(union)
        if jaccard > threshold:
            result.append({
                "source": source,
                "target": target,
                "jaccard": round(jaccard, 3),
                "shared_targets": len(intersection),
                "union_targets": len(union),
            })
    return sorted(result, key=lambda x: -x["jaccard"])


def compute_stats(nodes: dict, edges: list[tuple[str, str]]) -> dict:
    """Compute all density metrics for the graph."""
    n = len(nodes)
    e = len(edges)

    adj_out, adj_in = _build_adjacency(nodes, edges)

    # Degree sequences
    out_deg = {s: len(adj_out.get(s, set())) for s in nodes}
    in_deg = {s: len(adj_in.get(s, set())) for s in nodes}
    total_deg = {s: out_deg[s] + in_deg[s] for s in nodes}

    # Distributions
    def distribution(deg_map: dict) -> dict:
        dist: dict[int, int] = {}
        for v in deg_map.values():
            dist[v] = dist.get(v, 0) + 1
        return {str(k): v for k, v in sorted(dist.items())}

    # Mean and stddev of total degree
    degrees = list(total_deg.values())
    mean_deg = sum(degrees) / n if n else 0.0
    variance = sum((d - mean_deg) ** 2 for d in degrees) / n if n else 0.0
    std_deg = math.sqrt(variance)
    hub_threshold = mean_deg + 2 * std_deg

    hubs = []
    for slug, deg in sorted(total_deg.items(), key=lambda x: -x[1]):
        if deg > hub_threshold:
            z = (deg - mean_deg) / std_deg if std_deg else 0.0
            hubs.append({
                "slug": slug,
                "stem": nodes[slug]["stem"],
                "title": nodes[slug]["title"],
                "total_degree": deg,
                "in_degree": in_deg[slug],
                "out_degree": out_deg[slug],
                "z_score": round(z, 2),
            })

    leaves = [
        {"slug": slug, "stem": nodes[slug]["stem"], "title": nodes[slug]["title"], "total_degree": deg}
        for slug, deg in total_deg.items()
        if deg <= 1
    ]

    # Graph topology
    cc = _clustering_coefficient(nodes, adj_out, adj_in)
    weak = _weak_components(nodes, adj_out, adj_in)
    strong = _strong_components(nodes, adj_out)
    redundant = _redundant_neighborhoods(adj_out, edges)

    largest_weak_pct = (max(len(c) for c in weak) / n * 100.0) if weak and n else 0.0

    return {
        "contract_version": GRAPH_CONTRACT_VERSION,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": str(SITE_NOTES_DIR.relative_to(ROOT)),
        "node_count": n,
        "edge_count": e,
        "avg_out_degree": round(e / n, 3) if n else 0,
        "avg_in_degree": round(e / n, 3) if n else 0,
        "avg_total_degree": round(2 * e / n, 3) if n else 0,
        "degree_mean": round(mean_deg, 3),
        "degree_stddev": round(std_deg, 3),
        "hub_threshold": round(hub_threshold, 3),
        "degree_distribution": distribution(total_deg),
        "in_degree_distribution": distribution(in_deg),
        "out_degree_distribution": distribution(out_deg),
        "hubs": hubs,
        "hub_count": len(hubs),
        "leaves": leaves,
        "leaf_count": len(leaves),
        "clustering_coefficient": cc,
        "weak_component_count": len(weak),
        "strong_component_count": len(strong),
        "largest_weak_component_pct": round(largest_weak_pct, 1),
        "redundant_neighborhoods": redundant,
        "redundant_neighborhood_count": len(redundant),
    }


# ---------------------------------------------------------------------------
# Snapshot verification and generation
# ---------------------------------------------------------------------------

def verify_snapshot(nodes: dict, edges: list[tuple[str, str]]) -> int:
    """
    Compare Python-derived graph against public/graph.snapshot.json.
    Returns 0 if consistent, 1 if divergent or snapshot missing.
    """
    if not SNAPSHOT_PATH.exists():
        result = {
            "error": "Snapshot not found",
            "path": str(SNAPSHOT_PATH),
            "hint": "Run: python3 scripts/check-graph.py --generate-snapshot",
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1

    with open(SNAPSHOT_PATH, encoding="utf-8") as f:
        snapshot = json.load(f)

    snap_version = snapshot.get("contract_version", "unknown")
    snap_nodes: set[str] = {n["slug"] for n in snapshot.get("nodes", [])}
    snap_edges: set[tuple[str, str]] = {
        (e["source"], e["target"]) for e in snapshot.get("edges", [])
    }

    py_nodes: set[str] = set(nodes.keys())
    py_edges: set[tuple[str, str]] = set(edges)

    stale_nodes = sorted(snap_nodes - py_nodes)
    missing_nodes = sorted(py_nodes - snap_nodes)
    stale_edges = sorted(f"{s}→{t}" for s, t in snap_edges - py_edges)
    missing_edges = sorted(f"{s}→{t}" for s, t in py_edges - snap_edges)

    divergence = len(stale_nodes) + len(missing_nodes) + len(stale_edges) + len(missing_edges)

    result = {
        "snapshot_version": snap_version,
        "current_contract_version": GRAPH_CONTRACT_VERSION,
        "version_match": snap_version == GRAPH_CONTRACT_VERSION,
        "divergence_count": divergence,
        "snapshot_node_count": len(snap_nodes),
        "python_node_count": len(py_nodes),
        "snapshot_edge_count": len(snap_edges),
        "python_edge_count": len(py_edges),
        "stale_nodes": stale_nodes,
        "missing_nodes": missing_nodes,
        "stale_edges": stale_edges,
        "missing_edges": missing_edges,
        "status": "OK" if divergence == 0 else "DIVERGED",
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if divergence > 0 else 0


def _classify_edge_type(
    source: str, target: str, nodes: dict
) -> str:
    """Phase 1 heuristic edge type classification (per contract §6.2)."""
    source_stem = nodes.get(source, {}).get("stem", "")
    target_stem = nodes.get(target, {}).get("stem", "")
    if source_stem in MAP_FILE_STEMS or target_stem in MAP_FILE_STEMS:
        return "structural"
    # Same directory heuristic
    source_dir = "/".join(unquote(source).split("/")[:-1])
    target_dir = "/".join(unquote(target).split("/")[:-1])
    if source_dir and source_dir == target_dir:
        return "semantic"
    return "navigational"


def generate_snapshot(nodes: dict, edges: list[tuple[str, str]]) -> int:
    """
    Write public/graph.snapshot.json from the Python-derived graph.
    Returns 0 on success.
    """
    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)

    snapshot_nodes = [
        {"slug": slug, "title": data["title"]}
        for slug, data in sorted(nodes.items())
    ]

    snapshot_edges = [
        {
            "source": src,
            "target": tgt,
            "type": _classify_edge_type(src, tgt, nodes),
            "weight": 1.0,
            "importance": None,
            "defaultVisible": True,
        }
        for src, tgt in sorted(edges)
    ]

    snapshot = {
        "contract_version": GRAPH_CONTRACT_VERSION,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": snapshot_nodes,
        "edges": snapshot_edges,
    }

    with open(SNAPSHOT_PATH, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Snapshot written to {SNAPSHOT_PATH.relative_to(ROOT)}")
    print(f"  Nodes : {len(nodes)}")
    print(f"  Edges : {len(edges)}")
    print(f"  Version: {GRAPH_CONTRACT_VERSION}")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Knowledge graph integrity check")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show passing checks too")
    parser.add_argument("--ci", action="store_true", help="CI mode: no color, structured output")
    parser.add_argument("--no-smoke", action="store_true", help="Skip graph-render smoke test")
    parser.add_argument("--stats", action="store_true",
                        help="Output density metrics as JSON (site graph only)")
    parser.add_argument("--verify-snapshot", action="store_true",
                        help="Compare Python graph with public/graph.snapshot.json")
    parser.add_argument("--generate-snapshot", action="store_true",
                        help="Write public/graph.snapshot.json from current site graph")
    args = parser.parse_args()

    # --- Density stats mode (site graph only) ---
    if args.stats:
        nodes, edges = build_site_graph()
        stats = compute_stats(nodes, edges)
        print(json.dumps(stats, indent=2, ensure_ascii=False))
        return 0

    # --- Snapshot generation mode ---
    if args.generate_snapshot:
        nodes, edges = build_site_graph()
        return generate_snapshot(nodes, edges)

    # --- Snapshot verification mode ---
    if args.verify_snapshot:
        nodes, edges = build_site_graph()
        return verify_snapshot(nodes, edges)

    # --- Normal integrity check mode (docs/) ---
    if not DOCS_DIR.is_dir():
        print(f"ERROR: docs/ not found at {DOCS_DIR}", file=sys.stderr)
        return 1

    # Collect all files
    file_data: dict[str, dict] = {}  # stem.lower() → data
    for p in sorted(DOCS_DIR.rglob("*.md")):
        if is_excluded(p):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        meta = parse_metadata(text)
        stem = p.stem.lower()
        file_data[stem] = {
            "path": p,
            "rel": str(p.relative_to(DOCS_DIR)),
            "stem": p.stem,
            **meta,
            "inlinks": 0,
            "inlink_from": [],
        }

    # Build inlinks
    for stem, fd in file_data.items():
        for link in fd["outlinks"]:
            target = link.lower()
            if target in file_data and target != stem:
                file_data[target]["inlinks"] += 1
                if fd["rel"] not in file_data[target]["inlink_from"]:
                    file_data[target]["inlink_from"].append(fd["rel"])

    violations: list[tuple[str, str, str]] = []  # (rel, rule_id, message)

    for stem, fd in sorted(file_data.items(), key=lambda x: x[1]["rel"]):
        rel = fd["rel"]
        iso = fd["is_isolated"]

        # I-S1: semantic links section
        if not fd["has_semantic_links"] and not iso:
            violations.append((rel, "I-S1", "missing '## Семантичні зв'язки' section"))

        # I-S6: ≥1 inbound link
        if not iso and fd["inlinks"] == 0:
            violations.append((rel, "I-S6", "orphan — 0 inbound wiki-links"))

        # I-S5: ≥2 outbound links (except maps and isolated)
        if not iso and fd["stem"] not in EXEMPT_FROM_OUTBOUND and len(fd["outlinks"]) < 2:
            violations.append((rel, "I-S5", f"only {len(fd['outlinks'])} outbound wiki-links (need ≥2)"))

        # I-S2: no dangling links (skip known external refs)
        for link in fd["outlinks"]:
            if link.lower() not in file_data and link.lower() not in EXTERNAL_REFS:
                violations.append((rel, "I-S2", f"dangling link [[{link}]] — target not found"))

        # I-S8: no backslash-pipe links (Obsidian plugin format breaks JS parser)
        for bp in fd["backslash_pipe_links"]:
            violations.append((rel, "I-S8", f"backslash-pipe link [[{bp[:60]}]] — run normalize-wikilinks.py"))

        if args.verbose and not any(v[0] == rel for v in violations):
            print(f"  OK  {rel}")

    # Output
    for rel, rule, msg in sorted(violations):
        print(f"  [{rule}]  {rel}  —  {msg}")

    total = len(file_data)
    n_viol = len(violations)
    n_orphan = sum(1 for fd in file_data.values() if fd["inlinks"] == 0 and not fd["is_isolated"])
    n_iso = sum(1 for fd in file_data.values() if fd["is_isolated"])

    # Smoke test
    smoke_edges, smoke_msg = (-1, "SKIP") if args.no_smoke else run_smoke_test()
    smoke_fail = smoke_edges >= 0 and smoke_edges < SMOKE_MIN_EDGES

    print(f"\n{'─'*50}")
    print(f"check-graph")
    print(f"  Scanned  : {total}")
    print(f"  Isolated : {n_iso}")
    print(f"  Orphans  : {n_orphan}")
    print(f"  Violations: {n_viol}")
    print(f"  Smoke    : {smoke_msg}")
    print()

    return 1 if (n_viol > 0 or smoke_fail) else 0


if __name__ == "__main__":
    sys.exit(main())
