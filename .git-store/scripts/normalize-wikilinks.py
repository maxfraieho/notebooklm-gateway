#!/usr/bin/env python3
"""
normalize-wikilinks.py — Normalize wiki-link formats to canonical [[STEM]] form.

Problem: Obsidian Digital Garden plugin publishes notes with full-path links:
  [[exodus.pp.ua/path/FILE\|ALIAS]] → should be [[ALIAS]]

The JS parser (wikilinkParser.ts) captures the backslash as part of the target,
so [[path\|alias]] fails stem-lookup. Only [[SIMPLE_NAME]] resolves correctly.

Rules applied:
  1. src/site/notes/: [[path\|alias]] → [[alias]]   (strip domain prefix, use alias)
  2. docs/:           [[TARGET\|ALIAS]] → [[TARGET]] (keep canonical target, drop alias)
     (table cells use \| to escape | from markdown table parser)

Usage:
  python3 scripts/normalize-wikilinks.py [--dry-run] [--verbose]

Exit codes:
  0 — clean (no changes needed)
  1 — changes made (or would be made in --dry-run)
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE_NOTES_DIR = ROOT / "src/site/notes"
DOCS_DIR = ROOT / "docs"

# Regex to find [[...]] including content with backslash-pipe
WIKILINK_RE = re.compile(r'\[\[([^\]]+)\]\]')

# Frontmatter boundary (YAML or JSON on single line)
FRONTMATTER_RE = re.compile(r'^---\s*\n[\s\S]*?\n---\s*\n', re.MULTILINE)


def split_body(text: str) -> tuple[str, str]:
    """Split text into (frontmatter_block, body). Returns ('', text) if no frontmatter."""
    m = FRONTMATTER_RE.match(text)
    if m:
        return text[: m.end()], text[m.end():]
    return "", text


def normalize_site_link(inner: str) -> str:
    """
    [[exodus.pp.ua/path/FILE\|ALIAS]] → [[ALIAS]]
    [[SIMPLE]] → [[SIMPLE]]  (no change)
    """
    if "\\|" in inner:
        alias = inner.split("\\|", 1)[1].strip()
        return f"[[{alias}]]"
    return f"[[{inner}]]"


def normalize_docs_link(inner: str) -> str:
    """
    [[TARGET\|ALIAS]] → [[TARGET]]  (table-escaped alias, drop it)
    [[SIMPLE]] → [[SIMPLE]]  (no change)
    """
    if "\\|" in inner:
        target = inner.split("\\|", 1)[0].strip()
        return f"[[{target}]]"
    return f"[[{inner}]]"


def normalize_text(text: str, mode: str) -> tuple[str, int]:
    """
    Normalize wiki-links in the body of a file, skipping fenced code blocks and inline code.
    mode: 'site' or 'docs'
    Returns (new_text, change_count).
    """
    front, body = split_body(text)
    changes = 0

    # Split body into alternating segments: even=non-code, odd=code block.
    # Only normalize wiki-links in non-code segments (even indices).
    CODE_FENCE_RE = re.compile(r"(```[\s\S]*?```|`[^`\n]+`)")
    segments = CODE_FENCE_RE.split(body)
    result_segments: list[str] = []

    for i, segment in enumerate(segments):
        if i % 2 == 1:
            # Code block — preserve verbatim
            result_segments.append(segment)
        else:
            # Non-code text — normalize wiki-links
            def replace(m: re.Match, _mode: str = mode) -> str:
                nonlocal changes
                inner = m.group(1)
                result = normalize_site_link(inner) if _mode == "site" else normalize_docs_link(inner)
                if result != m.group(0):
                    changes += 1
                return result

            result_segments.append(WIKILINK_RE.sub(replace, segment))

    return front + "".join(result_segments), changes


def process_dir(directory: Path, mode: str, dry_run: bool, verbose: bool) -> int:
    """Process all .md files in directory. Returns total change count."""
    total_changes = 0
    files_changed = 0

    for p in sorted(directory.rglob("*.md")):
        text = p.read_text(encoding="utf-8", errors="replace")
        new_text, n = normalize_text(text, mode)
        if n > 0:
            total_changes += n
            files_changed += 1
            if verbose or dry_run:
                print(f"  {'[DRY]' if dry_run else 'FIXED'} {p.relative_to(ROOT)} ({n} links)")
            if not dry_run:
                p.write_text(new_text, encoding="utf-8")

    return total_changes


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize wiki-links to canonical [[STEM]] form")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change, don't write")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all changed files")
    args = parser.parse_args()

    print("normalize-wikilinks")
    print(f"  Mode: {'dry-run' if args.dry_run else 'apply'}")
    print()

    total = 0

    if SITE_NOTES_DIR.is_dir():
        print(f"[site] Processing {SITE_NOTES_DIR.relative_to(ROOT)} ...")
        n = process_dir(SITE_NOTES_DIR, "site", args.dry_run, args.verbose)
        print(f"  → {n} links normalized")
        total += n
    else:
        print(f"[site] SKIP — {SITE_NOTES_DIR} not found")

    if DOCS_DIR.is_dir():
        print(f"[docs] Processing {DOCS_DIR.relative_to(ROOT)} ...")
        n = process_dir(DOCS_DIR, "docs", args.dry_run, args.verbose)
        print(f"  → {n} links normalized")
        total += n
    else:
        print(f"[docs] SKIP — {DOCS_DIR} not found")

    print()
    print(f"Total links normalized: {total}")

    return 1 if total > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
