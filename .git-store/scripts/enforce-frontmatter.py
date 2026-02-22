#!/usr/bin/env python3
"""
enforce-frontmatter.py — Canonical YAML frontmatter enforcement for docs/

Ensures every *.md file in docs/ (except excluded layers) has the required fields:
  title: "..."
  dg-publish: true
  dg-metatags:
  dg-home:

Usage:
  python scripts/enforce-frontmatter.py [--dry-run] [--verbose] [--ci]

Exit codes:
  0 — all files compliant (no changes made/needed)
  1 — changes were made (or needed in --dry-run / --ci mode)
  2 — one or more files had unrecoverable errors
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DOCS_DIR = Path(__file__).resolve().parent.parent / "docs"

# Directory names (anywhere in path) that are excluded from processing
SKIP_DIR_NAMES: set[str] = {
    "historical",
    "_quarantine",
    ".git",
}

# File names that are always excluded
SKIP_FILE_NAMES: set[str] = {
    "CLAUDE.md",
}

# Required frontmatter fields in canonical order (after existing content)
REQUIRED_FIELDS: list[str] = [
    "title",
    "dg-publish",
    "dg-metatags",
    "dg-home",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def strip_bom(text: str) -> str:
    """Remove UTF-8 BOM if present."""
    if text.startswith("\ufeff"):
        return text[1:]
    return text


def split_preamble(text: str) -> tuple[str, str]:
    """
    Split off any leading content that comes *before* the first YAML fence.

    Preamble = leading blank lines and HTML comments (<!-- ... -->).
    Returns (preamble, rest) where rest starts at '---' or is the whole text.
    """
    preamble_lines: list[str] = []
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped == "":
            preamble_lines.append(line)
            i += 1
            continue
        if stripped.startswith("<!--"):
            # consume until closing -->
            preamble_lines.append(line)
            if "-->" not in stripped or stripped == "<!--":
                i += 1
                while i < len(lines):
                    preamble_lines.append(lines[i])
                    if "-->" in lines[i]:
                        i += 1
                        break
                    i += 1
            else:
                i += 1
            continue
        # Not blank, not HTML comment → stop
        break
    preamble = "".join(preamble_lines)
    rest = "".join(lines[i:])
    return preamble, rest


def extract_frontmatter(text: str) -> tuple[str | None, str]:
    """
    Extract YAML frontmatter from text.

    Returns (frontmatter_content, body) where:
    - frontmatter_content is the text between the --- fences (may be empty string)
    - body is everything after the closing ---
    Returns (None, text) if no valid frontmatter found.
    """
    if not text.startswith("---"):
        return None, text

    # Find closing fence: a line that is exactly '---' (possibly with trailing whitespace)
    closer = re.compile(r"^---[ \t]*$", re.MULTILINE)
    # Skip the opening fence line
    first_newline = text.find("\n")
    if first_newline == -1:
        return None, text

    search_start = first_newline + 1
    match = closer.search(text, search_start)
    if not match:
        # Unclosed frontmatter — treat as no frontmatter
        return None, text

    fm_content = text[search_start : match.start()]
    body = text[match.end() :]
    # body starts with \n if closer wasn't at EOF
    if body.startswith("\n"):
        body = body[1:]
    return fm_content, body


def get_top_level_keys(fm_content: str) -> dict[str, int]:
    """
    Return a mapping of {key: line_index} for all top-level YAML keys
    (non-indented lines of the form `key:` or `key: value`).
    """
    keys: dict[str, int] = {}
    for i, line in enumerate(fm_content.splitlines()):
        m = re.match(r"^([A-Za-z0-9_\-]+)\s*:", line)
        if m:
            keys[m.group(1)] = i
    return keys


def title_from_path(path: Path) -> str:
    """Derive a human-readable title from the file stem."""
    return path.stem.replace("_", " ")


def ensure_fields(
    fm_content: str,
    path: Path,
) -> tuple[str, bool]:
    """
    Add or fix required fields in the frontmatter content string.

    Returns (new_fm_content, changed).
    """
    lines = fm_content.splitlines(keepends=True)
    top_keys = get_top_level_keys(fm_content)
    changed = False

    # ---- Fix dg-publish ----
    if "dg-publish" in top_keys:
        idx = top_keys["dg-publish"]
        line = lines[idx]
        # Acceptable: 'dg-publish: true' (with optional trailing whitespace/comment)
        if not re.match(r"^dg-publish\s*:\s*true", line):
            lines[idx] = re.sub(r"^(dg-publish\s*:).*", r"\1 true", line).rstrip() + "\n"
            changed = True

    # ---- Fix title (fill if empty) ----
    if "title" in top_keys:
        idx = top_keys["title"]
        line = lines[idx]
        # Empty title: 'title:' or 'title: ' or 'title: ""' or 'title: '...'
        m = re.match(r'^title\s*:\s*(""|\'\'|)\s*$', line.rstrip())
        if m:
            title = title_from_path(path)
            lines[idx] = f'title: "{title}"\n'
            changed = True

    # ---- Append missing fields ----
    existing = set(top_keys.keys())
    to_add: list[str] = []

    for field in REQUIRED_FIELDS:
        if field not in existing:
            if field == "title":
                to_add.append(f'title: "{title_from_path(path)}"\n')
            elif field == "dg-publish":
                to_add.append("dg-publish: true\n")
            else:
                to_add.append(f"{field}:\n")
            changed = True

    if to_add:
        # Ensure the existing content ends with a newline before appending
        new_content = "".join(lines)
        if new_content and not new_content.endswith("\n"):
            new_content += "\n"
        new_content += "".join(to_add)
        return new_content, changed

    return "".join(lines), changed


def process_file(
    path: Path,
    *,
    dry_run: bool,
    verbose: bool,
) -> str:
    """
    Process a single markdown file.

    Returns one of: 'SKIPPED', 'FIXED', 'MODIFIED', 'ERROR'
    'FIXED'    — frontmatter was absent/malformed, now created from scratch
    'MODIFIED' — frontmatter existed but fields were missing/wrong
    'SKIPPED'  — file was already compliant
    'ERROR'    — file could not be processed
    """
    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"  ERROR  {path}: cannot read — {exc}", file=sys.stderr)
        return "ERROR"

    try:
        text = raw.decode("utf-8-sig")  # handles BOM automatically
    except UnicodeDecodeError as exc:
        print(f"  ERROR  {path}: UTF-8 decode failed — {exc}", file=sys.stderr)
        return "ERROR"

    preamble, rest = split_preamble(text)
    fm_content, body = extract_frontmatter(rest)

    if fm_content is None:
        # No frontmatter at all — create from scratch
        title = title_from_path(path)
        new_fm = (
            f'title: "{title}"\n'
            "dg-publish: true\n"
            "dg-metatags:\n"
            "dg-home:\n"
        )
        new_text = preamble + "---\n" + new_fm + "---\n" + (("\n" + rest) if rest else "")
        status = "FIXED"
    else:
        new_fm, changed = ensure_fields(fm_content, path)
        if not changed:
            if verbose:
                print(f"  SKIPPED  {path.relative_to(DOCS_DIR.parent)}")
            return "SKIPPED"
        new_text = preamble + "---\n" + new_fm + "---\n" + (("\n" + body) if body else "")
        status = "MODIFIED"

    print(f"  {status}  {path.relative_to(DOCS_DIR.parent)}")

    if not dry_run:
        try:
            path.write_text(new_text, encoding="utf-8")
        except OSError as exc:
            print(f"  ERROR  {path}: cannot write — {exc}", file=sys.stderr)
            return "ERROR"

    return status


def should_skip(path: Path) -> bool:
    """Return True if this path should be excluded from processing."""
    if path.name in SKIP_FILE_NAMES:
        return True
    for part in path.parts:
        if part in SKIP_DIR_NAMES:
            return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enforce canonical YAML frontmatter in docs/",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing files",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Also log SKIPPED files",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: exit 1 if any file needs changes (implies --dry-run)",
    )
    args = parser.parse_args()

    dry_run = args.dry_run or args.ci

    if not DOCS_DIR.is_dir():
        print(f"ERROR: docs/ directory not found at {DOCS_DIR}", file=sys.stderr)
        return 2

    counters = {"FIXED": 0, "MODIFIED": 0, "SKIPPED": 0, "ERROR": 0}

    for md_path in sorted(DOCS_DIR.rglob("*.md")):
        if should_skip(md_path):
            if args.verbose:
                print(f"  SKIPPED  {md_path.relative_to(DOCS_DIR.parent)}  (excluded)")
            continue
        result = process_file(md_path, dry_run=dry_run, verbose=args.verbose)
        counters[result] += 1

    total = sum(counters.values())
    changed = counters["FIXED"] + counters["MODIFIED"]

    mode = ""
    if args.ci:
        mode = " [CI]"
    elif dry_run:
        mode = " [DRY-RUN]"

    print(
        f"\n{'─'*50}\n"
        f"enforce-frontmatter{mode}\n"
        f"  Scanned : {total}\n"
        f"  Fixed   : {counters['FIXED']}\n"
        f"  Modified: {counters['MODIFIED']}\n"
        f"  Skipped : {counters['SKIPPED']}\n"
        f"  Errors  : {counters['ERROR']}\n"
    )

    if counters["ERROR"] > 0:
        return 2
    if changed > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
