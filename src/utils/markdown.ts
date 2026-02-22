import type { Entity } from "../types.js";

const WIKILINK_RE = /\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g;
const FRONTMATTER_RE = /^---\n([\s\S]*?)\n---\n/;
const TAG_RE = /#([a-zA-Z0-9_/-]+)/g;

export function parseMarkdown(raw: string, filePath: string): Entity {
  const id = pathToId(filePath);
  let content = raw;
  const meta: Record<string, unknown> = {};
  let title = id;
  let tags: string[] = [];
  let aliases: string[] = [];

  const fmMatch = content.match(FRONTMATTER_RE);
  if (fmMatch) {
    const fm = fmMatch[1];
    content = content.slice(fmMatch[0].length);
    for (const line of fm.split("\n")) {
      const [key, ...rest] = line.split(":");
      if (!key) continue;
      const k = key.trim().toLowerCase();
      const v = rest.join(":").trim();
      if (k === "title") title = v;
      else if (k === "tags") tags = parseYamlArray(v);
      else if (k === "aliases") aliases = parseYamlArray(v);
      else meta[k] = v;
    }
  }

  const inlineTags = [...content.matchAll(TAG_RE)].map((m) => m[1]);
  tags = [...new Set([...tags, ...inlineTags])];

  const links = [...content.matchAll(WIKILINK_RE)].map((m) =>
    m[1].trim().toLowerCase().replace(/\s+/g, "-"),
  );

  return {
    id,
    title: title || id,
    content,
    aliases,
    links: [...new Set(links)],
    backlinks: [],
    tags,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    meta,
  };
}

export function entityToMarkdown(entity: Entity): string {
  const lines: string[] = ["---"];
  lines.push(`title: ${entity.title}`);
  if (entity.tags.length) lines.push(`tags: [${entity.tags.join(", ")}]`);
  if (entity.aliases.length)
    lines.push(`aliases: [${entity.aliases.join(", ")}]`);
  for (const [k, v] of Object.entries(entity.meta)) {
    lines.push(`${k}: ${v}`);
  }
  lines.push("---");
  lines.push("");
  lines.push(entity.content);
  return lines.join("\n");
}

export function pathToId(filePath: string): string {
  return filePath
    .replace(/\.md$/, "")
    .replace(/\\/g, "/")
    .split("/")
    .pop()!
    .toLowerCase()
    .replace(/\s+/g, "-");
}

export function idToPath(id: string, basePath: string): string {
  return `${basePath}/${id}.md`;
}

function parseYamlArray(val: string): string[] {
  const trimmed = val.trim();
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return trimmed
      .slice(1, -1)
      .split(",")
      .map((s) => s.trim().replace(/^["']|["']$/g, ""))
      .filter(Boolean);
  }
  return trimmed ? [trimmed] : [];
}
