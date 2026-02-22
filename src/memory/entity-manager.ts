import { config } from "../config.js";
import type { Entity } from "../types.js";
import {
  parseMarkdown,
  entityToMarkdown,
  idToPath,
} from "../utils/markdown.js";
import {
  initGitStore,
  pullLatest,
  readFile,
  writeFile,
  deleteFile,
  commitAndPush,
  listFiles,
} from "./git-store.js";
import {
  initIndex,
  addToIndex,
  removeFromIndex,
  getEntity,
  getAllEntities,
  search,
} from "./bm25-index.js";

let loaded = false;

export async function loadEntities(): Promise<number> {
  await initGitStore();
  initIndex();

  const basePath = config.githubBasePath;
  const files = await listFiles(basePath);

  for (const filePath of files) {
    const raw = await readFile(filePath);
    if (!raw) continue;
    const entity = parseMarkdown(raw, filePath);
    addToIndex(entity);
  }

  rebuildBacklinks();
  loaded = true;
  return files.length;
}

export async function refreshFromRemote(): Promise<number> {
  await pullLatest();
  return loadEntities();
}

export function findEntity(id: string): Entity | undefined {
  return getEntity(id);
}

export function listEntities(): Entity[] {
  return getAllEntities();
}

export function searchEntities(query: string, limit?: number) {
  return search(query, limit);
}

export async function upsertEntity(
  entity: Partial<Entity> & { id: string; title: string; content: string },
): Promise<Entity> {
  const existing = getEntity(entity.id);
  const now = new Date().toISOString();

  const full: Entity = {
    id: entity.id,
    title: entity.title,
    content: entity.content,
    aliases: entity.aliases || existing?.aliases || [],
    links: [],
    backlinks: existing?.backlinks || [],
    tags: entity.tags || existing?.tags || [],
    createdAt: existing?.createdAt || now,
    updatedAt: now,
    meta: { ...existing?.meta, ...entity.meta },
  };

  const md = entityToMarkdown(full);
  const parsed = parseMarkdown(md, idToPath(full.id, config.githubBasePath));
  full.links = parsed.links;

  if (existing) removeFromIndex(entity.id);
  addToIndex(full);
  rebuildBacklinks();

  const relPath = idToPath(full.id, config.githubBasePath);
  await writeFile(relPath, md);

  return full;
}

export async function removeEntity(id: string): Promise<boolean> {
  const existing = getEntity(id);
  if (!existing) return false;

  removeFromIndex(id);
  rebuildBacklinks();

  const relPath = idToPath(id, config.githubBasePath);
  await deleteFile(relPath);

  return true;
}

export async function commitChanges(message: string): Promise<string> {
  return commitAndPush(message);
}

function rebuildBacklinks(): void {
  const all = getAllEntities();
  const backlinkMap = new Map<string, string[]>();

  for (const entity of all) {
    for (const link of entity.links) {
      const existing = backlinkMap.get(link) || [];
      existing.push(entity.id);
      backlinkMap.set(link, existing);
    }
  }

  for (const entity of all) {
    entity.backlinks = backlinkMap.get(entity.id) || [];
  }
}
