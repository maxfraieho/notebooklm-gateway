import {
  loadEntities,
  refreshFromRemote,
  findEntity,
  listEntities,
  upsertEntity,
  removeEntity,
  commitChanges,
} from "./entity-manager.js";
import { search, getEntityCount } from "./bm25-index.js";
import {
  assembleContext,
  assembleContextFromQuery,
} from "./context-manager.js";
import { computeDiff } from "./diff-engine.js";
import type {
  Entity,
  SearchResult,
  ContextGraph,
  DiffResult,
  CommitResult,
} from "../types.js";

export class MemoryAdapter {
  private initialized = false;

  async init(): Promise<{ entityCount: number }> {
    const count = await loadEntities();
    this.initialized = true;
    return { entityCount: count };
  }

  async refresh(): Promise<{ entityCount: number }> {
    const count = await refreshFromRemote();
    return { entityCount: count };
  }

  search(query: string, limit?: number): SearchResult[] {
    return search(query, limit);
  }

  getEntity(id: string): Entity | undefined {
    return findEntity(id);
  }

  listEntities(): Entity[] {
    return listEntities();
  }

  getContext(rootId: string, maxDepth?: number, maxTokens?: number): ContextGraph {
    return assembleContext(rootId, maxDepth, maxTokens);
  }

  getContextForQuery(query: string, maxDepth?: number, maxTokens?: number): ContextGraph {
    return assembleContextFromQuery(query, maxDepth, maxTokens);
  }

  async write(entity: Partial<Entity> & { id: string; title: string; content: string }): Promise<{ entity: Entity; diff: DiffResult }> {
    const existing = findEntity(entity.id);
    const beforeContent = existing?.content || "";

    const updated = await upsertEntity(entity);
    const diff = computeDiff(entity.id, beforeContent, updated.content);

    return { entity: updated, diff };
  }

  async delete(id: string): Promise<boolean> {
    return removeEntity(id);
  }

  async commit(message: string): Promise<CommitResult> {
    const sha = await commitChanges(message);
    return { sha, message, filesChanged: [] };
  }

  get isInitialized(): boolean {
    return this.initialized;
  }

  get entityCount(): number {
    return getEntityCount();
  }
}

export const memory = new MemoryAdapter();

let _adapterInstance: MemoryAdapter | null = null;

export function setAdapter(instance: MemoryAdapter): void {
  _adapterInstance = instance;
}

export function getAdapter(): MemoryAdapter {
  if (!_adapterInstance) throw new Error('MemoryAdapter not initialized. Call setAdapter() first.');
  return _adapterInstance;
}
