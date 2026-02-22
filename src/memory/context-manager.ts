import type { Entity, ContextGraph, ContextNode } from "../types.js";
import { config } from "../config.js";
import { countTokens } from "../utils/tokens.js";
import { getEntity } from "./bm25-index.js";
import { search } from "./bm25-index.js";

export function assembleContext(
  rootId: string,
  maxDepth?: number,
  maxTokens?: number,
): ContextGraph {
  const depth = maxDepth ?? config.maxDepth;
  const tokenBudget = maxTokens ?? config.maxContextTokens;

  const visited = new Set<string>();
  const nodes: ContextNode[] = [];
  let totalTokens = 0;

  function traverse(id: string, currentDepth: number, relevance: number) {
    if (currentDepth > depth) return;
    if (visited.has(id)) return;

    const entity = getEntity(id);
    if (!entity) return;

    const entityTokens = countTokens(entity.content);
    if (totalTokens + entityTokens > tokenBudget) return;

    visited.add(id);
    totalTokens += entityTokens;

    nodes.push({ entity, depth: currentDepth, relevance });

    const neighbors = [...entity.links, ...entity.backlinks];
    for (const neighbor of neighbors) {
      traverse(neighbor, currentDepth + 1, relevance * 0.7);
    }
  }

  traverse(rootId, 0, 1.0);

  return { root: rootId, nodes, totalTokens };
}

export function assembleContextFromQuery(
  query: string,
  maxDepth?: number,
  maxTokens?: number,
): ContextGraph {
  const results = search(query, 3);
  if (results.length === 0) {
    return { root: "", nodes: [], totalTokens: 0 };
  }

  const depth = maxDepth ?? config.maxDepth;
  const tokenBudget = maxTokens ?? config.maxContextTokens;

  const visited = new Set<string>();
  const nodes: ContextNode[] = [];
  let totalTokens = 0;

  for (const result of results) {
    function traverse(id: string, currentDepth: number, relevance: number) {
      if (currentDepth > depth) return;
      if (visited.has(id)) return;

      const entity = getEntity(id);
      if (!entity) return;

      const entityTokens = countTokens(entity.content);
      if (totalTokens + entityTokens > tokenBudget) return;

      visited.add(id);
      totalTokens += entityTokens;

      nodes.push({ entity, depth: currentDepth, relevance });

      const neighbors = [...entity.links, ...entity.backlinks];
      for (const neighbor of neighbors) {
        traverse(neighbor, currentDepth + 1, relevance * 0.7);
      }
    }

    traverse(result.id, 0, result.score);
  }

  return { root: results[0].id, nodes, totalTokens };
}
