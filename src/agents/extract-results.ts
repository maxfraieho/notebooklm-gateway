export function flattenToolCalls(
  steps: any[] | undefined,
  directToolCalls?: any[],
): any[] {
  if (directToolCalls && directToolCalls.length > 0) return directToolCalls;
  if (!steps) return [];
  const calls: any[] = [];
  for (const step of steps) {
    if (step.toolCalls) calls.push(...step.toolCalls);
  }
  return calls;
}

export function flattenToolResults(
  steps: any[] | undefined,
  directToolResults?: any[],
): any[] {
  if (directToolResults && directToolResults.length > 0) return directToolResults;
  if (!steps) return [];
  const results: any[] = [];
  for (const step of steps) {
    if (step.toolResults) results.push(...step.toolResults);
  }
  return results;
}

export function extractEntitiesFromToolCalls(
  toolResults: any[],
): Array<{ entityId: string; action: string; name: string }> {
  const entities: Array<{ entityId: string; action: string; name: string }> = [];
  const seen = new Set<string>();

  for (const call of toolResults) {
    if (call.toolName === "write-memory") {
      const result = call.result as { entityId?: string } | null;
      const entityId = result?.entityId;
      if (entityId && !seen.has(entityId)) {
        seen.add(entityId);
        const parts = entityId.split("/");
        entities.push({
          entityId,
          action: "updated",
          name: parts[parts.length - 1] ?? entityId,
        });
      }
    }
  }
  return entities;
}

export function extractCommitSha(
  toolResults: any[],
): string | undefined {
  for (const call of toolResults) {
    if (call.toolName === "commit-memory") {
      const result = call.result as { commitSha?: string } | null;
      if (result?.commitSha) return result.commitSha;
    }
  }
  return undefined;
}

export function extractSubQueries(
  toolCalls: any[],
): string[] {
  return toolCalls
    .filter((c: any) => c.toolName === "search-memory")
    .map((c: any) => c.args?.query ?? "")
    .filter(Boolean);
}

export function extractSources(
  toolResults: any[],
): Array<{ entityId: string; score: number; snippet?: string }> {
  const sources: Array<{ entityId: string; score: number; snippet?: string }> = [];
  for (const call of toolResults) {
    if (call.toolName === "search-memory") {
      const result = call.result as {
        results?: Array<{ entityId?: string; id?: string; score: number; snippet?: string }>;
      } | null;
      if (result?.results) {
        for (const r of result.results.slice(0, 3)) {
          const entityId = r.entityId || r.id;
          if (entityId) {
            sources.push({ entityId, score: r.score, snippet: r.snippet });
          }
        }
      }
    }
  }
  return sources;
}
