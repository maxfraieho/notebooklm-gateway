function getToolName(call: any): string {
  return call?.payload?.toolName ?? call?.toolName ?? "";
}

function getArgs(call: any): Record<string, any> {
  return call?.payload?.args ?? call?.args ?? {};
}

function getResult(call: any): any {
  return call?.payload?.result ?? call?.result ?? null;
}

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
    if (getToolName(call) === "write-memory") {
      const result = getResult(call);
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
    if (getToolName(call) === "commit-memory") {
      const result = getResult(call);
      if (result?.commitSha) return result.commitSha;
    }
  }
  return undefined;
}

export function extractSubQueries(
  toolCalls: any[],
): string[] {
  return toolCalls
    .filter((c: any) => getToolName(c) === "search-memory")
    .map((c: any) => getArgs(c)?.query ?? "")
    .filter(Boolean);
}

export function extractSources(
  toolResults: any[],
): Array<{ entityId: string; score: number; snippet?: string }> {
  const sources: Array<{ entityId: string; score: number; snippet?: string }> = [];
  const seen = new Set<string>();

  for (const call of toolResults) {
    if (getToolName(call) === "search-memory") {
      const result = getResult(call);
      if (result?.results) {
        for (const r of result.results.slice(0, 5)) {
          const entityId = r.entityId || r.id;
          if (entityId && !seen.has(entityId)) {
            seen.add(entityId);
            sources.push({ entityId, score: r.score, snippet: r.snippet });
          }
        }
      }
    }
  }
  return sources;
}
