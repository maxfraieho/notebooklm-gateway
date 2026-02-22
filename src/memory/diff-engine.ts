import { createPatch } from "diff";
import type { DiffResult } from "../types.js";

export function computeDiff(
  entityId: string,
  before: string,
  after: string,
): DiffResult {
  const patch = createPatch(entityId, before, after, "before", "after");

  let additions = 0;
  let deletions = 0;
  for (const line of patch.split("\n")) {
    if (line.startsWith("+") && !line.startsWith("+++")) additions++;
    if (line.startsWith("-") && !line.startsWith("---")) deletions++;
  }

  return {
    entityId,
    before,
    after,
    patch,
    additions,
    deletions,
  };
}
