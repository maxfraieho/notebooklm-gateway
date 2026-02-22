import BM25 from "wink-bm25-text-search";
import winkNLP from "wink-nlp";
import model from "wink-eng-lite-web-model";
import type { Entity, SearchResult } from "../types.js";

const nlp = winkNLP(model);
const its = nlp.its;

let engine: any = null;
let entityMap = new Map<string, Entity>();
let needsConsolidate = false;

function pipe(text: string): string[] {
  const doc = nlp.readDoc(text);
  const tokens = doc.tokens();
  const result: string[] = [];
  tokens.each((t: any) => {
    if (t.out(its.type) === "word" && !t.out(its.stopWordFlag)) {
      result.push(t.out(its.stem) as string);
    }
  });
  return result;
}

export function initIndex(): void {
  engine = new BM25();
  engine.defineConfig({ fldWeights: { title: 2, body: 1 } });
  engine.definePrepTasks([pipe]);
  entityMap = new Map();
  needsConsolidate = false;
}

export function addToIndex(entity: Entity): void {
  entityMap.set(entity.id, entity);
  engine.addDoc({ title: entity.title, body: entity.content }, entity.id);
  needsConsolidate = true;
}

export function removeFromIndex(id: string): void {
  entityMap.delete(id);
  const preserved = new Map(entityMap);
  engine = new BM25();
  engine.defineConfig({ fldWeights: { title: 2, body: 1 } });
  engine.definePrepTasks([pipe]);
  for (const e of preserved.values()) {
    engine.addDoc({ title: e.title, body: e.content }, e.id);
  }
  needsConsolidate = true;
}

function ensureConsolidated(): void {
  if (needsConsolidate) {
    try {
      engine.consolidate();
    } catch {
      // may fail if no docs
    }
    needsConsolidate = false;
  }
}

export function search(query: string, limit = 10): SearchResult[] {
  ensureConsolidated();
  try {
    const results = engine.search(query, limit);
    return results.map((r: [string, number]) => {
      const entity = entityMap.get(r[0]);
      return {
        id: r[0],
        title: entity?.title || r[0],
        score: r[1],
        snippet: entity?.content.slice(0, 200) || "",
      };
    });
  } catch {
    return [];
  }
}

export function getEntity(id: string): Entity | undefined {
  return entityMap.get(id);
}

export function getAllEntities(): Entity[] {
  return [...entityMap.values()];
}

export function getEntityCount(): number {
  return entityMap.size;
}
