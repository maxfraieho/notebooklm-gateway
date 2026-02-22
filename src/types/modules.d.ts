declare module "wink-bm25-text-search" {
  class BM25 {
    defineConfig(config: { fldWeights: Record<string, number> }): void;
    definePrepTasks(tasks: Array<(text: string) => string[]>): void;
    addDoc(doc: Record<string, string>, id: string): void;
    consolidate(): void;
    search(query: string, limit?: number): Array<[string, number]>;
  }
  export default BM25;
}

declare module "wink-eng-lite-web-model" {
  const model: any;
  export default model;
}

declare module "isomorphic-git/http/node" {
  const http: any;
  export default http;
}
