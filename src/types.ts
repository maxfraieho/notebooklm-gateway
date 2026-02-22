export interface Entity {
  id: string;
  title: string;
  content: string;
  aliases: string[];
  links: string[];
  backlinks: string[];
  tags: string[];
  createdAt: string;
  updatedAt: string;
  meta: Record<string, unknown>;
}

export interface SearchResult {
  id: string;
  title: string;
  score: number;
  snippet: string;
}

export interface ContextNode {
  entity: Entity;
  depth: number;
  relevance: number;
}

export interface ContextGraph {
  root: string;
  nodes: ContextNode[];
  totalTokens: number;
}

export interface DiffResult {
  entityId: string;
  before: string;
  after: string;
  patch: string;
  additions: number;
  deletions: number;
}

export interface CommitResult {
  sha: string;
  message: string;
  filesChanged: string[];
}

export interface MemoryQuery {
  query: string;
  maxDepth?: number;
  maxTokens?: number;
  tags?: string[];
}

export interface MemoryWrite {
  entityId?: string;
  title: string;
  content: string;
  tags?: string[];
  aliases?: string[];
  meta?: Record<string, unknown>;
}
