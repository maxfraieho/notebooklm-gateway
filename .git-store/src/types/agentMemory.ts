/**
 * Agent Memory Types — DiffMem-like git-based memory for AI agents.
 *
 * Based on DiffMem (Growth-Kinetics/DiffMem) architecture adapted for
 * Garden Bloom's TypeScript/Mastra stack.
 *
 * Core concepts:
 * - Memory = versioned Markdown files in git repo
 * - Current state (files) separated from history (git commits)
 * - BM25 + semantic search over current state
 * - Git diffs for temporal reasoning
 */

// ============================================
// Memory Entity Types
// ============================================

/** Memory entity — a single Markdown file in the memory repo */
export interface MemoryEntity {
  /** Entity ID (file path relative to user's memory root) */
  entityId: string;
  /** Entity type: person, project, concept, timeline, etc. */
  entityType: MemoryEntityType;
  /** Display name */
  name: string;
  /** Full Markdown content (current state) */
  content: string;
  /** Extracted tags */
  tags: string[];
  /** Last modified timestamp (unix ms) */
  updatedAt: number;
  /** Created timestamp (unix ms) */
  createdAt: number;
  /** Number of git commits touching this entity */
  commitCount: number;
}

export type MemoryEntityType =
  | 'person'
  | 'project'
  | 'concept'
  | 'timeline'
  | 'session'
  | 'artifact'
  | 'note'
  | 'custom';

// ============================================
// Context Assembly Types
// ============================================

/**
 * Context depth — mirrors DiffMem's 4-level depth model:
 * - basic: Top entities with ALWAYS_LOAD blocks (fastest, minimal tokens)
 * - wide: Semantic search results + ALWAYS_LOAD blocks
 * - deep: Complete entity files (comprehensive)
 * - temporal: Complete files + git history diffs (most detailed)
 */
export type ContextDepth = 'basic' | 'wide' | 'deep' | 'temporal';

export interface ContextRequest {
  /** Conversation messages to derive context from */
  conversation: Array<{ role: 'user' | 'assistant'; content: string }>;
  /** Context assembly depth */
  depth: ContextDepth;
  /** Optional: limit to specific entity types */
  entityTypes?: MemoryEntityType[];
  /** Optional: max tokens to return */
  maxTokens?: number;
}

export interface ContextResponse {
  success: true;
  /** Assembled context string for LLM consumption */
  context: string;
  /** Entities included in context */
  entities: ContextEntity[];
  /** Token count estimate */
  tokenCount: number;
  /** Depth used */
  depth: ContextDepth;
}

export interface ContextEntity {
  entityId: string;
  name: string;
  entityType: MemoryEntityType;
  /** Relevance score (0-1) */
  relevance: number;
  /** Whether full content was included */
  fullContent: boolean;
  /** Whether git history was included */
  includesHistory: boolean;
}

// ============================================
// Search Types
// ============================================

export interface MemorySearchRequest {
  /** Search query */
  query: string;
  /** Max results (default: 10) */
  k?: number;
  /** Filter by entity types */
  entityTypes?: MemoryEntityType[];
  /** Search method */
  method?: 'bm25' | 'semantic' | 'hybrid';
}

export interface MemorySearchResponse {
  success: true;
  results: MemorySearchResult[];
  query: string;
  method: string;
  totalEntities: number;
}

export interface MemorySearchResult {
  entityId: string;
  name: string;
  entityType: MemoryEntityType;
  /** BM25/semantic relevance score */
  score: number;
  /** Matched snippet */
  snippet: string;
  /** File path in memory repo */
  filePath: string;
}

// ============================================
// Write / Update Types
// ============================================

export interface MemoryProcessRequest {
  /** Raw memory input (conversation transcript, notes, etc.) */
  memoryInput: string;
  /** Session identifier for grouping commits */
  sessionId: string;
  /** Optional session date (ISO 8601) */
  sessionDate?: string;
  /** Whether to auto-commit after processing */
  autoCommit?: boolean;
}

export interface MemoryProcessResponse {
  success: true;
  /** Session ID */
  sessionId: string;
  /** Entities created or updated */
  entitiesAffected: Array<{
    entityId: string;
    action: 'created' | 'updated';
    name: string;
  }>;
  /** Git commit SHA (if autoCommit=true) */
  commitSha?: string;
  /** Commit message */
  commitMessage?: string;
}

export interface MemoryCommitRequest {
  /** Session to commit */
  sessionId: string;
  /** Optional custom commit message */
  message?: string;
}

export interface MemoryCommitResponse {
  success: true;
  sessionId: string;
  commitSha: string;
  commitMessage: string;
  filesChanged: number;
}

// ============================================
// Git History / Diff Types
// ============================================

export interface MemoryDiffRequest {
  /** Entity to get diff for */
  entityId: string;
  /** Number of commits back (default: 1) */
  depth?: number;
  /** Start date for diff range (ISO 8601) */
  since?: string;
  /** End date for diff range (ISO 8601) */
  until?: string;
}

export interface MemoryDiffResponse {
  success: true;
  entityId: string;
  diffs: MemoryDiff[];
}

export interface MemoryDiff {
  commitSha: string;
  commitMessage: string;
  author: string;
  date: number;
  /** Unified diff string */
  diff: string;
  /** Lines added */
  additions: number;
  /** Lines removed */
  deletions: number;
}

export interface MemoryTimelineRequest {
  /** Number of days back (default: 30) */
  daysBack?: number;
  /** Filter by entity types */
  entityTypes?: MemoryEntityType[];
  /** Max entries */
  limit?: number;
}

export interface MemoryTimelineResponse {
  success: true;
  entries: MemoryTimelineEntry[];
  period: { from: string; to: string };
}

export interface MemoryTimelineEntry {
  date: string;
  commitSha: string;
  commitMessage: string;
  entitiesAffected: Array<{
    entityId: string;
    name: string;
    action: 'created' | 'updated' | 'deleted';
  }>;
}

// ============================================
// User / Onboarding Types
// ============================================

export interface MemoryUserStatus {
  userId: string;
  initialized: boolean;
  entityCount: number;
  lastCommitAt: number | null;
  repoSize: number;
  indexStatus: 'ready' | 'building' | 'stale';
}

export interface MemoryOnboardRequest {
  /** User info for initial memory setup */
  userInfo: string;
  sessionId: string;
}

export interface MemoryOnboardResponse {
  success: true;
  userId: string;
  sessionId: string;
  entitiesCreated: number;
}

// ============================================
// Orchestrated Search (LLM-powered)
// ============================================

export interface OrchestratedSearchRequest {
  /** Conversation for LLM to derive search queries from */
  conversation: Array<{ role: 'user' | 'assistant'; content: string }>;
  /** Max results per sub-query */
  k?: number;
}

export interface OrchestratedSearchResponse {
  success: true;
  /** LLM-synthesized answer */
  answer: string;
  /** Sub-queries generated by LLM */
  subQueries: string[];
  /** Source results */
  sources: MemorySearchResult[];
}

// ============================================
// Memory Sync Types
// ============================================

export interface MemorySyncResponse {
  success: true;
  /** Git remote sync status */
  syncStatus: 'synced' | 'ahead' | 'behind' | 'diverged';
  /** Number of commits ahead of remote */
  commitsAhead: number;
  /** Number of commits behind remote */
  commitsBehind: number;
  lastSyncAt: number | null;
}

// ============================================
// Agent Memory Config
// ============================================

export interface AgentMemoryConfig {
  /** Memory API base URL (if different from gateway) */
  memoryBaseUrl?: string;
  /** Default user ID for memory operations */
  userId: string;
  /** Default context depth */
  defaultDepth: ContextDepth;
  /** Default search method */
  defaultSearchMethod: 'bm25' | 'semantic' | 'hybrid';
  /** Auto-sync with remote */
  autoSync: boolean;
  /** Polling interval for sync status (ms) */
  syncIntervalMs: number;
}
