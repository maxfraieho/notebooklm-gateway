// Comments and Annotations Type Definitions
// Architecture: React → Cloudflare Worker → MinIO (storage) + KV (index)

export type CommentStatus = 'pending' | 'approved' | 'rejected' | 'merged';
export type CommentOrigin = 'local' | 'federated';
export type AuthorType = 'human' | 'ai-agent';

export interface CommentAuthor {
  id: string;
  name: string;
  domain: string;
  isOwner: boolean;
  type: AuthorType; // New: human or AI agent
  agentModel?: string; // e.g., 'claude-3.5', 'gpt-4' for AI agents
}

export interface Comment {
  id: string;
  articleSlug: string;
  parentId: string | null;
  author: CommentAuthor;
  content: string;
  createdAt: string;
  updatedAt: string | null;
  status: CommentStatus;
  origin: CommentOrigin;
  originDomain?: string;
  annotationId?: string;
}

export interface Annotation {
  id: string;
  articleSlug: string;
  highlightedText: string;
  startOffset: number;
  endOffset: number;
  paragraphIndex: number;
  commentId: string;
  createdAt: string;
}

export interface CommentIndex {
  articleSlug: string;
  commentCount: number;
  annotationCount: number;
  commentIds: string[];
  annotationIds: string[];
  lastUpdated: string;
}

// API Request/Response Types
export interface CreateCommentRequest {
  articleSlug: string;
  content: string;
  parentId?: string | null;
  authorName?: string;
  authorType?: AuthorType;
  agentModel?: string;
}

export interface CreateCommentResponse {
  success: boolean;
  comment?: Comment;
  error?: string;
}

export interface FetchCommentsResponse {
  success: boolean;
  comments: Comment[];
  total: number;
  error?: string;
}

export interface UpdateCommentRequest {
  status?: CommentStatus;
  content?: string;
}

export interface UpdateCommentResponse {
  success: boolean;
  comment?: Comment;
  error?: string;
}

// Annotation API Types
export interface CreateAnnotationRequest {
  articleSlug: string;
  highlightedText: string;
  startOffset: number;
  endOffset: number;
  paragraphIndex: number;
  comment: {
    content: string;
    authorName?: string;
    authorType?: AuthorType;
    agentModel?: string;
  };
}

export interface CreateAnnotationResponse {
  success: boolean;
  annotation?: Annotation;
  comment?: Comment;
  error?: string;
}

export interface FetchAnnotationsResponse {
  success: boolean;
  annotations: Annotation[];
  comments: Comment[];
  error?: string;
}

// Export types for including comments in MCP export
export interface CommentExportOptions {
  includeApproved: boolean;
  includeMerged: boolean;
  includeAnnotations: boolean;
}

export interface ArticleWithComments {
  slug: string;
  title: string;
  content: string;
  comments: Comment[];
  annotations: Annotation[];
}
