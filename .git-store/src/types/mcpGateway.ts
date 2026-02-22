export type AccessType = 'web' | 'mcp' | 'both';

export type NotebookLMStatus =
  | 'not_created'
  | 'queued'
  | 'created'
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed';

// Unified error codes for UI mapping (V1 Appendix A canonical)
export type GatewayErrorCode =
  | 'NETWORK_OFFLINE'
  | 'TIMEOUT'
  | 'AUTH_REQUIRED'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'ZONE_EXPIRED'
  | 'ZONE_NOT_FOUND'
  | 'NOT_FOUND'
  | 'RATE_LIMITED'
  | 'SERVER_ERROR'
  | 'BAD_REQUEST'
  | 'UNKNOWN'
  // V1 Appendix A codes
  | 'CONCURRENT_MODIFICATION'
  | 'INVALID_TRANSITION'
  | 'VALIDATION_FAILED'
  | 'INVALID_JSON'
  | 'TOKEN_EXPIRED'
  | 'DUPLICATE_ENTRY'
  | 'UPSTREAM_UNAVAILABLE'
  | 'AGENT_TIMEOUT'
  | 'INVALID_AGENT_TRANSITION'
  | 'NLM_UNAVAILABLE';

export interface ApiError {
  message: string;
  code: GatewayErrorCode;
  details?: unknown;
  httpStatus?: number;
  retryable: boolean;
}

export interface NotebookLMMapping {
  notebookId: string | null;
  notebookUrl: string | null;
  importJobId: string | null;
  status: NotebookLMStatus;
  createdAt?: number | null;
  lastError?: string | null;
}

export interface NotebookLMJobStatus {
  jobId?: string;
  status: Exclude<NotebookLMStatus, 'not_created'>;
  progress?: number | null; // 0..100
  current_step?: number | null;
  total_steps?: number | null;
  notebook_url?: string | null;
  error?: string | null;
  results?: Array<{
    source?: {
      type?: string;
      bucket?: string | null;
      key?: string | null;
      url?: string | null;
    } | null;
    status?: string | null;
    source_id?: string | null;
    error?: string | null;
    retries?: number | null;
  }> | null;
}

export type NotebookLMChatKind = 'answer' | 'summary' | 'study_guide' | 'flashcards';

export interface NotebookLMChatRequest {
  notebookUrl: string;
  message: string;
  kind?: NotebookLMChatKind;
  history?: Array<{ role: 'user' | 'assistant'; content: string }>;
}

export interface NotebookLMChatResponse {
  success: true;
  answer: string;
  // Optional extra fields from backend (future-proof)
  citations?: Array<{ title?: string; url?: string; snippet?: string }>;
  raw?: unknown;
}

export interface CreateZoneRequest {
  name: string;
  description?: string;
  allowedPaths: string[];
  ttlMinutes: number;
  accessType: AccessType;
  notes?: { slug: string; title: string; content: string; tags: string[] }[];
  createNotebookLM?: boolean;
  notebookTitle?: string;
  notebookShareEmails?: string[];
  notebookSourceMode?: 'minio' | 'url';
  consentRequired?: boolean; // Default true - zone requires confidentiality consent
}

export interface CreateZoneResponse {
  success: true;
  zoneId: string;
  accessCode: string;
  zoneUrl?: string;
  expiresAt?: number;
  noteCount?: number;
  notebooklm?: NotebookLMMapping | null;
}

export interface ZoneListItem {
  id: string;
  name: string;
  description?: string;
  allowedPaths: string[];
  noteCount: number;
  accessType: AccessType;
  createdAt: number;
  expiresAt: number;
  accessCode?: string;
}

// Edit Proposals — canonical V1 lifecycle statuses
export type ProposalStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'auto_approved'
  | 'expired'
  | 'applying'
  | 'applied'
  | 'failed';

export interface GitCommitResult {
  success: boolean;
  sha?: string;
  url?: string;
  message?: string;
  error?: string;
  status?: number;
  hint?: string;
  // Extra diagnostic payload from gateway/backend (optional)
  fullResponse?: unknown;
}

export interface EditProposal {
  proposalId: string;
  zoneId: string;
  zoneName: string;
  noteSlug: string;
  noteTitle: string;
  originalContent: string;
  proposedContent: string;
  guestName: string;
  guestEmail: string | null;
  status: ProposalStatus;
  createdAt: number;
  updatedAt: number;
  reviewedAt: number | null;
}

export interface AcceptProposalResponse {
  success: true;
  proposal: EditProposal;
  gitCommitResult?: GitCommitResult;
}

export interface CreateProposalRequest {
  noteSlug: string;
  noteTitle?: string;
  originalContent: string;
  proposedContent: string;
  guestName?: string;
  guestEmail?: string;
}

export interface ProposalsListResponse {
  success: true;
  proposals: EditProposal[];
  total: number;
  zoneId?: string;
  zoneName?: string;
}
