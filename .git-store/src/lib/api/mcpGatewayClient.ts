import type {
  ApiError,
  GatewayErrorCode,
  CreateZoneRequest,
  CreateZoneResponse,
  NotebookLMChatRequest,
  NotebookLMChatResponse,
  NotebookLMJobStatus,
  NotebookLMMapping,
} from '@/types/mcpGateway';
import { pushApiError } from './apiErrorStore';
import { getOwnerToken } from '@/hooks/useOwnerAuth';

const DEFAULT_GATEWAY = 'https://garden-mcp-server.maxfraieho.workers.dev';
const REQUEST_TIMEOUT_MS = 30000;

export function getGatewayBaseUrl() {
  return import.meta.env.VITE_MCP_GATEWAY_URL || DEFAULT_GATEWAY;
}

// Human-friendly error messages
const ERROR_MESSAGES: Record<GatewayErrorCode, string> = {
  NETWORK_OFFLINE: "No internet connection. Check your network and try again.",
  TIMEOUT: "Request timed out. Please try again.",
  AUTH_REQUIRED: "Please log in to continue.",
  UNAUTHORIZED: "Session expired. Please log in again.",
  FORBIDDEN: "You do not have permission to access this resource.",
  ZONE_EXPIRED: "This zone has expired. Contact the owner for a new link.",
  ZONE_NOT_FOUND: "Zone not found. It may have been deleted.",
  NOT_FOUND: "The requested resource was not found.",
  RATE_LIMITED: "Too many requests. Please wait a moment.",
  SERVER_ERROR: "Something went wrong on our end. Please try again later.",
  BAD_REQUEST: "Invalid request. Please check your input.",
  UNKNOWN: "An unexpected error occurred. Please try again.",
  CONCURRENT_MODIFICATION: "This resource was modified by another user. Please refresh and try again.",
  INVALID_TRANSITION: "This action is not allowed in the current state.",
  VALIDATION_FAILED: "Input validation failed. Please check your data.",
  INVALID_JSON: "Invalid request format.",
  TOKEN_EXPIRED: "Your session has expired. Please log in again.",
  DUPLICATE_ENTRY: "This entry already exists.",
  UPSTREAM_UNAVAILABLE: "An external service is temporarily unavailable. Please try again later.",
  AGENT_TIMEOUT: "The agent took too long to respond. Please try again.",
  INVALID_AGENT_TRANSITION: "The agent attempted an invalid state transition.",
  NLM_UNAVAILABLE: "NotebookLM service is temporarily unavailable.",
};

// Whether the error is retryable
const RETRYABLE_CODES: Set<GatewayErrorCode> = new Set([
  'NETWORK_OFFLINE',
  'TIMEOUT',
  'RATE_LIMITED',
  'SERVER_ERROR',
  'UPSTREAM_UNAVAILABLE',
  'AGENT_TIMEOUT',
  'CONCURRENT_MODIFICATION',
  'NLM_UNAVAILABLE',
]);

function createApiError(
  code: GatewayErrorCode,
  httpStatus?: number,
  details?: unknown,
  customMessage?: string
): ApiError {
  return {
    code,
    message: customMessage || ERROR_MESSAGES[code],
    httpStatus,
    details,
    retryable: RETRYABLE_CODES.has(code),
  };
}

function mapHttpStatusToCode(status: number, serverCode?: string): GatewayErrorCode {
  // If backend sends a known error.code, use it directly (V1 contract)
  if (serverCode) {
    const upper = serverCode.toUpperCase() as GatewayErrorCode;
    if (upper in ERROR_MESSAGES) return upper;
    // Legacy fallback patterns
    if (upper.includes('ZONE_EXPIRED') || upper.includes('EXPIRED')) return 'ZONE_EXPIRED';
    if (upper.includes('ZONE_NOT_FOUND')) return 'ZONE_NOT_FOUND';
    if (upper.includes('NOT_AUTHENTICATED') || upper.includes('AUTH')) return 'AUTH_REQUIRED';
    if (upper.includes('RATE_LIMIT')) return 'RATE_LIMITED';
  }

  // Fallback mapping only if code absent
  switch (status) {
    case 400:
      return 'BAD_REQUEST';
    case 401:
      return 'UNAUTHORIZED';
    case 403:
      return 'FORBIDDEN';
    case 404:
      return 'NOT_FOUND';
    case 409:
      return 'CONCURRENT_MODIFICATION';
    case 410:
      return 'ZONE_EXPIRED';
    case 422:
      return 'VALIDATION_FAILED';
    case 429:
      return 'RATE_LIMITED';
    default:
      if (status >= 500) return 'SERVER_ERROR';
      return 'UNKNOWN';
  }
}

async function safeJson(res: Response): Promise<any> {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

export async function parseError(resOrErr: Response | unknown): Promise<ApiError> {
  // Network / thrown error
  if (!(resOrErr instanceof Response)) {
    const errObj = resOrErr instanceof Error ? resOrErr : null;
    const errMessage = errObj?.message?.toLowerCase() || '';

    // Detect specific error types
    if (errMessage.includes('timeout') || errMessage.includes('aborted')) {
      const err = createApiError('TIMEOUT');
      pushApiError(err);
      return err;
    }

    if (
      errMessage.includes('network') ||
      errMessage.includes('fetch') ||
      errMessage.includes('failed to fetch') ||
      errMessage.includes('offline') ||
      !navigator.onLine
    ) {
      const err = createApiError('NETWORK_OFFLINE');
      pushApiError(err);
      return err;
    }

    // Generic network error
    const err = createApiError('UNKNOWN', undefined, errObj?.message);
    pushApiError(err);
    return err;
  }

  const res = resOrErr;
  const data = await safeJson(res);

  // Extract server error code/message
  let serverCode: string | undefined;
  let serverMessage: string | undefined;

  if (data && typeof data === 'object') {
    // { success:false, error:"..." }
    if (typeof data.error === 'string') {
      serverMessage = data.error;
    }
    // { success:false, error:{code,message,details} }
    if (data.error && typeof data.error === 'object') {
      serverCode = data.error.code;
      serverMessage = data.error.message;
    }
    // Direct code on response
    if (data.code) {
      serverCode = data.code;
    }
  }

  const code = mapHttpStatusToCode(res.status, serverCode);

  // Use server message if it's user-friendly, otherwise use our mapping
  const isFriendlyMessage =
    serverMessage &&
    !serverMessage.includes('Error:') &&
    !serverMessage.includes('Exception') &&
    serverMessage.length < 150;

  const err = createApiError(
    code,
    res.status,
    data,
    isFriendlyMessage ? serverMessage : undefined
  );

  pushApiError(err);
  return err;
}

/** Generate UUID v4 for correlation tracking */
function generateCorrelationId(): string {
  return crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

async function requestJson<T>(
  path: string,
  init: RequestInit & { requireAuth?: boolean; timeoutMs?: number; retries?: number; retryDelayMs?: number } = {}
): Promise<T> {
  const maxRetries = init.retries ?? 0;
  const baseDelay = init.retryDelayMs ?? 1500;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await requestJsonOnce<T>(path, init);
    } catch (err: unknown) {
      const isRetryable = err && typeof err === 'object' && 'retryable' in err && (err as ApiError).retryable;
      const is503 = err && typeof err === 'object' && 'httpStatus' in err && (err as ApiError).httpStatus === 503;

      if (attempt < maxRetries && (isRetryable || is503)) {
        const delay = baseDelay * Math.pow(2, attempt);
        console.log(`[gateway] Retry ${attempt + 1}/${maxRetries} after ${delay}ms (503/retryable)`);
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      throw err;
    }
  }
  // Unreachable but TypeScript needs it
  throw createApiError('UNKNOWN');
}

async function requestJsonOnce<T>(
  path: string,
  init: RequestInit & { requireAuth?: boolean; timeoutMs?: number } = {}
): Promise<T> {
  const baseUrl = getGatewayBaseUrl();
  const url = `${baseUrl}${path}`;
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string> | undefined),
  };

  // Task 4: Correlation ID — generated per request, single location
  headers['X-Correlation-Id'] = generateCorrelationId();

  if (!headers['Content-Type'] && init.method && init.method !== 'GET') {
    headers['Content-Type'] = 'application/json';
  }

  if (init.requireAuth) {
    const token = getOwnerToken();
    if (!token) {
      const err = createApiError('AUTH_REQUIRED');
      pushApiError(err);
      throw err;
    }
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Add timeout via AbortController
  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(),
    init.timeoutMs || REQUEST_TIMEOUT_MS
  );

  try {
    const res = await fetch(url, {
      ...init,
      headers,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      throw await parseError(res);
    }

    const data = await safeJson(res);
    return data as T;
  } catch (err) {
    clearTimeout(timeoutId);

    // Already parsed ApiError
    if (err && typeof err === 'object' && 'code' in err && 'retryable' in err) {
      throw err;
    }

    // AbortError = timeout
    if (err instanceof Error && err.name === 'AbortError') {
      const timeoutErr = createApiError('TIMEOUT');
      pushApiError(timeoutErr);
      throw timeoutErr;
    }

    // Parse other errors
    throw await parseError(err);
  }
}

export async function createZone(payload: CreateZoneRequest): Promise<CreateZoneResponse> {
  return requestJson<CreateZoneResponse>('/zones/create', {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
  });
}

export async function getZoneNotebookLMStatus(zoneId: string): Promise<{ notebooklm: NotebookLMMapping | null }> {
  return requestJson<{ notebooklm: NotebookLMMapping | null }>(`/zones/${zoneId}/notebooklm`, {
    method: 'GET',
  });
}

export async function getNotebookLMJobStatus(
  zoneId: string,
  jobId: string
): Promise<NotebookLMJobStatus> {
  return requestJson<NotebookLMJobStatus>(`/zones/${zoneId}/notebooklm/job/${jobId}`, {
    method: 'GET',
  });
}

export async function retryNotebookLMImport(zoneId: string): Promise<{ notebooklm: NotebookLMMapping }> {
  return requestJson<{ notebooklm: NotebookLMMapping }>(`/zones/${zoneId}/notebooklm/retry-import`, {
    method: 'POST',
    body: JSON.stringify({}),
    requireAuth: true,
  });
}

export async function chatNotebookLM(payload: NotebookLMChatRequest): Promise<NotebookLMChatResponse> {
  // NotebookLM can be slow (browser automation). Allow longer client-side timeout.
  return requestJson<NotebookLMChatResponse>('/notebooklm/chat', {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
    timeoutMs: 120000,
  });
}

/**
 * Guest-facing NotebookLM chat endpoint.
 * Uses zone access code instead of owner auth.
 */
export async function chatNotebookLMGuest(
  zoneId: string,
  zoneCode: string,
  payload: Omit<NotebookLMChatRequest, 'notebookUrl'>
): Promise<NotebookLMChatResponse> {
  return requestJson<NotebookLMChatResponse>(`/zones/${zoneId}/notebooklm/chat`, {
    method: 'POST',
    body: JSON.stringify(payload),
    headers: {
      'X-Zone-Code': zoneCode,
    },
    timeoutMs: 120000,
  });
}

export async function pingHealth(): Promise<{ ok: boolean } | any> {
  return requestJson<any>('/health', { method: 'GET' });
}

// Git Status API (for testing Replit backend integration)
export interface GitStatusResponse {
  exists: boolean;
  path: string;
  sha?: string;
}

export async function getGitStatus(path: string): Promise<GitStatusResponse> {
  const encodedPath = encodeURIComponent(path);
  return requestJson<GitStatusResponse>(`/v1/git/status?path=${encodedPath}`, {
    method: 'GET',
    requireAuth: true,
  });
}

export async function getAuthStatus(): Promise<{
  success: true;
  initialized: boolean;
  notebookLMReady?: boolean;
  notebookLMMessage?: string | null;
  notebookCount?: number | null;
} | any> {
  return requestJson<any>('/auth/status', {
    method: 'POST',
    body: JSON.stringify({}),
  });
}

// ============================================
// Chats API
// ============================================

export interface ChatListItem {
  chatId: string;
  title: string;
  zoneId: string | null;
  zoneName: string | null;
  notebookUrl: string | null;
  lastMessagePreview: string | null;
  lastMessageAt: number;
  unreadCount: number;
  status: 'active' | 'archived';
  accessType: 'web' | 'mcp' | 'both';
  expiresAt: number | null;
  createdAt: number;
  updatedAt: number;
  pinned: boolean;
}

export interface ChatsListResponse {
  success: true;
  chats: ChatListItem[];
  total: number;
  zoneId?: string;
  zoneName?: string;
}

export async function getRecentChats(options?: {
  limit?: number;
  status?: 'active' | 'archived' | 'all';
}): Promise<ChatsListResponse> {
  const params = new URLSearchParams();
  if (options?.limit) params.set('limit', String(options.limit));
  if (options?.status) params.set('status', options.status);
  
  const query = params.toString();
  return requestJson<ChatsListResponse>(`/v1/chats/recent${query ? `?${query}` : ''}`, {
    method: 'GET',
    requireAuth: true,
  });
}

export async function getZoneChats(
  zoneId: string,
  options?: {
    limit?: number;
    status?: 'active' | 'archived' | 'all';
    zoneCode?: string;
  }
): Promise<ChatsListResponse> {
  const params = new URLSearchParams();
  if (options?.limit) params.set('limit', String(options.limit));
  if (options?.status) params.set('status', options.status);

  const query = params.toString();
  const headers: Record<string, string> = {};
  
  // Guest access via zone code
  if (options?.zoneCode) {
    headers['X-Zone-Code'] = options.zoneCode;
  }

  return requestJson<ChatsListResponse>(`/v1/zones/${zoneId}/chats${query ? `?${query}` : ''}`, {
    method: 'GET',
    headers,
  });
}

export async function createServerChat(data: {
  title: string;
  zoneId?: string;
  zoneName?: string;
  notebookUrl?: string;
  accessType?: 'web' | 'mcp' | 'both';
  expiresAt?: number;
}): Promise<{ success: true; chat: ChatListItem }> {
  return requestJson<{ success: true; chat: ChatListItem }>('/v1/chats', {
    method: 'POST',
    body: JSON.stringify(data),
    requireAuth: true,
  });
}

export async function touchChat(
  chatId: string,
  data: {
    lastMessagePreview?: string;
    lastMessageAt?: number;
    unreadCount?: number;
  }
): Promise<{ success: true; chat: ChatListItem }> {
  return requestJson<{ success: true; chat: ChatListItem }>(`/v1/chats/${chatId}/touch`, {
    method: 'POST',
    body: JSON.stringify(data),
    requireAuth: true,
  });
}

export async function patchChat(
  chatId: string,
  data: {
    pinned?: boolean;
    status?: 'active' | 'archived';
    unreadCount?: number;
    title?: string;
  }
): Promise<{ success: true; chat: ChatListItem }> {
  return requestJson<{ success: true; chat: ChatListItem }>(`/v1/chats/${chatId}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
    requireAuth: true,
  });
}

// ============================================
// Edit Proposals API
// ============================================

import type { EditProposal, CreateProposalRequest, ProposalsListResponse, AcceptProposalResponse } from '@/types/mcpGateway';

export async function createProposal(
  zoneId: string,
  zoneCode: string,
  payload: CreateProposalRequest
): Promise<{ success: true; proposal: EditProposal }> {
  return requestJson<{ success: true; proposal: EditProposal }>(`/zones/${zoneId}/proposals`, {
    method: 'POST',
    body: JSON.stringify(payload),
    headers: {
      'X-Zone-Code': zoneCode,
    },
  });
}

export async function getZoneProposals(
  zoneId: string,
  options?: { status?: 'pending' | 'approved' | 'rejected' | 'applied' | 'failed' | 'expired' | 'all'; zoneCode?: string }
): Promise<ProposalsListResponse> {
  const params = new URLSearchParams();
  if (options?.status) params.set('status', options.status);
  
  const query = params.toString();
  const headers: Record<string, string> = {};
  if (options?.zoneCode) {
    headers['X-Zone-Code'] = options.zoneCode;
  }
  
  return requestJson<ProposalsListResponse>(`/zones/${zoneId}/proposals${query ? `?${query}` : ''}`, {
    method: 'GET',
    headers,
  });
}

export async function getPendingProposals(limit?: number): Promise<ProposalsListResponse> {
  const params = new URLSearchParams();
  if (limit) params.set('limit', String(limit));
  
  const query = params.toString();
  return requestJson<ProposalsListResponse>(`/proposals/pending${query ? `?${query}` : ''}`, {
    method: 'GET',
    requireAuth: true,
  });
}

export async function getProposal(
  proposalId: string,
  zoneCode?: string
): Promise<{ success: true; proposal: EditProposal }> {
  const headers: Record<string, string> = {};
  if (zoneCode) {
    headers['X-Zone-Code'] = zoneCode;
  }
  
  return requestJson<{ success: true; proposal: EditProposal }>(`/proposals/${proposalId}`, {
    method: 'GET',
    headers,
  });
}

export async function acceptProposal(
  proposalId: string
): Promise<AcceptProposalResponse> {
  return requestJson<AcceptProposalResponse>(`/proposals/${proposalId}`, {
    method: 'PATCH',
    body: JSON.stringify({ status: 'approved' }),
    requireAuth: true,
  });
}

export async function rejectProposal(
  proposalId: string,
  decisionNote: string
): Promise<{ success: true; proposal: EditProposal }> {
  return requestJson<{ success: true; proposal: EditProposal }>(`/proposals/${proposalId}`, {
    method: 'PATCH',
    body: JSON.stringify({
      status: 'rejected',
      decision_note: decisionNote,
    }),
    requireAuth: true,
  });
}

// ============================================
// Notes Management API (GitHub Commits)
// ============================================

export interface NoteCommitRequest {
  slug?: string;
  title: string;
  content: string;
  tags?: string[];
  folder?: string;
  isNew?: boolean;
}

export interface NoteCommitResponse {
  success: boolean;
  sha?: string;
  url?: string;
  path?: string;
  error?: string;
}

export interface NoteDeleteResponse {
  success: boolean;
  sha?: string;
  path?: string;
  note?: string;
  error?: string;
}

/**
 * Create or update a note via GitHub commit.
 */
export async function commitNote(payload: NoteCommitRequest): Promise<NoteCommitResponse> {
  return requestJson<NoteCommitResponse>('/v1/notes/commit', {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
    retries: 2,
    retryDelayMs: 2000,
  });
}

/**
 * Delete a note via GitHub commit.
 */
export async function deleteNote(slug: string): Promise<NoteDeleteResponse> {
  return requestJson<NoteDeleteResponse>(`/v1/notes/${encodeURIComponent(slug)}`, {
    method: 'DELETE',
    requireAuth: true,
    retries: 2,
    retryDelayMs: 2000,
  });
}

// ============================================
// DRAKON Diagrams API
// ============================================

export interface DrakonCommitRequest {
  /** Note folder slug (e.g., 'exodus.pp.ua/article-name' or standalone 'diagrams/flow') */
  folderSlug?: string;
  /** Diagram ID (filename without extension) */
  diagramId: string;
  /** Diagram JSON content */
  diagram: object;
  /** Human-readable name for commit message */
  name?: string;
  /** Whether this is a new diagram */
  isNew?: boolean;
}

export interface DrakonCommitResponse {
  success: boolean;
  sha?: string;
  url?: string;
  path?: string;
  error?: string;
}

export interface DrakonDeleteResponse {
  success: boolean;
  sha?: string;
  path?: string;
  error?: string;
}

/**
 * Create or update a DRAKON diagram via GitHub commit.
 * Stores as: src/site/notes/{folderSlug}/diagrams/{diagramId}.drakon.json
 */
export async function commitDrakonDiagram(payload: DrakonCommitRequest): Promise<DrakonCommitResponse> {
  return requestJson<DrakonCommitResponse>('/v1/drakon/commit', {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
  });
}

/**
 * Delete a DRAKON diagram via GitHub commit.
 */
export async function deleteDrakonDiagram(
  folderSlug: string,
  diagramId: string
): Promise<DrakonDeleteResponse> {
  return requestJson<DrakonDeleteResponse>(
    `/v1/drakon/${encodeURIComponent(folderSlug)}/${encodeURIComponent(diagramId)}`,
    {
      method: 'DELETE',
      requireAuth: true,
    }
  );
}

// ============================================
// Comments API (used by useComments hook)
// ============================================

export async function fetchComments(
  articleSlug: string,
  options?: { zoneId?: string; zoneCode?: string }
): Promise<any> {
  const headers: Record<string, string> = {};
  if (options?.zoneId) headers['X-Zone-Id'] = options.zoneId;
  if (options?.zoneCode) headers['X-Zone-Code'] = options.zoneCode;
  return requestJson<any>(`/comments/${encodeURIComponent(articleSlug)}`, {
    method: 'GET',
    headers,
    requireAuth: !options?.zoneCode, // Owner auth if no zone code
  });
}

export async function createComment(payload: {
  articleSlug: string;
  content: string;
  parentId?: string | null;
  authorName?: string;
  zoneId?: string;
  zoneCode?: string;
}): Promise<any> {
  const headers: Record<string, string> = {};
  if (payload.zoneId) headers['X-Zone-Id'] = payload.zoneId;
  if (payload.zoneCode) headers['X-Zone-Code'] = payload.zoneCode;
  return requestJson<any>('/comments/create', {
    method: 'POST',
    body: JSON.stringify(payload),
    headers,
  });
}

export async function updateComment(
  commentId: string,
  updates: { status?: string; content?: string }
): Promise<any> {
  return requestJson<any>(`/comments/${commentId}`, {
    method: 'PATCH',
    body: JSON.stringify(updates),
    requireAuth: true,
  });
}

export async function deleteComment(commentId: string): Promise<any> {
  return requestJson<any>(`/comments/${commentId}`, {
    method: 'DELETE',
    requireAuth: true,
  });
}

// ============================================
// Annotations API (used by useAnnotations hook)
// ============================================

export async function fetchAnnotations(articleSlug: string): Promise<any> {
  return requestJson<any>(`/annotations/${encodeURIComponent(articleSlug)}`, {
    method: 'GET',
  });
}

export async function createAnnotation(payload: {
  articleSlug: string;
  highlightedText: string;
  startOffset: number;
  endOffset: number;
  paragraphIndex: number;
  comment: { content: string; authorName: string };
}): Promise<any> {
  return requestJson<any>('/annotations/create', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function deleteAnnotation(annotationId: string): Promise<any> {
  return requestJson<any>(`/annotations/${annotationId}`, {
    method: 'DELETE',
    requireAuth: true,
  });
}

// ============================================
// MCP Sessions API (used by useMCPSessions hook)
// ============================================

export async function createMCPSession(payload: {
  folders: string[];
  ttlMinutes: number;
  notes: any[];
  userId: string;
  metadata: any;
}): Promise<any> {
  return requestJson<any>('/sessions/create', {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
  });
}

export async function revokeMCPSession(sessionId: string): Promise<any> {
  return requestJson<any>('/sessions/revoke', {
    method: 'POST',
    body: JSON.stringify({ sessionId }),
    requireAuth: true,
  });
}

// ============================================
// Zone Validation API (used by useZoneValidation hook)
// ============================================

export async function validateZone(
  zoneId: string,
  accessCode?: string | null
): Promise<any> {
  const params = new URLSearchParams();
  if (accessCode) params.set('code', accessCode);
  const query = params.toString();
  return requestJson<any>(`/zones/validate/${zoneId}${query ? `?${query}` : ''}`, {
    method: 'GET',
  });
}

// ============================================
// Access Zones List/Revoke API (used by useAccessZones hook)
// ============================================

export async function listZones(): Promise<any> {
  return requestJson<any>('/zones/list', {
    method: 'GET',
    requireAuth: true,
  });
}

export async function revokeZone(zoneId: string): Promise<any> {
  return requestJson<any>(`/zones/${zoneId}`, {
    method: 'DELETE',
    requireAuth: true,
  });
}

export async function downloadZoneNotes(zoneId: string, zoneName: string): Promise<void> {
  const base = getGatewayBaseUrl();
  const token = getOwnerToken();
  const headers: Record<string, string> = {
    'X-Correlation-Id': generateCorrelationId(),
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const resp = await fetch(`${base}/zones/${zoneId}/download`, {
    method: 'GET',
    headers,
  });

  if (!resp.ok) {
    throw new Error(`Download failed: ${resp.status}`);
  }

  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${zoneName}-notes.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ============================================
// Auth API (used by useOwnerAuth hook)
// ============================================

// ============================================
// Agent Memory API (DiffMem-like)
// ============================================

import type {
  ContextRequest,
  ContextResponse,
  MemorySearchRequest,
  MemorySearchResponse,
  MemoryProcessRequest,
  MemoryProcessResponse,
  MemoryCommitRequest,
  MemoryCommitResponse,
  MemoryDiffRequest,
  MemoryDiffResponse,
  MemoryTimelineRequest,
  MemoryTimelineResponse,
  MemoryUserStatus,
  MemoryOnboardRequest,
  MemoryOnboardResponse,
  MemoryEntity,
  OrchestratedSearchRequest,
  OrchestratedSearchResponse,
  MemorySyncResponse,
} from '@/types/agentMemory';

export async function getMemoryContext(
  userId: string,
  payload: ContextRequest
): Promise<ContextResponse> {
  return requestJson<ContextResponse>(`/v1/memory/${encodeURIComponent(userId)}/context`, {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
    timeoutMs: 60000,
  });
}

export async function searchMemory(
  userId: string,
  payload: MemorySearchRequest
): Promise<MemorySearchResponse> {
  return requestJson<MemorySearchResponse>(`/v1/memory/${encodeURIComponent(userId)}/search`, {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
  });
}

export async function orchestratedSearchMemory(
  userId: string,
  payload: OrchestratedSearchRequest
): Promise<OrchestratedSearchResponse> {
  return requestJson<OrchestratedSearchResponse>(`/v1/memory/${encodeURIComponent(userId)}/orchestrated-search`, {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
    timeoutMs: 90000,
  });
}

export async function processAndCommitMemory(
  userId: string,
  payload: MemoryProcessRequest
): Promise<MemoryProcessResponse> {
  return requestJson<MemoryProcessResponse>(`/v1/memory/${encodeURIComponent(userId)}/process-and-commit`, {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
    timeoutMs: 120000,
  });
}

export async function processMemorySession(
  userId: string,
  payload: MemoryProcessRequest
): Promise<MemoryProcessResponse> {
  return requestJson<MemoryProcessResponse>(`/v1/memory/${encodeURIComponent(userId)}/process-session`, {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
    timeoutMs: 120000,
  });
}

export async function commitMemorySession(
  userId: string,
  payload: MemoryCommitRequest
): Promise<MemoryCommitResponse> {
  return requestJson<MemoryCommitResponse>(`/v1/memory/${encodeURIComponent(userId)}/commit-session`, {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
  });
}

export async function getMemoryEntity(
  userId: string,
  entityId: string
): Promise<{ success: true; entity: MemoryEntity }> {
  return requestJson<{ success: true; entity: MemoryEntity }>(
    `/v1/memory/${encodeURIComponent(userId)}/entity/${encodeURIComponent(entityId)}`,
    { method: 'GET', requireAuth: true }
  );
}

export async function getMemoryDiff(
  userId: string,
  payload: MemoryDiffRequest
): Promise<MemoryDiffResponse> {
  return requestJson<MemoryDiffResponse>(`/v1/memory/${encodeURIComponent(userId)}/diff`, {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
  });
}

export async function getMemoryStatus(
  userId: string
): Promise<{ success: true } & MemoryUserStatus> {
  return requestJson<{ success: true } & MemoryUserStatus>(
    `/v1/memory/${encodeURIComponent(userId)}/status`,
    { method: 'GET', requireAuth: true }
  );
}

export async function getMemoryTimeline(
  userId: string,
  options?: { daysBack?: number; limit?: number }
): Promise<MemoryTimelineResponse> {
  const params = new URLSearchParams();
  if (options?.daysBack) params.set('daysBack', String(options.daysBack));
  if (options?.limit) params.set('limit', String(options.limit));
  const query = params.toString();
  return requestJson<MemoryTimelineResponse>(
    `/v1/memory/${encodeURIComponent(userId)}/recent-timeline${query ? `?${query}` : ''}`,
    { method: 'GET', requireAuth: true }
  );
}

export async function onboardMemoryUser(
  userId: string,
  payload: MemoryOnboardRequest
): Promise<MemoryOnboardResponse> {
  return requestJson<MemoryOnboardResponse>(`/v1/memory/${encodeURIComponent(userId)}/onboard`, {
    method: 'POST',
    body: JSON.stringify(payload),
    requireAuth: true,
    timeoutMs: 60000,
  });
}

export async function syncMemory(): Promise<MemorySyncResponse> {
  return requestJson<MemorySyncResponse>('/v1/memory/sync', {
    method: 'POST',
    requireAuth: true,
  });
}

export async function getMemoryHealth(): Promise<{
  ok: boolean;
  gitReady: boolean;
  indexReady: boolean;
  entityCount: number;
  uptime: number;
}> {
  return requestJson<any>('/v1/memory/health', { method: 'GET' });
}

export async function authRequest(
  path: string,
  payload: unknown,
  token?: string
): Promise<Response> {
  const baseUrl = getGatewayBaseUrl();
  const url = `${baseUrl}${path}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Correlation-Id': generateCorrelationId(),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}
