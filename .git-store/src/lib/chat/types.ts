// Chat Canvas Type Definitions
// Architecture: React → Cloudflare Worker → MinIO (storage) + KV (index)

export type ParticipantRole = 'owner' | 'guest' | 'archivist' | 'tech-writer' | 'architect';
export type MessageStatus = 'sending' | 'sent' | 'failed';

export interface ChatParticipant {
  id: string;
  name: string;
  role: ParticipantRole;
  isAI: boolean;
  agentModel?: string; // e.g., 'claude-3.5', 'gpt-4'
  avatar?: string;
}

export interface ChatCitation {
  id: string;
  text: string; // Quoted excerpt
  source?: string; // Source name or title
  url?: string; // Optional link
}

export interface ChatMessage {
  id: string;
  chatId: string;
  participant: ChatParticipant;
  content: string;
  createdAt: string;
  status: MessageStatus;
  replyToId?: string;
  taskId?: string; // Reference to AI task if applicable
  citations?: ChatCitation[]; // Sources referenced in AI response
}

export interface Chat {
  id: string;
  title: string;
  participants: ChatParticipant[];
  createdAt: string;
  updatedAt: string;
  zoneId?: string; // Link to Access Zone if applicable
  noteSlug?: string; // Link to specific note if applicable
}

export interface ChatIndex {
  chatId: string;
  messageCount: number;
  lastMessageAt: string;
  participantIds: string[];
}

// Available AI Colleagues
export const AI_COLLEAGUES: ChatParticipant[] = [
  {
    id: 'archivist',
    name: 'Archivist',
    role: 'archivist',
    isAI: true,
    agentModel: 'claude-3.5',
    avatar: '📚',
  },
  {
    id: 'tech-writer',
    name: 'Tech Writer',
    role: 'tech-writer',
    isAI: true,
    agentModel: 'gpt-4',
    avatar: '✍️',
  },
  {
    id: 'architect',
    name: 'Architect',
    role: 'architect',
    isAI: true,
    agentModel: 'claude-3.5',
    avatar: '🏗️',
  },
];

// API Request/Response Types
export interface SendMessageRequest {
  chatId: string;
  content: string;
  participantId: string;
  replyToId?: string;
}

export interface SendMessageResponse {
  success: boolean;
  message?: ChatMessage;
  error?: string;
}

export interface FetchMessagesResponse {
  success: boolean;
  messages: ChatMessage[];
  total: number;
  error?: string;
}

export interface CreateChatRequest {
  title: string;
  participantIds: string[];
  zoneId?: string;
  noteSlug?: string;
}

export interface CreateChatResponse {
  success: boolean;
  chat?: Chat;
  error?: string;
}
