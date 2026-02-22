import { useCallback, useEffect, useMemo, useState } from 'react';
import { z } from 'zod';
import { touchChat, patchChat } from '@/lib/api/mcpGatewayClient';

export type NotebookLMChatStatus = 'active' | 'archived';

export type NotebookLMChat = {
  id: string;
  title: string;
  notebookUrl: string;
  createdAt: number;
  updatedAt: number;
  status?: NotebookLMChatStatus;
  pinned?: boolean;
  // Optional zone context (may be set when creating from a zone)
  zoneId?: string;
  zoneName?: string;
  zoneExpiresAt?: number;
  accessType?: 'web' | 'mcp' | 'both';
  // Inbox fields
  unreadCount?: number;
  lastMessagePreview?: string;
  lastMessageAt?: number;
};

export type NotebookLMMessage = {
  id: string;
  chatId: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: number;
};

const chatSchema = z.object({
  title: z.string().trim().min(1).max(80),
  notebookUrl: z.string().trim().url(),
});

const STORAGE_CHATS = 'notebooklm:chats:v1';
const STORAGE_MSG_PREFIX = 'notebooklm:messages:v1:';

function genId(prefix: string) {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function readJson<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function writeJson(key: string, value: unknown) {
  localStorage.setItem(key, JSON.stringify(value));
}

// Sort helper: unread first (if enabled), pinned, then by lastMessageAt/updatedAt
function sortChats(chats: NotebookLMChat[], unreadFirst = true): NotebookLMChat[] {
  return [...chats].sort((a, b) => {
    // Unread first (chats with unreadCount > 0)
    if (unreadFirst) {
      const aUnread = (a.unreadCount ?? 0) > 0;
      const bUnread = (b.unreadCount ?? 0) > 0;
      if (aUnread && !bUnread) return -1;
      if (!aUnread && bUnread) return 1;
    }
    // Pinned first
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    // Then by lastMessageAt (or updatedAt as fallback)
    const aTime = a.lastMessageAt ?? a.updatedAt;
    const bTime = b.lastMessageAt ?? b.updatedAt;
    return bTime - aTime;
  });
}

export function useNotebookLMChats() {
  const [chats, setChats] = useState<NotebookLMChat[]>([]);
  const [activeChatId, setActiveChatIdRaw] = useState<string | null>(null);
  const [messages, setMessages] = useState<NotebookLMMessage[]>([]);

  // Load chats list once
  useEffect(() => {
    const stored = readJson<NotebookLMChat[]>(STORAGE_CHATS);
    if (Array.isArray(stored)) {
      const sorted = sortChats(stored);
      setChats(sorted);
      setActiveChatIdRaw(sorted[0]?.id ?? null);
    }
  }, []);

  // Load messages for active chat
  useEffect(() => {
    if (!activeChatId) {
      setMessages([]);
      return;
    }
    const stored = readJson<NotebookLMMessage[]>(`${STORAGE_MSG_PREFIX}${activeChatId}`);
    setMessages(Array.isArray(stored) ? stored : []);
  }, [activeChatId]);

  const persistChats = useCallback((next: NotebookLMChat[]) => {
    const sorted = sortChats(next);
    setChats(sorted);
    writeJson(STORAGE_CHATS, sorted);
  }, []);

  const persistMessages = useCallback((chatId: string, next: NotebookLMMessage[]) => {
    setMessages(next);
    writeJson(`${STORAGE_MSG_PREFIX}${chatId}`, next);
  }, []);

  const activeChat = useMemo(
    () => chats.find((c) => c.id === activeChatId) ?? null,
    [chats, activeChatId]
  );

  // When selecting a chat, reset unread count
  const setActiveChatId = useCallback((chatId: string | null) => {
    setActiveChatIdRaw(chatId);
    
    if (!chatId) return;
    
    // Find the chat and check if it has unread messages
    const chat = chats.find((c) => c.id === chatId);
    if (chat && (chat.unreadCount ?? 0) > 0) {
      // Reset unread locally
      const now = Date.now();
      const updated = chats.map((c) =>
        c.id === chatId ? { ...c, unreadCount: 0, updatedAt: now } : c
      );
      persistChats(updated);
      
      // Sync to server (fire and forget)
      patchChat(chatId, { unreadCount: 0 }).catch(() => {
        // Ignore errors - local state is source of truth
      });
    }
  }, [chats, persistChats]);

  const createChat = useCallback((input: { title: string; notebookUrl: string }) => {
    const parsed = chatSchema.parse(input);
    const now = Date.now();
    const chat: NotebookLMChat = {
      id: genId('nlmchat'),
      title: parsed.title,
      notebookUrl: parsed.notebookUrl,
      createdAt: now,
      updatedAt: now,
      lastMessageAt: now,
      unreadCount: 0,
    };
    persistChats([chat, ...chats]);
    setActiveChatIdRaw(chat.id);
    persistMessages(chat.id, []);
    return chat;
  }, [chats, persistChats, persistMessages]);

  const deleteChat = useCallback((chatId: string) => {
    const next = chats.filter((c) => c.id !== chatId);
    persistChats(next);
    try {
      localStorage.removeItem(`${STORAGE_MSG_PREFIX}${chatId}`);
    } catch {
      // ignore
    }
    if (activeChatId === chatId) {
      setActiveChatIdRaw(next[0]?.id ?? null);
    }
  }, [chats, persistChats, activeChatId]);

  const renameChat = useCallback((chatId: string, title: string) => {
    const nextTitle = z.string().trim().min(1).max(80).parse(title);
    const now = Date.now();
    persistChats(
      chats.map((c) => (c.id === chatId ? { ...c, title: nextTitle, updatedAt: now } : c))
    );
  }, [chats, persistChats]);

  const togglePinChat = useCallback((chatId: string) => {
    const chat = chats.find((c) => c.id === chatId);
    const newPinned = !chat?.pinned;
    
    persistChats(
      chats.map((c) => (c.id === chatId ? { ...c, pinned: newPinned } : c))
    );
    
    // Sync to server
    patchChat(chatId, { pinned: newPinned }).catch(() => {});
  }, [chats, persistChats]);

  const ensureChatForNotebook = useCallback((opts: { notebookUrl: string; suggestedTitle?: string }) => {
    const notebookUrl = z.string().trim().url().parse(opts.notebookUrl);
    const existing = chats.find((c) => c.notebookUrl === notebookUrl);
    if (existing) {
      setActiveChatId(existing.id);
      return existing;
    }
    const title = (opts.suggestedTitle ?? 'Notebook chat').trim() || 'Notebook chat';
    return createChat({ title, notebookUrl });
  }, [chats, createChat, setActiveChatId]);

  const appendMessage = useCallback((msg: Omit<NotebookLMMessage, 'id' | 'createdAt'>) => {
    const now = Date.now();
    const message: NotebookLMMessage = {
      id: genId('nlmmsg'),
      createdAt: now,
      ...msg,
    };
    const chatId = msg.chatId;
    const nextMsgs = [...messages, message];
    persistMessages(chatId, nextMsgs);
    
    // Determine if this is an incoming message (assistant) or outgoing (user)
    const isIncoming = msg.role === 'assistant';
    const isActive = chatId === activeChatId;
    
    // Create preview (first 100 chars)
    const preview = msg.content.slice(0, 100);
    
    // Update chat metadata
    const updated = chats.map((c) => {
      if (c.id !== chatId) return c;
      return {
        ...c,
        updatedAt: now,
        lastMessageAt: now,
        lastMessagePreview: preview,
        // Increment unread only for incoming messages when chat is not active
        unreadCount: isIncoming && !isActive 
          ? (c.unreadCount ?? 0) + 1 
          : (c.unreadCount ?? 0),
      };
    });
    persistChats(updated);
    
    // Sync to server (fire and forget)
    touchChat(chatId, {
      lastMessagePreview: preview,
      lastMessageAt: now,
      unreadCount: isIncoming && !isActive ? 1 : 0,
    }).catch(() => {
      // Server sync failed - local state is still valid
    });
    
    return message;
  }, [messages, persistMessages, chats, persistChats, activeChatId]);

  const clearMessages = useCallback((chatId: string) => {
    persistMessages(chatId, []);
    const now = Date.now();
    persistChats(chats.map((c) => (c.id === chatId ? { ...c, updatedAt: now, lastMessagePreview: null } : c)));
  }, [persistMessages, chats, persistChats]);

  // Calculate total unread count
  const totalUnreadCount = useMemo(() => {
    return chats.reduce((sum, c) => sum + (c.unreadCount ?? 0), 0);
  }, [chats]);

  return {
    chats,
    activeChatId,
    setActiveChatId,
    activeChat,
    messages,
    createChat,
    deleteChat,
    renameChat,
    togglePinChat,
    ensureChatForNotebook,
    appendMessage,
    clearMessages,
    totalUnreadCount,
  };
}
