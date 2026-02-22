import { useState, useCallback, useEffect } from 'react';
import { 
  Chat, 
  ChatMessage, 
  ChatParticipant, 
  AI_COLLEAGUES,
  SendMessageRequest,
  CreateChatRequest 
} from '@/lib/chat/types';

// Gateway URL removed — this hook uses localStorage for MVP. Will migrate to gateway client when backend chat is ready.

// Generate unique ID
const generateId = () => `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

// Owner participant
const OWNER_PARTICIPANT: ChatParticipant = {
  id: 'owner',
  name: 'Owner',
  role: 'owner',
  isAI: false,
  avatar: '👤',
};

export function useColleagueChat(chatId?: string) {
  const [chat, setChat] = useState<Chat | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedColleague, setSelectedColleague] = useState<ChatParticipant>(AI_COLLEAGUES[0]);

  // Load chat from localStorage (MVP - will migrate to worker/MinIO later)
  const loadChat = useCallback((id: string) => {
    try {
      const stored = localStorage.getItem(`chat:${id}`);
      if (stored) {
        const data = JSON.parse(stored);
        setChat(data.chat);
        setMessages(data.messages || []);
      } else {
        // Create new chat
        const newChat: Chat = {
          id,
          title: 'New Conversation',
          participants: [OWNER_PARTICIPANT, ...AI_COLLEAGUES],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        setChat(newChat);
        setMessages([]);
      }
    } catch (err) {
      console.error('Failed to load chat:', err);
      setError('Failed to load chat');
    }
  }, []);

  // Save chat to localStorage
  const saveChat = useCallback((chatData: Chat, msgs: ChatMessage[]) => {
    try {
      localStorage.setItem(`chat:${chatData.id}`, JSON.stringify({
        chat: chatData,
        messages: msgs,
      }));
    } catch (err) {
      console.error('Failed to save chat:', err);
    }
  }, []);

  // Initialize chat
  useEffect(() => {
    if (chatId) {
      loadChat(chatId);
    } else {
      // Default chat
      loadChat('default');
    }
  }, [chatId, loadChat]);

  // Send message
  const sendMessage = useCallback(async (content: string) => {
    if (!chat || !content.trim()) return;

    setIsLoading(true);
    setError(null);

    // Create user message
    const userMessage: ChatMessage = {
      id: generateId(),
      chatId: chat.id,
      participant: OWNER_PARTICIPANT,
      content: content.trim(),
      createdAt: new Date().toISOString(),
      status: 'sent',
    };

    const updatedMessages = [...messages, userMessage];
    setMessages(updatedMessages);

    // Update chat
    const updatedChat = { ...chat, updatedAt: new Date().toISOString() };
    setChat(updatedChat);
    saveChat(updatedChat, updatedMessages);

    try {
      // Simulate AI response (MVP - will connect to n8n/AI later)
      await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));

      const aiResponse: ChatMessage = {
        id: generateId(),
        chatId: chat.id,
        participant: selectedColleague,
        content: generateAIResponse(content, selectedColleague),
        createdAt: new Date().toISOString(),
        status: 'sent',
        replyToId: userMessage.id,
      };

      const finalMessages = [...updatedMessages, aiResponse];
      setMessages(finalMessages);
      
      const finalChat = { ...updatedChat, updatedAt: new Date().toISOString() };
      setChat(finalChat);
      saveChat(finalChat, finalMessages);

    } catch (err) {
      console.error('Failed to get AI response:', err);
      setError('Failed to get AI response');
    } finally {
      setIsLoading(false);
    }
  }, [chat, messages, selectedColleague, saveChat]);

  // Clear chat
  const clearChat = useCallback(() => {
    if (!chat) return;
    setMessages([]);
    const clearedChat = { ...chat, updatedAt: new Date().toISOString() };
    setChat(clearedChat);
    saveChat(clearedChat, []);
  }, [chat, saveChat]);

  return {
    chat,
    messages,
    isLoading,
    error,
    selectedColleague,
    setSelectedColleague,
    sendMessage,
    clearChat,
    availableColleagues: AI_COLLEAGUES,
  };
}

// MVP: Simple response generator (will be replaced with actual AI)
function generateAIResponse(userMessage: string, colleague: ChatParticipant): string {
  const lowerMessage = userMessage.toLowerCase();
  
  const responses: Record<string, string[]> = {
    archivist: [
      `📚 I've analyzed your request about "${userMessage.slice(0, 30)}..."\n\nBased on the garden's content, I can help you organize and categorize this information. Would you like me to:\n\n1. Create a summary of related notes\n2. Suggest tags and connections\n3. Generate a digest`,
      `📚 Interesting question! Let me search through the garden's archives...\n\nI found several related entries that might help. Should I compile them into a structured report?`,
      `📚 As your Archivist, I recommend organizing this content by theme. I can create cross-references and identify patterns across your notes.`,
    ],
    'tech-writer': [
      `✍️ I can help document this. Here's my approach:\n\n**Proposed Structure:**\n1. Overview\n2. Key Points\n3. Technical Details\n4. Examples\n\nShall I proceed with this format?`,
      `✍️ Great topic for documentation! I'll create clear, concise content that's easy to understand.\n\nWhat's the target audience - technical or general readers?`,
      `✍️ I've drafted an outline based on your input. Technical writing tip: always start with the "why" before the "how".`,
    ],
    architect: [
      `🏗️ From an architectural perspective, here's how I see this:\n\n\`\`\`\n┌──────────────┐\n│   Your Idea  │\n└──────┬───────┘\n       │\n┌──────▼───────┐\n│  Components  │\n└──────────────┘\n\`\`\`\n\nWant me to detail the connections?`,
      `🏗️ Let me analyze the structure here. I see potential for modular design with clear separation of concerns.`,
      `🏗️ Architecturally speaking, this could be implemented in phases. Phase 1 would focus on the core functionality...`,
    ],
  };

  const roleResponses = responses[colleague.role] || responses.archivist;
  return roleResponses[Math.floor(Math.random() * roleResponses.length)];
}
