import { useMemo, useRef, useState } from 'react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { NewNotebookLMChatDialog } from '@/components/notebooklm/NewNotebookLMChatDialog';
import { NotebookLMChatsWall } from '@/components/notebooklm/NotebookLMChatsWall';
import { NotebookLMZonesWall } from '@/components/notebooklm/NotebookLMZonesWall';
import { NotebookLMChatPanel } from '@/components/notebooklm/NotebookLMChatPanel';
import { useNotebookLMChats } from '@/hooks/useNotebookLMChats';
import { chatNotebookLM } from '@/lib/api/mcpGatewayClient';
import type { NotebookLMChatKind } from '@/types/mcpGateway';

export function NotebookLMChatTab({ className }: { className?: string }) {
  const {
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
  } = useNotebookLMChats();

  const [newOpen, setNewOpen] = useState(false);
  const [initialUrl, setInitialUrl] = useState<string | undefined>(undefined);
  const sendingRef = useRef(false);

  const canClear = !!activeChat && messages.length > 0;

  const titleForNew = useMemo(() => {
    const n = chats.length + 1;
    return `Notebook chat ${n}`;
  }, [chats.length]);

  const buildHistory = (limit = 12) => {
    // backend expects only user/assistant history (without ids)
    return messages
      .slice(Math.max(0, messages.length - limit))
      .map((m) => ({ role: m.role, content: m.content }));
  };

  const sendToNotebookLM = async (kind: NotebookLMChatKind, content: string) => {
    if (!activeChat) return;
    const trimmed = content.trim();
    if (!trimmed) return;
    if (sendingRef.current) return;
    sendingRef.current = true;

    try {
      // Persist user message locally
      appendMessage({ chatId: activeChat.id, role: 'user', content: trimmed });

      const res = await chatNotebookLM({
        notebookUrl: activeChat.notebookUrl,
        message: trimmed,
        kind,
        history: buildHistory(),
      });

      appendMessage({
        chatId: activeChat.id,
        role: 'assistant',
        content: res.answer || '(empty response)',
      });
    } catch (e) {
      const msg = e && typeof e === 'object' && 'message' in (e as any) ? String((e as any).message) : 'Chat failed';
      toast.error(msg);
      appendMessage({
        chatId: activeChat.id,
        role: 'assistant',
        content: `⚠️ **Помилка NotebookLM**\n\n${msg}`,
      });
    } finally {
      sendingRef.current = false;
    }
  };

  return (
    <div className={cn('h-full grid grid-cols-1 lg:grid-cols-[280px_1fr_340px] gap-4', className)}>
      <NotebookLMChatsWall
        chats={chats}
        activeChatId={activeChatId}
        onSelect={setActiveChatId}
        onNew={() => {
          setInitialUrl(undefined);
          setNewOpen(true);
        }}
        onDelete={(id) => {
          deleteChat(id);
          toast.success('Chat deleted');
        }}
        onRename={(id, title) => {
          try {
            renameChat(id, title);
          } catch {
            // ignore until valid
          }
        }}
        onTogglePin={(id) => togglePinChat(id)}
        className="h-full"
      />

      <NotebookLMChatPanel
        chat={activeChat}
        messages={messages}
        onSend={(content) => {
          void sendToNotebookLM('answer', content);
        }}
        onQuickAction={(kind) => {
          // For quick actions, treat the latest user message as the question; if absent, ask for one.
          const lastUser = [...messages].reverse().find((m) => m.role === 'user')?.content;
          if (!lastUser) {
            toast.error('Спочатку введіть питання в чаті.');
            return;
          }
          void sendToNotebookLM(kind, lastUser);
        }}
        onClear={() => {
          if (!activeChat || !canClear) return;
          clearMessages(activeChat.id);
          toast.success('Cleared');
        }}
        className="h-full"
      />

      <NotebookLMZonesWall
        onChatForNotebook={(notebookUrl, suggestedTitle) => {
          const chat = ensureChatForNotebook({ notebookUrl, suggestedTitle });
          setActiveChatId(chat.id);
          toast.success('Chat opened');
        }}
        className="h-full"
      />

      <NewNotebookLMChatDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        initialNotebookUrl={initialUrl}
        onCreate={({ title, notebookUrl }) => {
          try {
            createChat({ title: title || titleForNew, notebookUrl });
            toast.success('Chat created');
          } catch (e) {
            toast.error('Invalid input');
          }
        }}
      />
    </div>
  );
}
