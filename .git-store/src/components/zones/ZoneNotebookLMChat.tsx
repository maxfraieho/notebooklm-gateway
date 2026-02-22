// Zone NotebookLM Chat - Guest-facing chat component for zones with NotebookLM
import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import { toast } from 'sonner';
import { Send, Sparkles, Loader2, Bot, BookOpen } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';
import { chatNotebookLMGuest } from '@/lib/api/mcpGatewayClient';
import { useOnlineStatus } from '@/hooks/useOnlineStatus';
import { useLocale } from '@/hooks/useLocale';
import type { NotebookLMMapping } from '@/types/mcpGateway';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: number;
}

interface ZoneNotebookLMChatProps {
  zoneId: string;
  zoneName: string;
  accessCode: string;
  notebooklm: NotebookLMMapping;
  className?: string;
}

function genId() {
  return `msg_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export function ZoneNotebookLMChat({
  zoneId,
  zoneName,
  accessCode,
  notebooklm,
  className,
}: ZoneNotebookLMChatProps) {
  const { t } = useLocale();
  const { isOnline } = useOnlineStatus();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  // Scroll to bottom when messages change
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length]);

  // Check if NotebookLM is ready
  const isReady = notebooklm.status === 'completed' && !!notebooklm.notebookUrl;

  // Build conversation history for context
  const conversationHistory = useMemo(() => {
    return messages.map((m) => ({
      role: m.role,
      content: m.content,
    }));
  }, [messages]);

  const sendMessage = useCallback(
    async (content: string, kind?: 'summary' | 'study_guide' | 'flashcards') => {
      if (!isReady || !content.trim()) return;

      const userMessage: ChatMessage = {
        id: genId(),
        role: 'user',
        content: content.trim(),
        createdAt: Date.now(),
      };

      setMessages((prev) => [...prev, userMessage]);
      setInput('');
      setIsLoading(true);
      setError(null);

      try {
        const response = await chatNotebookLMGuest(zoneId, accessCode, {
          message: content.trim(),
          kind: kind || 'answer',
          history: conversationHistory,
        });

        const assistantMessage: ChatMessage = {
          id: genId(),
          role: 'assistant',
          content: response.answer,
          createdAt: Date.now(),
        };

        setMessages((prev) => [...prev, assistantMessage]);
      } catch (err: any) {
        const errMsg = err?.message || 'Failed to get response';
        setError(errMsg);
        toast.error('NotebookLM Error', { description: errMsg });
      } finally {
        setIsLoading(false);
      }
    },
    [zoneId, accessCode, isReady, conversationHistory]
  );

  const handleQuickAction = useCallback(
    (kind: 'summary' | 'study_guide' | 'flashcards') => {
      const prompts = {
        summary: 'Please provide a comprehensive summary of the sources.',
        study_guide: 'Create a study guide based on the sources.',
        flashcards: 'Generate flashcards from the key concepts in the sources.',
      };
      sendMessage(prompts[kind], kind);
    },
    [sendMessage]
  );

  const canSend = isReady && input.trim().length > 0 && isOnline && !isLoading;

  // Not ready state
  if (!isReady) {
    return (
      <Card className={cn('flex flex-col', className)}>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Bot className="h-4 w-4" />
            NotebookLM Chat
          </CardTitle>
        </CardHeader>
        <CardContent className="flex-1 flex items-center justify-center text-center py-8">
          <div className="space-y-2">
            {notebooklm.status === 'failed' ? (
              <>
                <p className="text-destructive font-medium">
                  NotebookLM creation failed
                </p>
                <p className="text-sm text-muted-foreground">
                  {notebooklm.lastError || 'Please contact the zone owner.'}
                </p>
              </>
            ) : (
              <>
                <Loader2 className="h-6 w-6 animate-spin mx-auto text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  NotebookLM is being prepared...
                </p>
                <Badge variant="outline" className="capitalize">
                  {notebooklm.status}
                </Badge>
              </>
            )}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn('flex flex-col h-full', className)}>
      {/* Header */}
      <div className="p-3 border-b flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Bot className="h-4 w-4 text-primary flex-shrink-0" />
          <div className="min-w-0">
            <p className="text-sm font-medium truncate">NotebookLM Chat</p>
            <p className="text-xs text-muted-foreground truncate">
              {zoneName}
            </p>
          </div>
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              disabled={!isOnline || isLoading}
            >
              <Sparkles className="h-4 w-4" />
              <span className="hidden sm:inline">Actions</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="z-50 bg-popover">
            <DropdownMenuItem onClick={() => handleQuickAction('summary')}>
              <BookOpen className="h-4 w-4 mr-2" />
              Summary
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => handleQuickAction('study_guide')}>
              Study Guide
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => handleQuickAction('flashcards')}>
              Flashcards
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-hidden">
        <ScrollArea className="h-full">
          <div className="p-4 space-y-3">
            {messages.length === 0 ? (
              <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
                <Bot className="h-8 w-8 mx-auto mb-2 text-muted-foreground/50" />
                <p>Ask questions about the shared documents.</p>
                <p className="text-xs mt-1">
                  Use "Actions" for quick summaries or study guides.
                </p>
              </div>
            ) : (
              messages.map((m) => (
                <div
                  key={m.id}
                  className={cn(
                    'rounded-2xl px-4 py-2 text-sm',
                    m.role === 'user'
                      ? 'bg-primary text-primary-foreground ml-auto rounded-br-sm max-w-[85%]'
                      : 'bg-muted rounded-bl-sm max-w-[85%]'
                  )}
                >
                  {m.role === 'assistant' ? (
                    <div className="prose prose-sm dark:prose-invert max-w-none">
                      <ReactMarkdown>{m.content}</ReactMarkdown>
                    </div>
                  ) : (
                    <p className="whitespace-pre-wrap">{m.content}</p>
                  )}
                </div>
              ))
            )}

            {isLoading && (
              <div className="flex items-center gap-2 text-muted-foreground text-sm px-4 py-2">
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Thinking...</span>
              </div>
            )}

            {error && !isLoading && (
              <div className="text-sm text-destructive px-4 py-2">
                {error}
              </div>
            )}

            <div ref={endRef} />
          </div>
        </ScrollArea>
      </div>

      {/* Input */}
      <div className="p-4 border-t bg-muted/30">
        <div className="flex gap-2">
          <Textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={
              !isOnline
                ? 'Offline — check your connection'
                : 'Ask about the documents...'
            }
            className="min-h-[60px] max-h-[120px] resize-none"
            disabled={!isOnline || isLoading}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (canSend) sendMessage(input);
              }
            }}
          />
          <Button
            size="icon"
            className="h-[60px] w-[60px]"
            disabled={!canSend}
            onClick={() => sendMessage(input)}
          >
            {isLoading ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Send className="h-5 w-5" />
            )}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground mt-2">
          Enter to send, Shift+Enter for new line
        </p>
      </div>
    </Card>
  );
}
