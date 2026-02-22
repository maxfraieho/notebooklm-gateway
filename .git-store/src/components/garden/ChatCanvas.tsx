import { useState, useRef, useEffect, useMemo } from 'react';
import { useColleagueChat } from '@/hooks/useColleagueChat';
import { ChatMessage, DateSeparator, shouldShowDateSeparator } from './ChatMessage';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Send, Trash2, MessageSquare, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ChatCanvasProps {
  chatId?: string;
  className?: string;
  title?: string;
}

export function ChatCanvas({ chatId, className, title = 'Colleagues Chat' }: ChatCanvasProps) {
  const {
    messages,
    isLoading,
    error,
    selectedColleague,
    sendMessage,
    clearChat,
  } = useColleagueChat(chatId);

  const [inputValue, setInputValue] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async () => {
    if (!inputValue.trim() || isLoading) return;
    
    const message = inputValue;
    setInputValue('');
    await sendMessage(message);
    textareaRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Group messages with date separators
  const messagesWithSeparators = useMemo(() => {
    return messages.map((msg, idx) => ({
      message: msg,
      showDateSeparator: shouldShowDateSeparator(msg, messages[idx - 1]),
    }));
  }, [messages]);

  return (
    <Card className={cn('flex flex-col h-full', className)}>
      <CardHeader className="flex-shrink-0 pb-3 border-b">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-lg">
            <MessageSquare className="h-5 w-5 text-primary" />
            {title}
          </CardTitle>
          <div className="flex items-center gap-2">
            {/* Role/colleague selection removed per UX request */}
            <Button
              variant="ghost"
              size="icon"
              onClick={clearChat}
              disabled={isLoading || messages.length === 0}
              title="Clear chat"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="flex-1 flex flex-col p-0 overflow-hidden">
        {/* Messages Area */}
        <ScrollArea className="flex-1 px-3 py-2 sm:p-4">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center text-muted-foreground py-12">
              <div className="text-4xl mb-4">{selectedColleague.avatar}</div>
              <h3 className="font-medium mb-2">
                Chat with {selectedColleague.name}
              </h3>
              <p className="text-sm max-w-xs">
                Ask questions, request summaries, or get help with documentation. 
                Your AI colleague is ready to assist!
              </p>
            </div>
          ) : (
            <>
              {messagesWithSeparators.map(({ message, showDateSeparator }) => (
                <div key={message.id}>
                  {showDateSeparator && (
                    <DateSeparator date={new Date(message.createdAt)} />
                  )}
                  <ChatMessage
                    message={message}
                    isOwn={message.participant.role === 'owner'}
                  />
                </div>
              ))}
              {isLoading && (
                <div className="flex items-center gap-2 text-muted-foreground text-sm px-4 py-2">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>{selectedColleague.name} is typing...</span>
                </div>
              )}
              <div ref={messagesEndRef} />
            </>
          )}
        </ScrollArea>

        {/* Error Display */}
        {error && (
          <div className="px-4 py-2 text-sm text-destructive bg-destructive/10 border-t">
            {error}
          </div>
        )}

        {/* Input Area */}
        <div className="flex-shrink-0 p-4 border-t bg-muted/30">
          <div className="flex gap-2">
            <Textarea
              ref={textareaRef}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={`Message ${selectedColleague.name}...`}
              className="min-h-[60px] max-h-[120px] resize-none"
              disabled={isLoading}
            />
            <Button
              onClick={handleSend}
              disabled={!inputValue.trim() || isLoading}
              size="icon"
              className="h-[60px] w-[60px]"
            >
              {isLoading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Send className="h-5 w-5" />
              )}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            Press Enter to send, Shift+Enter for new line
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
