import { useState } from 'react';
import { ChatMessage as ChatMessageType, ChatCitation } from '@/lib/chat/types';
import { cn } from '@/lib/utils';
import { format, isToday, isYesterday, isSameDay } from 'date-fns';
import { uk } from 'date-fns/locale';
import { Loader2, Bot, User, ChevronDown, ExternalLink, Quote, Copy, Check } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';

interface ChatMessageProps {
  message: ChatMessageType;
  isOwn: boolean;
  showTimestamp?: boolean;
}

export function formatMessageDate(date: Date): string {
  if (isToday(date)) return 'Today';
  if (isYesterday(date)) return 'Yesterday';
  return format(date, 'd MMMM yyyy', { locale: uk });
}

export function shouldShowDateSeparator(
  currentMsg: ChatMessageType,
  prevMsg: ChatMessageType | undefined
): boolean {
  if (!prevMsg) return true;
  return !isSameDay(new Date(currentMsg.createdAt), new Date(prevMsg.createdAt));
}

export function DateSeparator({ date }: { date: Date }) {
  return (
    <div className="flex items-center justify-center my-4">
      <div className="bg-muted text-muted-foreground text-xs font-medium px-3 py-1 rounded-full">
        {formatMessageDate(date)}
      </div>
    </div>
  );
}

function CitationItem({ citation }: { citation: ChatCitation }) {
  return (
    <div className="flex gap-2 p-2 rounded-md bg-background/50 border border-border/50">
      <Quote className="h-3.5 w-3.5 text-muted-foreground shrink-0 mt-0.5" />
      <div className="min-w-0 flex-1">
        <p className="text-xs text-foreground line-clamp-2">{citation.text}</p>
        {(citation.source || citation.url) && (
          <div className="flex items-center gap-1.5 mt-1">
            {citation.source && (
              <span className="text-[10px] text-muted-foreground truncate">
                {citation.source}
              </span>
            )}
            {citation.url && (
              <a
                href={citation.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] text-primary hover:underline inline-flex items-center gap-0.5"
              >
                <ExternalLink className="h-2.5 w-2.5" />
              </a>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function CitationsBlock({ citations }: { citations: ChatCitation[] }) {
  const [isOpen, setIsOpen] = useState(false);

  if (!citations || citations.length === 0) return null;

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen} className="mt-2">
      <CollapsibleTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground gap-1.5"
        >
          <ChevronDown
            className={cn(
              'h-3.5 w-3.5 transition-transform duration-200',
              isOpen && 'rotate-180'
            )}
          />
          Sources ({citations.length})
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent className="mt-1.5 space-y-1.5 animate-in slide-in-from-top-1 duration-200">
        {citations.map((citation) => (
          <CitationItem key={citation.id} citation={citation} />
        ))}
      </CollapsibleContent>
    </Collapsible>
  );
}

function formatCitationsForCopy(citations: ChatCitation[]): string {
  return citations
    .map((c, i) => {
      let line = `[${i + 1}] "${c.text}"`;
      if (c.source) line += ` — ${c.source}`;
      if (c.url) line += ` (${c.url})`;
      return line;
    })
    .join('\n\n');
}

function CopyButton({
  text,
  label,
  className,
}: {
  text: string;
  label: string;
  className?: string;
}) {
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast({
        description: 'Copied',
        duration: 1500,
      });
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast({
        description: 'Failed to copy',
        variant: 'destructive',
        duration: 1500,
      });
    }
  };

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={handleCopy}
      className={cn('h-6 px-2 text-[10px] sm:text-xs gap-1', className)}
    >
      {copied ? (
        <Check className="h-3 w-3 text-green-500" />
      ) : (
        <Copy className="h-3 w-3" />
      )}
      <span className="hidden sm:inline">{label}</span>
    </Button>
  );
}

export function ChatMessage({ message, isOwn, showTimestamp = true }: ChatMessageProps) {
  const { participant, content, createdAt, status, citations } = message;
  const messageDate = new Date(createdAt);
  const hasCitations = citations && citations.length > 0;

  return (
    <div
      className={cn(
        'flex gap-2 sm:gap-3 mb-3 sm:mb-4',
        isOwn ? 'flex-row-reverse' : 'flex-row'
      )}
    >
      {/* Avatar */}
      <div
        className={cn(
          'flex-shrink-0 w-8 h-8 sm:w-10 sm:h-10 rounded-full flex items-center justify-center text-sm sm:text-lg',
          participant.isAI
            ? 'bg-primary/10 text-primary'
            : 'bg-secondary text-secondary-foreground'
        )}
      >
        {participant.avatar || (participant.isAI ? <Bot className="h-4 w-4 sm:h-5 sm:w-5" /> : <User className="h-4 w-4 sm:h-5 sm:w-5" />)}
      </div>

      {/* Message Content */}
      <div
        className={cn(
          'flex flex-col max-w-[80%] sm:max-w-[75%]',
          isOwn ? 'items-end' : 'items-start'
        )}
      >
        {/* Bubble */}
        <div
          className={cn(
            'rounded-2xl px-3 py-2 sm:px-4 text-sm relative group',
            isOwn
              ? 'bg-primary text-primary-foreground rounded-br-sm'
              : 'bg-muted rounded-bl-sm',
            status === 'sending' && 'opacity-70'
          )}
        >
          {participant.isAI ? (
            <div className="prose prose-sm dark:prose-invert max-w-none">
              <ReactMarkdown>{content}</ReactMarkdown>
            </div>
          ) : (
            <p className="whitespace-pre-wrap">{content}</p>
          )}
        </div>

        {/* Copy actions - only for AI messages */}
        {participant.isAI && status === 'sent' && (
          <div className="flex items-center gap-1 mt-1 opacity-60 hover:opacity-100 transition-opacity">
            <CopyButton text={content} label="Copy answer" />
            {hasCitations && (
              <CopyButton
                text={formatCitationsForCopy(citations)}
                label="Copy sources"
              />
            )}
          </div>
        )}

        {/* Citations - only for AI messages */}
        {participant.isAI && hasCitations && (
          <CitationsBlock citations={citations} />
        )}

        {/* Footer: name + timestamp - always visible on mobile */}
        {showTimestamp && (
          <div
            className={cn(
              'flex items-center gap-1.5 mt-1 text-[10px] sm:text-xs text-muted-foreground',
              isOwn ? 'flex-row-reverse' : 'flex-row'
            )}
          >
            <span className="font-medium truncate max-w-[100px] sm:max-w-none">
              {participant.name}
              {participant.isAI && <span className="ml-0.5">🤖</span>}
            </span>
            <span className="opacity-70">·</span>
            <span className="tabular-nums">{format(messageDate, 'HH:mm')}</span>
          </div>
        )}

        {/* Status indicator */}
        {status === 'sending' && (
          <div className="flex items-center gap-1 mt-1 text-[10px] sm:text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" />
            <span>Sending...</span>
          </div>
        )}
        {status === 'failed' && (
          <div className="mt-1 text-[10px] sm:text-xs text-destructive">
            Failed to send
          </div>
        )}
      </div>
    </div>
  );
}
