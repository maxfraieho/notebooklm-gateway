import { useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { toast } from 'sonner';
import { Download, FileJson, FileText, Send, Sparkles, Trash2, Loader2 } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { ConnectionBanner, type ConnectionState } from '@/components/ui/connection-banner';
import { ZoneContextHeader } from '@/components/zones/ZoneContextHeader';
import { ZoneAccessBanner, ZoneAccessLabel, type ZoneAccessState } from '@/components/zones/ZoneAccessBanner';
import { cn } from '@/lib/utils';
import { useOnlineStatus } from '@/hooks/useOnlineStatus';
import type { NotebookLMChat, NotebookLMMessage } from '@/hooks/useNotebookLMChats';
import type { AccessType } from '@/types/mcpGateway';

export interface ZoneContext {
  zoneId: string;
  zoneName: string;
  expiresAt: number;
  createdAt?: number;
  accessType: AccessType;
  noteCount?: number;
  isReadOnly?: boolean;
  ownerEmail?: string;
}

function asMarkdown(chat: NotebookLMChat, messages: NotebookLMMessage[]) {
  const header = `# ${chat.title}\n\nNotebook: ${chat.notebookUrl}\n`;
  const body = messages
    .map((m) => `\n## ${m.role === 'user' ? 'User' : 'Assistant'}\n\n${m.content}\n`)
    .join('\n');
  return header + body;
}

function downloadText(filename: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function NotebookLMChatPanel(props: {
  chat: NotebookLMChat | null;
  messages: NotebookLMMessage[];
  onSend: (content: string) => void;
  onQuickAction: (kind: 'summary' | 'study_guide' | 'flashcards') => void;
  onClear: () => void;
  onRetry?: () => void;
  isLoading?: boolean;
  error?: string | null;
  zoneContext?: ZoneContext | null;
  showDiagnostics?: boolean;
  onRequestRenewal?: () => void;
  className?: string;
}) {
  const [input, setInput] = useState('');
  const endRef = useRef<HTMLDivElement>(null);
  const { isOnline } = useOnlineStatus();
  const [isRetrying, setIsRetrying] = useState(false);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [props.messages.length, props.chat?.id]);

  // Zone access state
  const zoneAccessState: ZoneAccessState = useMemo(() => {
    if (!props.zoneContext) return 'active';
    if (props.zoneContext.expiresAt < Date.now()) return 'expired';
    if (props.zoneContext.isReadOnly) return 'read-only';
    return 'active';
  }, [props.zoneContext]);

  const isZoneBlocked = zoneAccessState !== 'active';

  const canSend = !!props.chat && input.trim().length > 0 && isOnline && !props.isLoading && !isZoneBlocked;

  const exportJson = useMemo(() => {
    if (!props.chat) return null;
    return JSON.stringify({ chat: props.chat, messages: props.messages }, null, 2);
  }, [props.chat, props.messages]);

  // Determine connection state
  const connectionState: ConnectionState = !isOnline
    ? 'offline'
    : props.error
    ? 'error'
    : isRetrying
    ? 'retrying'
    : 'online';

  const handleRetry = async () => {
    if (!props.onRetry) return;
    setIsRetrying(true);
    try {
      await props.onRetry();
    } finally {
      setIsRetrying(false);
    }
  };

  return (
    <Card className={cn('flex flex-col overflow-hidden', props.className)}>
      {/* Zone Context Header - sticky */}
      {props.zoneContext && (
        <ZoneContextHeader
          zoneId={props.zoneContext.zoneId}
          zoneName={props.zoneContext.zoneName}
          expiresAt={props.zoneContext.expiresAt}
          createdAt={props.zoneContext.createdAt}
          accessType={props.zoneContext.accessType}
          noteCount={props.zoneContext.noteCount}
          showDiagnostics={props.showDiagnostics}
        />
      )}

      {/* Zone Access Banner - expired/read-only */}
      {isZoneBlocked && props.zoneContext && (
        <ZoneAccessBanner
          state={zoneAccessState}
          zoneName={props.zoneContext.zoneName}
          ownerEmail={props.zoneContext.ownerEmail}
          onRequestRenewal={props.onRequestRenewal}
        />
      )}

      <div className="p-3 border-b flex items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium truncate">{props.chat ? props.chat.title : 'NotebookLM chat'}</p>
          <p className="text-xs text-muted-foreground truncate">
            {props.chat ? props.chat.notebookUrl : 'Select a zone (ready) or create a chat'}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="gap-2" disabled={!props.chat || !isOnline}>
                <Sparkles className="h-4 w-4" />
                Actions
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="z-50 bg-popover text-popover-foreground">
              <DropdownMenuItem onClick={() => props.onQuickAction('summary')} disabled={!props.chat}>
                Summary
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => props.onQuickAction('study_guide')} disabled={!props.chat}>
                Study guide
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => props.onQuickAction('flashcards')} disabled={!props.chat}>
                Flashcards
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="gap-2" disabled={!props.chat}>
                <Download className="h-4 w-4" />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="z-50 bg-popover text-popover-foreground">
              <DropdownMenuItem
                onClick={async () => {
                  if (!props.chat) return;
                  const md = asMarkdown(props.chat, props.messages);
                  await navigator.clipboard.writeText(md);
                  toast.success('Copied Markdown');
                }}
                className="gap-2"
              >
                <FileText className="h-4 w-4" /> Copy Markdown
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={async () => {
                  if (!exportJson) return;
                  await navigator.clipboard.writeText(exportJson);
                  toast.success('Copied JSON');
                }}
                className="gap-2"
              >
                <FileJson className="h-4 w-4" /> Copy JSON
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  if (!props.chat) return;
                  const md = asMarkdown(props.chat, props.messages);
                  downloadText(`${props.chat.title}.md`, md, 'text/markdown');
                }}
                className="gap-2"
              >
                <FileText className="h-4 w-4" /> Download .md
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  if (!props.chat || !exportJson) return;
                  downloadText(`${props.chat.title}.json`, exportJson, 'application/json');
                }}
                className="gap-2"
              >
                <FileJson className="h-4 w-4" /> Download .json
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <Button
            variant="ghost"
            size="icon"
            disabled={!props.chat || props.messages.length === 0}
            onClick={props.onClear}
            title="Clear messages"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Connection Banner */}
      {connectionState !== 'online' && (
        <ConnectionBanner
          state={connectionState}
          errorMessage={props.error || undefined}
          onRetry={props.onRetry ? handleRetry : undefined}
          isRetrying={isRetrying}
          className="mx-3 mt-3"
        />
      )}

      <div className="flex-1 overflow-hidden">
        <ScrollArea className="h-full">
          <div className="p-4 space-y-3 animate-enter">
            {!props.chat ? (
              <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
                Choose a ready zone on the right, or create a chat on the left.
              </div>
            ) : props.messages.length === 0 ? (
              <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
                Ask your first question about the notebook sources.
              </div>
            ) : (
              props.messages.map((m) => (
                <div
                  key={m.id}
                  className={cn(
                    'rounded-2xl px-4 py-2 text-sm',
                    m.role === 'user'
                      ? 'bg-primary text-primary-foreground ml-auto rounded-br-sm max-w-[80%]'
                      : 'bg-muted rounded-bl-sm max-w-[80%]'
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

            {/* Loading indicator */}
            {props.isLoading && (
              <div className="flex items-center gap-2 text-muted-foreground text-sm px-4 py-2">
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Thinking...</span>
              </div>
            )}

            <div ref={endRef} />
          </div>
        </ScrollArea>
      </div>

      <div className="p-4 border-t bg-muted/30">
        <div className="flex gap-2">
          <Textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={
              isZoneBlocked
                ? zoneAccessState === 'expired'
                  ? 'Zone expired — cannot send messages'
                  : 'Read-only — cannot send messages'
                : !isOnline
                ? 'Offline — check your connection'
                : props.chat
                ? 'Ask NotebookLM…'
                : 'Select a chat first…'
            }
            className={cn(
              "min-h-[60px] max-h-[120px] resize-none",
              isZoneBlocked && "opacity-60 cursor-not-allowed"
            )}
            disabled={!props.chat || !isOnline || props.isLoading || isZoneBlocked}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (!canSend) return;
                props.onSend(input);
                setInput('');
              }
            }}
          />
          <Button
            size="icon"
            className="h-[60px] w-[60px]"
            disabled={!canSend}
            onClick={() => {
              if (!canSend) return;
              props.onSend(input);
              setInput('');
            }}
          >
            {props.isLoading ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Send className="h-5 w-5" />
            )}
          </Button>
        </div>

        {/* Status label */}
        <div className="mt-2">
          {isZoneBlocked ? (
            <ZoneAccessLabel state={zoneAccessState} />
          ) : !isOnline ? (
            <p className="text-xs text-destructive">Waiting for connection…</p>
          ) : (
            <p className="text-xs text-muted-foreground">Enter to send, Shift+Enter for new line</p>
          )}
        </div>
      </div>
    </Card>
  );
}
