import { useMemo, useState } from 'react';
import { Plus, Trash2, MessageSquare, Archive, Clock, Globe, Laptop, SearchX, Pin } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { uk } from 'date-fns/locale';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { cn } from '@/lib/utils';
import { ChatsWallFilters, applyChatsFilters, type ChatsWallFiltersState } from './ChatsWallFilters';
import type { NotebookLMChat, NotebookLMChatStatus } from '@/hooks/useNotebookLMChats';

type TabFilter = 'active' | 'archived' | 'all';

const DEFAULT_FILTERS: ChatsWallFiltersState = {
  query: '',
  accessType: 'all',
  zoneId: 'all',
  sort: 'recent',
};

function ChatSkeleton() {
  return (
    <div className="rounded-md border border-border p-2.5 space-y-2">
      <div className="flex items-start gap-2">
        <div className="flex-1 min-w-0 space-y-1.5">
          <Skeleton className="h-4 w-2/3" />
          <Skeleton className="h-3 w-full" />
        </div>
        <Skeleton className="h-7 w-7 rounded-md shrink-0" />
      </div>
      <div className="flex gap-1.5">
        <Skeleton className="h-5 w-14 rounded-full" />
        <Skeleton className="h-5 w-16 rounded-full" />
      </div>
    </div>
  );
}

function EmptyChatsState({ 
  onNew, 
  tab, 
  hasFilters 
}: { 
  onNew: () => void; 
  tab: TabFilter;
  hasFilters: boolean;
}) {
  // Different message when filters are applied vs no chats at all
  if (hasFilters) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 p-6 text-center">
        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
          <SearchX className="h-5 w-5 text-muted-foreground" />
        </div>
        <div className="space-y-1">
          <p className="text-sm font-medium">No matching chats</p>
          <p className="text-xs text-muted-foreground">Try adjusting your filters or search</p>
        </div>
      </div>
    );
  }

  const messages: Record<TabFilter, { title: string; desc: string }> = {
    active: { title: 'No active chats', desc: 'Start a conversation with your notebook' },
    archived: { title: 'No archived chats', desc: 'Archived chats will appear here' },
    all: { title: 'No chats yet', desc: 'Start a conversation with your notebook' },
  };

  const { title, desc } = messages[tab];

  return (
    <div className="flex flex-col items-center justify-center gap-4 p-6 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted">
        {tab === 'archived' ? (
          <Archive className="h-6 w-6 text-muted-foreground" />
        ) : (
          <MessageSquare className="h-6 w-6 text-muted-foreground" />
        )}
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium">{title}</p>
        <p className="text-xs text-muted-foreground">{desc}</p>
      </div>
      {tab !== 'archived' && (
        <Button size="sm" variant="outline" className="gap-2" onClick={onNew}>
          <Plus className="h-4 w-4" />
          Start chat
        </Button>
      )}
    </div>
  );
}

function AccessTypeBadge({ type }: { type?: 'web' | 'mcp' | 'both' }) {
  if (!type) return null;

  const config = {
    web: { icon: Globe, label: 'Web' },
    mcp: { icon: Laptop, label: 'MCP' },
    both: { icon: Globe, label: 'Both' },
  };

  const { icon: Icon, label } = config[type];

  return (
    <Badge variant="outline" className="gap-1 text-[10px] h-5 px-1.5">
      <Icon className="h-3 w-3" />
      {label}
    </Badge>
  );
}

function ZoneTTLBadge({ expiresAt }: { expiresAt?: number }) {
  if (!expiresAt) return null;

  const now = Date.now();
  const isExpired = expiresAt < now;
  const remaining = expiresAt - now;
  const isUrgent = remaining < 6 * 60 * 60 * 1000; // < 6 hours

  return (
    <Badge
      variant={isExpired ? 'destructive' : isUrgent ? 'secondary' : 'outline'}
      className={cn(
        'gap-1 text-[10px] h-5 px-1.5',
        isUrgent && !isExpired && 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30'
      )}
    >
      <Clock className="h-3 w-3" />
      {isExpired ? 'Expired' : formatDistanceToNow(expiresAt, { addSuffix: false, locale: uk })}
    </Badge>
  );
}

function UnreadBadge({ count }: { count?: number }) {
  if (!count || count <= 0) return null;
  
  const display = count > 99 ? '99+' : String(count);
  
  return (
    <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-primary text-primary-foreground text-[10px] font-medium px-1.5">
      {display}
    </span>
  );
}

function ChatCard({
  chat,
  isActive,
  onSelect,
  onDelete,
  onRename,
  onTogglePin,
}: {
  chat: NotebookLMChat;
  isActive: boolean;
  onSelect: () => void;
  onDelete: () => void;
  onRename: (title: string) => void;
  onTogglePin: () => void;
}) {
  const lastActivity = formatDistanceToNow(chat.lastMessageAt ?? chat.updatedAt, { addSuffix: true, locale: uk });
  const hasUnread = (chat.unreadCount ?? 0) > 0;

  return (
    <div
      className={cn(
        'group rounded-md border border-border p-2.5 cursor-pointer transition-colors animate-fade-in',
        isActive ? 'bg-muted border-primary/50' : 'hover:bg-muted/50',
        chat.pinned && 'ring-1 ring-primary/20 bg-primary/5',
        hasUnread && !isActive && 'border-primary/40 bg-primary/5'
      )}
      onClick={onSelect}
    >
      {/* Header row */}
      <div className="flex items-start gap-2">
        {/* Pin indicator (visible when pinned) */}
        {chat.pinned && (
          <Pin className="h-3.5 w-3.5 text-primary shrink-0 mt-0.5 fill-primary" />
        )}
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <input
              className={cn(
                'flex-1 bg-transparent text-sm font-medium outline-none truncate',
                hasUnread && 'font-semibold'
              )}
              value={chat.title}
              onChange={(e) => onRename(e.target.value)}
              onClick={(e) => e.stopPropagation()}
            />
            <UnreadBadge count={chat.unreadCount} />
          </div>
          {/* Last message preview */}
          {chat.lastMessagePreview ? (
            <p className={cn(
              'text-[10px] sm:text-xs text-muted-foreground truncate mt-0.5',
              hasUnread && 'text-foreground/80'
            )}>
              {chat.lastMessagePreview}
            </p>
          ) : (
            <p className="text-[10px] sm:text-xs text-muted-foreground truncate mt-0.5">
              {chat.notebookUrl}
            </p>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-0.5 shrink-0">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className={cn(
                  'h-7 w-7 shrink-0',
                  chat.pinned ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'
                )}
                onClick={(e) => {
                  e.stopPropagation();
                  onTogglePin();
                }}
              >
                <Pin className={cn('h-3.5 w-3.5', chat.pinned && 'fill-current')} />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="top" className="text-xs">
              {chat.pinned ? 'Unpin chat' : 'Pin chat'}
            </TooltipContent>
          </Tooltip>

          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 opacity-0 group-hover:opacity-100 shrink-0"
            onClick={(e) => {
              e.stopPropagation();
              onDelete();
            }}
            title="Delete chat"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* Badges row */}
      <div className="flex flex-wrap items-center gap-1.5 mt-2">
        {chat.zoneName && (
          <Badge variant="secondary" className="text-[10px] h-5 px-1.5 max-w-[100px] truncate">
            {chat.zoneName}
          </Badge>
        )}
        <AccessTypeBadge type={chat.accessType} />
        <ZoneTTLBadge expiresAt={chat.zoneExpiresAt} />

        {/* Last activity - push to end */}
        <span className="text-[10px] text-muted-foreground ml-auto">{lastActivity}</span>
      </div>
    </div>
  );
}

export function NotebookLMChatsWall(props: {
  chats: NotebookLMChat[];
  activeChatId: string | null;
  onSelect: (id: string) => void;
  onNew: () => void;
  onDelete: (id: string) => void;
  onRename: (id: string, title: string) => void;
  onTogglePin: (id: string) => void;
  onArchive?: (id: string) => void;
  isLoading?: boolean;
  className?: string;
}) {
  const [filters, setFilters] = useState<ChatsWallFiltersState>(DEFAULT_FILTERS);
  const [tab, setTab] = useState<TabFilter>('active');
  const [toDelete, setToDelete] = useState<NotebookLMChat | null>(null);

  // Extract unique zones from chats for filter dropdown
  const availableZones = useMemo(() => {
    const zonesMap = new Map<string, string>();
    props.chats.forEach((c) => {
      if (c.zoneId && c.zoneName) {
        zonesMap.set(c.zoneId, c.zoneName);
      }
    });
    return Array.from(zonesMap.entries()).map(([id, name]) => ({ id, name }));
  }, [props.chats]);

  // Count by status
  const counts = useMemo(() => {
    const active = props.chats.filter((c) => c.status !== 'archived').length;
    const archived = props.chats.filter((c) => c.status === 'archived').length;
    return { active, archived, all: props.chats.length };
  }, [props.chats]);

  // Count active filters (excluding defaults)
  const activeFiltersCount = useMemo(() => {
    let count = 0;
    if (filters.accessType !== 'all') count++;
    if (filters.zoneId !== 'all') count++;
    if (filters.query.trim()) count++;
    if (filters.sort !== 'recent') count++;
    return count;
  }, [filters]);

  // Apply all filters
  const filtered = useMemo(() => {
    return applyChatsFilters(props.chats, filters, tab);
  }, [props.chats, filters, tab]);

  // Check if any filters are active (for empty state messaging)
  const hasActiveFilters = activeFiltersCount > 0;

  return (
    <Card className={cn('flex flex-col overflow-hidden', props.className)}>
      {/* Header */}
      <div className="p-3 border-b flex items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium truncate">Notebook chats</p>
          <p className="text-xs text-muted-foreground truncate">Saved locally</p>
        </div>
        <Button size="sm" onClick={props.onNew} className="gap-1.5 shrink-0">
          <Plus className="h-4 w-4" />
          <span className="hidden sm:inline">New</span>
        </Button>
      </div>

      {/* Tabs */}
      <div className="px-3 pt-2 border-b">
        <Tabs value={tab} onValueChange={(v) => setTab(v as TabFilter)}>
          <TabsList className="h-8 w-full grid grid-cols-3">
            <TabsTrigger value="active" className="text-xs h-7 gap-1">
              Active
              {counts.active > 0 && (
                <span className="text-[10px] text-muted-foreground">({counts.active})</span>
              )}
            </TabsTrigger>
            <TabsTrigger value="archived" className="text-xs h-7 gap-1">
              Archived
              {counts.archived > 0 && (
                <span className="text-[10px] text-muted-foreground">({counts.archived})</span>
              )}
            </TabsTrigger>
            <TabsTrigger value="all" className="text-xs h-7 gap-1">
              All
              {counts.all > 0 && (
                <span className="text-[10px] text-muted-foreground">({counts.all})</span>
              )}
            </TabsTrigger>
          </TabsList>
        </Tabs>
      </div>

      {/* Filters */}
      <div className="p-3 border-b">
        <ChatsWallFilters
          filters={filters}
          onChange={setFilters}
          availableZones={availableZones}
          activeFiltersCount={activeFiltersCount}
        />
      </div>

      {/* Chat list */}
      <ScrollArea className="flex-1">
        <div className="p-2 space-y-2">
          {props.isLoading && (
            <>
              <ChatSkeleton />
              <ChatSkeleton />
              <ChatSkeleton />
            </>
          )}

          {!props.isLoading && filtered.length === 0 && (
            <EmptyChatsState onNew={props.onNew} tab={tab} hasFilters={hasActiveFilters} />
          )}

          {!props.isLoading &&
            filtered.map((c) => (
              <ChatCard
                key={c.id}
                chat={c}
                isActive={c.id === props.activeChatId}
                onSelect={() => props.onSelect(c.id)}
                onDelete={() => setToDelete(c)}
                onRename={(title) => props.onRename(c.id, title)}
                onTogglePin={() => props.onTogglePin(c.id)}
              />
            ))}
        </div>
      </ScrollArea>

      {/* Delete confirmation */}
      <AlertDialog open={!!toDelete} onOpenChange={(open) => !open && setToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete chat?</AlertDialogTitle>
            <AlertDialogDescription>
              This will remove the chat and its messages from this browser.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (toDelete) props.onDelete(toDelete.id);
                setToDelete(null);
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}
