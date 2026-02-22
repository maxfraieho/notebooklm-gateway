import { useEffect, useMemo, useState } from 'react';
import { Search, MessageSquarePlus } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';
import { useAccessZones } from '@/hooks/useAccessZones';
import { NotebookLMStatusBadge } from '@/components/zones/NotebookLMStatusBadge';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { useQueries } from '@tanstack/react-query';
import { getZoneNotebookLMStatus } from '@/lib/api/mcpGatewayClient';

export function NotebookLMZonesWall(props: {
  onChatForNotebook: (notebookUrl: string, suggestedTitle: string) => void;
  className?: string;
}) {
  const { isAuthenticated } = useOwnerAuth();
  const { zones, isLoading, error, fetchZones, isExpired } = useAccessZones();
  const [query, setQuery] = useState('');

  useEffect(() => {
    // owner-only list endpoint
    if (!isAuthenticated) return;
    fetchZones();
  }, [fetchZones, isAuthenticated]);

  const activeZones = useMemo(() => zones.filter((z) => !isExpired(z.expiresAt)), [zones, isExpired]);

  // `zones/list` does not include NotebookLM mapping; fetch per-zone status and only show READY ones.
  const statusQueries = useQueries({
    queries: activeZones.map((z) => ({
      queryKey: ['zone-notebooklm', z.id],
      queryFn: () => getZoneNotebookLMStatus(z.id),
      staleTime: 30_000,
      retry: 1,
    })),
  });

  const statusByZoneId = useMemo(() => {
    const map = new Map<string, { status?: string; notebookUrl?: string }>();
    for (let i = 0; i < activeZones.length; i++) {
      const zone = activeZones[i];
      const q = statusQueries[i];
      const mapping = q?.data?.notebooklm ?? null;
      if (mapping) {
        map.set(zone.id, { status: mapping.status, notebookUrl: mapping.notebookUrl ?? undefined });
      } else {
        map.set(zone.id, { status: undefined, notebookUrl: undefined });
      }
    }
    return map;
  }, [activeZones, statusQueries]);

  const isStatusLoading = useMemo(() => statusQueries.some((q) => q.isLoading), [statusQueries]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return activeZones.filter((z) => {
      const s = statusByZoneId.get(z.id);
      const isReady = s?.status === 'completed' && !!s?.notebookUrl;
      if (!isReady) return false;

      if (q) {
        const hay = `${z.name} ${z.description ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [activeZones, query, statusByZoneId]);

  return (
    <Card className={cn('flex flex-col overflow-hidden', props.className)}>
      <div className="p-3 border-b">
        <p className="text-sm font-medium">Access Zones</p>
        <p className="text-xs text-muted-foreground">Pick a ready NotebookLM zone</p>
      </div>

      <div className="p-3 border-b space-y-3">
        <div className="relative">
          <Search className="h-4 w-4 text-muted-foreground absolute left-2 top-1/2 -translate-y-1/2" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search zones…"
            className="pl-8"
          />
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-2 space-y-2 animate-fade-in">
          {!isAuthenticated && (
            <div className="p-4 text-sm text-muted-foreground">
              Owner mode required to list zones.
            </div>
          )}

          {isAuthenticated && error && (
            <div className="p-3 text-sm text-destructive bg-destructive/10 rounded-md">{error}</div>
          )}

          {isAuthenticated && isLoading && filtered.length === 0 && (
            <div className="p-4 text-sm text-muted-foreground">Loading…</div>
          )}

          {isAuthenticated && !isLoading && isStatusLoading && filtered.length === 0 && (
            <div className="p-4 text-sm text-muted-foreground">Checking NotebookLM status…</div>
          )}

          {isAuthenticated && !isLoading && filtered.length === 0 && (
            <div className="p-4 text-sm text-muted-foreground">No matching zones.</div>
          )}

          {isAuthenticated && filtered.map((z) => {
            const notebookUrl = statusByZoneId.get(z.id)?.notebookUrl ?? null;
            const canChat = !!notebookUrl;
            return (
              <div key={z.id} className="rounded-md border border-border p-3 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate">{z.name}</p>
                    {z.description && (
                      <p className="text-xs text-muted-foreground truncate">{z.description}</p>
                    )}
                  </div>
                  <NotebookLMStatusBadge zoneId={z.id} />
                </div>

                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs text-muted-foreground truncate">📝 {z.noteCount}</p>
                  <Button
                    size="sm"
                    variant={canChat ? 'default' : 'outline'}
                    className="gap-2"
                    disabled={!canChat}
                    onClick={() => {
                      if (!notebookUrl) return;
                      props.onChatForNotebook(notebookUrl, z.name);
                    }}
                  >
                    <MessageSquarePlus className="h-4 w-4" />
                    Chat
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </Card>
  );
}
