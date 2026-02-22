import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Search, ArrowRight, FolderOpen } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { useAccessZones } from '@/hooks/useAccessZones';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';

function ZoneSkeleton() {
  return (
    <div className="rounded-md border border-border p-3 space-y-2">
      <div className="min-w-0 space-y-1.5">
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-3 w-1/2" />
      </div>
      <div className="flex items-center justify-between gap-2">
        <Skeleton className="h-3 w-12" />
        <Skeleton className="h-8 w-20 rounded-md" />
      </div>
    </div>
  );
}

function EmptyZonesState() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 p-6 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted">
        <FolderOpen className="h-6 w-6 text-muted-foreground" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium">No zones yet</p>
        <p className="text-xs text-muted-foreground">Create a zone to share notes with colleagues</p>
      </div>
    </div>
  );
}

export function AccessZonesWall(props: { className?: string }) {
  const { isAuthenticated } = useOwnerAuth();
  const { zones, isLoading, error, fetchZones, isExpired } = useAccessZones();
  const [query, setQuery] = useState('');

  useEffect(() => {
    if (!isAuthenticated) return;
    fetchZones();
  }, [fetchZones, isAuthenticated]);

  const activeZones = useMemo(() => zones.filter((z) => !isExpired(z.expiresAt)), [zones, isExpired]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return activeZones;
    return activeZones.filter((z) => {
      const hay = `${z.name} ${z.description ?? ''}`.toLowerCase();
      return hay.includes(q);
    });
  }, [activeZones, query]);

  return (
    <Card className={cn('flex flex-col overflow-hidden', props.className)}>
      <div className="p-3 border-b">
        <p className="text-sm font-medium">Access Zones</p>
        <p className="text-xs text-muted-foreground">Швидкий перехід до зон</p>
      </div>

      <div className="p-3 border-b">
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
        <div className="p-2 space-y-2">
          {!isAuthenticated && (
            <div className="p-4 text-sm text-muted-foreground">Owner mode required to list zones.</div>
          )}

          {isAuthenticated && error && (
            <div className="p-3 text-sm text-destructive bg-destructive/10 rounded-md">{error}</div>
          )}

          {isAuthenticated && isLoading && (
            <>
              <ZoneSkeleton />
              <ZoneSkeleton />
              <ZoneSkeleton />
              <ZoneSkeleton />
            </>
          )}

          {isAuthenticated && !isLoading && filtered.length === 0 && !query && (
            <EmptyZonesState />
          )}

          {isAuthenticated && !isLoading && filtered.length === 0 && query && (
            <div className="p-4 text-sm text-muted-foreground text-center">No matching zones.</div>
          )}

          {isAuthenticated &&
            !isLoading &&
            filtered.map((z) => (
              <div key={z.id} className="rounded-md border border-border p-3 space-y-2 animate-fade-in">
                <div className="min-w-0">
                  <p className="text-sm font-medium truncate">{z.name}</p>
                  {z.description && <p className="text-xs text-muted-foreground truncate">{z.description}</p>}
                </div>

                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs text-muted-foreground truncate">📝 {z.noteCount}</p>
                  <Button asChild size="sm" variant="outline" className="gap-2">
                    <Link to={`/zone/${z.id}${z.accessCode ? `?code=${encodeURIComponent(z.accessCode)}` : ''}`}>
                      <ArrowRight className="h-4 w-4" />
                      Open
                    </Link>
                  </Button>
                </div>
              </div>
            ))}
        </div>
      </ScrollArea>
    </Card>
  );
}
