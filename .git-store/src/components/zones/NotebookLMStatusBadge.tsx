import { useQuery } from '@tanstack/react-query';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { getZoneNotebookLMStatus } from '@/lib/api/mcpGatewayClient';
import type { NotebookLMMapping } from '@/types/mcpGateway';

function badgeVariantFor(mapping: NotebookLMMapping | null): 'secondary' | 'default' | 'destructive' | 'outline' {
  if (!mapping) return 'secondary';
  if (mapping.status === 'completed') return 'default';
  if (mapping.status === 'failed') return 'destructive';
  return 'outline';
}

function labelFor(mapping: NotebookLMMapping | null) {
  if (!mapping) return 'NotebookLM: none';
  if (mapping.status === 'completed') return 'NotebookLM: ready';
  if (mapping.status === 'failed') return 'NotebookLM: failed';
  return `NotebookLM: ${mapping.status}`;
}

export function NotebookLMStatusBadge({ zoneId }: { zoneId: string }) {
  const q = useQuery({
    queryKey: ['zone-notebooklm', zoneId],
    queryFn: () => getZoneNotebookLMStatus(zoneId),
    staleTime: 30_000,
    retry: 1,
  });

  if (q.isLoading) return <Skeleton className="h-5 w-28" />;
  if (q.isError) return <Badge variant="outline">NotebookLM: unknown</Badge>;

  const mapping = q.data?.notebooklm ?? null;
  return <Badge variant={badgeVariantFor(mapping)}>{labelFor(mapping)}</Badge>;
}
