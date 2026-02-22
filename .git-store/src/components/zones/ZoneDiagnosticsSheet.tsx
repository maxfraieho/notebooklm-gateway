import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  Loader2,
  RefreshCw,
  Wifi,
  WifiOff,
  Clock,
  HelpCircle,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
  SheetFooter,
} from '@/components/ui/sheet';
import { Separator } from '@/components/ui/separator';
import { useIsMobile } from '@/hooks/use-mobile';
import { getZoneNotebookLMStatus } from '@/lib/api/mcpGatewayClient';
import { cn } from '@/lib/utils';
import type { NotebookLMStatus, NotebookLMMapping } from '@/types/mcpGateway';

interface ZoneDiagnosticsSheetProps {
  zoneId: string;
  zoneName: string;
  trigger?: React.ReactNode;
  className?: string;
}

type StatusInfo = {
  label: string;
  variant: 'default' | 'secondary' | 'destructive' | 'outline';
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  advice?: string;
};

const STATUS_MAP: Record<NotebookLMStatus, StatusInfo> = {
  not_created: {
    label: 'Not Created',
    variant: 'secondary',
    icon: HelpCircle,
    description: 'NotebookLM has not been set up for this zone.',
    advice: 'Create a new zone with NotebookLM enabled, or update this zone.',
  },
  queued: {
    label: 'Queued',
    variant: 'outline',
    icon: Clock,
    description: 'NotebookLM creation is waiting in queue.',
    advice: 'Please wait, this usually takes 1-2 minutes.',
  },
  created: {
    label: 'Created',
    variant: 'outline',
    icon: Activity,
    description: 'NotebookLM notebook has been created.',
  },
  pending: {
    label: 'Pending',
    variant: 'outline',
    icon: Clock,
    description: 'Waiting for sources to be imported.',
    advice: 'This may take a few minutes for large zones.',
  },
  running: {
    label: 'Running',
    variant: 'outline',
    icon: Loader2,
    description: 'Sources are being imported into NotebookLM.',
    advice: 'Please wait, import is in progress.',
  },
  completed: {
    label: 'Ready',
    variant: 'default',
    icon: CheckCircle2,
    description: 'NotebookLM is ready to use.',
  },
  failed: {
    label: 'Failed',
    variant: 'destructive',
    icon: AlertCircle,
    description: 'NotebookLM setup failed.',
    advice: 'Try refreshing status or contact support if the issue persists.',
  },
};

function StatusRow({
  label,
  value,
  variant = 'secondary',
}: {
  label: string;
  value: string;
  variant?: 'default' | 'secondary' | 'destructive' | 'outline';
}) {
  return (
    <div className="flex items-center justify-between py-2">
      <span className="text-sm text-muted-foreground">{label}</span>
      <Badge variant={variant} className="text-xs">
        {value}
      </Badge>
    </div>
  );
}

export function ZoneDiagnosticsSheet({
  zoneId,
  zoneName,
  trigger,
  className,
}: ZoneDiagnosticsSheetProps) {
  const [open, setOpen] = useState(false);
  const isMobile = useIsMobile();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['zone-notebooklm', zoneId],
    queryFn: () => getZoneNotebookLMStatus(zoneId),
    staleTime: 30_000,
    retry: 1,
    enabled: open, // Only fetch when sheet is open
  });

  const mapping = query.data?.notebooklm ?? null;
  const status = mapping?.status ?? 'not_created';
  const statusInfo = STATUS_MAP[status];
  const StatusIcon = statusInfo.icon;

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['zone-notebooklm', zoneId] });
    query.refetch();
  };

  // Parse user-friendly error message
  const getErrorMessage = (error?: string | null) => {
    if (!error) return null;
    
    // Strip technical details, show user-friendly message
    if (error.includes('NOT_AUTHENTICATED') || error.includes('401')) {
      return 'Session expired. Please refresh the page and try again.';
    }
    if (error.includes('TIMEOUT') || error.includes('504')) {
      return 'Request timed out. The server may be busy, try again later.';
    }
    if (error.includes('RATE_LIMITED') || error.includes('429')) {
      return 'Too many requests. Please wait a moment and try again.';
    }
    if (error.includes('FORBIDDEN') || error.includes('403')) {
      return 'Access denied. You may not have permission for this action.';
    }
    
    // Generic fallback - don't show raw error
    return 'An error occurred during setup. Try refreshing or contact support.';
  };

  const errorMessage = getErrorMessage(mapping?.lastError);

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild className={className}>
        {trigger}
      </SheetTrigger>
      <SheetContent
        side={isMobile ? 'bottom' : 'right'}
        className={cn(isMobile && 'h-auto max-h-[85vh] rounded-t-xl')}
      >
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Zone Diagnostics
          </SheetTitle>
        </SheetHeader>

        <div className="py-4 space-y-4">
          {/* Zone info */}
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Zone</p>
            <p className="text-sm font-medium truncate">{zoneName}</p>
          </div>

          <Separator />

          {/* Connection status */}
          <div className="flex items-center gap-2">
            {navigator.onLine ? (
              <>
                <Wifi className="h-4 w-4 text-green-500" />
                <span className="text-sm">Connected</span>
              </>
            ) : (
              <>
                <WifiOff className="h-4 w-4 text-destructive" />
                <span className="text-sm text-destructive">Offline</span>
              </>
            )}
          </div>

          <Separator />

          {/* NotebookLM Status */}
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide mb-2">
              NotebookLM Status
            </p>

            {query.isLoading ? (
              <div className="flex items-center gap-2 py-2">
                <Loader2 className="h-4 w-4 animate-spin" />
                <span className="text-sm">Checking status...</span>
              </div>
            ) : query.isError ? (
              <div className="rounded-md bg-destructive/10 p-3 text-sm">
                <p className="text-destructive font-medium">Unable to check status</p>
                <p className="text-muted-foreground mt-1">
                  Check your connection and try again.
                </p>
              </div>
            ) : (
              <>
                {/* Status badge with icon */}
                <div className="flex items-center gap-2 py-2">
                  <StatusIcon
                    className={cn(
                      'h-5 w-5',
                      status === 'completed' && 'text-green-500',
                      status === 'failed' && 'text-destructive',
                      status === 'running' && 'animate-spin text-primary',
                      (status === 'queued' || status === 'pending') && 'text-muted-foreground'
                    )}
                  />
                  <Badge variant={statusInfo.variant} className="text-sm">
                    {statusInfo.label}
                  </Badge>
                </div>

                {/* Description */}
                <p className="text-sm text-muted-foreground">{statusInfo.description}</p>

                {/* Advice */}
                {statusInfo.advice && (
                  <div className="mt-2 rounded-md bg-muted p-2.5">
                    <p className="text-xs text-muted-foreground">{statusInfo.advice}</p>
                  </div>
                )}

                {/* Error message (if failed) */}
                {status === 'failed' && errorMessage && (
                  <div className="mt-3 rounded-md bg-destructive/10 border border-destructive/20 p-3">
                    <div className="flex items-start gap-2">
                      <AlertCircle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
                      <div>
                        <p className="text-sm font-medium text-destructive">Error Details</p>
                        <p className="text-xs text-muted-foreground mt-1">{errorMessage}</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Notebook URL if available */}
                {mapping?.notebookUrl && (
                  <StatusRow label="Notebook URL" value="Available" variant="default" />
                )}
              </>
            )}
          </div>
        </div>

        <SheetFooter className="gap-2 sm:gap-0">
          <Button
            variant="outline"
            onClick={handleRefresh}
            disabled={query.isFetching}
            className="gap-2"
          >
            <RefreshCw className={cn('h-4 w-4', query.isFetching && 'animate-spin')} />
            {query.isFetching ? 'Checking...' : 'Refresh Status'}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
