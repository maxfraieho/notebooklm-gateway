import { WifiOff, RefreshCw, AlertTriangle } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type ConnectionState = "online" | "offline" | "error" | "retrying";

interface ConnectionBannerProps {
  state: ConnectionState;
  errorMessage?: string;
  onRetry?: () => void;
  isRetrying?: boolean;
  className?: string;
}

export function ConnectionBanner({
  state,
  errorMessage,
  onRetry,
  isRetrying = false,
  className,
}: ConnectionBannerProps) {
  if (state === "online") return null;

  const isOffline = state === "offline";
  const isError = state === "error";

  return (
    <Alert
      variant={isOffline ? "destructive" : "default"}
      className={cn(
        "flex items-center justify-between gap-3 py-2 px-3",
        isOffline && "bg-destructive/10 border-destructive/30",
        isError && "bg-amber-500/10 border-amber-500/30",
        state === "retrying" && "bg-muted",
        className
      )}
    >
      <div className="flex items-center gap-2 min-w-0">
        {isOffline ? (
          <WifiOff className="h-4 w-4 shrink-0 text-destructive" />
        ) : (
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-500" />
        )}
        <AlertDescription className="text-sm truncate">
          {isOffline
            ? "No internet connection"
            : errorMessage || "Something went wrong"}
        </AlertDescription>
      </div>

      {onRetry && (
        <Button
          variant="outline"
          size="sm"
          onClick={onRetry}
          disabled={isRetrying}
          className="shrink-0 h-7 gap-1.5 text-xs"
        >
          <RefreshCw
            className={cn("h-3 w-3", isRetrying && "animate-spin")}
          />
          {isRetrying ? "Retrying…" : "Retry"}
        </Button>
      )}
    </Alert>
  );
}
