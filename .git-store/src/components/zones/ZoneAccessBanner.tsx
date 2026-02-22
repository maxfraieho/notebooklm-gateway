import { AlertTriangle, Clock, Mail, Lock } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type ZoneAccessState = "active" | "expired" | "read-only";

interface ZoneAccessBannerProps {
  state: ZoneAccessState;
  zoneName?: string;
  ownerEmail?: string;
  onRequestRenewal?: () => void;
  className?: string;
}

export function ZoneAccessBanner({
  state,
  zoneName,
  ownerEmail,
  onRequestRenewal,
  className,
}: ZoneAccessBannerProps) {
  if (state === "active") return null;

  const isExpired = state === "expired";

  const handleContactOwner = () => {
    if (ownerEmail) {
      const subject = encodeURIComponent(
        `Access request: ${zoneName || "Zone"}`
      );
      const body = encodeURIComponent(
        `Hi,\n\nI would like to request ${isExpired ? "renewal of" : "write access to"} the zone "${zoneName || "this zone"}".\n\nThank you!`
      );
      window.open(`mailto:${ownerEmail}?subject=${subject}&body=${body}`);
    } else if (onRequestRenewal) {
      onRequestRenewal();
    }
  };

  return (
    <Alert
      variant={isExpired ? "destructive" : "default"}
      className={cn(
        "mx-3 mt-3",
        isExpired && "bg-destructive/10 border-destructive/40",
        !isExpired && "bg-amber-500/10 border-amber-500/40",
        className
      )}
    >
      <div className="flex items-start gap-3">
        {isExpired ? (
          <Clock className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
        ) : (
          <Lock className="h-5 w-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
        )}

        <div className="flex-1 min-w-0">
          <AlertTitle className="text-sm font-semibold mb-1">
            {isExpired ? "Zone Expired" : "Read-Only Access"}
          </AlertTitle>
          <AlertDescription className="text-xs sm:text-sm">
            {isExpired
              ? "This access zone has expired. You can view the chat history, but cannot send new messages."
              : "You have read-only access to this zone. Contact the owner to request write permissions."}
          </AlertDescription>

          <div className="flex flex-wrap items-center gap-2 mt-3">
            <Button
              size="sm"
              variant={isExpired ? "destructive" : "outline"}
              className="h-8 gap-1.5 text-xs"
              onClick={handleContactOwner}
            >
              <Mail className="h-3.5 w-3.5" />
              {isExpired ? "Request Renewal" : "Contact Owner"}
            </Button>

            {isExpired && (
              <span className="text-[10px] sm:text-xs text-muted-foreground">
                or ask the owner for a new link
              </span>
            )}
          </div>
        </div>
      </div>
    </Alert>
  );
}

/**
 * Compact inline indicator for input area
 */
export function ZoneAccessLabel({
  state,
  className,
}: {
  state: ZoneAccessState;
  className?: string;
}) {
  if (state === "active") return null;

  const isExpired = state === "expired";

  return (
    <div
      className={cn(
        "flex items-center gap-1.5 text-xs",
        isExpired ? "text-destructive" : "text-amber-600 dark:text-amber-400",
        className
      )}
    >
      {isExpired ? (
        <>
          <AlertTriangle className="h-3.5 w-3.5" />
          <span>Zone expired — messages disabled</span>
        </>
      ) : (
        <>
          <Lock className="h-3.5 w-3.5" />
          <span>Read-only — cannot send messages</span>
        </>
      )}
    </div>
  );
}
