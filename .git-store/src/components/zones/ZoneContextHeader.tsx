import { useState } from "react";
import { Link } from "react-router-dom";
import { FileText, Settings2, Globe, Lock, Laptop, ChevronDown, ChevronUp } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ExpirationIndicator } from "@/components/garden/ExpirationIndicator";
import { NotebookLMStatusBadge } from "@/components/zones/NotebookLMStatusBadge";
import { ZoneDiagnosticsSheet } from "@/components/zones/ZoneDiagnosticsSheet";
import { cn } from "@/lib/utils";
import type { AccessType } from "@/types/mcpGateway";

interface ZoneContextHeaderProps {
  zoneId: string;
  zoneName: string;
  expiresAt: number;
  createdAt?: number;
  accessType: AccessType;
  noteCount?: number;
  showDiagnostics?: boolean;
  className?: string;
}

function AccessTypeBadge({ type }: { type: AccessType }) {
  const config = {
    web: { icon: Globe, label: "Web", variant: "outline" as const },
    mcp: { icon: Laptop, label: "MCP", variant: "secondary" as const },
    both: { icon: Lock, label: "Web + MCP", variant: "default" as const },
  };

  const { icon: Icon, label, variant } = config[type] || config.web;

  return (
    <Badge variant={variant} className="gap-1 text-[10px] sm:text-xs h-5 sm:h-6">
      <Icon className="h-3 w-3" />
      <span className="hidden sm:inline">{label}</span>
    </Badge>
  );
}

export function ZoneContextHeader({
  zoneId,
  zoneName,
  expiresAt,
  createdAt,
  accessType,
  noteCount,
  showDiagnostics = false,
  className,
}: ZoneContextHeaderProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const isExpired = expiresAt < Date.now();

  return (
    <div
      className={cn(
        "sticky top-0 z-10 bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/80 border-b",
        className
      )}
    >
      {/* Compact row - always visible */}
      <div className="flex items-center justify-between gap-2 px-3 py-2">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <h3 className="text-sm font-medium truncate">{zoneName}</h3>
          {isExpired && (
            <Badge variant="destructive" className="text-[10px] h-5">
              Expired
            </Badge>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <ExpirationIndicator
            expiresAt={expiresAt}
            createdAt={createdAt}
            showLabel
            className="hidden sm:flex"
          />

          {/* Mobile: compact TTL */}
          <ExpirationIndicator
            expiresAt={expiresAt}
            createdAt={createdAt}
            showLabel
            className="flex sm:hidden [&_.w-16]:w-10"
          />

          <Collapsible open={isExpanded} onOpenChange={setIsExpanded}>
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="icon" className="h-7 w-7">
                {isExpanded ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </Button>
            </CollapsibleTrigger>
          </Collapsible>
        </div>
      </div>

      {/* Expanded details */}
      <Collapsible open={isExpanded} onOpenChange={setIsExpanded}>
        <CollapsibleContent className="px-3 pb-2 space-y-2 animate-in slide-in-from-top-1 duration-200">
          {/* Badges row */}
          <div className="flex flex-wrap items-center gap-2">
            <AccessTypeBadge type={accessType} />
            <NotebookLMStatusBadge zoneId={zoneId} />
            {noteCount !== undefined && (
              <Badge variant="outline" className="gap-1 text-[10px] sm:text-xs h-5 sm:h-6">
                <FileText className="h-3 w-3" />
                {noteCount} notes
              </Badge>
            )}
          </div>

          {/* Actions row */}
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="h-7 text-xs gap-1.5" asChild>
              <Link to={`/zone/${zoneId}`}>
                <FileText className="h-3.5 w-3.5" />
                View Notes
              </Link>
            </Button>

            {showDiagnostics && (
              <ZoneDiagnosticsSheet
                zoneId={zoneId}
                zoneName={zoneName}
                trigger={
                  <Button variant="outline" size="sm" className="h-7 text-xs gap-1.5">
                    <Settings2 className="h-3.5 w-3.5" />
                    Diagnostics
                  </Button>
                }
              />
            )}
          </div>
        </CollapsibleContent>
      </Collapsible>
    </div>
  );
}
