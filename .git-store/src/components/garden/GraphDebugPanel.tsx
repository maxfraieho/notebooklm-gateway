// Graph Debug Panel — dev-only diagnostics overlay
// Shows nodes, edges, unresolved links, malformed links, contract info

import { useState } from 'react';
import { Bug, ChevronDown, ChevronUp, AlertTriangle, XCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { getGraphDiagnostics } from '@/lib/notes/linkGraph';

const IS_DEV = import.meta.env.DEV;

export function GraphDebugPanel() {
  const [open, setOpen] = useState(false);
  
  // Only render in dev mode
  if (!IS_DEV) return null;
  
  const diag = getGraphDiagnostics();
  const hasWarnings = diag.malformedLinks.length > 0 || diag.unresolvedLinks.length > 0;
  
  return (
    <div className="fixed bottom-4 right-4 z-50 max-w-sm">
      {/* Toggle button */}
      <Button
        variant="outline"
        size="sm"
        onClick={() => setOpen(!open)}
        className={`mb-1 gap-1.5 text-xs ${hasWarnings ? 'border-yellow-500 text-yellow-600' : ''}`}
      >
        <Bug className="h-3.5 w-3.5" />
        Graph Debug
        {hasWarnings && <AlertTriangle className="h-3 w-3 text-yellow-500" />}
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />}
      </Button>
      
      {open && (
        <div className="rounded-lg border border-border bg-card shadow-lg p-3 text-xs font-mono space-y-2 max-h-96 overflow-y-auto">
          {/* Stats */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            <span className="text-muted-foreground">Nodes:</span>
            <span className="font-semibold">{diag.totalNodes}</span>
            <span className="text-muted-foreground">Edges:</span>
            <span className="font-semibold">{diag.totalEdges}</span>
            <span className="text-muted-foreground">Unresolved:</span>
            <span className={`font-semibold ${diag.unresolvedLinks.length > 0 ? 'text-yellow-600' : ''}`}>
              {diag.unresolvedLinks.length}
            </span>
            <span className="text-muted-foreground">Contract:</span>
            <span>{diag.contractVersion}</span>
            <span className="text-muted-foreground">Source:</span>
            <span>{diag.source}</span>
          </div>
          
          {/* Malformed links warning */}
          {diag.malformedLinks.length > 0 && (
            <div className="border-t border-border pt-2">
              <div className="flex items-center gap-1 text-red-500 font-semibold mb-1">
                <XCircle className="h-3 w-3" />
                Malformed links ({diag.malformedLinks.length})
              </div>
              <ul className="space-y-0.5 text-[10px] text-muted-foreground max-h-24 overflow-y-auto">
                {diag.malformedLinks.slice(0, 10).map((ml, i) => (
                  <li key={i} className="truncate">
                    <span className="text-red-400">{ml.reason}</span>{' '}
                    in {ml.sourceTitle}: <code>{ml.raw.slice(0, 40)}</code>
                  </li>
                ))}
                {diag.malformedLinks.length > 10 && (
                  <li className="text-muted-foreground">…and {diag.malformedLinks.length - 10} more</li>
                )}
              </ul>
            </div>
          )}
          
          {/* Unresolved links */}
          {diag.unresolvedLinks.length > 0 && (
            <div className="border-t border-border pt-2">
              <div className="flex items-center gap-1 text-yellow-600 font-semibold mb-1">
                <AlertTriangle className="h-3 w-3" />
                Unresolved links (top 10)
              </div>
              <ul className="space-y-0.5 text-[10px] text-muted-foreground max-h-24 overflow-y-auto">
                {diag.unresolvedLinks.slice(0, 10).map((ul, i) => (
                  <li key={i} className="truncate">
                    {ul.sourceTitle} → <code>[[{ul.targetText}]]</code>
                  </li>
                ))}
                {diag.unresolvedLinks.length > 10 && (
                  <li className="text-muted-foreground">…and {diag.unresolvedLinks.length - 10} more</li>
                )}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
