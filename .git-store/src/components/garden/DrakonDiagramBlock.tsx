// src/components/garden/DrakonDiagramBlock.tsx

import { Suspense, lazy, useState, useEffect } from 'react';
import { Loader2, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { DrakonBlockParams } from '@/lib/drakon/types';
import type { DrakonDiagram } from '@/types/drakonwidget';

// Lazy load the viewer
const DrakonViewer = lazy(() =>
  import('./DrakonViewer').then(m => ({ default: m.DrakonViewer }))
);

interface DrakonDiagramBlockProps {
  params: DrakonBlockParams;
  noteSlug: string;
  className?: string;
}

export function DrakonDiagramBlock({
  params,
  noteSlug,
  className,
}: DrakonDiagramBlockProps) {
  const [diagram, setDiagram] = useState<DrakonDiagram | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadDiagram() {
      try {
        // Phase 1: Load from static JSON file
        const decodedSlug = decodeURIComponent(noteSlug);
        const folderSlug = decodedSlug.endsWith('/index')
          ? decodedSlug.slice(0, -'/index'.length)
          : decodedSlug;

        const response = await fetch(
          `/site/notes/${folderSlug}/diagrams/${params.id}.drakon.json`
        );
        if (!response.ok) {
          throw new Error(`Diagram not found: ${params.id}`);
        }
        const stored = await response.json();
        setDiagram(stored.diagram || stored);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load diagram');
      }
    }

    loadDiagram();
  }, [params.id, noteSlug]);

  if (error) {
    return (
      <div className={cn(
        'flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3',
        className
      )}>
        <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
        <span className="text-sm text-destructive">
          DRAKON: {error}
        </span>
      </div>
    );
  }

  if (!diagram) {
    return (
      <div
        className="flex items-center justify-center rounded-lg border bg-muted/30"
        style={{ height: params.height || 400 }}
      >
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <Suspense
      fallback={
        <div
          className="flex items-center justify-center rounded-lg border bg-muted/30"
          style={{ height: params.height || 400 }}
        >
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </div>
      }
    >
      <DrakonViewer
        diagram={diagram}
        diagramId={params.id}
        height={params.height}
        initialZoom={params.zoom}
        className={className}
      />
    </Suspense>
  );
}
