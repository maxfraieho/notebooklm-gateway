// Global graph page
// Displays the full knowledge graph visualization

import { useMemo } from 'react';
import { GlobalGraphView } from '@/components/garden/GlobalGraphView';
import { getFullGraph } from '@/lib/notes/linkGraph';
import { useLocale } from '@/hooks/useLocale';
import { GardenHeader } from '@/components/garden/GardenHeader';
import { GardenFooter } from '@/components/garden/GardenFooter';
import { GraphDebugPanel } from '@/components/garden/GraphDebugPanel';

export default function GraphPage() {
  const { nodes, edges } = useMemo(() => {
    const graph = getFullGraph();
    console.info(`[graph] Rendering: ${graph.nodes.length} nodes, ${graph.edges.length} edges`);
    return graph;
  }, []);
  const { t } = useLocale();

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <GardenHeader />

      <main className="flex-1">
        <div className="max-w-6xl mx-auto px-4 py-8">
          <header className="mb-6">
            <h1 className="text-2xl font-semibold text-foreground mb-2 font-serif">
              {t.graph.title}
            </h1>
            <p className="text-sm text-muted-foreground font-sans">
              {t.graph.description}
            </p>
          </header>

          <GlobalGraphView nodes={nodes} edges={edges} />
        </div>
      </main>

      <GardenFooter />
      <GraphDebugPanel />
    </div>
  );
}
