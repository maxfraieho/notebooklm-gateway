// Local graph visualization component
// Renders a visual representation of note connections

import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLocale } from '@/hooks/useLocale';
import type { LocalGraph, GraphNode } from '@/lib/notes/linkGraph';

interface LocalGraphViewProps {
  graph: LocalGraph;
}

interface PositionedNode extends GraphNode {
  x: number;
  y: number;
  type: 'center' | 'inbound' | 'outbound';
}

/**
 * Compute positions for nodes in a radial layout
 * Center node in the middle, inbound on left arc, outbound on right arc
 */
function computeNodePositions(graph: LocalGraph, width: number, height: number): PositionedNode[] {
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) * 0.35;
  
  const nodes: PositionedNode[] = [];
  
  // Center node
  nodes.push({
    ...graph.center,
    x: centerX,
    y: centerY,
    type: 'center',
  });
  
  // Inbound nodes (left arc, from top-left to bottom-left)
  const inboundCount = graph.inbound.length;
  graph.inbound.forEach((node, i) => {
    const angle = Math.PI * 0.75 + (Math.PI * 0.5 * (i + 0.5)) / Math.max(inboundCount, 1);
    nodes.push({
      ...node,
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
      type: 'inbound',
    });
  });
  
  // Outbound nodes (right arc, from top-right to bottom-right)
  const outboundCount = graph.outbound.length;
  graph.outbound.forEach((node, i) => {
    const angle = -Math.PI * 0.25 + (Math.PI * 0.5 * (i + 0.5)) / Math.max(outboundCount, 1);
    nodes.push({
      ...node,
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
      type: 'outbound',
    });
  });
  
  return nodes;
}

/**
 * Get node color based on type
 */
function getNodeColor(type: PositionedNode['type'], exists: boolean): string {
  if (!exists) return 'hsl(var(--muted))';
  
  switch (type) {
    case 'center':
      return 'hsl(var(--primary))';
    case 'inbound':
      return 'hsl(var(--accent))';
    case 'outbound':
      return 'hsl(var(--secondary))';
    default:
      return 'hsl(var(--muted-foreground))';
  }
}

/**
 * Truncate text for display
 */
function truncateTitle(title: string, maxLength: number = 20): string {
  if (title.length <= maxLength) return title;
  return title.slice(0, maxLength - 1) + '…';
}

export function LocalGraphView({ graph }: LocalGraphViewProps) {
  const navigate = useNavigate();
  const { t } = useLocale();
  
  const width = 320;
  const height = 240;
  
  const nodes = useMemo(() => computeNodePositions(graph, width, height), [graph]);
  
  const nodeMap = useMemo(() => {
    const map = new Map<string, PositionedNode>();
    nodes.forEach(n => map.set(n.slug, n));
    return map;
  }, [nodes]);
  
  const handleNodeClick = (node: PositionedNode) => {
    if (node.type === 'center') return; // Don't navigate to current note
    if (!node.exists) return; // Don't navigate to non-existent notes
    navigate(`/notes/${node.slug}`);
  };
  
  const centerNode = nodes.find(n => n.type === 'center')!;
  
  return (
    <div className="w-full overflow-hidden rounded-lg border border-border bg-card">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-auto"
        style={{ maxHeight: '300px' }}
      >
        {/* Edges */}
        <g className="edges">
          {graph.edges.map((edge, i) => {
            const source = nodeMap.get(edge.source);
            const target = nodeMap.get(edge.target);
            if (!source || !target) return null;
            
            return (
              <line
                key={`edge-${i}`}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke="hsl(var(--border))"
                strokeWidth={1.5}
                strokeOpacity={0.6}
              />
            );
          })}
        </g>
        
        {/* Nodes */}
        <g className="nodes">
          {nodes.map((node) => {
            const isCenter = node.type === 'center';
            const isClickable = !isCenter && node.exists;
            const nodeRadius = isCenter ? 8 : 6;
            
            return (
              <g
                key={node.slug}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={() => handleNodeClick(node)}
                className={isClickable ? 'cursor-pointer' : isCenter ? '' : 'opacity-50'}
                role={isClickable ? 'button' : undefined}
                tabIndex={isClickable ? 0 : undefined}
                onKeyDown={(e) => {
                  if (isClickable && (e.key === 'Enter' || e.key === ' ')) {
                    handleNodeClick(node);
                  }
                }}
              >
                {/* Node circle */}
                <circle
                  r={nodeRadius}
                  fill={getNodeColor(node.type, node.exists)}
                  stroke={isCenter ? 'hsl(var(--primary-foreground))' : 'none'}
                  strokeWidth={isCenter ? 2 : 0}
                  className={isClickable ? 'transition-transform hover:scale-125' : ''}
                />
                
                {/* Node label */}
                <text
                  y={nodeRadius + 12}
                  textAnchor="middle"
                  className="text-[10px] font-sans fill-muted-foreground"
                  style={{ pointerEvents: 'none' }}
                >
                  {truncateTitle(node.title, 18)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      
      {/* Legend */}
      <div className="flex justify-center gap-4 px-3 py-2 border-t border-border text-[10px] text-muted-foreground font-sans">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-primary" />
          {t.localGraph.current}
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-accent" />
          {t.localGraph.linksHere}
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-secondary" />
          {t.localGraph.linkedFromHere}
        </span>
      </div>
    </div>
  );
}
