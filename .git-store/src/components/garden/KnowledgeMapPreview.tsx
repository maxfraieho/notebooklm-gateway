import { Link, useNavigate } from 'react-router-dom';
import { Network } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { getFullGraph } from '@/lib/notes/linkGraph';
import { useLocale } from '@/hooks/useLocale';
import { useMemo, useState, useRef, useEffect, useCallback } from 'react';

const SIZE = 400;
const REPULSION = 2200;
const ATTRACTION = 0.012;
const DAMPING = 0.82;
const CENTER_GRAVITY = 0.015;
const MIN_DIST = 20;

interface MiniNode {
  slug: string;
  title: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  connections: number;
  dragging?: boolean;
}

export function KnowledgeMapPreview() {
  const { t } = useLocale();
  const graph = useMemo(() => getFullGraph(), []);
  const navigate = useNavigate();
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [dragNode, setDragNode] = useState<string | null>(null);
  const dragMovedRef = useRef(false);

  const nodeCount = graph.nodes.length;
  const edgeCount = graph.edges.length;

  const simRef = useRef<MiniNode[]>([]);
  const rafRef = useRef<number>(0);
  const svgRef = useRef<SVGSVGElement>(null);
  const [, tick] = useState(0);

  useEffect(() => {
    const nodes = graph.nodes;
    const edges = graph.edges;

    const connCount = new Map<string, number>();
    for (const e of edges) {
      connCount.set(e.source, (connCount.get(e.source) || 0) + 1);
      connCount.set(e.target, (connCount.get(e.target) || 0) + 1);
    }

    const cx = SIZE / 2;
    const cy = SIZE / 2;
    const radius = SIZE * 0.35;

    simRef.current = nodes.map((n, i) => {
      const angle = (2 * Math.PI * i) / nodes.length;
      return {
        slug: n.slug,
        title: n.title,
        x: cx + radius * Math.cos(angle) + (Math.random() - 0.5) * 15,
        y: cy + radius * Math.sin(angle) + (Math.random() - 0.5) * 15,
        vx: 0,
        vy: 0,
        connections: connCount.get(n.slug) || 0,
      };
    });

    let running = true;
    let frame = 0;

    const step = () => {
      if (!running) return;
      const sn = simRef.current;
      const n = sn.length;

      for (const nd of sn) {
        if (nd.dragging) { nd.vx = 0; nd.vy = 0; continue; }
        nd.vx *= DAMPING; nd.vy *= DAMPING;
      }

      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          let dx = sn[i].x - sn[j].x;
          let dy = sn[i].y - sn[j].y;
          let dist = Math.sqrt(dx * dx + dy * dy) || 1;
          if (dist < MIN_DIST) dist = MIN_DIST;
          const f = REPULSION / (dist * dist);
          const fx = (dx / dist) * f;
          const fy = (dy / dist) * f;
          if (!sn[i].dragging) { sn[i].vx += fx; sn[i].vy += fy; }
          if (!sn[j].dragging) { sn[j].vx -= fx; sn[j].vy -= fy; }
        }
      }

      const idx = new Map(sn.map((nd, i) => [nd.slug, i]));
      for (const e of edges) {
        const ai = idx.get(e.source);
        const bi = idx.get(e.target);
        if (ai === undefined || bi === undefined) continue;
        const a = sn[ai], b = sn[bi];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = dist * ATTRACTION;
        const fx = (dx / dist) * f;
        const fy = (dy / dist) * f;
        if (!a.dragging) { a.vx += fx; a.vy += fy; }
        if (!b.dragging) { b.vx -= fx; b.vy -= fy; }
      }

      const cxc = SIZE / 2, cyc = SIZE / 2;
      for (const nd of sn) {
        if (nd.dragging) continue;
        nd.vx += (cxc - nd.x) * CENTER_GRAVITY;
        nd.vy += (cyc - nd.y) * CENTER_GRAVITY;
        nd.x += nd.vx;
        nd.y += nd.vy;
        // Clamp to bounds
        nd.x = Math.max(15, Math.min(SIZE - 15, nd.x));
        nd.y = Math.max(15, Math.min(SIZE - 15, nd.y));
      }

      frame++;
      if (frame % 2 === 0) tick(v => v + 1);
      rafRef.current = requestAnimationFrame(step);
    };

    rafRef.current = requestAnimationFrame(step);
    return () => { running = false; cancelAnimationFrame(rafRef.current); };
  }, [graph]);

  const nodeR = useCallback((connections: number) => Math.max(3, Math.min(10, 3 + connections * 1.2)), []);

  const getSVGPoint = useCallback((e: React.MouseEvent) => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    const scale = SIZE / rect.width;
    return {
      x: (e.clientX - rect.left) * scale,
      y: (e.clientY - rect.top) * scale,
    };
  }, []);

  const handlePointerDown = useCallback((e: React.PointerEvent, slug: string) => {
    e.preventDefault();
    e.stopPropagation();
    (e.target as Element).setPointerCapture(e.pointerId);
    dragMovedRef.current = false;
    setDragNode(slug);
    const nd = simRef.current.find(n => n.slug === slug);
    if (nd) nd.dragging = true;
  }, []);

  const handlePointerMove = useCallback((e: React.PointerEvent) => {
    if (!dragNode) return;
    dragMovedRef.current = true;
    const pt = getSVGPoint(e);
    const nd = simRef.current.find(n => n.slug === dragNode);
    if (nd) {
      nd.x = Math.max(15, Math.min(SIZE - 15, pt.x));
      nd.y = Math.max(15, Math.min(SIZE - 15, pt.y));
    }
  }, [dragNode, getSVGPoint]);

  const handlePointerUp = useCallback(() => {
    if (dragNode) {
      const nd = simRef.current.find(n => n.slug === dragNode);
      if (nd) nd.dragging = false;
      if (!dragMovedRef.current) {
        navigate(`/notes/${dragNode}`);
      }
      setDragNode(null);
    }
  }, [dragNode, navigate]);

  const simNodes = simRef.current;
  const slugMap = new Map(simNodes.map(n => [n.slug, n]));

  const truncateTitle = (title: string, max = 14) =>
    title.length > max ? title.slice(0, max) + '…' : title;

  return (
    <div className="border border-border rounded-lg p-4 bg-card transition-all duration-200">
      <div className="flex items-center gap-2 mb-4">
        <Network className="w-5 h-5 text-primary" />
        <h2 className="font-semibold text-foreground font-sans">
          {t.index.knowledgeMap}
        </h2>
      </div>

      {/* Square interactive graph */}
      <div
        className="bg-gradient-to-b from-background to-background/50 rounded-lg border border-border/50 mb-4 overflow-hidden hover:border-border transition-colors duration-200"
        style={{ aspectRatio: '1 / 1' }}
      >
        <svg
          ref={svgRef}
          width="100%"
          height="100%"
          viewBox={`0 0 ${SIZE} ${SIZE}`}
          className="block touch-none"
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerLeave={handlePointerUp}
        >
          {/* Edges */}
          {graph.edges.map((edge, i) => {
            const s = slugMap.get(edge.source);
            const tgt = slugMap.get(edge.target);
            if (!s || !tgt) return null;
            const highlighted = hoveredNode === edge.source || hoveredNode === edge.target;
            return (
              <line
                key={`e-${i}`}
                x1={s.x} y1={s.y} x2={tgt.x} y2={tgt.y}
                stroke="hsl(var(--primary))"
                strokeWidth={highlighted ? 1.5 : 0.6}
                strokeOpacity={highlighted ? 0.7 : 0.2}
              />
            );
          })}

          {/* Nodes + Labels */}
          {simNodes.map(node => {
            const isHovered = hoveredNode === node.slug;
            const r = nodeR(node.connections);
            return (
              <g key={node.slug}>
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={isHovered ? r + 2 : r}
                  fill="hsl(var(--primary))"
                  fillOpacity={isHovered ? 1 : 0.85}
                  stroke={isHovered ? 'hsl(var(--primary-foreground))' : 'none'}
                  strokeWidth={isHovered ? 1.5 : 0}
                  onPointerDown={(e) => handlePointerDown(e, node.slug)}
                  onMouseEnter={() => setHoveredNode(node.slug)}
                  onMouseLeave={() => setHoveredNode(null)}
                  className="cursor-pointer active:cursor-grabbing"
                />
                <text
                  x={node.x}
                  y={node.y + r + 8}
                  textAnchor="middle"
                  fill="hsl(var(--foreground))"
                  fillOpacity={isHovered ? 0.9 : 0.55}
                  fontSize={isHovered ? 7 : 5.5}
                  fontWeight={isHovered ? 600 : 400}
                  pointerEvents="none"
                  className="select-none"
                >
                  {truncateTitle(node.title)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Explore button */}
      <Button
        asChild
        variant="default"
        className="w-full mb-4 font-semibold transition-all duration-200 hover:shadow-md"
      >
        <Link to="/graph">{t.index.exploreGraph}</Link>
      </Button>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-2 text-center">
        <div className="p-2 rounded-md bg-muted/50 transition-all duration-200 hover:bg-muted">
          <div className="text-sm font-semibold text-primary">{nodeCount}</div>
          <div className="text-xs text-muted-foreground">{t.common.notes}</div>
        </div>
        <div className="p-2 rounded-md bg-muted/50 transition-all duration-200 hover:bg-muted">
          <div className="text-sm font-semibold text-primary">{edgeCount}</div>
          <div className="text-xs text-muted-foreground">{t.index.connections}</div>
        </div>
      </div>
    </div>
  );
}
