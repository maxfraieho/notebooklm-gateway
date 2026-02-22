// src/components/garden/DrakonViewer.tsx

import { useRef, useEffect, useState, useCallback } from 'react';
import { useTheme } from '@/components/theme-provider';
import { 
  Loader2, 
  AlertCircle, 
  ZoomIn, 
  ZoomOut, 
  Maximize2,
  Home,
  X
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { loadDrakonWidget, createWidget } from '@/lib/drakon/adapter';
import { getGardenDrakonTheme } from '@/lib/drakon/themeAdapter';
import { createDrakonTranslate, getDrakonLabels } from '@/lib/drakon/i18n';
import { useLocale } from '@/hooks/useLocale';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import type { 
  DrakonDiagram, 
  DrakonWidget, 
  DrakonConfig, 
  DrakonEditSender 
} from '@/types/drakonwidget';

interface DrakonViewerProps {
  diagram: DrakonDiagram;
  diagramId: string;
  height?: number;
  initialZoom?: number;
  className?: string;
}

const ZOOM_STEP = 2000;
const MIN_ZOOM = 4000;
const MAX_ZOOM = 30000;

export function DrakonViewer({
  diagram,
  diagramId,
  height = 400,
  initialZoom = 4000,
  className,
}: DrakonViewerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const fullscreenContainerRef = useRef<HTMLDivElement>(null);
  const widgetRef = useRef<DrakonWidget | null>(null);
  const fullscreenWidgetRef = useRef<DrakonWidget | null>(null);
  
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [zoom, setZoom] = useState(initialZoom);
  const [isFullscreen, setIsFullscreen] = useState(false);
  
  const { theme } = useTheme();
  const { t } = useLocale();
  const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

  // No-op edit sender for read-only mode
  const editSender: DrakonEditSender = {
    pushEdit: () => {},
    stop: () => {},
  };

  // Build config with text rendering enabled
  const drakonLabels = getDrakonLabels(t.drakon);
  const drakonTranslate = createDrakonTranslate(t.drakon);

  const buildConfig = useCallback((): DrakonConfig => ({
    startEditContent: () => {},
    showContextMenu: () => {},
    canSelect: false,
    canvasIcons: false,
    textFormat: 'plain',
    font: '14px system-ui, -apple-system, sans-serif',
    headerFont: 'bold 16px system-ui, -apple-system, sans-serif',
    branchFont: 'bold 13px system-ui, -apple-system, sans-serif',
    theme: getGardenDrakonTheme(isDark),
    translate: drakonTranslate,
    ...drakonLabels,
    onZoomChanged: (newZoom) => setZoom(newZoom),
  }), [isDark, drakonLabels, drakonTranslate]);

  // Initialize widget
  useEffect(() => {
    let mounted = true;

    async function init() {
      if (!containerRef.current) return;

      try {
        await loadDrakonWidget();
        if (!mounted) return;

        const widget = createWidget();
        widgetRef.current = widget;

        const container = containerRef.current;
        const rect = container.getBoundingClientRect();
        container.innerHTML = '';

        const config = buildConfig();
        const element = widget.render(rect.width, rect.height, config);
        container.appendChild(element);

        await widget.setDiagram(diagramId, diagram, editSender);
        widget.setZoom(initialZoom);
        widget.goHome();

        setIsLoading(false);
      } catch (err) {
        if (!mounted) return;
        setError(err instanceof Error ? err.message : 'Failed to load diagram');
        setIsLoading(false);
      }
    }

    init();

    return () => {
      mounted = false;
      if (widgetRef.current) {
        editSender.stop();
        widgetRef.current = null;
      }
      if (containerRef.current) {
        containerRef.current.innerHTML = '';
      }
    };
  }, [diagramId, diagram, initialZoom, buildConfig]);

  // Handle theme changes
  useEffect(() => {
    if (!widgetRef.current || !containerRef.current || isLoading) return;

    const widget = widgetRef.current;
    const container = containerRef.current;
    const rect = container.getBoundingClientRect();

    container.innerHTML = '';
    const config = buildConfig();
    const element = widget.render(rect.width, rect.height, config);
    container.appendChild(element);
    widget.redraw();
  }, [isDark, buildConfig, isLoading]);

  // Handle resize
  useEffect(() => {
    if (!containerRef.current || !widgetRef.current || isLoading) return;

    const container = containerRef.current;
    const widget = widgetRef.current;

    let resizeTimeout: ReturnType<typeof setTimeout>;

    const observer = new ResizeObserver(() => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => {
        if (!container || !widget) return;
        const rect = container.getBoundingClientRect();
        container.innerHTML = '';
        const config = buildConfig();
        const element = widget.render(rect.width, rect.height, config);
        container.appendChild(element);
        widget.redraw();
      }, 200);
    });

    observer.observe(container);

    return () => {
      clearTimeout(resizeTimeout);
      observer.disconnect();
    };
  }, [isLoading, buildConfig]);

  // Initialize fullscreen widget when dialog opens
  useEffect(() => {
    if (!isFullscreen) {
      if (fullscreenWidgetRef.current) {
        fullscreenWidgetRef.current = null;
      }
      return;
    }

    let mounted = true;

    async function initFullscreen() {
      // Wait for dialog to render
      await new Promise(resolve => setTimeout(resolve, 100));
      
      if (!mounted || !fullscreenContainerRef.current) return;

      try {
        await loadDrakonWidget();
        if (!mounted) return;

        const widget = createWidget();
        fullscreenWidgetRef.current = widget;

        const container = fullscreenContainerRef.current;
        const rect = container.getBoundingClientRect();
        container.innerHTML = '';

        const config = buildConfig();
        const element = widget.render(rect.width, rect.height, config);
        container.appendChild(element);

        await widget.setDiagram(diagramId, diagram, editSender);
        widget.setZoom(zoom);
        widget.goHome();
      } catch (err) {
        console.error('Fullscreen init error:', err);
      }
    }

    initFullscreen();

    return () => {
      mounted = false;
    };
  }, [isFullscreen, diagram, diagramId, zoom, buildConfig]);

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    const newZoom = Math.min(zoom + ZOOM_STEP, MAX_ZOOM);
    setZoom(newZoom);
    widgetRef.current?.setZoom(newZoom);
    fullscreenWidgetRef.current?.setZoom(newZoom);
  }, [zoom]);

  const handleZoomOut = useCallback(() => {
    const newZoom = Math.max(zoom - ZOOM_STEP, MIN_ZOOM);
    setZoom(newZoom);
    widgetRef.current?.setZoom(newZoom);
    fullscreenWidgetRef.current?.setZoom(newZoom);
  }, [zoom]);

  const handleGoHome = useCallback(() => {
    widgetRef.current?.goHome();
    fullscreenWidgetRef.current?.goHome();
  }, []);

  if (error) {
    return (
      <div className={cn(
        'flex items-center justify-center gap-2 rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-destructive',
        className
      )} style={{ height }}>
        <AlertCircle className="h-5 w-5" />
        <span className="text-sm">{error}</span>
      </div>
    );
  }

  const zoomPercentage = Math.round(zoom / 100);

  return (
    <>
      <div className={cn('relative group', className)}>
        {isLoading && (
          <div
            className="absolute inset-0 flex items-center justify-center bg-muted/50 rounded-lg z-10"
            style={{ height }}
          >
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        )}
        
        {/* Controls overlay */}
        {!isLoading && (
          <div className="absolute top-2 right-2 z-20 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <Button
              variant="secondary"
              size="icon"
              className="h-8 w-8 bg-background/80 backdrop-blur-sm shadow-sm"
              onClick={handleZoomOut}
              disabled={zoom <= MIN_ZOOM}
              title="Зменшити"
            >
              <ZoomOut className="h-4 w-4" />
            </Button>
            <div className="flex items-center px-2 bg-background/80 backdrop-blur-sm rounded-md text-xs font-medium min-w-[50px] justify-center shadow-sm">
              {zoomPercentage}%
            </div>
            <Button
              variant="secondary"
              size="icon"
              className="h-8 w-8 bg-background/80 backdrop-blur-sm shadow-sm"
              onClick={handleZoomIn}
              disabled={zoom >= MAX_ZOOM}
              title="Збільшити"
            >
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button
              variant="secondary"
              size="icon"
              className="h-8 w-8 bg-background/80 backdrop-blur-sm shadow-sm"
              onClick={handleGoHome}
              title="На початок"
            >
              <Home className="h-4 w-4" />
            </Button>
            <Button
              variant="secondary"
              size="icon"
              className="h-8 w-8 bg-background/80 backdrop-blur-sm shadow-sm"
              onClick={() => setIsFullscreen(true)}
              title="Повноекранний режим"
            >
              <Maximize2 className="h-4 w-4" />
            </Button>
          </div>
        )}

        <div
          ref={containerRef}
          className="drakon-container rounded-lg border overflow-hidden"
          style={{ height, minHeight: 200 }}
        />
      </div>

      {/* Fullscreen Dialog */}
      <Dialog open={isFullscreen} onOpenChange={setIsFullscreen}>
        <DialogContent className="max-w-[95vw] w-[95vw] h-[90vh] p-0 gap-0">
          <DialogHeader className="p-4 pb-2 flex-row items-center justify-between space-y-0">
            <DialogTitle className="text-lg">
              {diagram.name || 'DRAKON діаграма'}
            </DialogTitle>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={handleZoomOut}
                disabled={zoom <= MIN_ZOOM}
              >
                <ZoomOut className="h-4 w-4" />
              </Button>
              <span className="text-sm font-medium min-w-[50px] text-center">
                {zoomPercentage}%
              </span>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={handleZoomIn}
                disabled={zoom >= MAX_ZOOM}
              >
                <ZoomIn className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={handleGoHome}
              >
                <Home className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={() => setIsFullscreen(false)}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          </DialogHeader>
          <div 
            ref={fullscreenContainerRef}
            className="flex-1 drakon-container overflow-hidden"
            style={{ height: 'calc(90vh - 60px)' }}
          />
        </DialogContent>
      </Dialog>
    </>
  );
}
