// src/lib/drakon/types.ts

import type { DrakonDiagram } from '@/types/drakonwidget';

// Re-export for convenience
export type { DrakonDiagram };

export interface StoredDrakonDiagram {
  version: '1.0';
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  diagram: DrakonDiagram;
}

export interface DrakonBlockParams {
  id: string;
  height?: number;
  mode?: 'view' | 'edit';
  theme?: string;
  zoom?: number;
}

/**
 * Parse :::drakon::: directive from markdown
 */
export function parseDrakonDirective(text: string): DrakonBlockParams | null {
  const match = text.match(
    /^:::drakon\s+((?:\w+="[^"]*"\s*)+):::$/
  );
  if (!match) return null;

  const params: Record<string, string> = {};
  const attrRegex = /(\w+)="([^"]*)"/g;
  let attrMatch: RegExpExecArray | null;
  while ((attrMatch = attrRegex.exec(match[1])) !== null) {
    params[attrMatch[1]] = attrMatch[2];
  }

  if (!params.id) return null;

  return {
    id: params.id,
    height: params.height ? parseInt(params.height, 10) : 400,
    mode: (params.mode as 'view' | 'edit') || 'view',
    theme: params.theme || 'auto',
    zoom: params.zoom ? parseInt(params.zoom, 10) : 10000,
  };
}
