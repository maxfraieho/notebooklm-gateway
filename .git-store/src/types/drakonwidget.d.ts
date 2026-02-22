// src/types/drakonwidget.d.ts

/**
 * TypeScript declarations for DrakonWidget
 * @see https://github.com/stepan-mitkin/drakonwidget
 */

export interface DrakonItem {
  type: string;
  content?: string;
  secondary?: string;
  link?: string;
  one?: string;
  two?: string;
  side?: string;
  flag1?: number;
  branchId?: number;
  margin?: number;
  style?: string;
}

export interface DrakonDiagram {
  name: string;
  access: 'read' | 'write';
  params?: string;
  style?: string;
  items: Record<string, DrakonItem>;
}

export interface DrakonConfigTheme {
  background?: string;
  backText?: string;
  borderWidth?: number;
  candyBorder?: string;
  candyFill?: string;
  color?: string;
  commentBack?: string;
  iconBack?: string;
  iconBorder?: string;
  icons?: Record<string, Partial<DrakonConfigTheme>>;
  internalLine?: string;
  lines?: string;
  lineWidth?: number;
  scrollBar?: string;
  scrollBarHover?: string;
  shadowBlur?: number;
  shadowColor?: string;
}

export interface DrakonMenuItem {
  hint?: string;
  text: string;
  action?: () => void;
  type?: 'separator';
  icon?: string;
}

export interface DrakonEditItem {
  id: string;
  type: string;
  content: string;
  secondary?: string;
  link?: string;
  left: number;
  top: number;
  width: number;
  height: number;
}

export interface DrakonSelectionItem {
  id: string;
  type: string;
  content: string;
  style?: Record<string, unknown>;
}

export interface DrakonConfig {
  startEditContent: (item: DrakonEditItem, isReadonly: boolean) => void;
  showContextMenu: (left: number, top: number, items: DrakonMenuItem[]) => void;
  startEditLink?: (item: DrakonEditItem, isReadonly: boolean) => void;
  startEditSecondary?: (item: DrakonEditItem, isReadonly: boolean) => void;
  startEditStyle?: (ids: string[], oldStyle: Record<string, unknown>, x: number, y: number, accepted: Record<string, boolean>) => void;
  startEditDiagramStyle?: (oldStyle: Record<string, unknown>, x: number, y: number) => void;
  onSelectionChanged?: (items: DrakonSelectionItem[] | null) => void;
  onZoomChanged?: (newZoomValue: number) => void;
  translate?: (text: string) => string;
  allowResize?: boolean;
  canSelect?: boolean;
  canvasIcons?: boolean;
  canvasLabels?: string;
  centerContent?: boolean;
  drawZones?: boolean;
  editorWatermark?: boolean;
  font?: string;
  headerFont?: string;
  branchFont?: string;
  iconRadius?: number;
  lineHeight?: number;
  lineRadius?: number;
  maxHeight?: number;
  maxWidth?: number;
  minWidth?: number;
  metre?: number;
  padding?: number;
  textFormat?: 'plain' | 'markdown' | 'html';
  theme?: DrakonConfigTheme;
  branch?: string;
  end?: string;
  exit?: string;
  yes?: string;
  no?: string;
  watermark?: string;
}

export interface DrakonEditChange {
  id?: string;
  op: 'insert' | 'update' | 'delete';
  fields?: Record<string, unknown>;
}

export interface DrakonEdit {
  id: string;
  changes: DrakonEditChange[];
}

export interface DrakonEditSender {
  pushEdit: (edit: DrakonEdit) => void;
  stop: () => void;
}

export interface DrakonWidget {
  render: (width: number, height: number, config: DrakonConfig) => HTMLElement;
  redraw: () => void;
  setDiagram: (diagramId: string, diagram: DrakonDiagram, editSender: DrakonEditSender) => Promise<string[]>;
  exportJson: () => string;
  exportCanvas: (zoom100: number) => HTMLCanvasElement;
  setContent: (itemId: string, content: string) => string[];
  setSecondary: (itemId: string, content: string) => string[];
  setStyle: (ids: string[], style: Record<string, unknown>) => string[];
  setLink: (itemId: string, link: string) => void;
  setDiagramStyle: (style: Record<string, unknown>) => string[];
  patchDiagramStyle: (style: Record<string, unknown>) => string[];
  setDiagramProperty: (name: string, value: string) => void;
  getDiagramProperties: () => Record<string, unknown>;
  setZoom: (zoomLevel: number) => void;
  getZoom: () => number;
  getVersion: () => string;
  getLoadedImages: () => Record<string, { content: string }>;
  goHome: () => void;
  showItem: (itemId: string) => void;
  insertIcon: (type: string) => void;
  showInsertionSockets: (type: string, imageData?: { id: string } | { content: string }) => void;
  showPaste: () => void;
  arrowUp: () => void;
  arrowDown: () => void;
  arrowLeft: () => void;
  arrowRight: () => void;
  copySelection: () => void;
  cutSelection: () => void;
  deleteSelection: () => void;
  editContent: () => void;
  swapYesNo: (id: string) => void;
  toggleSilhouette: () => void;
  undo: () => Promise<void>;
  redo: () => Promise<void>;
  onChange: (change: unknown) => void;
}

export type CreateDrakonWidgetFn = () => DrakonWidget;

declare global {
  interface Window {
    createDrakonWidget: CreateDrakonWidgetFn;
  }
}
