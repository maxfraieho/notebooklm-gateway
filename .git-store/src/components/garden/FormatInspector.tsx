// src/components/garden/FormatInspector.tsx

import { useState, useMemo, useCallback } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ChevronDown, Code, Copy, Check } from 'lucide-react';
import { cn } from '@/lib/utils';

// --- Schema: known style keys and their types ---

type FieldType = 'string' | 'number' | 'boolean' | 'color' | 'select';

interface FieldSchema {
  type: FieldType;
  label?: string;
  options?: string[]; // for select
  min?: number;
  max?: number;
  step?: number;
}

const KNOWN_FIELDS: Record<string, FieldSchema> = {
  background: { type: 'color', label: 'Background' },
  backText: { type: 'color', label: 'Back Text' },
  color: { type: 'color', label: 'Text Color' },
  lines: { type: 'color', label: 'Lines' },
  commentBack: { type: 'color', label: 'Comment Background' },
  iconBack: { type: 'color', label: 'Icon Background' },
  iconBorder: { type: 'color', label: 'Icon Border' },
  internalLine: { type: 'color', label: 'Internal Line' },
  candyBorder: { type: 'color', label: 'Candy Border' },
  candyFill: { type: 'color', label: 'Candy Fill' },
  shadowColor: { type: 'color', label: 'Shadow Color' },
  scrollBar: { type: 'color', label: 'Scrollbar' },
  scrollBarHover: { type: 'color', label: 'Scrollbar Hover' },
  borderWidth: { type: 'number', label: 'Border Width', min: 0, max: 20, step: 1 },
  lineWidth: { type: 'number', label: 'Line Width', min: 0, max: 20, step: 1 },
  shadowBlur: { type: 'number', label: 'Shadow Blur', min: 0, max: 50, step: 1 },
  padding: { type: 'number', label: 'Padding', min: 0, max: 100, step: 1 },
  margin: { type: 'number', label: 'Margin', min: 0, max: 100, step: 1 },
  metre: { type: 'number', label: 'Metre', min: 0, max: 200, step: 1 },
  lineHeight: { type: 'number', label: 'Line Height', min: 0, max: 100, step: 1 },
  iconRadius: { type: 'number', label: 'Icon Radius', min: 0, max: 100, step: 1 },
  lineRadius: { type: 'number', label: 'Line Radius', min: 0, max: 100, step: 1 },
  maxWidth: { type: 'number', label: 'Max Width', min: 0, step: 10 },
  minWidth: { type: 'number', label: 'Min Width', min: 0, step: 10 },
  maxHeight: { type: 'number', label: 'Max Height', min: 0, step: 10 },
  font: { type: 'string', label: 'Font' },
  headerFont: { type: 'string', label: 'Header Font' },
  branchFont: { type: 'string', label: 'Branch Font' },
  textFormat: { type: 'select', label: 'Text Format', options: ['plain', 'markdown', 'html'] },
};

// Infer type from key name and value
function inferFieldType(key: string, value: unknown): FieldType {
  const schema = KNOWN_FIELDS[key];
  if (schema) return schema.type;
  // Heuristic: keys ending in Color/color/Back/Fill → color
  if (/color|back|fill|border$/i.test(key) && typeof value === 'string') return 'color';
  if (typeof value === 'number') return 'number';
  if (typeof value === 'boolean') return 'boolean';
  return 'string';
}

// Validate a single field
function validateField(type: FieldType, value: unknown): string | null {
  if (value === '' || value === null || value === undefined) return null; // empty is ok
  if (type === 'number') {
    const n = Number(value);
    if (isNaN(n)) return 'Invalid number';
  }
  if (type === 'color' && typeof value === 'string' && value !== '') {
    // Accept: #RGB, #RRGGBB, #RRGGBBAA, rgba(...), rgb(...), named colors, transparent, empty
    if (!/^(#[0-9a-fA-F]{3,8}|rgba?\(.*\)|transparent|[a-zA-Z]+)$/.test(value.trim())) {
      return 'Invalid color (e.g. #FF0000, rgba(…), transparent)';
    }
  }
  return null;
}

// Coerce input to proper type
function coerceValue(type: FieldType, input: string): unknown {
  if (input === '') return '';
  switch (type) {
    case 'number': {
      const n = Number(input);
      return isNaN(n) ? input : n;
    }
    case 'boolean':
      return input === 'true' || (input as unknown) === true;
    default:
      return input;
  }
}

// --- Color Input with picker + text ---

function ColorInput({ value, onChange, error }: { value: string; onChange: (v: string) => void; error?: string | null }) {
  const safeColor = /^#[0-9a-fA-F]{6}$/.test(value) ? value : '#000000';
  return (
    <div className="flex items-center gap-2">
      <input
        type="color"
        value={safeColor}
        onChange={(e) => onChange(e.target.value)}
        className="h-8 w-8 rounded border border-input cursor-pointer shrink-0"
      />
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="#000000"
        className={cn("h-8 text-xs font-mono", error && "border-destructive")}
      />
    </div>
  );
}

// --- Row Component ---

interface FieldRowProps {
  fieldKey: string;
  value: unknown;
  onChange: (key: string, value: unknown) => void;
  isCustom: boolean;
}

function FieldRow({ fieldKey, value, onChange, isCustom }: FieldRowProps) {
  const type = inferFieldType(fieldKey, value);
  const schema = KNOWN_FIELDS[fieldKey];
  const label = schema?.label || fieldKey;
  const strValue = value === null || value === undefined ? '' : String(value);
  const error = validateField(type, value);

  return (
    <div className="grid grid-cols-[1fr_1.5fr] items-center gap-3 py-1.5 px-1">
      <div className="flex items-center gap-2 min-w-0">
        <Label className="text-xs font-mono truncate" title={fieldKey}>
          {label}
        </Label>
        {isCustom && (
          <Badge variant="outline" className="text-[10px] px-1 py-0 shrink-0">custom</Badge>
        )}
      </div>
      <div>
        {type === 'boolean' ? (
          <Switch
            checked={!!value}
            onCheckedChange={(checked) => onChange(fieldKey, checked)}
          />
        ) : type === 'color' ? (
          <ColorInput
            value={strValue}
            onChange={(v) => onChange(fieldKey, v)}
            error={error}
          />
        ) : type === 'select' && schema?.options ? (
          <Select value={strValue} onValueChange={(v) => onChange(fieldKey, v)}>
            <SelectTrigger className="h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {schema.options.map((opt) => (
                <SelectItem key={opt} value={opt}>{opt}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : type === 'number' ? (
          <Input
            type="number"
            value={strValue}
            onChange={(e) => onChange(fieldKey, coerceValue('number', e.target.value))}
            min={schema?.min}
            max={schema?.max}
            step={schema?.step}
            className={cn("h-8 text-xs font-mono", error && "border-destructive")}
          />
        ) : (
          <Input
            value={strValue}
            onChange={(e) => onChange(fieldKey, e.target.value)}
            className="h-8 text-xs"
          />
        )}
        {error && <p className="text-[10px] text-destructive mt-0.5">{error}</p>}
      </div>
    </div>
  );
}

// --- Main Component ---

export interface FormatInspectorProps {
  open: boolean;
  title: string;
  style: Record<string, unknown>;
  onConfirm: (updatedStyle: Record<string, unknown>) => void;
  onCancel: () => void;
}

export function FormatInspector({ open, title, style, onConfirm, onCancel }: FormatInspectorProps) {
  const [values, setValues] = useState<Record<string, unknown>>(() => ({ ...style }));
  const [showJson, setShowJson] = useState(false);
  const [copied, setCopied] = useState(false);

  // Reset when style changes (dialog opens with new data)
  const styleKey = JSON.stringify(style);
  useMemo(() => {
    setValues({ ...style });
  }, [styleKey]);

  const handleChange = useCallback((key: string, value: unknown) => {
    setValues(prev => ({ ...prev, [key]: value }));
  }, []);

  // Sorted keys: known first, then custom
  const sortedKeys = useMemo(() => {
    const keys = Object.keys(values);
    const known = keys.filter(k => k in KNOWN_FIELDS);
    const custom = keys.filter(k => !(k in KNOWN_FIELDS));
    return [...known, ...custom];
  }, [values]);

  // Validate all
  const hasErrors = useMemo(() => {
    return sortedKeys.some(key => {
      const type = inferFieldType(key, values[key]);
      return validateField(type, values[key]) !== null;
    });
  }, [sortedKeys, values]);

  const jsonOutput = useMemo(() => {
    // Clean empty strings
    const clean: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(values)) {
      if (v !== '' && v !== null && v !== undefined) {
        clean[k] = v;
      }
    }
    return JSON.stringify(clean, null, 2);
  }, [values]);

  const handleCopyJson = useCallback(() => {
    navigator.clipboard.writeText(jsonOutput);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [jsonOutput]);

  const handleSubmit = useCallback(() => {
    if (hasErrors) return;
    // Build clean result
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(values)) {
      if (v !== '' && v !== null && v !== undefined) {
        result[k] = v;
      }
    }
    onConfirm(result);
  }, [values, hasErrors, onConfirm]);

  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) onCancel(); }}>
      <DialogContent className="sm:max-w-lg max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>

        <ScrollArea className="flex-1 -mx-6 px-6">
          <div className="divide-y divide-border">
            {sortedKeys.map(key => (
              <FieldRow
                key={key}
                fieldKey={key}
                value={values[key]}
                onChange={handleChange}
                isCustom={!(key in KNOWN_FIELDS)}
              />
            ))}
            {sortedKeys.length === 0 && (
              <p className="text-sm text-muted-foreground py-4 text-center">No style properties</p>
            )}
          </div>
        </ScrollArea>

        {/* Advanced: JSON toggle */}
        <Collapsible open={showJson} onOpenChange={setShowJson}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" size="sm" className="w-full justify-between text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <Code className="h-3.5 w-3.5" />
                JSON
              </span>
              <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", showJson && "rotate-180")} />
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <div className="relative">
              <pre className="text-[11px] font-mono bg-muted rounded-md p-3 max-h-40 overflow-auto whitespace-pre-wrap">
                {jsonOutput}
              </pre>
              <Button
                variant="ghost"
                size="icon"
                className="absolute top-1 right-1 h-6 w-6"
                onClick={handleCopyJson}
              >
                {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
              </Button>
            </div>
          </CollapsibleContent>
        </Collapsible>

        {/* Actions */}
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" size="sm" onClick={onCancel}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSubmit} disabled={hasErrors}>
            OK
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
