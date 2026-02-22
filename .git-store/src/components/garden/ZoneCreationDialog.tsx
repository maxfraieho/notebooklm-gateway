// Zone Creation Dialog
// UI for creating delegated access zones with folder selection, TTL, and access type

import { useState, useMemo } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Checkbox } from '@/components/ui/checkbox';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { 
  Folder, 
  Clock, 
  Globe, 
  Link2, 
  Loader2,
  TriangleAlert,
  ChevronRight,
  ChevronDown,
  Lock,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { getFolderStructure, getAllNotes } from '@/lib/notes/noteLoader';
import { useLocale } from '@/hooks/useLocale';
import type { CreateZoneParams } from '@/hooks/useAccessZones';
import type { AccessType } from '@/types/mcpGateway';
import { getAuthStatus } from '@/lib/api/mcpGatewayClient';

interface ZoneCreationDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreateZone: (params: CreateZoneParams) => Promise<void>;
  isCreating: boolean;
}

const TTL_OPTIONS = [
  { value: 15, label: '15m' },
  { value: 60, label: '1h' },
  { value: 360, label: '6h' },
  { value: 1440, label: '24h' },
  { value: 10080, label: '7d' },
];

interface FolderItemProps {
  name: string;
  path: string;
  isSelected: boolean;
  onToggle: (path: string) => void;
  depth: number;
  hasChildren: boolean;
  isExpanded: boolean;
  onExpandToggle: () => void;
}

function FolderItem({ 
  name, 
  path, 
  isSelected, 
  onToggle, 
  depth, 
  hasChildren,
  isExpanded,
  onExpandToggle,
}: FolderItemProps) {
  return (
    <div 
      className={cn(
        "flex items-center gap-2 py-1.5 px-2 rounded hover:bg-muted/50 cursor-pointer",
        isSelected && "bg-primary/10"
      )}
      style={{ paddingLeft: `${depth * 16 + 8}px` }}
    >
      {hasChildren ? (
        <button 
          onClick={(e) => { e.stopPropagation(); onExpandToggle(); }}
          className="p-0.5 hover:bg-muted rounded"
        >
          {isExpanded ? (
            <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
          )}
        </button>
      ) : (
        <span className="w-4" />
      )}
      <Checkbox
        checked={isSelected}
        onCheckedChange={() => onToggle(path)}
        className="data-[state=checked]:bg-primary"
      />
      <Folder className="w-4 h-4 text-muted-foreground" />
      <span className="text-sm truncate">{name}</span>
    </div>
  );
}

export function ZoneCreationDialog({
  open,
  onOpenChange,
  onCreateZone,
  isCreating,
}: ZoneCreationDialogProps) {
  const { t } = useLocale();
  
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [selectedFolders, setSelectedFolders] = useState<Set<string>>(new Set());
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());
  const [accessType, setAccessType] = useState<AccessType>('both');
  const [selectedTTL, setSelectedTTL] = useState(1440); // Default 24h
  const [customTTL, setCustomTTL] = useState('');
  const [isCustomTTL, setIsCustomTTL] = useState(false);

  // Confidentiality consent - default ON
  const [consentRequired, setConsentRequired] = useState(true);

  const [createNotebookLM, setCreateNotebookLM] = useState(false);
  const [notebookTitle, setNotebookTitle] = useState('');
  const [notebookShareEmails, setNotebookShareEmails] = useState('');
  const [showAdvancedNotebook, setShowAdvancedNotebook] = useState(false);
  const [notebookSourceMode, setNotebookSourceMode] = useState<'minio' | 'url'>('minio');

  const [notebookHealthChecking, setNotebookHealthChecking] = useState(false);
  const [notebookHealthError, setNotebookHealthError] = useState<string | null>(null);

  const folders = useMemo(() => getFolderStructure(), []);
  const allNotes = useMemo(() => getAllNotes(), []);

  // Count notes in selected folders
  const noteCount = useMemo(() => {
    if (selectedFolders.size === 0) return 0;
    
    const folderArr = Array.from(selectedFolders);
    return allNotes.filter(note => {
      const decodedSlug = decodeURIComponent(note.slug);
      return folderArr.some(folder => 
        decodedSlug.startsWith(folder + '/') || decodedSlug === folder
      );
    }).length;
  }, [selectedFolders, allNotes]);

  // Get notes for export
  const getNotesForExport = () => {
    if (selectedFolders.size === 0) return [];
    
    const folderArr = Array.from(selectedFolders);
    console.log('[ZoneCreation] selectedFolders:', folderArr);
    console.log('[ZoneCreation] total allNotes:', allNotes.length);
    
    const filtered = allNotes
      .filter(note => {
        const decodedSlug = decodeURIComponent(note.slug);
        return folderArr.some(folder => 
          decodedSlug.startsWith(folder + '/') || decodedSlug === folder
        );
      });
    
    console.log('[ZoneCreation] filtered notes for export:', filtered.length);
    if (filtered.length < allNotes.length) {
      const excluded = allNotes.filter(n => !filtered.includes(n));
      console.log('[ZoneCreation] excluded notes (first 5):', excluded.slice(0, 5).map(n => decodeURIComponent(n.slug)));
    }
    
    return filtered.map(note => ({
        slug: note.slug,
        title: note.title,
        content: note.content,
        tags: (note.frontmatter?.tags as string[]) || [],
      }));
  };

  const toggleFolder = (path: string) => {
    setSelectedFolders(prev => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  const toggleExpand = (path: string) => {
    setExpandedFolders(prev => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  const selectAll = () => {
    const allPaths = new Set<string>();
    const collectPaths = (items: typeof folders) => {
      for (const item of items) {
        allPaths.add(item.path);
        if (item.subfolders.length > 0) {
          collectPaths(item.subfolders);
        }
      }
    };
    collectPaths(folders);
    setSelectedFolders(allPaths);
  };

  const clearAll = () => {
    setSelectedFolders(new Set());
  };

  const effectiveTTL = isCustomTTL ? parseInt(customTTL) : selectedTTL;
  const isValidTTL = !isNaN(effectiveTTL) && effectiveTTL >= 5 && effectiveTTL <= 10080;
  const canCreate =
    name.trim().length > 0 &&
    selectedFolders.size > 0 &&
    isValidTTL &&
    !isCreating &&
    !notebookHealthChecking;

  const handleCreate = async () => {
    if (!canCreate) return;

    setNotebookHealthError(null);

    // Pre-check NotebookLM backend health BEFORE starting the import flow.
    // If health is not OK or authenticated!==true, do not create zone with NotebookLM.
    if (createNotebookLM) {
      setNotebookHealthChecking(true);
      try {
        const MAX_RETRIES = 3;
        const BASE_DELAY = 2000;

        const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
        const fetchWithRetry = async (attempt = 0): Promise<any> => {
          try {
            return await getAuthStatus();
          } catch (e: any) {
            const status = e?.httpStatus ?? e?.status;
            const isTransient = status === 502 || status === 504;
            if (isTransient && attempt < MAX_RETRIES - 1) {
              await sleep(BASE_DELAY * (attempt + 1));
              return fetchWithRetry(attempt + 1);
            }
            throw e;
          }
        };

        const authStatus = await fetchWithRetry();
        const isNotebookLMReady = authStatus?.notebookLMReady === true;
        if (!isNotebookLMReady) {
          setNotebookHealthError(
            [
              'NotebookLM сервіс не авторизовано або не готовий.',
              'Зверніться до адміністратора для завершення налаштування.',
              authStatus?.notebookLMMessage ? `\n${authStatus.notebookLMMessage}` : null,
            ]
              .filter(Boolean)
              .join('\n')
          );
          return;
        }
      } catch (e: any) {
        setNotebookHealthError(
          'NotebookLM сервіс не авторизовано або не готовий.\nЗверніться до адміністратора для завершення налаштування.'
        );
        return;
      } finally {
        setNotebookHealthChecking(false);
      }
    }

    const emails = notebookShareEmails
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);

    await onCreateZone({
      name: name.trim(),
      description: description.trim() || undefined,
      folders: Array.from(selectedFolders),
      noteCount,
      accessType,
      ttlMinutes: effectiveTTL,
      notes: getNotesForExport(),
      createNotebookLM,
      notebookTitle: notebookTitle.trim() || undefined,
      notebookShareEmails: createNotebookLM ? (emails.length ? emails : undefined) : undefined,
      notebookSourceMode: createNotebookLM ? notebookSourceMode : undefined,
      consentRequired,
    });

    // Reset form
    setName('');
    setDescription('');
    setSelectedFolders(new Set());
    setAccessType('both');
    setSelectedTTL(1440);
    setIsCustomTTL(false);
    setCustomTTL('');
    setConsentRequired(true);

    setCreateNotebookLM(false);
    setNotebookTitle('');
    setNotebookShareEmails('');
    setShowAdvancedNotebook(false);
    setNotebookSourceMode('minio');
  };

  const renderFolders = (items: typeof folders, depth = 0) => {
    return items.map(folder => (
      <div key={folder.path}>
        <FolderItem
          name={folder.name}
          path={folder.path}
          isSelected={selectedFolders.has(folder.path)}
          onToggle={toggleFolder}
          depth={depth}
          hasChildren={folder.subfolders.length > 0}
          isExpanded={expandedFolders.has(folder.path)}
          onExpandToggle={() => toggleExpand(folder.path)}
        />
        {folder.subfolders.length > 0 && expandedFolders.has(folder.path) && (
          renderFolders(folder.subfolders, depth + 1)
        )}
      </div>
    ));
  };

  const accessTypes = [
    { value: 'web' as AccessType, icon: Globe, label: t.zones.webOnly },
    { value: 'mcp' as AccessType, icon: Link2, label: t.zones.mcpOnly },
    { value: 'both' as AccessType, icon: Link2, label: t.zones.webAndMcp },
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Link2 className="w-5 h-5" />
            {t.zones.createTitle}
          </DialogTitle>
          <DialogDescription>
            {t.zones.createDescription}
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-6 py-4">
          {/* Name & Description */}
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="zone-name">{t.zones.zoneName}</Label>
              <Input
                id="zone-name"
                placeholder={t.zones.zoneNamePlaceholder}
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={50}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="zone-desc">{t.zones.zoneDescription}</Label>
              <Textarea
                id="zone-desc"
                placeholder={t.zones.zoneDescriptionPlaceholder}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={200}
                rows={2}
              />
            </div>
          </div>

          {/* Folder Selection */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>{t.zones.folderSelection}</Label>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" onClick={selectAll}>
                  {t.export.selectAll}
                </Button>
                <Button variant="ghost" size="sm" onClick={clearAll}>
                  {t.zones.clearAll}
                </Button>
              </div>
            </div>
            <ScrollArea className="h-48 border rounded-md">
              <div className="p-2">
                {folders.length > 0 ? (
                  renderFolders(folders)
                ) : (
                  <p className="text-sm text-muted-foreground text-center py-4">
                    {t.export.noFolders}
                  </p>
                )}
              </div>
            </ScrollArea>
            <p className="text-sm text-muted-foreground">
              📁 {selectedFolders.size} {t.export.folders} · 📝 {noteCount} {t.common.notes}
            </p>
          </div>

          {/* Access Type */}
          <div className="space-y-2">
            <Label>{t.zones.accessType}</Label>
            <div className="grid grid-cols-3 gap-2">
              {accessTypes.map(type => (
                <button
                  key={type.value}
                  onClick={() => setAccessType(type.value)}
                  className={cn(
                    "flex flex-col items-center gap-1 p-3 rounded-lg border transition-colors",
                    accessType === type.value
                      ? "border-primary bg-primary/10"
                      : "border-border hover:border-muted-foreground/50"
                  )}
                >
                  <type.icon className={cn(
                    "w-5 h-5",
                    accessType === type.value ? "text-primary" : "text-muted-foreground"
                  )} />
                  <span className="text-xs font-medium">{type.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* TTL Selection */}
          <div className="space-y-2">
            <Label className="flex items-center gap-2">
              <Clock className="w-4 h-4" />
              {t.zones.timeToLive}
            </Label>
            <div className="flex flex-wrap gap-2">
              {TTL_OPTIONS.map(option => (
                <Button
                  key={option.value}
                  variant={!isCustomTTL && selectedTTL === option.value ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => {
                    setSelectedTTL(option.value);
                    setIsCustomTTL(false);
                  }}
                >
                  {option.label}
                </Button>
              ))}
              <Button
                variant={isCustomTTL ? 'default' : 'outline'}
                size="sm"
                onClick={() => setIsCustomTTL(true)}
              >
                {t.zones.custom}
              </Button>
            </div>
            {isCustomTTL && (
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min={5}
                  max={10080}
                  placeholder={t.zones.customMinutes}
                  value={customTTL}
                  onChange={(e) => setCustomTTL(e.target.value)}
                  className="w-32"
                />
                <span className="text-sm text-muted-foreground">{t.zones.minutes}</span>
              </div>
            )}
          </div>

          {/* Confidentiality Settings */}
          <div className="space-y-3">
            <Label className="flex items-center gap-2">
              <Lock className="w-4 h-4" />
              {t.zones.confidentialitySettings}
            </Label>
            <div className="flex items-center gap-3 p-3 rounded-lg border border-border bg-muted/30">
              <Checkbox
                id="consent-required"
                checked={consentRequired}
                onCheckedChange={(v) => setConsentRequired(Boolean(v))}
                className="data-[state=checked]:bg-primary"
              />
              <div className="flex-1 space-y-0.5">
                <Label htmlFor="consent-required" className="text-sm font-medium cursor-pointer">
                  {t.zones.requireConsent}
                </Label>
                <p className="text-xs text-muted-foreground">
                  {t.zones.requireConsentDesc}
                </p>
              </div>
              <span className={cn(
                "text-xs font-medium px-2 py-0.5 rounded",
                consentRequired 
                  ? "bg-destructive/10 text-destructive" 
                  : "bg-green-500/10 text-green-600"
              )}>
                {consentRequired ? t.zones.confidentialZone : t.zones.publicZone}
              </span>
            </div>
          </div>

          {/* NotebookLM (optional) */}
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <Checkbox
                checked={createNotebookLM}
                onCheckedChange={(v) => setCreateNotebookLM(Boolean(v))}
                className="data-[state=checked]:bg-primary"
              />
              <div className="space-y-0.5">
                <p className="text-sm font-medium">Create NotebookLM</p>
                <p className="text-xs text-muted-foreground">
                  Optional: create a Google NotebookLM and import selected sources.
                </p>
              </div>
            </div>

            {createNotebookLM && (
              <div className="space-y-3 rounded-lg border border-border p-3">
                {notebookHealthError && (
                  <Alert>
                    <TriangleAlert className="h-4 w-4" />
                    <AlertTitle>NotebookLM</AlertTitle>
                    <AlertDescription>
                      <p className="whitespace-pre-line">{notebookHealthError}</p>
                      <p className="mt-2">
                        <a href="/admin/diagnostics" className="underline">
                          Перейти до діагностики
                        </a>
                      </p>
                    </AlertDescription>
                  </Alert>
                )}

                <div className="space-y-2">
                  <Label htmlFor="notebook-title">Notebook title (optional)</Label>
                  <Input
                    id="notebook-title"
                    value={notebookTitle}
                    onChange={(e) => setNotebookTitle(e.target.value)}
                    placeholder="e.g. Research pack"
                    maxLength={80}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="notebook-emails">Share emails (optional)</Label>
                  <Input
                    id="notebook-emails"
                    value={notebookShareEmails}
                    onChange={(e) => setNotebookShareEmails(e.target.value)}
                    placeholder="email1@domain.com, email2@domain.com"
                  />
                  <p className="text-xs text-muted-foreground">Comma-separated. Will be sent to the Worker.</p>
                </div>

                <button
                  type="button"
                  className="text-sm text-primary hover:underline"
                  onClick={() => setShowAdvancedNotebook(v => !v)}
                >
                  {showAdvancedNotebook ? 'Hide advanced' : 'Advanced'}
                </button>

                {showAdvancedNotebook && (
                  <div className="space-y-2">
                    <Label>Source mode</Label>
                    <div className="flex gap-2">
                      <Button
                        type="button"
                        size="sm"
                        variant={notebookSourceMode === 'minio' ? 'default' : 'outline'}
                        onClick={() => setNotebookSourceMode('minio')}
                      >
                        MinIO
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant={notebookSourceMode === 'url' ? 'default' : 'outline'}
                        onClick={() => setNotebookSourceMode('url')}
                      >
                        URL
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground">Advanced option; keep default unless required.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t.export.cancel}
          </Button>
          <Button onClick={handleCreate} disabled={!canCreate}>
            {isCreating ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                {t.zones.creating}
              </>
            ) : (
              <>
                <Link2 className="w-4 h-4 mr-2" />
                {t.zones.create}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
