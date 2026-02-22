// Export Modal for AI context export with MCP Access Management

import { useState, useMemo } from 'react';
import { Download, Copy, Check, FileText, Folder, Link2, MessageSquare } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { toast } from 'sonner';
import { getAllNotes } from '@/lib/notes/noteLoader';
import { formatNotes, getFileExtension, type ExportFormat } from '@/lib/export/formatters';
import { useLocale } from '@/hooks/useLocale';
import { useMCPSessions } from '@/hooks/useMCPSessions';
import { MCPAccessPanel } from './MCPAccessPanel';
import { MCPEndpointList } from './MCPEndpointList';
import type { CommentExportOptions } from '@/lib/comments/types';

interface ExportModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ExportModal({ open, onOpenChange }: ExportModalProps) {
  const { t } = useLocale();
  const [format, setFormat] = useState<ExportFormat>('markdown');
  const [includeMetadata, setIncludeMetadata] = useState(true);
  const [includeContent, setIncludeContent] = useState(true);
  const [copied, setCopied] = useState(false);
  
  // Comments/Annotations export options
  const [commentOptions, setCommentOptions] = useState<CommentExportOptions>({
    includeApproved: true,
    includeMerged: true,
    includeAnnotations: true,
  });
  
  // MCP Sessions hook
  const {
    sessions,
    isCreating,
    creationError,
    createSession,
    revokeSession,
    copyEndpoint,
  } = useMCPSessions();
  
  // Get all notes and build folder structure
  const allNotes = useMemo(() => getAllNotes(), []);
  
  const folders = useMemo(() => {
    const folderMap = new Map<string, number>();
    
    for (const note of allNotes) {
      const decodedSlug = decodeURIComponent(note.slug);
      const parts = decodedSlug.split('/');
      
      if (parts.length > 1) {
        const folderPath = parts.slice(0, -1).join('/');
        folderMap.set(folderPath, (folderMap.get(folderPath) || 0) + 1);
      }
    }
    
    return Array.from(folderMap.entries())
      .map(([path, count]) => ({
        path,
        name: path.split('/').pop() || path,
        noteCount: count,
        selected: true,
      }))
      .sort((a, b) => a.path.localeCompare(b.path));
  }, [allNotes]);
  
  const [selectedFolders, setSelectedFolders] = useState<Set<string>>(
    new Set(folders.map(f => f.path))
  );
  
  // Filter notes based on selected folders
  const selectedNotes = useMemo(() => {
    return allNotes.filter(note => {
      const decodedSlug = decodeURIComponent(note.slug);
      const parts = decodedSlug.split('/');
      
      if (parts.length > 1) {
        const folderPath = parts.slice(0, -1).join('/');
        return selectedFolders.has(folderPath);
      }
      
      return selectedFolders.size === folders.length; // Include root notes if all folders selected
    });
  }, [allNotes, selectedFolders, folders.length]);
  
  // Generate export content
  const exportContent = useMemo(() => {
    return formatNotes(selectedNotes, format, { 
      includeMetadata, 
      includeContent,
      commentOptions: (commentOptions.includeApproved || commentOptions.includeMerged || commentOptions.includeAnnotations) 
        ? commentOptions 
        : undefined
    });
  }, [selectedNotes, format, includeMetadata, includeContent, commentOptions]);
  
  const handleFolderToggle = (folderPath: string) => {
    const newSelection = new Set(selectedFolders);
    if (newSelection.has(folderPath)) {
      newSelection.delete(folderPath);
    } else {
      newSelection.add(folderPath);
    }
    setSelectedFolders(newSelection);
  };
  
  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedFolders(new Set(folders.map(f => f.path)));
    } else {
      setSelectedFolders(new Set());
    }
  };
  
  const handleDownload = () => {
    if (selectedNotes.length === 0) {
      toast.error(t.export.selectAtLeastOne);
      return;
    }
    
    const blob = new Blob([exportContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `garden-export-${new Date().toISOString().split('T')[0]}.${getFileExtension(format)}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    toast.success(t.export.exportSuccess);
    onOpenChange(false);
  };
  
  const handleCopy = async () => {
    if (selectedNotes.length === 0) {
      toast.error(t.export.selectAtLeastOne);
      return;
    }
    
    try {
      await navigator.clipboard.writeText(exportContent);
      setCopied(true);
      toast.success(t.export.copySuccess);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      toast.error(t.export.copyError);
    }
  };
  
  const allSelected = selectedFolders.size === folders.length;
  
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="w-5 h-5 text-primary" />
            {t.export.title}
          </DialogTitle>
          <DialogDescription>
            {t.export.description}
          </DialogDescription>
        </DialogHeader>
        
        <Tabs defaultValue="settings" className="flex-1 flex flex-col overflow-hidden">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="settings">{t.export.settingsTab}</TabsTrigger>
            <TabsTrigger value="preview">{t.export.previewTab}</TabsTrigger>
            <TabsTrigger value="mcp" className="gap-1">
              <Link2 className="w-4 h-4" />
              MCP
            </TabsTrigger>
          </TabsList>
          
          {/* Settings Tab */}
          <TabsContent value="settings" className="flex-1 overflow-y-auto space-y-6 pr-2">
            {/* Folder Selection */}
            <div className="space-y-3">
              <h3 className="font-semibold text-sm">{t.export.folderSelection}</h3>
              
              <div className="flex items-center gap-2 p-2 bg-muted rounded-lg">
                <Checkbox
                  checked={allSelected}
                  onCheckedChange={(checked) => handleSelectAll(!!checked)}
                  id="select-all"
                />
                <label htmlFor="select-all" className="text-sm font-medium cursor-pointer">
                  {t.export.selectAll} ({folders.length} {t.export.folders})
                </label>
              </div>
              
              <div className="space-y-1 max-h-48 overflow-y-auto border rounded-lg p-2">
                {folders.map((folder) => (
                  <div key={folder.path} className="flex items-center gap-2 py-1.5 px-2 hover:bg-muted/50 rounded">
                    <Checkbox
                      checked={selectedFolders.has(folder.path)}
                      onCheckedChange={() => handleFolderToggle(folder.path)}
                      id={`folder-${folder.path}`}
                    />
                    <Folder className="w-4 h-4 text-primary" />
                    <label htmlFor={`folder-${folder.path}`} className="text-sm flex-1 cursor-pointer">
                      {folder.path}
                    </label>
                    <span className="text-xs text-muted-foreground">
                      ({folder.noteCount} {folder.noteCount === 1 ? t.common.note : t.common.notes})
                    </span>
                  </div>
                ))}
                
                {folders.length === 0 && (
                  <p className="text-sm text-muted-foreground py-4 text-center">
                    {t.export.noFolders}
                  </p>
                )}
              </div>
            </div>
            
            {/* Format Selection */}
            <div className="space-y-3">
              <h3 className="font-semibold text-sm">{t.export.formatSelection}</h3>
              
              <Select value={format} onValueChange={(v) => setFormat(v as ExportFormat)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="markdown">
                    <div className="flex flex-col items-start">
                      <span className="font-medium">{t.export.markdownFormat}</span>
                      <span className="text-xs text-muted-foreground">{t.export.markdownDescription}</span>
                    </div>
                  </SelectItem>
                  <SelectItem value="json">
                    <div className="flex flex-col items-start">
                      <span className="font-medium">{t.export.jsonFormat}</span>
                      <span className="text-xs text-muted-foreground">{t.export.jsonDescription}</span>
                    </div>
                  </SelectItem>
                  <SelectItem value="jsonl">
                    <div className="flex flex-col items-start">
                      <span className="font-medium">{t.export.jsonlFormat}</span>
                      <span className="text-xs text-muted-foreground">{t.export.jsonlDescription}</span>
                    </div>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            {/* Options */}
            <div className="space-y-3">
              <h3 className="font-semibold text-sm">{t.export.additionalOptions}</h3>
              
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={includeMetadata}
                    onCheckedChange={(checked) => setIncludeMetadata(!!checked)}
                    id="include-metadata"
                  />
                  <label htmlFor="include-metadata" className="text-sm cursor-pointer">
                    {t.export.includeMetadata}
                  </label>
                </div>
                
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={includeContent}
                    onCheckedChange={(checked) => setIncludeContent(!!checked)}
                    id="include-content"
                  />
                  <label htmlFor="include-content" className="text-sm cursor-pointer">
                    {t.export.includeContent}
                  </label>
                </div>
              </div>
            </div>
            
            {/* Comments & Annotations for AI */}
            <div className="space-y-3">
              <h3 className="font-semibold text-sm flex items-center gap-2">
                <MessageSquare className="w-4 h-4 text-primary" />
                Коментарі та анотації
              </h3>
              <p className="text-xs text-muted-foreground">
                Включити схвалені коментарі як додатковий контекст для AI-моделей
              </p>
              
              <div className="space-y-2 pl-1">
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={commentOptions.includeApproved}
                    onCheckedChange={(checked) => 
                      setCommentOptions(prev => ({ ...prev, includeApproved: !!checked }))
                    }
                    id="include-approved-comments"
                  />
                  <label htmlFor="include-approved-comments" className="text-sm cursor-pointer">
                    Схвалені коментарі
                  </label>
                </div>
                
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={commentOptions.includeMerged}
                    onCheckedChange={(checked) => 
                      setCommentOptions(prev => ({ ...prev, includeMerged: !!checked }))
                    }
                    id="include-merged-comments"
                  />
                  <label htmlFor="include-merged-comments" className="text-sm cursor-pointer">
                    Інтегровані в статтю (merged)
                  </label>
                </div>
                
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={commentOptions.includeAnnotations}
                    onCheckedChange={(checked) => 
                      setCommentOptions(prev => ({ ...prev, includeAnnotations: !!checked }))
                    }
                    id="include-annotations"
                  />
                  <label htmlFor="include-annotations" className="text-sm cursor-pointer">
                    Анотації (коментарі до фрагментів тексту)
                  </label>
                </div>
              </div>
            </div>
            
            {/* Export Stats */}
            <div className="p-3 bg-primary/10 rounded-lg border border-primary/20">
              <div className="flex items-center gap-2 text-sm">
                <FileText className="w-4 h-4 text-primary" />
                <span className="text-foreground">
                  <strong>{t.export.willExport}</strong> {selectedNotes.length} {t.export.notesFrom} {selectedFolders.size} {t.export.folders}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {t.export.approximateSize} ~{Math.round(exportContent.length / 1024)} KB
              </p>
            </div>
            
            {/* Action Buttons */}
            <div className="flex gap-2 justify-end pt-2 border-t">
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                {t.export.cancel}
              </Button>
              <Button
                variant="outline"
                onClick={handleCopy}
                disabled={selectedNotes.length === 0}
                className="gap-2"
              >
                {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                {copied ? t.export.copied : t.export.copy}
              </Button>
              <Button
                onClick={handleDownload}
                disabled={selectedNotes.length === 0}
                className="gap-2"
              >
                <Download className="w-4 h-4" />
                {t.export.download}
              </Button>
            </div>
          </TabsContent>
          
          {/* Preview Tab */}
          <TabsContent value="preview" className="flex-1 overflow-hidden flex flex-col">
            <div className="flex-1 overflow-y-auto bg-muted rounded-lg border p-4">
              <pre className="text-xs whitespace-pre-wrap break-words font-mono text-foreground">
                {selectedNotes.length > 0 
                  ? exportContent.slice(0, 2000) + (exportContent.length > 2000 ? '\n\n' + t.export.truncatedPreview : '')
                  : t.export.selectFoldersForExport
                }
              </pre>
            </div>
            
            <div className="flex gap-2 justify-end pt-4">
              <Button
                variant="outline"
                onClick={handleCopy}
                disabled={selectedNotes.length === 0}
                className="gap-2"
              >
                {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                {t.export.copyToClipboard}
              </Button>
            </div>
          </TabsContent>

          {/* MCP Access Tab */}
          <TabsContent value="mcp" className="flex-1 overflow-y-auto space-y-6 pr-2">
            {/* MCP Access Panel */}
            <MCPAccessPanel
              selectedFolders={Array.from(selectedFolders)}
              noteCount={selectedNotes.length}
              onCreateAccess={async (ttlMinutes) => {
                // Convert notes to MCP format
                const mcpNotes = selectedNotes.map(note => ({
                  slug: note.slug,
                  title: note.title,
                  tags: note.frontmatter.tags || [],
                  content: note.content || '',
                }));
                await createSession(Array.from(selectedFolders), ttlMinutes, mcpNotes);
              }}
              isCreating={isCreating}
              error={creationError}
            />
            
            {/* Separator */}
            <div className="border-t border-border" />
            
            {/* Active Sessions List */}
            <MCPEndpointList
              sessions={sessions}
              onDeleteSession={revokeSession}
              onCopyEndpoint={copyEndpoint}
            />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
