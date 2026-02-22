 import { useState, useRef, useCallback, useEffect, useMemo } from 'react';
 import { NoteRenderer } from './NoteRenderer';
 import { EditorToolbar } from './EditorToolbar';
 import { TagEditor } from './TagEditor';
 import { WikilinkAutocomplete } from './WikilinkAutocomplete';
 import { useWikilinkDetection } from '@/hooks/useWikilinkSuggestions';
 import type { WikilinkSuggestion } from '@/hooks/useWikilinkSuggestions';
 import { useLocale } from '@/hooks/useLocale';
 import { Input } from '@/components/ui/input';
 import { Textarea } from '@/components/ui/textarea';
 import { Button } from '@/components/ui/button';
 import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
 import { ScrollArea } from '@/components/ui/scroll-area';
 import { Card } from '@/components/ui/card';
 import { Alert, AlertDescription } from '@/components/ui/alert';
 import { 
   Save, 
   X, 
   FileText, 
   Eye, 
   AlertCircle, 
   RotateCcw, 
   Trash2,
   Folder
 } from 'lucide-react';
 import { cn } from '@/lib/utils';
 
 interface NoteEditorProps {
   title: string;
   content: string;
   tags: string[];
   isDirty: boolean;
   isSaving: boolean;
   hasDraft: boolean;
   selectedFolder?: string | null;
   onTitleChange: (title: string) => void;
   onContentChange: (content: string) => void;
   onTagsChange: (tags: string[]) => void;
   onFolderChange?: (folder: string | null) => void;
   onSave: () => void;
   onCancel?: () => void;
   onRestoreDraft?: () => void;
   onDiscardDraft?: () => void;
   insertAtCursor: (
     ref: React.RefObject<HTMLTextAreaElement>,
     before: string,
     after?: string
   ) => void;
 }
 
 export function NoteEditor({
   title,
   content,
   tags,
   isDirty,
   isSaving,
   hasDraft,
   selectedFolder,
   onTitleChange,
   onContentChange,
   onTagsChange,
   onFolderChange,
   onSave,
   onCancel,
   onRestoreDraft,
   onDiscardDraft,
   insertAtCursor,
 }: NoteEditorProps) {
   const { t } = useLocale();
   const textareaRef = useRef<HTMLTextAreaElement>(null);
   const [cursorPosition, setCursorPosition] = useState(0);
   const [activeTab, setActiveTab] = useState<'edit' | 'preview'>('edit');
 
   // Wikilink autocomplete detection
   const wikilinkState = useWikilinkDetection(content, cursorPosition);
 
   // Handle textarea cursor changes
   const handleTextareaChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
     onContentChange(e.target.value);
     setCursorPosition(e.target.selectionStart);
   }, [onContentChange]);
 
   const handleTextareaSelect = useCallback((e: React.SyntheticEvent<HTMLTextAreaElement>) => {
     const target = e.target as HTMLTextAreaElement;
     setCursorPosition(target.selectionStart);
   }, []);
 
   // Handle wikilink selection
   const handleWikilinkSelect = useCallback((suggestion: WikilinkSuggestion) => {
     if (!wikilinkState.isActive) return;
 
     const beforeWikilink = content.substring(0, wikilinkState.startIndex);
     const afterCursor = content.substring(cursorPosition);
     
     // Insert [[title]] format
     const newContent = `${beforeWikilink}[[${suggestion.title}]]${afterCursor}`;
     onContentChange(newContent);
     
     // Move cursor after the inserted wikilink
     const newCursorPos = wikilinkState.startIndex + suggestion.title.length + 4;
     requestAnimationFrame(() => {
       if (textareaRef.current) {
         textareaRef.current.focus();
         textareaRef.current.setSelectionRange(newCursorPos, newCursorPos);
         setCursorPosition(newCursorPos);
       }
     });
   }, [content, cursorPosition, wikilinkState, onContentChange]);
 
   // Toolbar formatting
   const handleFormat = useCallback((before: string, after: string = '') => {
     insertAtCursor(textareaRef, before, after);
   }, [insertAtCursor]);
 
   // Insert wikilink placeholder
   const handleInsertWikilink = useCallback(() => {
     insertAtCursor(textareaRef, '[[', ']]');
   }, [insertAtCursor]);
 
   // Keyboard shortcuts (Notemod-style)
   useEffect(() => {
     const handleKeyDown = (e: KeyboardEvent) => {
       // Ctrl/Cmd + S = Save
       if ((e.ctrlKey || e.metaKey) && e.key === 's') {
         e.preventDefault();
         if (!isSaving) onSave();
       }
       // Ctrl/Cmd + B = Bold
       if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
         e.preventDefault();
         handleFormat('**', '**');
       }
       // Ctrl/Cmd + I = Italic
       if ((e.ctrlKey || e.metaKey) && e.key === 'i') {
         e.preventDefault();
         handleFormat('*', '*');
       }
       // Ctrl/Cmd + K = Link
       if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
         e.preventDefault();
         handleFormat('[', '](url)');
       }
       // Ctrl/Cmd + 1/2/3 = Headings
       if ((e.ctrlKey || e.metaKey) && e.key === '1') {
         e.preventDefault();
         handleFormat('# ', '');
       }
       if ((e.ctrlKey || e.metaKey) && e.key === '2') {
         e.preventDefault();
         handleFormat('## ', '');
       }
       if ((e.ctrlKey || e.metaKey) && e.key === '3') {
         e.preventDefault();
         handleFormat('### ', '');
       }
       // Escape = toggle preview
       if (e.key === 'Escape' && activeTab === 'preview') {
         setActiveTab('edit');
       }
     };
 
     document.addEventListener('keydown', handleKeyDown);
     return () => document.removeEventListener('keydown', handleKeyDown);
   }, [isSaving, onSave, handleFormat, activeTab, setActiveTab]);
 
   // Create a mock note object for preview
   const previewNote = {
     slug: 'preview',
     title,
     content,
     frontmatter: { tags },
     rawContent: content,
   };
 
    // Editor textarea - rendered inline to avoid remount on each keystroke
 
   // Preview panel component
   const PreviewPanel = ({ className = '' }: { className?: string }) => (
     <ScrollArea className={cn("h-full", className)}>
       <article className="prose prose-slate dark:prose-invert max-w-none p-4">
         <NoteRenderer note={previewNote} />
       </article>
     </ScrollArea>
   );
   
   // Folder display name
   const folderDisplayName = useMemo(() => {
     if (!selectedFolder) return t.editor?.rootFolder || 'Root';
     const parts = selectedFolder.split('/');
     return parts[parts.length - 1];
   }, [selectedFolder, t]);
 
   return (
     <div className="flex flex-col h-full">
       {/* Draft restoration alert */}
       {hasDraft && (
         <Alert className="mb-3 border-primary/50 bg-primary/5">
           <AlertCircle className="h-4 w-4 text-primary" />
           <AlertDescription className="flex items-center justify-between flex-wrap gap-2">
             <span className="text-sm">{t.editor?.draftFound || 'Unsaved draft found'}</span>
             <div className="flex gap-2">
               <Button
                 variant="outline"
                 size="sm"
                 onClick={onRestoreDraft}
                 className="gap-1.5 h-7"
               >
                 <RotateCcw className="h-3 w-3" />
                 {t.editor?.restoreDraft || 'Restore'}
               </Button>
               <Button
                 variant="ghost"
                 size="sm"
                 onClick={onDiscardDraft}
                 className="gap-1.5 h-7 text-muted-foreground"
               >
                 <Trash2 className="h-3 w-3" />
                 {t.editor?.discardDraft || 'Discard'}
               </Button>
             </div>
           </AlertDescription>
         </Alert>
       )}
 
       {/* Title + folder info row */}
       <div className="mb-3 flex gap-3 items-start">
         <Input
           value={title}
           onChange={(e) => onTitleChange(e.target.value)}
           placeholder={t.editor?.titlePlaceholder || 'Note title...'}
           className={cn(
             "text-xl font-semibold h-11 px-3 flex-1",
             "border-border/50 focus-visible:border-primary",
             "bg-background"
           )}
           disabled={isSaving}
         />
         
         {/* Folder indicator (mobile) */}
         <div className="md:hidden flex items-center gap-1.5 h-11 px-3 bg-muted/50 rounded-md border border-border/50">
           <Folder className="h-4 w-4 text-muted-foreground" />
           <span className="text-sm text-muted-foreground truncate max-w-24">
             {folderDisplayName}
           </span>
         </div>
       </div>
 
       {/* Tabs: Edit / Preview - full width */}
       <Tabs 
         value={activeTab} 
         onValueChange={(v) => setActiveTab(v as 'edit' | 'preview')} 
         className="flex-1 min-h-0 flex flex-col"
       >
         <div className="flex items-center gap-2 mb-2">
           <TabsList className="h-9">
             <TabsTrigger value="edit" className="gap-1.5 text-sm px-4">
               <FileText className="h-3.5 w-3.5" />
               {t.editor?.edit || 'Edit'}
             </TabsTrigger>
             <TabsTrigger value="preview" className="gap-1.5 text-sm px-4">
               <Eye className="h-3.5 w-3.5" />
               {t.editor?.preview || 'Preview'}
             </TabsTrigger>
           </TabsList>
         </div>
         
         <TabsContent value="edit" className="flex-1 min-h-0 mt-0 data-[state=inactive]:hidden">
           <Card className="h-full flex flex-col overflow-hidden border-border/50">
             <EditorToolbar
               onFormat={handleFormat}
               onInsertWikilink={handleInsertWikilink}
               disabled={isSaving}
             />
              <div className="relative flex-1 min-h-0">
                <Textarea
                  ref={textareaRef}
                  value={content}
                  onChange={handleTextareaChange}
                  onSelect={handleTextareaSelect}
                  onClick={handleTextareaSelect}
                  onKeyUp={handleTextareaSelect}
                  placeholder={t.editor?.placeholder || 'Start writing...'}
                  className={cn(
                    "h-full w-full font-mono text-sm resize-none",
                    "border-0 rounded-none focus-visible:ring-0",
                    "bg-transparent"
                  )}
                  disabled={isSaving}
                />
                <WikilinkAutocomplete
                  query={wikilinkState.query}
                  isOpen={wikilinkState.isActive}
                  onSelect={handleWikilinkSelect}
                  onClose={() => setCursorPosition(0)}
                />
              </div>
           </Card>
         </TabsContent>
         
         <TabsContent value="preview" className="flex-1 min-h-0 mt-0 data-[state=inactive]:hidden">
           <Card className="h-full overflow-hidden border-border/50">
             <PreviewPanel />
           </Card>
         </TabsContent>
       </Tabs>
 
       {/* Tags editor */}
       <div className="mt-3 pt-3 border-t border-border/50">
         <label className="text-sm font-medium text-muted-foreground mb-2 block">
           {t.common?.tags || 'Tags'}
         </label>
         <TagEditor
           tags={tags}
           onChange={onTagsChange}
           placeholder={t.editor?.addTag || 'Add tag...'}
           disabled={isSaving}
         />
       </div>
 
       {/* Action buttons - Notemod style footer */}
       <div className="flex items-center justify-between mt-3 pt-3 border-t border-border/50">
         <div className="text-sm text-muted-foreground flex items-center gap-2">
           {isDirty && (
             <span className="flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-primary" />
               {t.editor?.unsavedChanges || 'Unsaved changes'}
             </span>
           )}
         </div>
         <div className="flex gap-2">
           {onCancel && (
             <Button
               variant="outline"
               onClick={onCancel}
               disabled={isSaving}
               className="gap-1.5"
               size="sm"
             >
               <X className="h-4 w-4" />
               {t.editor?.cancel || 'Cancel'}
             </Button>
           )}
           <Button
             onClick={onSave}
             disabled={isSaving || !title.trim()}
             className="gap-1.5"
             size="sm"
           >
             <Save className="h-4 w-4" />
             {isSaving ? (t.editor?.saving || 'Saving...') : (t.editor?.save || 'Save')}
           </Button>
         </div>
       </div>
     </div>
   );
 }