 import { useState, useMemo } from 'react';
import { ChevronRight, ChevronDown, Folder, FolderOpen, Check, PanelLeftClose, PanelLeft, FileText } from 'lucide-react';
import { Link } from 'react-router-dom';
 import { getFolderStructure } from '@/lib/notes/noteLoader';
 import { useLocale } from '@/hooks/useLocale';
 import { Button } from '@/components/ui/button';
 import { ScrollArea } from '@/components/ui/scroll-area';
 import { cn } from '@/lib/utils';
 
 interface FolderInfo {
   name: string;
   path: string;
   notes: { slug: string; title: string; isHome: boolean }[];
   subfolders: FolderInfo[];
 }
 
 interface FolderItemProps {
   folder: FolderInfo;
   level: number;
   selectedFolder: string | null;
   onSelect: (path: string) => void;
   expandedFolders: Set<string>;
   onToggleExpand: (path: string) => void;
  currentSlug?: string;
 }
 
 function FolderItem({ 
   folder, 
   level, 
   selectedFolder, 
   onSelect,
   expandedFolders,
  onToggleExpand,
  currentSlug
 }: FolderItemProps) {
   const isExpanded = expandedFolders.has(folder.path);
   const isSelected = selectedFolder === folder.path;
  const hasChildren = folder.subfolders.length > 0 || folder.notes.length > 0;
   
   return (
     <div>
       <button
         onClick={() => onSelect(folder.path)}
         className={cn(
           "w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded-md transition-colors",
           "hover:bg-accent/50",
           isSelected && "bg-primary/10 text-primary font-medium"
         )}
         style={{ paddingLeft: `${8 + level * 16}px` }}
       >
         {/* Expand/collapse toggle */}
          {hasChildren ? (
            <span
              role="button"
              onClick={(e) => {
                e.stopPropagation();
                onToggleExpand(folder.path);
              }}
              className="p-0.5 hover:bg-accent rounded cursor-pointer"
            >
              {isExpanded ? (
                <ChevronDown className="h-3.5 w-3.5" />
              ) : (
                <ChevronRight className="h-3.5 w-3.5" />
              )}
            </span>
         ) : (
           <span className="w-4" />
         )}
         
         {isExpanded ? (
           <FolderOpen className="h-4 w-4 text-muted-foreground flex-shrink-0" />
         ) : (
           <Folder className="h-4 w-4 text-muted-foreground flex-shrink-0" />
         )}
         
         <span className="truncate flex-1 text-left">{folder.name}</span>
         
         {isSelected && (
           <Check className="h-3.5 w-3.5 text-primary flex-shrink-0" />
         )}
       </button>
       
       {/* Subfolders */}
       {isExpanded && hasChildren && (
         <div>
           {folder.subfolders.map((subfolder) => (
             <FolderItem
               key={subfolder.path}
               folder={subfolder}
               level={level + 1}
               selectedFolder={selectedFolder}
               onSelect={onSelect}
               expandedFolders={expandedFolders}
               onToggleExpand={onToggleExpand}
               currentSlug={currentSlug}
             />
           ))}
           
           {/* Notes in this folder */}
           {folder.notes.map((note) => (
             <Link
               key={note.slug}
               to={`/notes/${note.slug}/edit`}
               className={cn(
                 "w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded-md transition-colors",
                 "hover:bg-accent/50",
                 currentSlug === note.slug && "bg-primary/10 text-primary font-medium"
               )}
               style={{ paddingLeft: `${8 + (level + 1) * 16}px` }}
             >
               <span className="w-4" />
               <FileText className="h-4 w-4 text-muted-foreground flex-shrink-0" />
               <span className="truncate flex-1 text-left">{note.title}</span>
             </Link>
           ))}
         </div>
       )}
     </div>
   );
 }
 
 interface EditorFolderTreeProps {
   selectedFolder: string | null;
   onSelectFolder: (path: string | null) => void;
   isCollapsed: boolean;
   onToggleCollapse: () => void;
  currentSlug?: string;
 }
 
 export function EditorFolderTree({
   selectedFolder,
   onSelectFolder,
   isCollapsed,
   onToggleCollapse,
  currentSlug,
 }: EditorFolderTreeProps) {
   const { t } = useLocale();
   const folders = useMemo(() => getFolderStructure(), []);
   
   // Track expanded folders
   const [expandedFolders, setExpandedFolders] = useState<Set<string>>(() => {
     // Initially expand all folders
     const allPaths = new Set<string>();
     const collectPaths = (folderList: FolderInfo[]) => {
       for (const folder of folderList) {
         allPaths.add(folder.path);
         collectPaths(folder.subfolders);
       }
     };
     collectPaths(folders);
     return allPaths;
   });
   
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
   
   const expandAll = () => {
     const allPaths = new Set<string>();
     const collectPaths = (folderList: FolderInfo[]) => {
       for (const folder of folderList) {
         allPaths.add(folder.path);
         collectPaths(folder.subfolders);
       }
     };
     collectPaths(folders);
     setExpandedFolders(allPaths);
   };
   
   const collapseAll = () => {
     setExpandedFolders(new Set());
   };
   
   if (isCollapsed) {
     return (
       <div className="flex flex-col items-center py-2 border-r border-border bg-muted/30">
         <Button
           variant="ghost"
           size="icon"
           onClick={onToggleCollapse}
           className="h-8 w-8"
           title={t.editor?.showFolders || 'Show folders'}
         >
           <PanelLeft className="h-4 w-4" />
         </Button>
       </div>
     );
   }
   
   return (
     <div className="w-56 flex-shrink-0 border-r border-border bg-muted/30 flex flex-col">
       {/* Header */}
       <div className="p-2 border-b border-border flex items-center justify-between">
         <span className="text-sm font-medium text-muted-foreground">
           {t.editor?.saveLocation || 'Save to folder'}
         </span>
         <Button
           variant="ghost"
           size="icon"
           onClick={onToggleCollapse}
           className="h-7 w-7"
           title={t.editor?.hideFolders || 'Hide folders'}
         >
           <PanelLeftClose className="h-4 w-4" />
         </Button>
       </div>
       
       {/* Expand/Collapse all */}
       <div className="px-2 py-1.5 border-b border-border flex gap-1">
         <Button
           variant="ghost"
           size="sm"
           onClick={expandAll}
           className="h-6 px-2 text-xs flex-1"
         >
           {t.editor?.expandAll || 'Expand'}
         </Button>
         <Button
           variant="ghost"
           size="sm"
           onClick={collapseAll}
           className="h-6 px-2 text-xs flex-1"
         >
           {t.editor?.collapseAll || 'Collapse'}
         </Button>
       </div>
       
       {/* Root option */}
       <button
         onClick={() => onSelectFolder(null)}
         className={cn(
           "w-full flex items-center gap-2 px-3 py-2 text-sm transition-colors",
           "hover:bg-accent/50 border-b border-border/50",
           selectedFolder === null && "bg-primary/10 text-primary font-medium"
         )}
       >
         <Folder className="h-4 w-4 text-muted-foreground" />
         <span className="flex-1 text-left">{t.editor?.rootFolder || 'Root'}</span>
         {selectedFolder === null && (
           <Check className="h-3.5 w-3.5 text-primary" />
         )}
       </button>
       
       {/* Folder tree */}
       <ScrollArea className="flex-1">
         <div className="py-1">
           {folders.map((folder) => (
             <FolderItem
               key={folder.path}
               folder={folder}
               level={0}
               selectedFolder={selectedFolder}
               onSelect={onSelectFolder}
               expandedFolders={expandedFolders}
               onToggleExpand={toggleExpand}
             />
           ))}
           
           {folders.length === 0 && (
             <p className="text-sm text-muted-foreground px-3 py-4 text-center">
               {t.editor?.noFolders || 'No folders yet'}
             </p>
           )}
         </div>
       </ScrollArea>
     </div>
   );
 }