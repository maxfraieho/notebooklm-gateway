// Full-screen file/folder structure view
import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronRight, ChevronDown, FileText, Folder, Home, FolderTree, Download, Plus, FilePlus, Pencil, GitBranch } from 'lucide-react';
import { getFolderStructure, getHomeNote } from '@/lib/notes/noteLoader';
import { GardenHeader } from '@/components/garden/GardenHeader';
import { GardenFooter } from '@/components/garden/GardenFooter';
import { ExportModal } from '@/components/garden/ExportModal';
import { Button } from '@/components/ui/button';
import { useLocale } from '@/hooks/useLocale';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { cn } from '@/lib/utils';

interface FolderInfo {
  name: string;
  path: string;
  notes: { slug: string; title: string; isHome: boolean }[];
  subfolders: FolderInfo[];
}

interface FolderItemProps {
  folder: FolderInfo;
  level?: number;
  isAuthenticated?: boolean;
}

function FolderItem({ folder, level = 0, isAuthenticated = false }: FolderItemProps) {
  const [isOpen, setIsOpen] = useState(true);
  const location = useLocation();
  const { t } = useLocale();
  
  const hasContent = folder.notes.length > 0 || folder.subfolders.length > 0;
  
  return (
    <div className="w-full">
      <div className="group flex items-center">
        <button
          onClick={() => setIsOpen(!isOpen)}
          className={cn(
            "flex-1 flex items-center gap-3 px-4 py-3 text-base hover:bg-accent/50 rounded-lg transition-colors",
            "font-medium text-foreground"
          )}
          style={{ paddingLeft: `${16 + level * 24}px` }}
        >
          {hasContent ? (
            isOpen ? (
              <ChevronDown className="w-5 h-5 text-muted-foreground flex-shrink-0" />
            ) : (
              <ChevronRight className="w-5 h-5 text-muted-foreground flex-shrink-0" />
            )
          ) : (
            <span className="w-5" />
          )}
          <Folder className="w-5 h-5 text-primary flex-shrink-0" />
          <span className="text-left">{folder.name}</span>
        </button>
        
        {/* Add note / DRAKON buttons - visible on hover */}
        {isAuthenticated && (
          <div className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 mr-2">
            <Link
              to={`/notes/new?folder=${encodeURIComponent(folder.path)}`}
              className="p-2 rounded-md hover:bg-primary/10 text-muted-foreground hover:text-primary"
              title={t.editor?.newNoteHere || 'New note here'}
            >
              <FilePlus className="w-4 h-4" />
            </Link>
            <Link
              to={`/drakon?new=true&folder=${encodeURIComponent(folder.path)}`}
              className="p-2 rounded-md hover:bg-primary/10 text-muted-foreground hover:text-primary"
              title={t.drakonEditor?.newDrakonHere || 'New DRAKON here'}
            >
              <GitBranch className="w-4 h-4" />
            </Link>
          </div>
        )}
      </div>
      
      {isOpen && hasContent && (
        <div className="mt-1">
          {/* Subfolders */}
          {folder.subfolders.map((subfolder) => (
            <FolderItem 
              key={subfolder.path} 
              folder={subfolder} 
              level={level + 1}
              isAuthenticated={isAuthenticated}
            />
          ))}
          
          {/* Notes */}
          {folder.notes.map((note) => {
            const isActive = location.pathname === `/notes/${note.slug}`;
            
            return (
              <div
                key={note.slug}
                className={cn(
                  "group flex items-center gap-3 px-4 py-3 text-base rounded-lg transition-colors",
                  isActive
                    ? "bg-primary/10 text-primary font-medium"
                    : "hover:bg-accent/50"
                )}
                style={{ paddingLeft: `${40 + level * 24}px` }}
              >
                <Link
                  to={note.isHome ? '/' : `/notes/${note.slug}`}
                  className={cn(
                    "flex-1 flex items-center gap-3",
                    isActive ? "" : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  {note.isHome ? (
                    <Home className="w-5 h-5 flex-shrink-0" />
                  ) : (
                    <FileText className="w-5 h-5 flex-shrink-0" />
                  )}
                  <span className="text-left">{note.title}</span>
                </Link>
                
                {/* Edit button - visible on hover */}
                {isAuthenticated && (
                  <Link
                    to={`/notes/${note.slug}/edit`}
                    className={cn(
                      "opacity-0 group-hover:opacity-100 transition-opacity",
                      "p-1.5 rounded-md hover:bg-primary/10 text-muted-foreground hover:text-primary"
                    )}
                    title={t.common?.edit || 'Edit'}
                  >
                    <Pencil className="w-4 h-4" />
                  </Link>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function FilesPage() {
  const folders = getFolderStructure();
  const homeNote = getHomeNote();
  const { t } = useLocale();
  const location = useLocation();
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const { isAuthenticated } = useOwnerAuth();
  
  // Count total notes and folders
  const countItems = (folders: FolderInfo[]): { notes: number; folders: number } => {
    let notes = 0;
    let folderCount = 0;
    
    for (const folder of folders) {
      folderCount++;
      notes += folder.notes.length;
      const sub = countItems(folder.subfolders);
      notes += sub.notes;
      folderCount += sub.folders;
    }
    
    return { notes, folders: folderCount };
  };
  
  const counts = countItems(folders);
  
  return (
    <div className="min-h-screen flex flex-col bg-background">
      <GardenHeader />
      
      <main className="flex-1 max-w-4xl mx-auto w-full px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between gap-3 mb-2">
            <div className="flex items-center gap-3">
              <FolderTree className="w-8 h-8 text-primary" />
              <h1 className="text-3xl font-semibold text-foreground font-serif">
                {t.sidebar.fileStructure || 'File Structure'}
              </h1>
            </div>
            <div className="flex gap-2">
              {isAuthenticated && (
                <Button asChild variant="default" size="sm" className="gap-2">
                  <Link to="/notes/new">
                    <Plus className="w-4 h-4" />
                    <span className="hidden sm:inline">{t.editor?.newNote || 'New Note'}</span>
                  </Link>
                </Button>
              )}
              <Button
                onClick={() => setExportModalOpen(true)}
                variant="outline"
                size="sm"
                className="gap-2"
              >
                <Download className="w-4 h-4" />
                <span className="hidden sm:inline">Export</span>
              </Button>
            </div>
          </div>
          <p className="text-muted-foreground">
            {counts.folders} {counts.folders === 1 ? 'folder' : 'folders'}, {counts.notes} {counts.notes === 1 ? 'note' : 'notes'}
          </p>
        </div>
        
        <ExportModal open={exportModalOpen} onOpenChange={setExportModalOpen} />
        
        {/* Tree structure */}
        <div className="bg-card rounded-xl border border-border p-4 shadow-sm">
          {/* Home link if exists */}
          {homeNote && (
            <Link
              to="/"
              className={cn(
                "flex items-center gap-3 px-4 py-3 text-base rounded-lg transition-colors mb-2",
                location.pathname === '/'
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
              )}
            >
              <Home className="w-5 h-5 flex-shrink-0" />
              <span>{t.sidebar.home}</span>
            </Link>
          )}
          
          {/* Folder structure */}
          {folders.map((folder) => (
          <FolderItem 
            key={folder.path} 
            folder={folder}
            isAuthenticated={isAuthenticated}
          />
          ))}
          
          {folders.length === 0 && (
            <div className="text-center py-12">
              <FolderTree className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-50" />
              <p className="text-muted-foreground">No files found</p>
            </div>
          )}
        </div>
      </main>
      
      <GardenFooter />
    </div>
  );
}
