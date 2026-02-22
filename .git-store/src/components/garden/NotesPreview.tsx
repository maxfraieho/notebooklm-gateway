// Notes Preview Component
// Shows list of notes that will be included in a zone

import { useMemo } from 'react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { FileText, Folder } from 'lucide-react';
import { getAllNotes } from '@/lib/notes/noteLoader';
import { useLocale } from '@/hooks/useLocale';

interface NotesPreviewProps {
  selectedFolders: Set<string>;
  maxHeight?: string;
}

interface PreviewNote {
  slug: string;
  title: string;
  folder: string;
  tags: string[];
}

export function NotesPreview({ selectedFolders, maxHeight = '200px' }: NotesPreviewProps) {
  const { t } = useLocale();
  const allNotes = useMemo(() => getAllNotes(), []);

  const previewNotes = useMemo((): PreviewNote[] => {
    if (selectedFolders.size === 0) return [];

    return allNotes
      .filter(note => {
        const decodedSlug = decodeURIComponent(note.slug);
        return Array.from(selectedFolders).some(folder =>
          decodedSlug.startsWith(folder + '/') || decodedSlug.startsWith(folder)
        );
      })
      .map(note => {
        const decodedSlug = decodeURIComponent(note.slug);
        const lastSlash = decodedSlug.lastIndexOf('/');
        const folder = lastSlash > 0 ? decodedSlug.slice(0, lastSlash) : '';
        
        return {
          slug: note.slug,
          title: note.title,
          folder,
          tags: (note.frontmatter?.tags as string[]) || [],
        };
      })
      .sort((a, b) => a.folder.localeCompare(b.folder) || a.title.localeCompare(b.title));
  }, [selectedFolders, allNotes]);

  // Group by folder
  const groupedNotes = useMemo(() => {
    const groups: Record<string, PreviewNote[]> = {};
    
    for (const note of previewNotes) {
      const key = note.folder || '(root)';
      if (!groups[key]) groups[key] = [];
      groups[key].push(note);
    }
    
    return groups;
  }, [previewNotes]);

  if (selectedFolders.size === 0) {
    return (
      <div className="text-center py-4 text-sm text-muted-foreground">
        {t.zoneView.selectFoldersForPreview}
      </div>
    );
  }

  if (previewNotes.length === 0) {
    return (
      <div className="text-center py-4 text-sm text-muted-foreground">
        {t.zoneView.noNotesInFolders}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium">{t.zoneView.notesPreview}</span>
        <Badge variant="secondary">
          {previewNotes.length} {t.common.notes}
        </Badge>
      </div>
      
      <ScrollArea className="border rounded-md" style={{ maxHeight }}>
        <div className="p-2 space-y-3">
          {Object.entries(groupedNotes).map(([folder, notes]) => (
            <div key={folder}>
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1 px-1">
                <Folder className="h-3 w-3" />
                <span className="truncate">{folder}</span>
                <span className="text-muted-foreground/60">({notes.length})</span>
              </div>
              <div className="space-y-0.5">
                {notes.map(note => (
                  <div 
                    key={note.slug}
                    className="flex items-center gap-2 px-2 py-1 rounded hover:bg-muted/50 text-sm"
                  >
                    <FileText className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                    <span className="truncate flex-1">{note.title}</span>
                    {note.tags.length > 0 && (
                      <div className="flex gap-1 flex-shrink-0">
                        {note.tags.slice(0, 2).map(tag => (
                          <Badge key={tag} variant="outline" className="text-[10px] px-1 py-0">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}
