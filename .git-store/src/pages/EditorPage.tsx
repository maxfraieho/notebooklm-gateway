import { useState } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { NoteEditor } from '@/components/garden/NoteEditor';
import { GardenHeader } from '@/components/garden/GardenHeader';
import { GardenFooter } from '@/components/garden/GardenFooter';
import { EditorFolderTree } from '@/components/garden/EditorFolderTree';
import { DeleteNoteDialog } from '@/components/garden/DeleteNoteDialog';
import { useNoteEditor } from '@/hooks/useNoteEditor';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { useLocale } from '@/hooks/useLocale';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Lock, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';
 
 export default function EditorPage() {
   const { slug } = useParams<{ slug: string }>();
   const [searchParams] = useSearchParams();
   const navigate = useNavigate();
   const { t } = useLocale();
  const { isAuthenticated } = useOwnerAuth();
 
   // Get folder from query params (for creating notes in specific folder)
   const folderFromUrl = searchParams.get('folder') || null;
   
  // Folder selection state - for new notes use URL param, for existing notes extract from slug
  const [selectedFolder, setSelectedFolder] = useState<string | null>(() => {
    if (folderFromUrl) return folderFromUrl;
    if (slug && slug !== 'new') {
      // Extract folder path from slug (e.g., "folder/subfolder/note" -> "folder/subfolder")
      const lastSlashIndex = slug.lastIndexOf('/');
      if (lastSlashIndex > 0) {
        return slug.substring(0, lastSlashIndex);
      }
    }
    return null;
  });
   const [isFolderTreeCollapsed, setIsFolderTreeCollapsed] = useState(false);
 
   const editor = useNoteEditor({ 
     slug: slug === 'new' ? undefined : slug,
     folder: selectedFolder || undefined 
   });
 
   // Redirect non-owners
  if (!isAuthenticated) {
     return (
       <div className="min-h-screen bg-background flex flex-col">
         <GardenHeader />
         <main className="flex-1 flex items-center justify-center p-4">
           <Card className="max-w-md w-full p-8 text-center">
             <Lock className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
             <h1 className="text-xl font-semibold mb-2">
               Access Denied
             </h1>
             <p className="text-muted-foreground mb-6">
               Only the garden owner can create or edit notes.
             </p>
             <Button asChild>
               <Link to="/">
                 <ArrowLeft className="mr-2 h-4 w-4" />
                 Return to Garden
               </Link>
             </Button>
           </Card>
         </main>
         <GardenFooter />
       </div>
     );
   }
 
   const handleSave = async () => {
     const savedSlug = await editor.save();
     if (savedSlug) {
       navigate(`/notes/${savedSlug}`);
     }
   };
 
   const handleCancel = () => {
     if (editor.isDirty) {
       // TODO: Show confirmation dialog
       if (window.confirm('Discard unsaved changes?')) {
         navigate(-1);
       }
     } else {
       navigate(-1);
     }
   };
 
   return (
     <div className="min-h-screen bg-background flex flex-col">
       <GardenHeader />
       
       <main className="flex-1 flex min-h-0">
         {/* Folder tree sidebar (desktop) */}
         <div className="hidden md:flex">
           <EditorFolderTree
             selectedFolder={selectedFolder}
             onSelectFolder={setSelectedFolder}
             isCollapsed={isFolderTreeCollapsed}
             onToggleCollapse={() => setIsFolderTreeCollapsed(!isFolderTreeCollapsed)}
              currentSlug={slug === 'new' ? undefined : slug}
           />
         </div>
         
         {/* Editor content */}
         <div className="flex-1 flex flex-col min-w-0 px-4 py-4">
            {/* Page title + actions */}
            <div className="flex items-center justify-between gap-3 mb-4">
              <div className="flex items-center gap-3">
                <Link 
                  to="/" 
                  className="inline-flex items-center gap-2 text-sm text-primary hover:text-primary/80 transition-colors"
                >
                  <ArrowLeft className="w-4 h-4" />
                  <span className="hidden sm:inline">Back</span>
                </Link>
                <h1 className="text-xl font-semibold">
                  {editor.isNewNote ? t.editor.newNote : t.editor.editNote}
                </h1>
              </div>
              
              {/* Delete button for existing notes */}
              {!editor.isNewNote && slug && (
                <DeleteNoteDialog 
                  noteSlug={slug} 
                  noteTitle={editor.title || 'Untitled'} 
                />
              )}
            </div>
 
           {/* Editor */}
           <div className="flex-1 min-h-0">
             <NoteEditor
               title={editor.title}
               content={editor.content}
               tags={editor.tags}
               isDirty={editor.isDirty}
               isSaving={editor.isSaving}
               hasDraft={editor.hasDraft}
               selectedFolder={selectedFolder}
               onTitleChange={editor.setTitle}
               onContentChange={editor.setContent}
               onTagsChange={editor.setTags}
               onFolderChange={setSelectedFolder}
               onSave={handleSave}
               onCancel={handleCancel}
               onRestoreDraft={editor.restoreDraft}
               onDiscardDraft={editor.discardDraft}
               insertAtCursor={editor.insertAtCursor}
             />
           </div>
         </div>
       </main>
       
       <GardenFooter />
     </div>
   );
 }