import { useState, useMemo } from 'react';
import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import { GardenHeader } from '@/components/garden/GardenHeader';
import { GardenFooter } from '@/components/garden/GardenFooter';
import { DrakonEditor } from '@/components/garden/DrakonEditor';
import { EditorFolderTree } from '@/components/garden/EditorFolderTree';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { useLocale } from '@/hooks/useLocale';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Lock, ArrowLeft, GitBranch } from 'lucide-react';
import { slugify } from '@/lib/utils';

export default function DrakonPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { t } = useLocale();
  const { isAuthenticated } = useOwnerAuth();

  const diagramIdFromUrl = searchParams.get('id');
  const folderSlug = searchParams.get('folder') || undefined;
  const isNew = searchParams.get('new') === 'true';

  const [selectedFolder, setSelectedFolder] = useState<string | null>(folderSlug || null);
  const [isFolderTreeCollapsed, setIsFolderTreeCollapsed] = useState(false);

  // For new diagrams, the name typed in the editor toolbar generates the slug
  const currentDiagramId = diagramIdFromUrl || '';

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        <GardenHeader />
        <main className="flex-1 flex items-center justify-center p-4">
          <Card className="max-w-md w-full p-8 text-center">
            <Lock className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h1 className="text-xl font-semibold mb-2">{t.drakonEditor.accessDenied}</h1>
            <p className="text-muted-foreground mb-6">{t.drakonEditor.ownerOnly}</p>
            <Button asChild>
              <Link to="/">
                <ArrowLeft className="mr-2 h-4 w-4" />
                {t.drakonEditor.returnToGarden}
              </Link>
            </Button>
          </Card>
        </main>
        <GardenFooter />
      </div>
    );
  }

  const handleSaved = (_id: string) => {
    if (folderSlug || selectedFolder) {
      navigate(`/notes/${folderSlug || selectedFolder}`);
    }
  };

  // Resolve effective folder — from sidebar selection or URL
  const effectiveFolder = selectedFolder || folderSlug;

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <GardenHeader />
      
      <main className="flex-1 flex min-h-0">
        {/* Folder tree sidebar — same as article editor */}
        <div className="hidden md:flex">
          <EditorFolderTree
            selectedFolder={selectedFolder}
            onSelectFolder={setSelectedFolder}
            isCollapsed={isFolderTreeCollapsed}
            onToggleCollapse={() => setIsFolderTreeCollapsed(!isFolderTreeCollapsed)}
          />
        </div>

        <div className="flex-1 flex flex-col min-w-0 px-4 py-4">
          {/* Page header */}
          <div className="flex items-center gap-3 mb-4">
            <Link 
              to={folderSlug ? `/notes/${folderSlug}` : '/files'}
              className="inline-flex items-center gap-2 text-sm text-primary hover:text-primary/80 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:inline">{t.drakonEditor.back}</span>
            </Link>
            <div className="flex items-center gap-2">
              <GitBranch className="w-5 h-5 text-muted-foreground" />
              <h1 className="text-xl font-semibold">
                {isNew ? t.drakonEditor.createNewDiagram : `DRAKON: ${currentDiagramId}`}
              </h1>
            </div>
          </div>

          {/* Editor — directly, no intermediate step */}
          <div className="flex-1 min-h-0">
            <DrakonEditor
              diagramId={currentDiagramId}
              folderSlug={effectiveFolder}
              height={600}
              isNew={isNew}
              onSaved={handleSaved}
              className="h-full"
            />
          </div>
        </div>
      </main>
      
      <GardenFooter />
    </div>
  );
}
