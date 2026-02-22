import { FileText, Tag, Link as LinkIcon, Clock } from 'lucide-react';
import { getAllNotes } from '@/lib/notes/noteLoader';
import { getAllTags } from '@/lib/notes/tagResolver';
import { getFullGraph } from '@/lib/notes/linkGraph';
import { useMemo } from 'react';
import { useLocale } from '@/hooks/useLocale';

export function GardenFooter() {
  const { t } = useLocale();

  const stats = useMemo(() => {
    const notes = getAllNotes();
    const tags = getAllTags();
    const graph = getFullGraph();

    return {
      notesCount: notes.length,
      tagsCount: tags.length,
      connectionsCount: graph.edges.length,
    };
  }, []);

  const lastUpdated = new Date().toLocaleDateString('en-US', {
    month: 'long',
    year: 'numeric',
  });

  return (
    <footer className="border-t border-border bg-card py-4 mt-8">
      <div className="max-w-6xl mx-auto px-4 flex flex-wrap items-center justify-center gap-4 text-xs text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <FileText className="w-3.5 h-3.5" />
          <span>
            {stats.notesCount} {t.common.notes}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <Tag className="w-3.5 h-3.5" />
          <span>
            {stats.tagsCount} {t.common.tags}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <LinkIcon className="w-3.5 h-3.5" />
          <span>
            {stats.connectionsCount} {t.index.connections}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5" />
          <span>{t.index.lastUpdated}: {lastUpdated}</span>
        </div>
      </div>
    </footer>
  );
}
