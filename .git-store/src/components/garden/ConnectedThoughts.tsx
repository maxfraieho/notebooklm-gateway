import { Link } from 'react-router-dom';
import { Link2, TrendingUp } from 'lucide-react';
import { getFullGraph } from '@/lib/notes/linkGraph';
import { getAllNotes } from '@/lib/notes/noteLoader';
import { useMemo } from 'react';
import { useLocale } from '@/hooks/useLocale';
import { Card, CardContent } from '@/components/ui/card';

interface BacklinkPreview {
  from: {
    slug: string;
    title: string;
  };
  to: {
    slug: string;
    title: string;
  };
  preview: string;
}

export function ConnectedThoughts({ maxLinks = 3 }: { maxLinks?: number }) {
  const { t } = useLocale();

  const connections = useMemo(() => {
    const graph = getFullGraph();
    const notes = getAllNotes();
    const noteMap = new Map(notes.map((n) => [n.slug, n]));

    // Get actual edges and create backlink previews
    const backlinks: BacklinkPreview[] = [];

    for (const edge of graph.edges.slice(0, maxLinks)) {
      const sourceNote = noteMap.get(edge.source);
      const targetNote = noteMap.get(edge.target);

      if (sourceNote && targetNote) {
        // Build preview with wikilink reference to target
        const previewText = `This connects to [[${targetNote.title}]] methodology...`;

        backlinks.push({
          from: { slug: sourceNote.slug, title: sourceNote.title },
          to: { slug: targetNote.slug, title: targetNote.title },
          preview: previewText,
        });
      }
    }

    return backlinks;
  }, [maxLinks]);

  if (connections.length === 0) {
    return null;
  }

  // Helper to render preview with styled wikilinks
  const renderPreview = (preview: string, toSlug: string) => {
    const parts = preview.split(/\[\[|\]\]/);
    return parts.map((part, i) => {
      // Odd indices are the link text
      if (i % 2 === 1) {
        return (
          <Link
            key={i}
            to={`/notes/${toSlug}`}
            className="text-primary underline decoration-dotted hover:bg-primary/10 px-1 rounded"
          >
            {part}
          </Link>
        );
      }
      return <span key={i}>{part}</span>;
    });
  };

  return (
    <section>
      <div className="flex items-center gap-2 mb-4">
        <TrendingUp className="w-5 h-5 text-primary" />
        <h2 className="font-serif text-xl font-semibold text-primary">
          {t.index.connectedThoughts}
        </h2>
      </div>

      <Card className="bg-card border-border">
        <CardContent className="p-6">
          <div className="space-y-4">
            {connections.map((connection, idx) => (
              <div
                key={idx}
                className="border-l-2 border-primary pl-4 py-2"
              >
                <div className="flex items-start gap-2 mb-1 min-w-0">
                  <Link2 className="w-4 h-4 mt-1 text-primary flex-shrink-0" />
                  <div className="min-w-0 overflow-hidden">
                    {/* From → To */}
                    <div className="font-medium text-sm text-primary truncate">
                      <Link
                        to={`/notes/${connection.from.slug}`}
                        className="hover:underline"
                      >
                        {connection.from.title}
                      </Link>
                      <span className="mx-2">→</span>
                      <Link
                        to={`/notes/${connection.to.slug}`}
                        className="hover:underline"
                      >
                        {connection.to.title}
                      </Link>
                    </div>

                    {/* Preview text with styled wikilink */}
                    <p className="text-sm text-muted-foreground leading-relaxed mt-1">
                      {renderPreview(connection.preview, connection.to.slug)}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
