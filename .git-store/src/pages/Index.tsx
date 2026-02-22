import { getAllNotes } from '@/lib/notes/noteLoader';
import { getOutboundLinks } from '@/lib/notes/linkGraph';
import { NoteCard } from '@/components/garden/NoteCard';
import { TagCloud } from '@/components/garden/TagCloud';
import { KnowledgeMapPreview } from '@/components/garden/KnowledgeMapPreview';
import { ConnectedThoughts } from '@/components/garden/ConnectedThoughts';
import { GardenHeader } from '@/components/garden/GardenHeader';
import { GardenFooter } from '@/components/garden/GardenFooter';
import { useLocale } from '@/hooks/useLocale';
import { useMemo } from 'react';
import { Calendar } from 'lucide-react';

export default function Index() {
  const { t } = useLocale();
  const notes = getAllNotes();

  // Get recent notes with connection counts
  const recentNotes = useMemo(() => {
    return notes.slice(0, 5).map((note) => {
      const outbound = getOutboundLinks(note.slug);
      // Get content preview (first 80 chars of content)
      const preview = note.content
        .replace(/^#.*$/gm, '')
        .replace(/\[\[.*?\]\]/g, '')
        .replace(/\n+/g, ' ')
        .trim()
        .slice(0, 80);

      return {
        slug: note.slug,
        title: note.title,
        date: note.frontmatter.updated || note.frontmatter.created,
        preview,
        tags: note.frontmatter.tags || [],
        connectionCount: outbound.length,
      };
    });
  }, [notes]);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <GardenHeader />

      {/* Main content */}
      <main className="flex-1 max-w-6xl mx-auto w-full px-4 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left sidebar - Browse Tags + Connected Thoughts */}
          <aside className="lg:col-span-4 space-y-6">
            <TagCloud maxTags={15} />
            <ConnectedThoughts maxLinks={3} />
          </aside>

          {/* Main area - Knowledge Map + Recent Notes */}
          <section className="lg:col-span-8 space-y-6">
            <KnowledgeMapPreview />

            {/* Recent Notes */}
            <div className="border border-border rounded-lg p-4 bg-card">
              <div className="flex items-center gap-2 mb-4">
                <Calendar className="w-4 h-4 text-primary" />
                <h2 className="font-semibold text-foreground font-sans">
                  {t.index.recentNotes}
                </h2>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {recentNotes.map((note) => (
                  <NoteCard
                    key={note.slug}
                    slug={note.slug}
                    title={note.title}
                    date={note.date}
                    preview={note.preview}
                    tags={note.tags}
                    connectionCount={note.connectionCount}
                  />
                ))}
              </div>
            </div>
          </section>
        </div>
      </main>

      {/* Footer */}
      <GardenFooter />
    </div>
  );
}
