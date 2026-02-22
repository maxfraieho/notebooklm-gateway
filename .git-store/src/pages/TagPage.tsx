import { useParams, Link } from 'react-router-dom';
import { useNotesByTag, useTagExists } from '@/hooks/useTags';
import { Layout } from '@/components/garden/Layout';
import { ArrowLeft, Tag, FileText } from 'lucide-react';
import { useLocale } from '@/hooks/useLocale';

export default function TagPage() {
  const { tag } = useParams<{ tag: string }>();
  const decodedTag = tag ? decodeURIComponent(tag) : '';
  const notes = useNotesByTag(decodedTag);
  const exists = useTagExists(decodedTag);
  const { t } = useLocale();

  if (!decodedTag) {
    return (
      <Layout>
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center px-6">
            <Tag className="w-16 h-16 text-muted-foreground mx-auto mb-6" />
            <h1 className="text-2xl font-semibold text-foreground mb-2 font-sans">
              {t.tagPage.noTagSpecified}
            </h1>
            <Link
              to="/"
              className="inline-flex items-center gap-2 text-primary hover:text-primary/80 transition-colors font-sans"
            >
              <ArrowLeft className="w-4 h-4" />
              {t.tagPage.returnToGarden}
            </Link>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="max-w-2xl mx-auto px-6 py-12">
        {/* Header */}
        <header className="mb-8">
          <Link
            to="/"
            className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors text-sm mb-6"
          >
            <ArrowLeft className="w-4 h-4" />
            {t.tags.allNotes}
          </Link>

          <div className="flex items-center gap-3">
            <Tag className="w-6 h-6 text-primary" />
            <h1 className="text-3xl font-semibold text-foreground font-sans">
              #{decodedTag}
            </h1>
          </div>

          <p className="text-muted-foreground mt-2">
            {notes.length} {notes.length === 1 ? t.tags.noteTagged : t.tags.notesTagged}
          </p>
        </header>

        {/* Notes List */}
        {notes.length > 0 ? (
          <ul className="space-y-4">
            {notes.map((note) => (
              <li key={note.slug}>
                <Link
                  to={`/notes/${note.slug}`}
                  className="block p-4 rounded-lg border border-border bg-card hover:bg-accent/50 transition-colors group"
                >
                  <div className="flex items-start gap-3">
                    <FileText className="w-5 h-5 text-muted-foreground mt-0.5 group-hover:text-primary transition-colors" />
                    <div>
                      <h2 className="text-lg font-medium text-foreground group-hover:text-primary transition-colors">
                        {note.title}
                      </h2>
                      {note.updated && (
                        <p className="text-sm text-muted-foreground mt-1">
                          {t.tags.updated} {note.updated}
                        </p>
                      )}
                    </div>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-center py-12">
            <Tag className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-50" />
            <p className="text-muted-foreground">
              {t.tags.noNotesWithTag}
            </p>
          </div>
        )}

        {/* All Tags Link */}
        <div className="mt-12 pt-6 border-t border-border">
          <Link
            to="/tags"
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            {t.tags.viewAllTags}
          </Link>
        </div>
      </div>
    </Layout>
  );
}
