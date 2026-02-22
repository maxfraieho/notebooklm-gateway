// Tags index page with new design
import { Link } from 'react-router-dom';
import { useAllTags } from '@/hooks/useTags';
import { GardenHeader } from '@/components/garden/GardenHeader';
import { GardenFooter } from '@/components/garden/GardenFooter';
import { Tag, Tags } from 'lucide-react';
import { useLocale } from '@/hooks/useLocale';

export default function TagsIndex() {
  const tags = useAllTags();
  const { t } = useLocale();

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <GardenHeader />
      
      <main className="flex-1 max-w-4xl mx-auto w-full px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Tags className="w-8 h-8 text-primary" />
            <h1 className="text-3xl font-semibold text-foreground font-serif">
              {t.tags.allTags}
            </h1>
          </div>
          <p className="text-muted-foreground">
            {tags.length} {tags.length === 1 ? t.tags.tagInGarden : t.tags.tagsInGarden}
          </p>
        </div>

        {/* Tags Grid */}
        <div className="bg-card rounded-xl border border-border p-6 shadow-sm">
          {tags.length > 0 ? (
            <div className="flex flex-wrap gap-3">
              {tags.map((tagInfo) => (
                <Link
                  key={tagInfo.tag}
                  to={`/tags/${encodeURIComponent(tagInfo.tag)}`}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-background hover:bg-accent/50 hover:border-primary/30 transition-colors group"
                >
                  <Tag className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                  <span className="text-foreground group-hover:text-primary transition-colors font-medium">
                    #{tagInfo.tag}
                  </span>
                  <span className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded-full">
                    {tagInfo.noteCount}
                  </span>
                </Link>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <Tag className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-50" />
              <p className="text-muted-foreground">
                {t.tags.noTagsYet}
              </p>
            </div>
          )}
        </div>
      </main>
      
      <GardenFooter />
    </div>
  );
}
