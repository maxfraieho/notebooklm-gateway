// Backlinks display component - shows notes that link to the current note

import { Link } from 'react-router-dom';
import { useBacklinks } from '@/hooks/useBacklinks';
import { useLocale } from '@/hooks/useLocale';

interface BacklinksSectionProps {
  noteSlug: string;
}

export function BacklinksSection({ noteSlug }: BacklinksSectionProps) {
  const backlinks = useBacklinks(noteSlug);
  const { t } = useLocale();
  
  if (backlinks.length === 0) {
    return null;
  }
  
  return (
    <section className="mt-12 pt-8 border-t border-border/50">
      <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground mb-4">
        {t.backlinks.linkedFrom}
      </h2>
      <ul className="space-y-2">
        {backlinks.map((backlink) => (
          <li key={backlink.slug}>
            <Link
              to={`/notes/${backlink.slug}`}
              className="text-primary hover:text-primary/80 underline decoration-primary/30 hover:decoration-primary/60 transition-colors"
            >
              {backlink.title}
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
