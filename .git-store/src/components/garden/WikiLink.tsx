import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';

interface WikiLinkProps {
  slug: string;
  displayText: string;
  exists: boolean;
  className?: string;
}

export function WikiLink({ slug, displayText, exists, className }: WikiLinkProps) {
  if (exists) {
    return (
      <Link
        to={`/notes/${slug}`}
        className={cn('wiki-link', className)}
        title={`Navigate to: ${displayText}`}
      >
        {displayText}
      </Link>
    );
  }

  // Broken/missing link styling
  return (
    <span
      className={cn('wiki-link-broken', className)}
      title={`Note not found: ${slug}`}
    >
      {displayText}
    </span>
  );
}
