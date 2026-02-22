import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';

interface TagLinkProps {
  tag: string;
  className?: string;
}

export function TagLink({ tag, className }: TagLinkProps) {
  return (
    <Link
      to={`/tags/${encodeURIComponent(tag)}`}
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium',
        'bg-muted text-muted-foreground',
        'hover:bg-accent hover:text-accent-foreground',
        'transition-colors duration-150',
        className
      )}
    >
      #{tag}
    </Link>
  );
}
