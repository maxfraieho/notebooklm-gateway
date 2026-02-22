import { Link } from 'react-router-dom';
import { Link as LinkIcon, Calendar, FileText } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

interface NoteCardProps {
  slug: string;
  title: string;
  date?: string;
  preview?: string;
  tags?: string[];
  connectionCount?: number;
}

export function NoteCard({
  slug,
  title,
  date,
  preview,
  tags = [],
  connectionCount = 0,
}: NoteCardProps) {
  return (
    <Link
      to={`/notes/${slug}`}
      className="group block border border-border rounded-lg bg-card overflow-hidden transition-all duration-200 hover:border-primary/50 hover:shadow-md hover:shadow-primary/10"
    >
      {/* Card Header */}
      <div className="px-4 py-3 border-b border-border transition-colors duration-200 group-hover:bg-accent/30">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5 flex-1 min-w-0">
            <FileText className="w-5 h-5 text-primary mt-0.5 flex-shrink-0 transition-colors duration-200" />
            <h3 className="text-sm font-semibold text-foreground line-clamp-2 transition-colors duration-200 group-hover:text-primary">
              {title}
            </h3>
          </div>
          {connectionCount > 0 && (
            <div className="flex items-center gap-1 text-xs text-muted-foreground flex-shrink-0 px-2 py-1 rounded bg-muted/50 transition-all duration-200 group-hover:bg-primary/10 group-hover:text-primary">
              <LinkIcon className="w-3 h-3" />
              <span className="font-medium">{connectionCount}</span>
            </div>
          )}
        </div>
      </div>

      {/* Card Content */}
      {preview && (
        <div className="px-4 py-3 border-b border-border">
          <p className="text-sm text-muted-foreground line-clamp-2 transition-colors duration-200 group-hover:text-foreground">
            {preview}
          </p>
        </div>
      )}

      {/* Card Footer */}
      <div className="px-4 py-3 flex items-center justify-between gap-2 transition-colors duration-200 group-hover:bg-accent/20">
        {/* Tags */}
        <div className="flex flex-wrap gap-1.5">
          {tags.slice(0, 2).map((tag) => (
            <Badge
              key={tag}
              variant="secondary"
              className="text-xs bg-primary/10 text-primary border-0 px-2 py-0.5 transition-all duration-200 group-hover:bg-primary/20"
            >
              {tag}
            </Badge>
          ))}
          {tags.length > 2 && (
            <Badge
              variant="secondary"
              className="text-xs bg-muted text-muted-foreground border-0 px-2 py-0.5 transition-colors duration-200 group-hover:bg-muted/80"
            >
              +{tags.length - 2}
            </Badge>
          )}
        </div>

        {/* Date */}
        {date && (
          <div className="flex items-center gap-1 text-xs text-muted-foreground flex-shrink-0 whitespace-nowrap transition-colors duration-200 group-hover:text-foreground">
            <Calendar className="w-3 h-3" />
            <span>{date}</span>
          </div>
        )}
      </div>
    </Link>
  );
}
