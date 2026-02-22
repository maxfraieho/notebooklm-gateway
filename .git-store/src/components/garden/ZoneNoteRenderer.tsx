// Zone Note Renderer
// Renders markdown content with restricted wikilinks for zone view

import { useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { cn } from '@/lib/utils';
import type { Components } from 'react-markdown';

interface ZoneNoteRendererProps {
  content: string;
  allowedSlugs: string[];
  onNavigate: (slug: string) => void;
}

// Regex to find wikilink markers
const WIKILINK_REGEX = /\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g;

function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^\w\-]+/g, '')
    .replace(/\-\-+/g, '-');
}

export function ZoneNoteRenderer({ content, allowedSlugs, onNavigate }: ZoneNoteRendererProps) {
  // Transform content to replace wikilinks with interactive elements
  const transformedContent = useMemo(() => {
    return content.replace(WIKILINK_REGEX, (match, target, alias) => {
      const displayText = alias?.trim() || target.trim();
      const slug = slugify(target.trim());
      const isAllowed = allowedSlugs.some(s => 
        decodeURIComponent(s).toLowerCase().includes(target.toLowerCase()) ||
        slugify(decodeURIComponent(s)) === slug
      );
      
      // Mark as allowed or restricted
      return `%%ZONELINK:${slug}:${encodeURIComponent(displayText)}:${isAllowed}%%`;
    });
  }, [content, allowedSlugs]);

  // Parse zone links
  function parseZoneLinks(text: string): (string | JSX.Element)[] {
    const parts: (string | JSX.Element)[] = [];
    const regex = /%%ZONELINK:([^:]+):([^:]+):(true|false)%%/g;
    let lastIndex = 0;
    let match: RegExpExecArray | null;

    regex.lastIndex = 0;

    while ((match = regex.exec(text)) !== null) {
      if (match.index > lastIndex) {
        parts.push(text.slice(lastIndex, match.index));
      }

      const slug = match[1];
      const displayText = decodeURIComponent(match[2]);
      const isAllowed = match[3] === 'true';

      if (isAllowed) {
        parts.push(
          <button
            key={`${slug}-${match.index}`}
            onClick={() => onNavigate(slug)}
            className={cn(
              "text-primary underline underline-offset-2",
              "hover:text-primary/80 transition-colors"
            )}
          >
            {displayText}
          </button>
        );
      } else {
        parts.push(
          <span
            key={`${slug}-${match.index}`}
            className="text-muted-foreground cursor-not-allowed"
            title="This note is not included in this access zone"
          >
            {displayText}
          </span>
        );
      }

      lastIndex = match.index + match[0].length;
    }

    if (lastIndex < text.length) {
      parts.push(text.slice(lastIndex));
    }

    return parts.length > 0 ? parts : [text];
  }

  function processChildren(children: React.ReactNode): React.ReactNode {
    if (!children) return children;

    if (typeof children === 'string') {
      const parts = parseZoneLinks(children);
      return parts.length === 1 && typeof parts[0] === 'string' ? parts[0] : <>{parts}</>;
    }

    if (Array.isArray(children)) {
      return children.map((child, index) => {
        if (typeof child === 'string') {
          const parts = parseZoneLinks(child);
          return parts.length === 1 && typeof parts[0] === 'string'
            ? parts[0]
            : <span key={index}>{parts}</span>;
        }
        return child;
      });
    }

    return children;
  }

  const components: Components = useMemo(() => ({
    p: ({ children, ...props }) => (
      <p {...props}>{processChildren(children)}</p>
    ),
    li: ({ children, ...props }) => (
      <li {...props}>{processChildren(children)}</li>
    ),
    strong: ({ children, ...props }) => (
      <strong {...props}>{processChildren(children)}</strong>
    ),
    em: ({ children, ...props }) => (
      <em {...props}>{processChildren(children)}</em>
    ),
    h1: ({ children, ...props }) => (
      <h1 {...props}>{processChildren(children)}</h1>
    ),
    h2: ({ children, ...props }) => (
      <h2 {...props}>{processChildren(children)}</h2>
    ),
    h3: ({ children, ...props }) => (
      <h3 {...props}>{processChildren(children)}</h3>
    ),
  }), [allowedSlugs, onNavigate]);

  return (
    <article className="prose-garden">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {transformedContent}
      </ReactMarkdown>
    </article>
  );
}
