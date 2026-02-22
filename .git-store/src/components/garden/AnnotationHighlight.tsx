// Annotation Highlight Component
// Visual marker for annotated text with tooltip showing the comment

import { useState } from 'react';
import { 
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { Button } from '@/components/ui/button';
import { Trash2, Bot, User } from 'lucide-react';
import type { Annotation, Comment } from '@/lib/comments/types';

interface AnnotationHighlightProps {
  annotation: Annotation;
  comment?: Comment;
  children: React.ReactNode;
  isOwner?: boolean;
  onDelete?: (annotationId: string) => void;
}

export function AnnotationHighlight({ 
  annotation, 
  comment,
  children, 
  isOwner = false,
  onDelete,
}: AnnotationHighlightProps) {
  const [isOpen, setIsOpen] = useState(false);

  const handleDelete = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onDelete) {
      onDelete(annotation.id);
    }
    setIsOpen(false);
  };

  // Determine author type icon
  const AuthorIcon = comment?.author?.name?.toLowerCase().includes('ai') || 
                     comment?.author?.name?.toLowerCase().includes('agent') 
                     ? Bot : User;

  return (
    <TooltipProvider>
      <Tooltip open={isOpen} onOpenChange={setIsOpen}>
        <TooltipTrigger asChild>
          <mark 
            className="bg-accent/40 hover:bg-accent/60 text-foreground rounded-sm px-0.5 cursor-pointer transition-colors border-b-2 border-accent"
            data-annotation-id={annotation.id}
          >
            {children}
          </mark>
        </TooltipTrigger>
        <TooltipContent 
          side="top" 
          align="center" 
          className="max-w-xs p-3 bg-popover"
        >
          {comment ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <AuthorIcon className="w-3 h-3" />
                <span className="font-medium">{comment.author.name}</span>
                <span>•</span>
                <span>{new Date(comment.createdAt).toLocaleDateString('uk-UA')}</span>
              </div>
              <p className="text-sm text-foreground">{comment.content}</p>
              
              {isOwner && onDelete && (
                <div className="flex justify-end pt-1 border-t border-border mt-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 text-xs text-destructive hover:text-destructive hover:bg-destructive/10"
                    onClick={handleDelete}
                  >
                    <Trash2 className="w-3 h-3 mr-1" />
                    Видалити
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Завантаження...</p>
          )}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
