// Annotation Popup Component
// Shows popup when user selects text to add annotation

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { MessageSquarePlus, X, Send, Loader2 } from 'lucide-react';
import type { TextSelection } from '@/hooks/useTextSelection';

interface AnnotationPopupProps {
  selection: TextSelection;
  onSubmit: (comment: string) => Promise<void>;
  onClose: () => void;
  isSubmitting?: boolean;
}

export function AnnotationPopup({ 
  selection, 
  onSubmit, 
  onClose,
  isSubmitting = false 
}: AnnotationPopupProps) {
  const [comment, setComment] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);

  if (!selection.rect) return null;

  const handleSubmit = async () => {
    if (!comment.trim()) return;
    await onSubmit(comment.trim());
    setComment('');
    setIsExpanded(false);
  };

  // Calculate position - show above the selection
  const top = selection.rect.top + window.scrollY - 8;
  const left = selection.rect.left + selection.rect.width / 2;

  return (
    <div
      className="fixed z-50 transform -translate-x-1/2 -translate-y-full"
      style={{ 
        top: top,
        left: Math.min(Math.max(left, 100), window.innerWidth - 100),
      }}
    >
      {!isExpanded ? (
        // Mini button to initiate annotation
        <Button
          size="sm"
          variant="default"
          className="shadow-lg gap-2 animate-in fade-in-0 zoom-in-95"
          onClick={() => setIsExpanded(true)}
        >
          <MessageSquarePlus className="w-4 h-4" />
          Анотувати
        </Button>
      ) : (
        // Expanded annotation form
        <div className="bg-card border border-border rounded-lg shadow-xl p-3 w-80 animate-in fade-in-0 zoom-in-95">
          <div className="flex items-start justify-between gap-2 mb-2">
            <div className="flex-1">
              <p className="text-xs text-muted-foreground mb-1">Виділений текст:</p>
              <p className="text-sm font-medium text-foreground line-clamp-2 bg-primary/10 px-2 py-1 rounded">
                "{selection.text.slice(0, 100)}{selection.text.length > 100 ? '...' : ''}"
              </p>
            </div>
            <Button
              size="icon"
              variant="ghost"
              className="h-6 w-6 shrink-0"
              onClick={onClose}
            >
              <X className="w-4 h-4" />
            </Button>
          </div>
          
          <Textarea
            placeholder="Додайте свій коментар до цього фрагменту..."
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            className="min-h-[80px] text-sm resize-none"
            disabled={isSubmitting}
            autoFocus
          />
          
          <div className="flex justify-end gap-2 mt-2">
            <Button
              size="sm"
              variant="ghost"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Скасувати
            </Button>
            <Button
              size="sm"
              onClick={handleSubmit}
              disabled={!comment.trim() || isSubmitting}
              className="gap-2"
            >
              {isSubmitting ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              Зберегти
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
