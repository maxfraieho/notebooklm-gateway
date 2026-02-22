// Annotation Layer Component
// Wraps article content with text selection detection and annotation popup

import { useRef, useState, useCallback } from 'react';
import { useTextSelection } from '@/hooks/useTextSelection';
import { useAnnotations } from '@/hooks/useAnnotations';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { AnnotationPopup } from './AnnotationPopup';

interface AnnotationLayerProps {
  articleSlug: string;
  children: React.ReactNode;
}

export function AnnotationLayer({ articleSlug, children }: AnnotationLayerProps) {
  const contentRef = useRef<HTMLDivElement>(null);
  const { isAuthenticated: isOwner } = useOwnerAuth();
  const { selection, clearSelection } = useTextSelection(contentRef);
  const { createAnnotation } = useAnnotations(articleSlug, { autoFetch: false });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmitAnnotation = useCallback(async (comment: string) => {
    if (!selection) return;

    setIsSubmitting(true);
    try {
      await createAnnotation(
        selection.text,
        selection.startOffset,
        selection.endOffset,
        selection.paragraphIndex,
        comment
      );
      clearSelection();
      // Clear browser selection
      window.getSelection()?.removeAllRanges();
    } finally {
      setIsSubmitting(false);
    }
  }, [selection, createAnnotation, clearSelection]);

  const handleClosePopup = useCallback(() => {
    clearSelection();
    window.getSelection()?.removeAllRanges();
  }, [clearSelection]);

  return (
    <div className="relative">
      <div ref={contentRef}>
        {children}
      </div>
      
      {selection && (
        <AnnotationPopup
          selection={selection}
          onSubmit={handleSubmitAnnotation}
          onClose={handleClosePopup}
          isSubmitting={isSubmitting}
        />
      )}
    </div>
  );
}
