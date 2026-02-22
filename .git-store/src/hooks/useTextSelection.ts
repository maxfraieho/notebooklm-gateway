// Hook for tracking text selection in article content
// Used for creating annotations on highlighted text

import { useState, useCallback, useEffect } from 'react';

export interface TextSelection {
  text: string;
  startOffset: number;
  endOffset: number;
  paragraphIndex: number;
  range: Range | null;
  rect: DOMRect | null;
}

export function useTextSelection(containerRef: React.RefObject<HTMLElement>) {
  const [selection, setSelection] = useState<TextSelection | null>(null);

  const clearSelection = useCallback(() => {
    setSelection(null);
  }, []);

  const handleSelectionChange = useCallback(() => {
    const windowSelection = window.getSelection();
    
    if (!windowSelection || windowSelection.isCollapsed || !containerRef.current) {
      return;
    }

    const selectedText = windowSelection.toString().trim();
    if (!selectedText || selectedText.length < 3) {
      return;
    }

    const range = windowSelection.getRangeAt(0);
    
    // Check if selection is within our container
    if (!containerRef.current.contains(range.commonAncestorContainer)) {
      return;
    }

    // Find the paragraph element containing the selection
    let paragraphElement = range.startContainer.parentElement;
    while (paragraphElement && paragraphElement.tagName !== 'P' && paragraphElement !== containerRef.current) {
      paragraphElement = paragraphElement.parentElement;
    }

    // Calculate paragraph index
    let paragraphIndex = 0;
    if (paragraphElement && paragraphElement.tagName === 'P') {
      const allParagraphs = containerRef.current.querySelectorAll('p');
      paragraphIndex = Array.from(allParagraphs).indexOf(paragraphElement as HTMLParagraphElement);
    }

    // Calculate offsets relative to the paragraph
    const startOffset = range.startOffset;
    const endOffset = range.endOffset;

    // Get selection position for popup
    const rect = range.getBoundingClientRect();

    setSelection({
      text: selectedText,
      startOffset,
      endOffset,
      paragraphIndex,
      range,
      rect,
    });
  }, [containerRef]);

  // Listen for mouse up events to capture selection
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const handleMouseUp = () => {
      // Small delay to ensure selection is complete
      setTimeout(handleSelectionChange, 10);
    };

    const handleMouseDown = () => {
      // Clear previous selection on new mouse down
      clearSelection();
    };

    container.addEventListener('mouseup', handleMouseUp);
    container.addEventListener('mousedown', handleMouseDown);

    return () => {
      container.removeEventListener('mouseup', handleMouseUp);
      container.removeEventListener('mousedown', handleMouseDown);
    };
  }, [containerRef, handleSelectionChange, clearSelection]);

  return {
    selection,
    clearSelection,
  };
}
