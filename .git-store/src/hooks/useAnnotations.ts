// Annotations Hook for fetching and managing article annotations
// Architecture: React → mcpGatewayClient → Cloudflare Worker → MinIO + KV

import { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import { useOwnerAuth } from './useOwnerAuth';
import {
  fetchAnnotations as apiFetchAnnotations,
  createAnnotation as apiCreateAnnotation,
  deleteAnnotation as apiDeleteAnnotation,
} from '@/lib/api/mcpGatewayClient';
import type { 
  Annotation,
  Comment,
} from '@/lib/comments/types';

interface UseAnnotationsOptions {
  autoFetch?: boolean;
}

export function useAnnotations(articleSlug: string, options: UseAnnotationsOptions = {}) {
  const { autoFetch = true } = options;
  const { isAuthenticated: isOwner } = useOwnerAuth();
  
  const [annotations, setAnnotations] = useState<Annotation[]>([]);
  const [annotationComments, setAnnotationComments] = useState<Comment[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch annotations for article
  const fetchAnnotations = useCallback(async () => {
    if (!articleSlug) return;
    
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await apiFetchAnnotations(articleSlug);
      
      if (data.success) {
        setAnnotations(data.annotations);
        setAnnotationComments(data.comments);
      } else {
        throw new Error(data.error || 'Failed to fetch annotations');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Unknown error';
      setError(message);
      console.error('[Annotations] Fetch error:', message);
    } finally {
      setIsLoading(false);
    }
  }, [articleSlug]);

  // Auto-fetch on mount
  useEffect(() => {
    if (autoFetch && articleSlug) {
      fetchAnnotations();
    }
  }, [autoFetch, articleSlug, fetchAnnotations]);

  // Create new annotation with linked comment
  const createAnnotation = useCallback(async (
    highlightedText: string,
    startOffset: number,
    endOffset: number,
    paragraphIndex: number,
    commentContent: string,
    authorName?: string
  ): Promise<{ annotation: Annotation; comment: Comment } | null> => {
    try {
      const data = await apiCreateAnnotation({
        articleSlug,
        highlightedText,
        startOffset,
        endOffset,
        paragraphIndex,
        comment: {
          content: commentContent,
          authorName: authorName || (isOwner ? 'Owner' : 'Guest'),
        },
      });
      
      if (data.success && data.annotation && data.comment) {
        setAnnotations(prev => [...prev, data.annotation!]);
        setAnnotationComments(prev => [...prev, data.comment!]);
        toast.success('📝 Анотацію додано');
        return { annotation: data.annotation, comment: data.comment };
      } else {
        throw new Error(data.error || 'Failed to create annotation');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message :
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Unknown error';
      toast.error('Помилка створення анотації', { description: message });
      return null;
    }
  }, [articleSlug, isOwner]);

  // Delete annotation
  const deleteAnnotation = useCallback(async (annotationId: string): Promise<boolean> => {
    try {
      await apiDeleteAnnotation(annotationId);
      
      const annotation = annotations.find(a => a.id === annotationId);
      if (annotation) {
        setAnnotations(prev => prev.filter(a => a.id !== annotationId));
        setAnnotationComments(prev => prev.filter(c => c.id !== annotation.commentId));
      }
      
      toast.success('🗑️ Анотацію видалено');
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message :
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Unknown error';
      toast.error('Помилка видалення', { description: message });
      return false;
    }
  }, [annotations]);

  // Get comment for specific annotation
  const getAnnotationComment = useCallback((annotationId: string): Comment | undefined => {
    const annotation = annotations.find(a => a.id === annotationId);
    if (!annotation) return undefined;
    return annotationComments.find(c => c.id === annotation.commentId);
  }, [annotations, annotationComments]);

  return {
    annotations,
    annotationComments,
    isLoading,
    error,
    fetchAnnotations,
    createAnnotation,
    deleteAnnotation,
    getAnnotationComment,
  };
}
