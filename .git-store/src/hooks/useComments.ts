// Comments Hook for fetching and managing article comments
// Architecture: React → mcpGatewayClient → Cloudflare Worker → MinIO + KV

import { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import { useOwnerAuth } from './useOwnerAuth';
import {
  fetchComments as apiFetchComments,
  createComment as apiCreateComment,
  updateComment as apiUpdateComment,
  deleteComment as apiDeleteComment,
} from '@/lib/api/mcpGatewayClient';
import type { 
  Comment, 
  CommentStatus,
} from '@/lib/comments/types';

interface UseCommentsOptions {
  autoFetch?: boolean;
}

export function useComments(articleSlug: string, options: UseCommentsOptions = {}) {
  const { autoFetch = true } = options;
  const { isAuthenticated: isOwner } = useOwnerAuth();
  
  const [comments, setComments] = useState<Comment[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch comments for article
  const fetchComments = useCallback(async () => {
    if (!articleSlug) return;
    
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await apiFetchComments(articleSlug);
      
      if (data.success) {
        setComments(data.comments);
      } else {
        throw new Error(data.error || 'Failed to fetch comments');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message :
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Unknown error';
      setError(message);
      console.error('[Comments] Fetch error:', message);
    } finally {
      setIsLoading(false);
    }
  }, [articleSlug]);

  // Auto-fetch on mount
  useEffect(() => {
    if (autoFetch && articleSlug) {
      fetchComments();
    }
  }, [autoFetch, articleSlug, fetchComments]);

  // Create new comment
  const createComment = useCallback(async (
    content: string,
    parentId?: string | null,
    authorName?: string
  ): Promise<Comment | null> => {
    try {
      const data = await apiCreateComment({
        articleSlug,
        content,
        parentId: parentId || null,
        authorName: authorName || (isOwner ? 'Owner' : 'Guest'),
      });
      
      if (data.success && data.comment) {
        setComments(prev => [...prev, data.comment!]);
        toast.success('💬 Коментар додано');
        return data.comment;
      } else {
        throw new Error(data.error || 'Failed to create comment');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message :
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Unknown error';
      toast.error('Помилка створення коментаря', { description: message });
      return null;
    }
  }, [articleSlug, isOwner]);

  // Update comment (owner only - for moderation)
  const updateComment = useCallback(async (
    commentId: string,
    updates: { status?: CommentStatus; content?: string }
  ): Promise<Comment | null> => {
    try {
      const data = await apiUpdateComment(commentId, updates);
      
      if (data.success && data.comment) {
        setComments(prev => 
          prev.map(c => c.id === commentId ? data.comment! : c)
        );
        
        if (updates.status === 'approved') {
          toast.success('✅ Коментар схвалено');
        } else if (updates.status === 'rejected') {
          toast.success('🚫 Коментар відхилено');
        }
        
        return data.comment;
      } else {
        throw new Error(data.error || 'Failed to update comment');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message :
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Unknown error';
      toast.error('Помилка оновлення', { description: message });
      return null;
    }
  }, []);

  // Delete comment (owner only)
  const deleteComment = useCallback(async (commentId: string): Promise<boolean> => {
    try {
      await apiDeleteComment(commentId);
      setComments(prev => prev.filter(c => c.id !== commentId));
      toast.success('🗑️ Коментар видалено');
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message :
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Unknown error';
      toast.error('Помилка видалення', { description: message });
      return false;
    }
  }, []);

  // Filter helpers
  const rootComments = comments.filter(c => !c.parentId);
  const getReplies = (parentId: string) => comments.filter(c => c.parentId === parentId);
  const approvedComments = comments.filter(c => c.status === 'approved');
  const pendingComments = comments.filter(c => c.status === 'pending');

  return {
    comments,
    rootComments,
    approvedComments,
    pendingComments,
    getReplies,
    isLoading,
    error,
    fetchComments,
    createComment,
    updateComment,
    deleteComment,
  };
}
