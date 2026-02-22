// Zone Comment Section Component
// Simplified commenting for zone guests with accessCode validation

import { useState, useEffect, useCallback } from 'react';
import { MessageSquare, Loader2, AlertCircle, Send, User } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { formatDistanceToNow } from 'date-fns';
import { uk } from 'date-fns/locale';
import type { Comment } from '@/lib/comments/types';
import { AIAgentBadge } from './AIAgentBadge';
import {
  fetchComments as apiFetchComments,
  createComment as apiCreateComment,
} from '@/lib/api/mcpGatewayClient';

interface ZoneCommentSectionProps {
  articleSlug: string;
  zoneId: string;
  accessCode: string;
}

export function ZoneCommentSection({ articleSlug, zoneId, accessCode }: ZoneCommentSectionProps) {
  const [comments, setComments] = useState<Comment[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [newComment, setNewComment] = useState('');
  const [authorName, setAuthorName] = useState('');

  // Fetch comments for article
  const fetchComments = useCallback(async () => {
    if (!articleSlug) return;
    
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await apiFetchComments(articleSlug, { zoneId, zoneCode: accessCode });
      
      if (data.success) {
        // Only show approved comments to zone guests
        const approvedComments = (data.comments || []).filter(
          (c: Comment) => c.status === 'approved'
        );
        setComments(approvedComments);
      } else {
        throw new Error(data.error || 'Failed to fetch comments');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message :
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Unknown error';
      setError(message);
      console.error('[ZoneComments] Fetch error:', message);
    } finally {
      setIsLoading(false);
    }
  }, [articleSlug, zoneId, accessCode]);

  useEffect(() => {
    fetchComments();
  }, [fetchComments]);

  // Submit new comment
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const content = newComment.trim();
    if (!content) return;
    
    setIsSubmitting(true);
    
    try {
      const data = await apiCreateComment({
        articleSlug,
        content,
        authorName: authorName.trim() || 'Zone Guest',
        zoneId,
        zoneCode: accessCode,
      });
      
      if (data.success) {
        setNewComment('');
        toast.success('💬 Коментар надіслано', {
          description: 'Очікує схвалення власником'
        });
      } else {
        throw new Error(data.error || 'Failed to create comment');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message :
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Unknown error';
      toast.error('Помилка відправки', { description: message });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="mt-8">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <MessageSquare className="w-5 h-5 text-primary" />
        <h3 className="text-lg font-semibold text-foreground">
          Коментарі
        </h3>
        {comments.length > 0 && (
          <Badge variant="secondary">
            {comments.length}
          </Badge>
        )}
      </div>

      {/* Loading state */}
      {isLoading && (
        <div className="flex items-center justify-center py-6 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin mr-2" />
          Завантаження...
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 text-destructive mb-4">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {/* Comments list */}
      {!isLoading && !error && (
        <div className="space-y-3 mb-6">
          {comments.length === 0 ? (
            <p className="text-center text-muted-foreground py-6 text-sm">
              Поки що немає коментарів до цієї нотатки.
            </p>
          ) : (
            comments.map((comment) => (
              <ZoneCommentItem key={comment.id} comment={comment} />
            ))
          )}
        </div>
      )}

      {/* Comment form */}
      <Card className="border-dashed">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">
            Залишити коментар
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-3">
            <Input
              value={authorName}
              onChange={(e) => setAuthorName(e.target.value)}
              placeholder="Ваше ім'я (необов'язково)"
              className="text-sm"
              maxLength={50}
            />
            <Textarea
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              placeholder="Напишіть коментар..."
              className="min-h-[80px] text-sm resize-none"
              maxLength={2000}
            />
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                Коментар буде опублікований після схвалення
              </p>
              <Button 
                type="submit" 
                size="sm"
                disabled={isSubmitting || !newComment.trim()}
              >
                {isSubmitting ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <>
                    <Send className="w-4 h-4 mr-1" />
                    Надіслати
                  </>
                )}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </section>
  );
}

// Individual comment display
function ZoneCommentItem({ comment }: { comment: Comment }) {
  const timeAgo = formatDistanceToNow(new Date(comment.createdAt), { 
    addSuffix: true, 
    locale: uk 
  });

  const isAI = comment.author.type === 'ai-agent';

  return (
    <div className={cn(
      "p-3 rounded-lg",
      isAI ? "bg-[hsl(270_70%_97%)] dark:bg-[hsl(270_30%_15%)] border-l-4 border-[hsl(270_70%_60%)]" : "bg-muted/50"
    )}>
      <div className="flex items-center gap-2 mb-2">
        <div className={cn(
          "w-6 h-6 rounded-full flex items-center justify-center text-xs",
          isAI ? "bg-[hsl(270_70%_60%)/0.2] text-[hsl(270_70%_60%)]" : "bg-muted text-muted-foreground"
        )}>
          <User className="w-3 h-3" />
        </div>
        <span className="font-medium text-sm text-foreground">
          {comment.author.name}
        </span>
        {isAI && <AIAgentBadge model={comment.author.agentModel} />}
        <span className="text-xs text-muted-foreground">
          {timeAgo}
        </span>
      </div>
      <p className="text-sm text-foreground whitespace-pre-wrap pl-8">
        {comment.content}
      </p>
    </div>
  );
}
