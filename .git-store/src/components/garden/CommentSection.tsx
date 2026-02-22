// Comment Section Component
// Container for article comments with form and moderation

import { MessageSquare, Loader2, AlertCircle } from 'lucide-react';
import { useComments } from '@/hooks/useComments';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { CommentForm } from './CommentForm';
import { CommentItem } from './CommentItem';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';

interface CommentSectionProps {
  articleSlug: string;
}

export function CommentSection({ articleSlug }: CommentSectionProps) {
  const { isAuthenticated: isOwner } = useOwnerAuth();
  const {
    rootComments,
    approvedComments,
    pendingComments,
    getReplies,
    isLoading,
    error,
    createComment,
    updateComment,
    deleteComment,
  } = useComments(articleSlug);

  // Visible comments: approved for everyone, + pending for owner
  const visibleRootComments = isOwner 
    ? rootComments 
    : rootComments.filter(c => c.status === 'approved');

  const handleSubmit = async (content: string) => {
    await createComment(content);
  };

  const handleReply = async (content: string, parentId: string) => {
    await createComment(content, parentId);
  };

  const handleUpdateStatus = async (commentId: string, status: 'approved' | 'rejected') => {
    await updateComment(commentId, { status });
  };

  const handleDelete = async (commentId: string) => {
    await deleteComment(commentId);
  };

  return (
    <section className="mt-12 pt-8 border-t border-border">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <MessageSquare className="w-5 h-5 text-primary" />
          <h2 className="text-xl font-semibold text-foreground">
            Коментарі
          </h2>
          {approvedComments.length > 0 && (
            <Badge variant="secondary">
              {approvedComments.length}
            </Badge>
          )}
        </div>
        
        {/* Owner: show pending count */}
        {isOwner && pendingComments.length > 0 && (
          <Badge variant="outline" className="text-amber-600 border-amber-300">
            {pendingComments.length} очікують
          </Badge>
        )}
      </div>

      {/* Loading state */}
      {isLoading && (
        <div className="flex items-center justify-center py-8 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin mr-2" />
          Завантаження коментарів...
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="flex items-center gap-2 p-4 rounded-lg bg-destructive/10 text-destructive mb-6">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Comments list */}
      {!isLoading && !error && (
        <div className="space-y-4 mb-8">
          {visibleRootComments.length === 0 ? (
            <p className="text-center text-muted-foreground py-8">
              Поки що немає коментарів. Будьте першим!
            </p>
          ) : (
            visibleRootComments.map((comment) => (
              <CommentItem
                key={comment.id}
                comment={comment}
                replies={getReplies(comment.id)}
                isOwner={isOwner}
                onReply={handleReply}
                onUpdateStatus={handleUpdateStatus}
                onDelete={handleDelete}
              />
            ))
          )}
        </div>
      )}

      {/* Comment form */}
      {isOwner && (
        <>
          <Separator className="my-6" />
          <div className="bg-card p-4 rounded-lg border border-border">
            <h3 className="text-sm font-medium text-foreground mb-3">
              Додати коментар
            </h3>
            <CommentForm onSubmit={handleSubmit} />
          </div>
        </>
      )}

      {/* Guest message */}
      {!isOwner && (
        <div className="text-center py-4 text-sm text-muted-foreground">
          <p>Коментування доступне для власника сайту.</p>
        </div>
      )}
    </section>
  );
}
