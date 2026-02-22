// Comment Item Component
// Displays a single comment with author info and moderation actions

import { useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import { uk } from 'date-fns/locale';
import { 
  MessageSquare, 
  Check, 
  X, 
  Trash2, 
  MoreHorizontal,
  User,
  Shield,
  Clock,
  Bot
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';
import { CommentForm } from './CommentForm';
import { AIAgentBadge } from './AIAgentBadge';
import type { Comment, CommentStatus } from '@/lib/comments/types';

interface CommentItemProps {
  comment: Comment;
  replies?: Comment[];
  isOwner: boolean;
  onReply?: (content: string, parentId: string) => Promise<void>;
  onUpdateStatus?: (commentId: string, status: CommentStatus) => Promise<void>;
  onDelete?: (commentId: string) => Promise<void>;
  depth?: number;
}

export function CommentItem({
  comment,
  replies = [],
  isOwner,
  onReply,
  onUpdateStatus,
  onDelete,
  depth = 0,
}: CommentItemProps) {
  const [isReplying, setIsReplying] = useState(false);
  
  const handleReply = async (content: string) => {
    if (onReply) {
      await onReply(content, comment.id);
      setIsReplying(false);
    }
  };

  const statusBadge = {
    pending: { label: 'Очікує', variant: 'outline' as const, className: 'text-amber-600 border-amber-300' },
    approved: { label: 'Схвалено', variant: 'outline' as const, className: 'text-green-600 border-green-300' },
    rejected: { label: 'Відхилено', variant: 'outline' as const, className: 'text-red-600 border-red-300' },
    merged: { label: 'Включено', variant: 'default' as const, className: 'bg-primary' },
  };

  const status = statusBadge[comment.status];
  const timeAgo = formatDistanceToNow(new Date(comment.createdAt), { 
    addSuffix: true, 
    locale: uk 
  });

  // Don't show rejected comments to non-owners
  if (comment.status === 'rejected' && !isOwner) {
    return null;
  }

  const isAI = comment.author.type === 'ai-agent';

  return (
    <div className={cn(
      "group",
      depth > 0 && "ml-6 pl-4 border-l-2 border-border"
    )}>
      <div className={cn(
        "p-4 rounded-lg transition-colors",
        comment.status === 'pending' && "bg-amber-50/50 dark:bg-amber-950/20",
        comment.status === 'approved' && !isAI && "bg-card",
        comment.status === 'approved' && isAI && "bg-[hsl(270_70%_97%)] dark:bg-[hsl(270_30%_15%)] border-l-4 border-[hsl(270_70%_60%)]",
        comment.status === 'rejected' && "bg-red-50/50 dark:bg-red-950/20 opacity-60",
      )}>
        {/* Header */}
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex items-center gap-2 text-sm">
            <div className={cn(
              "w-8 h-8 rounded-full flex items-center justify-center",
              comment.author.isOwner 
                ? "bg-primary/10 text-primary" 
                : isAI 
                  ? "bg-[hsl(270_70%_60%)/0.2] text-[hsl(270_70%_60%)]"
                  : "bg-muted text-muted-foreground"
            )}>
              {comment.author.isOwner ? (
                <Shield className="w-4 h-4" />
              ) : isAI ? (
                <Bot className="w-4 h-4" />
              ) : (
                <User className="w-4 h-4" />
              )}
            </div>
            
            <div className="flex items-center gap-2">
              <span className="font-medium text-foreground">
                {comment.author.name}
              </span>
              {comment.author.isOwner && (
                <Badge variant="secondary" className="text-xs">
                  Автор
                </Badge>
              )}
              {isAI && (
                <AIAgentBadge model={comment.author.agentModel} size="sm" />
              )}
            </div>
            
            <span className="text-muted-foreground flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {timeAgo}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {/* Status badge (visible to owner) */}
            {isOwner && comment.status !== 'approved' && (
              <Badge variant={status.variant} className={status.className}>
                {status.label}
              </Badge>
            )}
            
            {/* Actions dropdown */}
            {isOwner && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="opacity-0 group-hover:opacity-100 transition-opacity h-8 w-8"
                  >
                    <MoreHorizontal className="w-4 h-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  {comment.status === 'pending' && (
                    <>
                      <DropdownMenuItem
                        onClick={() => onUpdateStatus?.(comment.id, 'approved')}
                        className="text-green-600"
                      >
                        <Check className="w-4 h-4 mr-2" />
                        Схвалити
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onUpdateStatus?.(comment.id, 'rejected')}
                        className="text-red-600"
                      >
                        <X className="w-4 h-4 mr-2" />
                        Відхилити
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                    </>
                  )}
                  <DropdownMenuItem
                    onClick={() => onDelete?.(comment.id)}
                    className="text-destructive"
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Видалити
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        </div>

        {/* Content */}
        <div className="prose prose-sm dark:prose-invert max-w-none text-foreground">
          <p className="whitespace-pre-wrap">{comment.content}</p>
        </div>

        {/* Reply button */}
        {!isReplying && depth === 0 && onReply && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsReplying(true)}
            className="mt-2 text-muted-foreground hover:text-foreground gap-1"
          >
            <MessageSquare className="w-4 h-4" />
            Відповісти
          </Button>
        )}

        {/* Reply form */}
        {isReplying && (
          <div className="mt-4">
            <CommentForm
              onSubmit={handleReply}
              placeholder="Напишіть відповідь..."
              submitLabel="Відповісти"
              isReply
              onCancel={() => setIsReplying(false)}
              autoFocus
            />
          </div>
        )}
      </div>

      {/* Replies */}
      {replies.length > 0 && (
        <div className="mt-2 space-y-2">
          {replies.map((reply) => (
            <CommentItem
              key={reply.id}
              comment={reply}
              isOwner={isOwner}
              onUpdateStatus={onUpdateStatus}
              onDelete={onDelete}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}
