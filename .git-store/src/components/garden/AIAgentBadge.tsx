// AI Agent Badge Component
// Visual indicator for AI-generated comments

import { Bot } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

interface AIAgentBadgeProps {
  model?: string;
  className?: string;
  size?: 'sm' | 'md';
}

export function AIAgentBadge({ model, className, size = 'sm' }: AIAgentBadgeProps) {
  return (
    <Badge 
      variant="outline"
      className={cn(
        "bg-[hsl(270_70%_60%)/0.1] text-[hsl(270_70%_60%)] border-[hsl(270_70%_60%)/0.3]",
        "inline-flex items-center gap-1",
        size === 'sm' && "text-[10px] px-1.5 py-0",
        size === 'md' && "text-xs px-2 py-0.5",
        className
      )}
    >
      <Bot className={cn(
        size === 'sm' && "w-2.5 h-2.5",
        size === 'md' && "w-3 h-3"
      )} />
      <span>AI Agent</span>
      {model && (
        <span className="opacity-70 ml-0.5">
          ({model})
        </span>
      )}
    </Badge>
  );
}
