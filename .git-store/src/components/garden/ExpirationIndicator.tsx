// Expiration Indicator Component
// Shows progress bar with color-coded time remaining

import { useMemo } from 'react';
import { Progress } from '@/components/ui/progress';
import { Clock } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ExpirationIndicatorProps {
  expiresAt: number;
  createdAt?: number;
  className?: string;
  showLabel?: boolean;
}

export function ExpirationIndicator({ 
  expiresAt, 
  createdAt,
  className,
  showLabel = true,
}: ExpirationIndicatorProps) {
  const { progress, color, timeRemaining, isUrgent } = useMemo(() => {
    const now = Date.now();
    const remaining = expiresAt - now;
    
    if (remaining <= 0) {
      return { progress: 0, color: 'bg-destructive', timeRemaining: 'Expired', isUrgent: true };
    }

    const oneHour = 60 * 60 * 1000;
    const sixHours = 6 * oneHour;
    
    // Calculate progress
    const created = createdAt || (expiresAt - 24 * oneHour);
    const total = expiresAt - created;
    const elapsed = now - created;
    const progressValue = Math.max(0, Math.min(100, (1 - elapsed / total) * 100));
    
    // Determine color based on remaining time
    let colorClass = 'bg-green-500';
    let urgent = false;
    
    if (remaining < oneHour) {
      colorClass = 'bg-destructive';
      urgent = true;
    } else if (remaining < sixHours) {
      colorClass = 'bg-orange-500';
    }
    
    // Format time remaining
    const minutes = Math.floor(remaining / (60 * 1000));
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    let timeStr = '';
    if (days > 0) {
      timeStr = `${days}d ${hours % 24}h`;
    } else if (hours > 0) {
      timeStr = `${hours}h ${minutes % 60}m`;
    } else {
      timeStr = `${minutes}m`;
    }
    
    return { 
      progress: progressValue, 
      color: colorClass, 
      timeRemaining: timeStr,
      isUrgent: urgent,
    };
  }, [expiresAt, createdAt]);

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <Clock className={cn(
        "h-3.5 w-3.5",
        isUrgent ? "text-destructive" : "text-muted-foreground"
      )} />
      {showLabel && (
        <span className={cn(
          "text-sm font-medium tabular-nums",
          color === 'bg-destructive' && "text-destructive",
          color === 'bg-orange-500' && "text-orange-600 dark:text-orange-400"
        )}>
          {timeRemaining}
        </span>
      )}
      <Progress 
        value={progress} 
        className="h-1.5 w-16 flex-shrink-0"
        indicatorClassName={color}
      />
    </div>
  );
}
