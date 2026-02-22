import { ChatParticipant } from '@/lib/chat/types';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { ChevronDown, Bot } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ColleaguePickerProps {
  selected: ChatParticipant;
  colleagues: ChatParticipant[];
  onSelect: (colleague: ChatParticipant) => void;
  disabled?: boolean;
}

const roleDescriptions: Record<string, string> = {
  archivist: 'Organizes & summarizes content',
  'tech-writer': 'Creates documentation',
  architect: 'Designs system structure',
};

export function ColleaguePicker({
  selected,
  colleagues,
  onSelect,
  disabled,
}: ColleaguePickerProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          disabled={disabled}
          className="gap-2 min-w-[140px] justify-between"
        >
          <span className="flex items-center gap-2">
            <span>{selected.avatar}</span>
            <span>{selected.name}</span>
          </span>
          <ChevronDown className="h-4 w-4 opacity-50" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-[220px]">
        <DropdownMenuLabel className="flex items-center gap-2">
          <Bot className="h-4 w-4" />
          AI Colleagues
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {colleagues.map((colleague) => (
          <DropdownMenuItem
            key={colleague.id}
            onClick={() => onSelect(colleague)}
            className={cn(
              'flex flex-col items-start gap-0.5 cursor-pointer',
              selected.id === colleague.id && 'bg-accent'
            )}
          >
            <div className="flex items-center gap-2 font-medium">
              <span>{colleague.avatar}</span>
              <span>{colleague.name}</span>
              {selected.id === colleague.id && (
                <span className="text-xs text-primary">✓</span>
              )}
            </div>
            <span className="text-xs text-muted-foreground pl-6">
              {roleDescriptions[colleague.role] || colleague.role}
            </span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
