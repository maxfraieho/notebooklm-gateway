import { useMemo, useState } from 'react';
import { Filter, Search, SlidersHorizontal, X, ArrowUpDown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
  SheetFooter,
  SheetClose,
} from '@/components/ui/sheet';
import { Separator } from '@/components/ui/separator';
import { useIsMobile } from '@/hooks/use-mobile';
import { cn } from '@/lib/utils';
import type { NotebookLMChat } from '@/hooks/useNotebookLMChats';

export type AccessTypeFilter = 'all' | 'web' | 'mcp' | 'both';
export type SortOption = 'recent' | 'oldest' | 'name-asc' | 'name-desc';

export interface ChatsWallFiltersState {
  query: string;
  accessType: AccessTypeFilter;
  zoneId: string; // 'all' or specific zone id
  sort: SortOption;
}

interface ChatsWallFiltersProps {
  filters: ChatsWallFiltersState;
  onChange: (filters: ChatsWallFiltersState) => void;
  availableZones: Array<{ id: string; name: string }>;
  activeFiltersCount: number;
  className?: string;
}

const SORT_OPTIONS: Array<{ value: SortOption; label: string }> = [
  { value: 'recent', label: 'Most recent' },
  { value: 'oldest', label: 'Oldest first' },
  { value: 'name-asc', label: 'Name A-Z' },
  { value: 'name-desc', label: 'Name Z-A' },
];

const ACCESS_TYPE_OPTIONS: Array<{ value: AccessTypeFilter; label: string }> = [
  { value: 'all', label: 'All types' },
  { value: 'web', label: 'Web only' },
  { value: 'mcp', label: 'MCP only' },
  { value: 'both', label: 'Web + MCP' },
];

function FilterControls({
  filters,
  onChange,
  availableZones,
  onReset,
}: ChatsWallFiltersProps & { onReset: () => void }) {
  return (
    <div className="space-y-4">
      {/* Access Type */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-muted-foreground">Access Type</label>
        <Select
          value={filters.accessType}
          onValueChange={(v) => onChange({ ...filters, accessType: v as AccessTypeFilter })}
        >
          <SelectTrigger className="h-9">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            {ACCESS_TYPE_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Zone Filter */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-muted-foreground">Zone</label>
        <Select
          value={filters.zoneId}
          onValueChange={(v) => onChange({ ...filters, zoneId: v })}
        >
          <SelectTrigger className="h-9">
            <SelectValue placeholder="All zones" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All zones</SelectItem>
            {availableZones.map((zone) => (
              <SelectItem key={zone.id} value={zone.id}>
                {zone.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Sort */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-muted-foreground">Sort by</label>
        <Select
          value={filters.sort}
          onValueChange={(v) => onChange({ ...filters, sort: v as SortOption })}
        >
          <SelectTrigger className="h-9">
            <SelectValue placeholder="Most recent" />
          </SelectTrigger>
          <SelectContent>
            {SORT_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Reset */}
      <Button variant="ghost" size="sm" className="w-full" onClick={onReset}>
        <X className="h-4 w-4 mr-2" />
        Reset filters
      </Button>
    </div>
  );
}

export function ChatsWallFilters({
  filters,
  onChange,
  availableZones,
  activeFiltersCount,
  className,
}: ChatsWallFiltersProps) {
  const isMobile = useIsMobile();
  const [sheetOpen, setSheetOpen] = useState(false);

  const handleReset = () => {
    onChange({
      query: '',
      accessType: 'all',
      zoneId: 'all',
      sort: 'recent',
    });
  };

  return (
    <div className={cn('space-y-3', className)}>
      {/* Search + Filter button row */}
      <div className="flex gap-2">
        {/* Search input */}
        <div className="relative flex-1">
          <Search className="h-4 w-4 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
          <Input
            value={filters.query}
            onChange={(e) => onChange({ ...filters, query: e.target.value })}
            placeholder="Search chats…"
            className="pl-8 h-9"
          />
          {filters.query && (
            <Button
              variant="ghost"
              size="icon"
              className="h-5 w-5 absolute right-2 top-1/2 -translate-y-1/2"
              onClick={() => onChange({ ...filters, query: '' })}
            >
              <X className="h-3 w-3" />
            </Button>
          )}
        </div>

        {/* Mobile: Sheet trigger */}
        {isMobile ? (
          <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
            <SheetTrigger asChild>
              <Button variant="outline" size="icon" className="h-9 w-9 relative shrink-0">
                <SlidersHorizontal className="h-4 w-4" />
                {activeFiltersCount > 0 && (
                  <Badge
                    variant="destructive"
                    className="absolute -top-1 -right-1 h-4 w-4 p-0 text-[10px] flex items-center justify-center"
                  >
                    {activeFiltersCount}
                  </Badge>
                )}
              </Button>
            </SheetTrigger>
            <SheetContent side="bottom" className="h-auto max-h-[80vh]">
              <SheetHeader>
                <SheetTitle className="flex items-center gap-2">
                  <Filter className="h-4 w-4" />
                  Filter & Sort
                </SheetTitle>
              </SheetHeader>
              <Separator className="my-4" />
              <FilterControls
                filters={filters}
                onChange={onChange}
                availableZones={availableZones}
                activeFiltersCount={activeFiltersCount}
                onReset={() => {
                  handleReset();
                  setSheetOpen(false);
                }}
              />
              <SheetFooter className="mt-4">
                <SheetClose asChild>
                  <Button className="w-full">Apply</Button>
                </SheetClose>
              </SheetFooter>
            </SheetContent>
          </Sheet>
        ) : (
          /* Desktop: Sort dropdown inline */
          <Select
            value={filters.sort}
            onValueChange={(v) => onChange({ ...filters, sort: v as SortOption })}
          >
            <SelectTrigger className="h-9 w-[140px] shrink-0">
              <ArrowUpDown className="h-3.5 w-3.5 mr-1.5" />
              <SelectValue placeholder="Sort" />
            </SelectTrigger>
            <SelectContent>
              {SORT_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      {/* Desktop: Inline filter chips */}
      {!isMobile && (
        <div className="flex flex-wrap gap-2">
          {/* Access Type */}
          <Select
            value={filters.accessType}
            onValueChange={(v) => onChange({ ...filters, accessType: v as AccessTypeFilter })}
          >
            <SelectTrigger className="h-7 w-auto text-xs gap-1 px-2">
              <SelectValue placeholder="Access type" />
            </SelectTrigger>
            <SelectContent>
              {ACCESS_TYPE_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* Zone */}
          <Select
            value={filters.zoneId}
            onValueChange={(v) => onChange({ ...filters, zoneId: v })}
          >
            <SelectTrigger className="h-7 w-auto text-xs gap-1 px-2 max-w-[150px]">
              <SelectValue placeholder="Zone" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All zones</SelectItem>
              {availableZones.map((zone) => (
                <SelectItem key={zone.id} value={zone.id}>
                  {zone.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* Reset button if filters active */}
          {activeFiltersCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs px-2 text-muted-foreground"
              onClick={handleReset}
            >
              <X className="h-3 w-3 mr-1" />
              Clear ({activeFiltersCount})
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

// Helper to apply filters and sorting to chats list
export function applyChatsFilters(
  chats: NotebookLMChat[],
  filters: ChatsWallFiltersState,
  tabFilter: 'active' | 'archived' | 'all'
): NotebookLMChat[] {
  let result = [...chats];

  // Tab filter
  if (tabFilter === 'active') {
    result = result.filter((c) => c.status !== 'archived');
  } else if (tabFilter === 'archived') {
    result = result.filter((c) => c.status === 'archived');
  }

  // Search query
  const q = filters.query.trim().toLowerCase();
  if (q) {
    result = result.filter((c) => {
      const hay = `${c.title} ${c.zoneName || ''} ${c.notebookUrl}`.toLowerCase();
      return hay.includes(q);
    });
  }

  // Access type filter
  if (filters.accessType !== 'all') {
    result = result.filter((c) => c.accessType === filters.accessType);
  }

  // Zone filter
  if (filters.zoneId !== 'all') {
    result = result.filter((c) => c.zoneId === filters.zoneId);
  }

  // Sort (always pinned first, then by selected sort)
  const sortFn = (a: NotebookLMChat, b: NotebookLMChat): number => {
    // Pinned always first
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    
    // Then apply selected sort
    switch (filters.sort) {
      case 'recent':
        return b.updatedAt - a.updatedAt;
      case 'oldest':
        return a.updatedAt - b.updatedAt;
      case 'name-asc':
        return a.title.localeCompare(b.title);
      case 'name-desc':
        return b.title.localeCompare(a.title);
      default:
        return 0;
    }
  };

  result.sort(sortFn);

  return result;
}
