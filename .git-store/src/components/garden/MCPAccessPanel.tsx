// MCP Access Panel Component

import { useState } from 'react';
import { Link2, Clock, Loader2, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

interface MCPAccessPanelProps {
  selectedFolders: string[];
  noteCount: number;
  onCreateAccess: (ttlMinutes: number) => Promise<void>;
  isCreating: boolean;
  error: string | null;
}

const TTL_OPTIONS = [
  { value: 15, label: '15 хв' },
  { value: 60, label: '1 год' },
  { value: 1440, label: '24 год' },
];

export function MCPAccessPanel({
  selectedFolders,
  noteCount,
  onCreateAccess,
  isCreating,
  error,
}: MCPAccessPanelProps) {
  const [selectedTTL, setSelectedTTL] = useState<number>(60);
  const [customTTL, setCustomTTL] = useState<string>('');
  const [isCustom, setIsCustom] = useState(false);

  const handleCreate = async () => {
    const ttl = isCustom ? parseInt(customTTL) : selectedTTL;
    if (isNaN(ttl) || ttl < 5 || ttl > 1440) {
      return;
    }
    await onCreateAccess(ttl);
  };

  const effectiveTTL = isCustom ? parseInt(customTTL) : selectedTTL;
  const isValidTTL = !isNaN(effectiveTTL) && effectiveTTL >= 5 && effectiveTTL <= 1440;
  const canCreate = selectedFolders.length > 0 && isValidTTL && !isCreating;

  return (
    <div className="space-y-4 p-4 bg-secondary/30 rounded-lg border border-border">
      <div className="flex items-center gap-2">
        <Link2 className="w-5 h-5 text-primary" />
        <h3 className="font-semibold text-sm">🔗 MCP Access</h3>
      </div>

      <p className="text-sm text-muted-foreground">
        Поділіться вибраними папками як MCP endpoint для Claude Desktop, CLI або прямого API доступу.
      </p>

      {/* TTL Selection */}
      <div className="space-y-2">
        <label className="text-sm font-medium flex items-center gap-2">
          <Clock className="w-4 h-4" />
          Time-to-Live
        </label>
        
        <div className="flex flex-wrap gap-2">
          {TTL_OPTIONS.map((option) => (
            <Button
              key={option.value}
              variant={!isCustom && selectedTTL === option.value ? 'default' : 'outline'}
              size="sm"
              onClick={() => {
                setSelectedTTL(option.value);
                setIsCustom(false);
              }}
            >
              {option.label}
            </Button>
          ))}
          <Button
            variant={isCustom ? 'default' : 'outline'}
            size="sm"
            onClick={() => setIsCustom(true)}
          >
            Інший
          </Button>
        </div>

        {isCustom && (
          <div className="flex items-center gap-2">
            <Input
              type="number"
              min={5}
              max={1440}
              placeholder="Хвилини (5-1440)"
              value={customTTL}
              onChange={(e) => setCustomTTL(e.target.value)}
              className="w-40"
            />
            <span className="text-sm text-muted-foreground">хвилин</span>
          </div>
        )}
      </div>

      {/* Error Display */}
      {error && (
        <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-2 rounded">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Selection Info */}
      <div className="text-sm text-muted-foreground space-y-1">
        {selectedFolders.length === 0 ? (
          <span className="text-amber-500">⚠️ Оберіть папки вище</span>
        ) : (
          <>
            <div>📁 Обрано папок: {selectedFolders.length}</div>
            <div>📝 Нотаток: {noteCount}</div>
          </>
        )}
      </div>

      {/* Create Button */}
      <Button
        onClick={handleCreate}
        disabled={!canCreate}
        className={cn("w-full gap-2", isCreating && "opacity-70")}
      >
        {isCreating ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            Створення...
          </>
        ) : (
          <>
            <Link2 className="w-4 h-4" />
            Створити MCP Access
          </>
        )}
      </Button>
    </div>
  );
}
