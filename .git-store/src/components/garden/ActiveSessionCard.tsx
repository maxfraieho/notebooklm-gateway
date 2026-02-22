// Active MCP Session Card Component with Format Links

import { useState, useEffect } from 'react';
import { Copy, Trash2, BookOpen, Clock, Folder, Check, FileJson, FileText, Database } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import type { MCPSession } from '@/hooks/useMCPSessions';

interface ActiveSessionCardProps {
  session: MCPSession;
  onDelete: (sessionId: string) => Promise<boolean | void>;
  onCopy: (endpoint: string) => void;
  onShowInstructions: (sessionId: string) => void;
}

function formatTimeRemaining(expiresAt: Date): string {
  const now = new Date();
  const diff = expiresAt.getTime() - now.getTime();
  
  if (diff <= 0) return 'Закінчився';
  
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  
  if (hours > 0) {
    const remainingMinutes = minutes % 60;
    return `${hours}г ${remainingMinutes}хв`;
  }
  
  return `${minutes}хв`;
}

function formatExpirationDate(expiresAt: Date): string {
  return expiresAt.toLocaleString('uk-UA', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

const FORMAT_INFO = [
  { key: 'json', label: 'JSON', icon: FileJson, description: 'Структуровані дані' },
  { key: 'markdown', label: 'MD', icon: FileText, description: 'Markdown + YAML' },
  { key: 'jsonl', label: 'JSONL', icon: Database, description: 'JSON Lines' },
] as const;

export function ActiveSessionCard({
  session,
  onDelete,
  onCopy,
  onShowInstructions,
}: ActiveSessionCardProps) {
  const [timeRemaining, setTimeRemaining] = useState(formatTimeRemaining(session.expiresAt));
  const [copied, setCopied] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Update countdown every second
  useEffect(() => {
    const interval = setInterval(() => {
      setTimeRemaining(formatTimeRemaining(session.expiresAt));
    }, 1000);
    
    return () => clearInterval(interval);
  }, [session.expiresAt]);

  const handleCopyFormat = (formatKey: string, url: string) => {
    navigator.clipboard.writeText(url);
    setCopied(formatKey);
    toast.success(`📋 ${formatKey.toUpperCase()} URL скопійовано`);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleCopyMain = () => {
    onCopy(session.endpoint);
    setCopied('main');
    setTimeout(() => setCopied(null), 2000);
  };

  const handleDelete = async () => {
    setIsDeleting(true);
    await onDelete(session.sessionId);
    setIsDeleting(false);
  };

  const shortSessionId = session.sessionId.slice(0, 16);
  const isExpired = new Date() >= session.expiresAt;
  const displayFolders = session.folders.slice(0, 2);
  const moreFolders = session.folders.length - 2;

  return (
    <div className="p-4 bg-card border border-border rounded-lg space-y-3">
      {/* Session ID & Note Count */}
      <div className="flex items-center justify-between">
        <span className="font-mono text-sm text-muted-foreground">
          Session: {shortSessionId}...
        </span>
        <div className="flex items-center gap-2">
          {session.noteCount !== undefined && (
            <span className="text-xs bg-primary/10 text-primary px-2 py-0.5 rounded">
              {session.noteCount} нотаток
            </span>
          )}
          {isExpired && (
            <span className="text-xs text-destructive font-medium">Закінчився</span>
          )}
        </div>
      </div>

      {/* Expiration */}
      <div className="flex items-center gap-2 text-sm">
        <Clock className="w-4 h-4 text-muted-foreground" />
        <span className="text-muted-foreground">
          {formatExpirationDate(session.expiresAt)}
        </span>
        <span className={`font-medium ${isExpired ? 'text-destructive' : 'text-primary'}`}>
          ({timeRemaining})
        </span>
      </div>

      {/* Folders */}
      <div className="flex items-center gap-2 text-sm">
        <Folder className="w-4 h-4 text-muted-foreground flex-shrink-0" />
        <div className="flex flex-wrap gap-1">
          {displayFolders.map((folder, i) => (
            <span key={i} className="bg-secondary px-2 py-0.5 rounded text-xs">
              {folder.split('/').pop()}
            </span>
          ))}
          {moreFolders > 0 && (
            <span className="text-xs text-muted-foreground">+{moreFolders} more</span>
          )}
        </div>
      </div>

      {/* Format URLs */}
      {session.formats && (
        <div className="space-y-2">
          <span className="text-xs text-muted-foreground font-medium">Формати:</span>
          <div className="grid grid-cols-3 gap-1">
            {FORMAT_INFO.map(({ key, label, icon: Icon, description }) => {
              const url = session.formats?.[key as keyof typeof session.formats];
              if (!url) return null;
              
              return (
                <Button
                  key={key}
                  variant="outline"
                  size="sm"
                  onClick={() => handleCopyFormat(key, url)}
                  disabled={isExpired}
                  className="h-auto py-2 px-2 flex flex-col items-center gap-1"
                  title={description}
                >
                  {copied === key ? (
                    <Check className="w-3 h-3 text-green-500" />
                  ) : (
                    <Icon className="w-3 h-3" />
                  )}
                  <span className="text-xs">{label}</span>
                </Button>
              );
            })}
          </div>
        </div>
      )}

      {/* Main Endpoint URL (fallback if no formats) */}
      {!session.formats && (
        <div className="bg-muted p-2 rounded text-xs font-mono break-all text-muted-foreground">
          {session.endpoint}
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={handleCopyMain}
          className="flex-1 gap-1"
          disabled={isExpired}
        >
          {copied === 'main' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
          {copied === 'main' ? 'Скопійовано' : 'Copy Base URL'}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => onShowInstructions(session.sessionId)}
          className="gap-1"
        >
          <BookOpen className="w-3 h-3" />
          Інструкції
        </Button>
        <Button
          variant="destructive"
          size="sm"
          onClick={handleDelete}
          disabled={isDeleting}
          className="gap-1"
        >
          <Trash2 className="w-3 h-3" />
        </Button>
      </div>
    </div>
  );
}
