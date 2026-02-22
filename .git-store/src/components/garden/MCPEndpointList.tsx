// MCP Endpoint List Component

import { useState } from 'react';
import { Link2Off } from 'lucide-react';
import { ActiveSessionCard } from './ActiveSessionCard';
import { ConnectionInstructions } from './ConnectionInstructions';
import type { MCPSession } from '@/hooks/useMCPSessions';

interface MCPEndpointListProps {
  sessions: MCPSession[];
  onDeleteSession: (sessionId: string) => Promise<boolean | void>;
  onCopyEndpoint: (endpoint: string) => void;
}

export function MCPEndpointList({
  sessions,
  onDeleteSession,
  onCopyEndpoint,
}: MCPEndpointListProps) {
  const [instructionsSession, setInstructionsSession] = useState<MCPSession | null>(null);

  // Sort by expiration time (soonest first)
  const sortedSessions = [...sessions].sort(
    (a, b) => a.expiresAt.getTime() - b.expiresAt.getTime()
  );

  const handleShowInstructions = (sessionId: string) => {
    const session = sessions.find((s) => s.sessionId === sessionId);
    if (session) {
      setInstructionsSession(session);
    }
  };

  if (sessions.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-center">
        <Link2Off className="w-10 h-10 text-muted-foreground/50 mb-3" />
        <p className="text-sm text-muted-foreground">
          Немає активних MCP сесій
        </p>
        <p className="text-xs text-muted-foreground mt-1">
          Створіть нову сесію, щоб поділитися доступом
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium">📋 Активні MCP Endpoints</span>
        <span className="text-xs text-muted-foreground">({sessions.length})</span>
      </div>

      <div className="space-y-3 max-h-[400px] overflow-y-auto pr-1">
        {sortedSessions.map((session) => (
          <ActiveSessionCard
            key={session.sessionId}
            session={session}
            onDelete={onDeleteSession}
            onCopy={onCopyEndpoint}
            onShowInstructions={handleShowInstructions}
          />
        ))}
      </div>

      {instructionsSession && (
        <ConnectionInstructions
          sessionId={instructionsSession.sessionId}
          endpoint={instructionsSession.endpoint}
          isOpen={!!instructionsSession}
          onClose={() => setInstructionsSession(null)}
        />
      )}
    </div>
  );
}
