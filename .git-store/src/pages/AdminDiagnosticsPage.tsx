import { useMemo, useState } from 'react';
import { GardenHeader } from '@/components/garden/GardenHeader';
import { GardenFooter } from '@/components/garden/GardenFooter';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { getApiErrors } from '@/lib/api/apiErrorStore';
import { chatNotebookLM, getAuthStatus, getGatewayBaseUrl, getGitStatus, pingHealth } from '@/lib/api/mcpGatewayClient';
import { toast } from 'sonner';
import { Copy } from 'lucide-react';
import { z } from 'zod';

const chatTestSchema = z.object({
  notebookUrl: z.string().trim().url(),
  message: z.string().trim().min(1).max(5000),
  kind: z.enum(['answer', 'summary', 'study_guide', 'flashcards']),
});

export default function AdminDiagnosticsPage() {
  const { isAuthenticated, gatewayAvailable } = useOwnerAuth();
  const [health, setHealth] = useState<any>(null);
  const [authStatus, setAuthStatus] = useState<any>(null);
  const [gitStatus, setGitStatus] = useState<any>(null);
  const [gitPath, setGitPath] = useState('src/site/notes/Test Garden Seedling 2026.md');
  const [gitLoading, setGitLoading] = useState(false);
  const [chatTest, setChatTest] = useState({
    notebookUrl: '',
    message: 'Сформуй стислий підсумок основних тез.',
    kind: 'summary' as 'answer' | 'summary' | 'study_guide' | 'flashcards',
  });
  const [chatResult, setChatResult] = useState<any>(null);
  const [chatError, setChatError] = useState<any>(null);
  const [chatLoading, setChatLoading] = useState(false);
  const baseUrl = getGatewayBaseUrl();

  const errors = useMemo(() => getApiErrors(), [health]);

  const copy = async (v: string) => {
    try {
      await navigator.clipboard.writeText(v);
      toast.success('Copied');
    } catch {
      toast.error('Copy failed');
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <GardenHeader />
      <main className="flex-1 max-w-5xl mx-auto w-full px-4 py-8 space-y-6">
        <header className="space-y-1">
          <h1 className="text-3xl font-semibold text-foreground font-serif">Diagnostics</h1>
          <p className="text-sm text-muted-foreground">
            Quick checks for the MCP gateway + NotebookLM flows.
          </p>
        </header>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Runtime</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={gatewayAvailable ? 'default' : 'destructive'}>
                gateway {gatewayAvailable ? 'reachable' : 'unreachable'}
              </Badge>
              <Badge variant={isAuthenticated ? 'default' : 'secondary'}>
                owner {isAuthenticated ? 'authenticated' : 'not authenticated'}
              </Badge>
            </div>
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="text-sm font-medium">Gateway base URL</p>
                <p className="text-sm text-muted-foreground truncate">{baseUrl}</p>
              </div>
              <Button variant="outline" size="sm" className="gap-2" onClick={() => copy(baseUrl)}>
                <Copy className="h-4 w-4" />
                Copy
              </Button>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="default"
                size="sm"
                onClick={async () => {
                  try {
                    const res = await pingHealth();
                    setHealth(res);
                    toast.success('Health OK');
                  } catch {
                    toast.error('Health check failed');
                  }
                }}
              >
                Ping /health
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  try {
                    const res = await getAuthStatus();
                    setAuthStatus(res);
                    toast.success('Auth status loaded');
                  } catch {
                    toast.error('Auth status failed');
                  }
                }}
              >
                Check /auth/status
              </Button>
            </div>

            {health && (
              <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">
                {JSON.stringify(health, null, 2)}
              </pre>
            )}

            {authStatus && (
              <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">
                {JSON.stringify(authStatus, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Git Status (Replit Backend)</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Tests <span className="font-mono">GET /v1/git/status</span> — checks if file exists in <span className="font-mono">garden-seedling</span> repo.
            </p>
            
            <div className="flex gap-2">
              <Input
                value={gitPath}
                onChange={(e) => setGitPath(e.target.value)}
                placeholder="README.md"
                className="flex-1"
              />
              <Button
                variant="default"
                size="sm"
                disabled={gitLoading || !gitPath.trim()}
                onClick={async () => {
                  setGitStatus(null);
                  setGitLoading(true);
                  try {
                    const res = await getGitStatus(gitPath.trim());
                    setGitStatus(res);
                    if (res.exists) {
                      toast.success(`File exists (sha: ${res.sha?.slice(0, 7)}...)`);
                    } else {
                      toast.info('File does not exist');
                    }
                  } catch (e) {
                    const msg = e && typeof e === 'object' && 'message' in (e as any) ? String((e as any).message) : 'Git status failed';
                    toast.error(msg);
                    setGitStatus({ error: e });
                  } finally {
                    setGitLoading(false);
                  }
                }}
              >
                {gitLoading ? 'Checking…' : 'Check'}
              </Button>
            </div>

            {gitStatus && (
              <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">
                {JSON.stringify(gitStatus, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Test NotebookLM Chat</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Sends a test request via the gateway <span className="font-mono">POST /notebooklm/chat</span> (owner-only).
            </p>

            <div className="space-y-2">
              <div className="space-y-1">
                <p className="text-sm font-medium">Notebook URL</p>
                <Input
                  value={chatTest.notebookUrl}
                  onChange={(e) => setChatTest((s) => ({ ...s, notebookUrl: e.target.value }))}
                  placeholder="https://notebooklm.google.com/notebook/..."
                />
              </div>

              <div className="space-y-1">
                <p className="text-sm font-medium">Kind</p>
                <div className="flex flex-wrap gap-2">
                  {(['answer', 'summary', 'study_guide', 'flashcards'] as const).map((k) => (
                    <Button
                      key={k}
                      type="button"
                      variant={chatTest.kind === k ? 'default' : 'outline'}
                      size="sm"
                      onClick={() => setChatTest((s) => ({ ...s, kind: k }))}
                    >
                      {k}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="space-y-1">
                <p className="text-sm font-medium">Message</p>
                <Textarea
                  value={chatTest.message}
                  onChange={(e) => setChatTest((s) => ({ ...s, message: e.target.value }))}
                  rows={4}
                  placeholder="Type a question..."
                />
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              <Button
                variant="default"
                size="sm"
                disabled={chatLoading}
                onClick={async () => {
                  setChatResult(null);
                  setChatError(null);

                  const parsed = chatTestSchema.safeParse(chatTest);
                  if (!parsed.success) {
                    toast.error('Invalid input');
                    setChatError(parsed.error.format());
                    return;
                  }

                  setChatLoading(true);
                  try {
                    const res = await chatNotebookLM({
                      notebookUrl: parsed.data.notebookUrl,
                      message: parsed.data.message,
                      kind: parsed.data.kind,
                      history: [],
                    });
                    setChatResult(res);
                    toast.success('Chat OK');
                  } catch (e) {
                    setChatError(e);
                    const msg = e && typeof e === 'object' && 'message' in (e as any) ? String((e as any).message) : 'Chat failed';
                    toast.error(msg);
                  } finally {
                    setChatLoading(false);
                  }
                }}
              >
                {chatLoading ? 'Sending…' : 'Send test message'}
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setChatResult(null);
                  setChatError(null);
                }}
              >
                Clear
              </Button>
            </div>

            {chatResult && (
              <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">
                {JSON.stringify(chatResult, null, 2)}
              </pre>
            )}

            {chatError && (
              <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">
                {JSON.stringify(chatError, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Last API errors (client)</CardTitle>
          </CardHeader>
          <CardContent>
            {errors.length === 0 ? (
              <p className="text-sm text-muted-foreground">No errors recorded.</p>
            ) : (
              <ScrollArea className="h-56">
                <div className="space-y-3 pr-3">
                  {errors.map((e, idx) => (
                    <div key={idx} className="border border-border rounded-md p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-sm font-medium truncate">{e.message}</p>
                        {e.httpStatus ? (
                          <Badge variant="outline">{e.httpStatus}</Badge>
                        ) : null}
                      </div>
                      {(e.code || e.details) && (
                        <pre className="text-xs text-muted-foreground mt-2 overflow-auto">
                          {JSON.stringify({ code: e.code, details: e.details }, null, 2)}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </main>
      <GardenFooter />
    </div>
  );
}
