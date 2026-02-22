import { useState, useMemo } from 'react';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2, Shield, Lock, Database, Eye, EyeOff, CheckCircle2, AlertCircle, Activity, Copy } from 'lucide-react';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { useLocale } from '@/hooks/useLocale';
import { Layout } from '@/components/garden/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Textarea } from '@/components/ui/textarea';
import { toast } from 'sonner';
import { getApiErrors } from '@/lib/api/apiErrorStore';
import { chatNotebookLM, getAuthStatus, getGatewayBaseUrl, getGitStatus, pingHealth } from '@/lib/api/mcpGatewayClient';
import { z } from 'zod';

const chatTestSchema = z.object({
  notebookUrl: z.string().trim().url(),
  message: z.string().trim().min(1).max(5000),
  kind: z.enum(['answer', 'summary', 'study_guide', 'flashcards']),
});

export default function AdminSettingsPage() {
  const { isAuthenticated, isLoading: authLoading, changePassword, error, gatewayAvailable } = useOwnerAuth();
  const { t } = useLocale();
  const navigate = useNavigate();
  const s = t.adminSettings;

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);

  // Diagnostics state
  const [health, setHealth] = useState<any>(null);
  const [authStatus, setAuthStatus] = useState<any>(null);
  const [gitStatus, setGitStatus] = useState<any>(null);
  const [gitPath, setGitPath] = useState('src/site/notes/Test Garden Seedling 2026.md');
  const [gitLoading, setGitLoading] = useState(false);
  const [chatTest, setChatTest] = useState<{
    notebookUrl: string;
    message: string;
    kind: 'answer' | 'summary' | 'study_guide' | 'flashcards';
  }>({
    notebookUrl: '',
    message: 'Сформуй стислий підсумок основних тез.',
    kind: 'summary',
  });
  const [chatResult, setChatResult] = useState<any>(null);
  const [chatError, setChatError] = useState<any>(null);
  const [chatLoading, setChatLoading] = useState(false);
  const baseUrl = getGatewayBaseUrl();
  const errors = useMemo(() => getApiErrors(), [health]);

  const copyText = async (v: string) => {
    try {
      await navigator.clipboard.writeText(v);
      toast.success(t.common.copied);
    } catch {
      toast.error('Copy failed');
    }
  };

  // Redirect if not authenticated
  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, authLoading, navigate]);

  const passwordsMatch = newPassword === confirmPassword;
  const isValidLength = newPassword.length >= 8;
  const canSubmit = currentPassword && newPassword && confirmPassword && passwordsMatch && isValidLength && !isChangingPassword;

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;

    setIsChangingPassword(true);
    const success = await changePassword(currentPassword, newPassword);
    setIsChangingPassword(false);

    if (success) {
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      toast.success(s.passwordChanged);
    }
  };

  if (authLoading) {
    return (
      <Layout hideSidebar>
        <div className="min-h-screen flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </Layout>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  return (
    <Layout hideSidebar>
      <div className="max-w-4xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-2 flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            {s.title}
          </h1>
          <p className="text-muted-foreground">{s.subtitle}</p>
        </div>

        <Tabs defaultValue="security" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="security" className="gap-2">
              <Lock className="h-4 w-4" />
              <span className="hidden sm:inline">{s.tabSecurity}</span>
            </TabsTrigger>
            <TabsTrigger value="access" className="gap-2">
              <Database className="h-4 w-4" />
              <span className="hidden sm:inline">{s.tabAccessControl}</span>
            </TabsTrigger>
            <TabsTrigger value="diagnostics" className="gap-2">
              <Activity className="h-4 w-4" />
              <span className="hidden sm:inline">{s.tabDiagnostics}</span>
            </TabsTrigger>
            <TabsTrigger value="advanced" className="gap-2">
              <Shield className="h-4 w-4" />
              <span className="hidden sm:inline">{s.tabAdvanced}</span>
            </TabsTrigger>
          </TabsList>

          {/* SECURITY TAB */}
          <TabsContent value="security" className="space-y-6 mt-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Lock className="h-5 w-5 text-primary" />
                  {s.changePassword}
                </CardTitle>
                <CardDescription>{s.changePasswordDesc}</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleChangePassword} className="space-y-4">
                  {error && (
                    <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-3 rounded-lg">
                      <AlertCircle className="w-4 h-4 flex-shrink-0" />
                      <span>{error}</span>
                    </div>
                  )}

                  <div className="space-y-2">
                    <Label htmlFor="current-password">{s.currentPassword}</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <Input
                        id="current-password"
                        type={showPasswords ? 'text' : 'password'}
                        value={currentPassword}
                        onChange={(e) => setCurrentPassword(e.target.value)}
                        placeholder={s.currentPasswordPlaceholder}
                        className="pl-10"
                        disabled={isChangingPassword}
                      />
                    </div>
                  </div>

                  <Separator />

                  <div className="space-y-2">
                    <Label htmlFor="new-password">{s.newPassword}</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <Input
                        id="new-password"
                        type={showPasswords ? 'text' : 'password'}
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder={s.newPasswordPlaceholder}
                        className="pl-10 pr-10"
                        disabled={isChangingPassword}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                        onClick={() => setShowPasswords(!showPasswords)}
                      >
                        {showPasswords ? (
                          <EyeOff className="h-4 w-4 text-muted-foreground" />
                        ) : (
                          <Eye className="h-4 w-4 text-muted-foreground" />
                        )}
                      </Button>
                    </div>
                    {newPassword && !isValidLength && (
                      <p className="text-xs text-destructive flex items-center gap-1">
                        {t.ownerAuth.passwordMinLength}
                      </p>
                    )}
                    {newPassword && isValidLength && (
                      <p className="text-xs text-green-600 dark:text-green-400 flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" />
                        {t.ownerAuth.passwordLengthOk}
                      </p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="confirm-new-password">{s.confirmNewPassword}</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <Input
                        id="confirm-new-password"
                        type={showPasswords ? 'text' : 'password'}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder={s.confirmNewPasswordPlaceholder}
                        className="pl-10 pr-10"
                        disabled={isChangingPassword}
                      />
                    </div>
                    {confirmPassword && !passwordsMatch && (
                      <p className="text-xs text-destructive">{t.ownerAuth.passwordsNoMatch}</p>
                    )}
                    {confirmPassword && passwordsMatch && (
                      <p className="text-xs text-green-600 dark:text-green-400 flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" />
                        {t.ownerAuth.passwordsMatch}
                      </p>
                    )}
                  </div>

                  <div className="flex justify-end pt-4">
                    <Button type="submit" disabled={!canSubmit}>
                      {isChangingPassword && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                      {s.changePasswordBtn}
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">{s.securityBestPractices}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm text-muted-foreground">
                <div className="flex gap-3">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 flex-shrink-0" />
                  <p>{s.tipStrongPassword}</p>
                </div>
                <div className="flex gap-3">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 flex-shrink-0" />
                  <p>{s.tipChangeRegularly}</p>
                </div>
                <div className="flex gap-3">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 flex-shrink-0" />
                  <p>{s.tipNeverShare}</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* ACCESS CONTROL TAB */}
          <TabsContent value="access" className="space-y-6 mt-6">
            <Card>
              <CardHeader>
                <CardTitle>{s.accessZones}</CardTitle>
                <CardDescription>{s.accessZonesDesc}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-sm text-muted-foreground mb-4">{s.accessZonesInfo}</div>
                <Button asChild variant="default">
                  <a href="/admin/zones">{s.manageZones}</a>
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">{s.accessControlInfo}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm text-muted-foreground">
                <div className="flex gap-3">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 flex-shrink-0" />
                  <p><strong>{s.webAccess}:</strong> {s.webAccessDesc}</p>
                </div>
                <div className="flex gap-3">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 flex-shrink-0" />
                  <p><strong>{s.mcpAccess}:</strong> {s.mcpAccessDesc}</p>
                </div>
                <div className="flex gap-3">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 flex-shrink-0" />
                  <p><strong>{s.ttlAccess}:</strong> {s.ttlAccessDesc}</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* DIAGNOSTICS TAB */}
          <TabsContent value="diagnostics" className="space-y-6 mt-6">
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
                  <Button variant="outline" size="sm" className="gap-2" onClick={() => copyText(baseUrl)}>
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="default" size="sm" onClick={async () => {
                    try { const res = await pingHealth(); setHealth(res); toast.success('Health OK'); }
                    catch { toast.error('Health check failed'); }
                  }}>Ping /health</Button>
                  <Button variant="outline" size="sm" onClick={async () => {
                    try { const res = await getAuthStatus(); setAuthStatus(res); toast.success('Auth status loaded'); }
                    catch { toast.error('Auth status failed'); }
                  }}>Check /auth/status</Button>
                </div>
                {health && <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">{JSON.stringify(health, null, 2)}</pre>}
                {authStatus && <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">{JSON.stringify(authStatus, null, 2)}</pre>}
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
                  <Input value={gitPath} onChange={(e) => setGitPath(e.target.value)} placeholder="src/site/notes/..." className="flex-1" />
                  <Button variant="default" size="sm" disabled={gitLoading || !gitPath.trim()} onClick={async () => {
                    setGitStatus(null); setGitLoading(true);
                    try {
                      const res = await getGitStatus(gitPath.trim()); setGitStatus(res);
                      if (res.exists) toast.success(`File exists (sha: ${res.sha?.slice(0, 7)}...)`);
                      else toast.info('File does not exist');
                    } catch (e) {
                      const msg = e && typeof e === 'object' && 'message' in (e as any) ? String((e as any).message) : 'Git status failed';
                      toast.error(msg); setGitStatus({ error: e });
                    } finally { setGitLoading(false); }
                  }}>{gitLoading ? 'Checking…' : 'Check'}</Button>
                </div>
                {gitStatus && <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">{JSON.stringify(gitStatus, null, 2)}</pre>}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Test NotebookLM Chat</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">
                  Sends a test request via <span className="font-mono">POST /notebooklm/chat</span> (owner-only).
                </p>
                <div className="space-y-2">
                  <div className="space-y-1">
                    <p className="text-sm font-medium">Notebook URL</p>
                    <Input value={chatTest.notebookUrl} onChange={(e) => setChatTest((c) => ({ ...c, notebookUrl: e.target.value }))} placeholder="https://notebooklm.google.com/notebook/..." />
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm font-medium">Kind</p>
                    <div className="flex flex-wrap gap-2">
                      {(['answer', 'summary', 'study_guide', 'flashcards'] as const).map((k) => (
                        <Button key={k} type="button" variant={chatTest.kind === k ? 'default' : 'outline'} size="sm" onClick={() => setChatTest((c) => ({ ...c, kind: k }))}>{k}</Button>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm font-medium">Message</p>
                    <Textarea value={chatTest.message} onChange={(e) => setChatTest((c) => ({ ...c, message: e.target.value }))} rows={4} placeholder="Type a question..." />
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="default" size="sm" disabled={chatLoading} onClick={async () => {
                    setChatResult(null); setChatError(null);
                    const parsed = chatTestSchema.safeParse(chatTest);
                    if (!parsed.success) { toast.error('Invalid input'); setChatError(parsed.error.format()); return; }
                    setChatLoading(true);
                    try {
                      const res = await chatNotebookLM({ notebookUrl: parsed.data.notebookUrl, message: parsed.data.message, kind: parsed.data.kind, history: [] });
                      setChatResult(res); toast.success('Chat OK');
                    } catch (e) {
                      setChatError(e);
                      const msg = e && typeof e === 'object' && 'message' in (e as any) ? String((e as any).message) : 'Chat failed';
                      toast.error(msg);
                    } finally { setChatLoading(false); }
                  }}>{chatLoading ? 'Sending…' : 'Send test message'}</Button>
                  <Button variant="outline" size="sm" onClick={() => { setChatResult(null); setChatError(null); }}>Clear</Button>
                </div>
                {chatResult && <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">{JSON.stringify(chatResult, null, 2)}</pre>}
                {chatError && <pre className="text-xs bg-muted/50 border border-border rounded-md p-3 overflow-auto">{JSON.stringify(chatError, null, 2)}</pre>}
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
                            {e.httpStatus ? <Badge variant="outline">{e.httpStatus}</Badge> : null}
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
          </TabsContent>

          {/* ADVANCED TAB */}
          <TabsContent value="advanced" className="space-y-6 mt-6">
            <Card>
              <CardHeader>
                <CardTitle>{s.gardenInfo}</CardTitle>
                <CardDescription>{s.gardenInfoDesc}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label className="text-xs uppercase text-muted-foreground">{s.status}</Label>
                  <p className="text-sm font-medium text-green-600 dark:text-green-400 mt-1 flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4" />
                    {s.activeReady}
                  </p>
                </div>
                <Separator />
                <div>
                  <Label className="text-xs uppercase text-muted-foreground">{s.ownerMode}</Label>
                  <p className="text-sm font-medium mt-1">{s.enabled}</p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>{s.advancedOptions}</CardTitle>
                <CardDescription>{s.advancedOptionsDesc}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="text-sm text-muted-foreground">
                  <ul className="space-y-2 text-xs">
                    <li className="flex gap-2"><span className="text-primary">•</span><span>{s.featureMcpGateway}</span></li>
                    <li className="flex gap-2"><span className="text-primary">•</span><span>{s.featureNotebookLM}</span></li>
                    <li className="flex gap-2"><span className="text-primary">•</span><span>{s.featureFolderRestrictions}</span></li>
                    <li className="flex gap-2"><span className="text-primary">•</span><span>{s.featureAccessTTL}</span></li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </Layout>
  );
}