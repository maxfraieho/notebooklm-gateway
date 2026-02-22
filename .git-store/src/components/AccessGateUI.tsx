// Access Gate UI
// Shown when user is not authenticated and not accessing a zone

import { useState } from 'react';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Lock, Loader2 } from 'lucide-react';
import { useLocale } from '@/hooks/useLocale';
import { LanguageSwitcher } from '@/components/garden/LanguageSwitcher';
import { ThemeToggle } from '@/components/garden/ThemeToggle';

export function AccessGateUI() {
  const [password, setPassword] = useState('');
  const { login, isLoading, error } = useOwnerAuth();
  const { t } = useLocale();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password.trim()) {
      await login(password);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4 relative">
      {/* Language & Theme controls - top right corner */}
      <div className="absolute top-4 right-4 flex items-center gap-2">
        <LanguageSwitcher />
        <ThemeToggle />
      </div>
      
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
            <Lock className="h-6 w-6 text-primary" />
          </div>
          <CardTitle>{t.accessGate.title}</CardTitle>
          <CardDescription>
            {t.accessGate.description}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              type="password"
              placeholder={t.accessGate.placeholder}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isLoading}
              autoFocus
            />
            {error && (
              <p className="text-sm text-destructive text-center">{error}</p>
            )}
            <Button type="submit" className="w-full" disabled={isLoading || !password.trim()}>
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  {t.ownerAuth.verifying}
                </>
              ) : (
                t.accessGate.unlock
              )}
            </Button>
          </form>
          
          <div className="mt-6 pt-4 border-t text-center">
            <p className="text-xs text-muted-foreground">
              {t.accessGate.hint}
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}