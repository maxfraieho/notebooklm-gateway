import { useState } from 'react';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { useLocale } from '@/hooks/useLocale';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Lock, Eye, EyeOff, Shield, Loader2, CheckCircle2 } from 'lucide-react';

export function OwnerSetupWizard() {
  const { setupPassword, isLoading, error } = useOwnerAuth();
  const { t } = useLocale();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const passwordsMatch = password === confirmPassword;
  const isValidLength = password.length >= 8;
  const canSubmit = password.trim() && confirmPassword.trim() && passwordsMatch && isValidLength;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    await setupPassword(password);
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <CardTitle className="text-2xl">{t.ownerAuth.setupTitle}</CardTitle>
          <CardDescription>
            {t.ownerAuth.setupDescription}
          </CardDescription>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="new-password">{t.ownerAuth.masterPassword}</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="new-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t.ownerAuth.createPassword}
                  className="pl-10 pr-10"
                  autoFocus
                  disabled={isLoading}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={isLoading}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4 text-muted-foreground" />
                  ) : (
                    <Eye className="h-4 w-4 text-muted-foreground" />
                  )}
                </Button>
              </div>
              {password && !isValidLength && (
                <p className="text-xs text-muted-foreground">
                  {t.ownerAuth.passwordMinLength}
                </p>
              )}
              {password && isValidLength && (
                <p className="text-xs text-green-600 dark:text-green-400 flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" />
                  {t.ownerAuth.passwordLengthOk}
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirm-password">{t.ownerAuth.confirmPassword}</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="confirm-password"
                  type={showPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder={t.ownerAuth.confirmPassword}
                  className="pl-10"
                  disabled={isLoading}
                />
              </div>
              {confirmPassword && !passwordsMatch && (
                <p className="text-xs text-destructive">
                  {t.ownerAuth.passwordsNoMatch}
                </p>
              )}
              {confirmPassword && passwordsMatch && (
                <p className="text-xs text-green-600 dark:text-green-400 flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" />
                  {t.ownerAuth.passwordsMatch}
                </p>
              )}
            </div>

            {error && (
              <p className="text-sm text-destructive text-center">{error}</p>
            )}

            <Button 
              type="submit" 
              className="w-full" 
              disabled={!canSubmit || isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {t.ownerAuth.settingUp}
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  {t.ownerAuth.initializeOwner}
                </>
              )}
            </Button>

            <p className="text-xs text-muted-foreground text-center">
              {t.ownerAuth.setupHint}
            </p>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
