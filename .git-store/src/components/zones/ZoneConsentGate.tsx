// Zone Consent Gate
// Displays confidentiality agreement before allowing access to zone content

import { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { Shield, ExternalLink, Loader2 } from 'lucide-react';
import { useLocale } from '@/hooks/useLocale';
import { toast } from 'sonner';
import { LanguageSwitcher } from '@/components/garden/LanguageSwitcher';
import { ThemeToggle } from '@/components/garden/ThemeToggle';

const POLICY_VERSION = '2026-02-06';
const CONSENT_STORAGE_PREFIX = 'zone_consent_';

interface ZoneConsentGateProps {
  zoneId: string;
  zoneName: string;
  onConsent: () => void;
  onDecline: () => void;
}

/**
 * Check if user has already consented to this zone
 */
export function hasZoneConsent(zoneId: string): boolean {
  try {
    const stored = localStorage.getItem(`${CONSENT_STORAGE_PREFIX}${zoneId}`);
    if (!stored) return false;
    
    const data = JSON.parse(stored);
    // Check if consent is still valid (same policy version and not expired)
    if (data.policyVersion !== POLICY_VERSION) return false;
    if (data.expiresAt && Date.now() > data.expiresAt) return false;
    
    return data.accepted === true;
  } catch {
    return false;
  }
}

/**
 * Store zone consent
 */
export function storeZoneConsent(zoneId: string, expiresAt?: number): void {
  const data = {
    accepted: true,
    policyVersion: POLICY_VERSION,
    acceptedAt: Date.now(),
    expiresAt: expiresAt || undefined,
  };
  localStorage.setItem(`${CONSENT_STORAGE_PREFIX}${zoneId}`, JSON.stringify(data));
}

/**
 * Clear zone consent
 */
export function clearZoneConsent(zoneId: string): void {
  localStorage.removeItem(`${CONSENT_STORAGE_PREFIX}${zoneId}`);
}

export function ZoneConsentGate({ 
  zoneId, 
  zoneName, 
  onConsent, 
  onDecline 
}: ZoneConsentGateProps) {
  const { t } = useLocale();
  const [agreed, setAgreed] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleContinue = useCallback(async () => {
    if (!agreed) return;
    
    setIsSubmitting(true);
    
    try {
      // In Phase 1, we just store consent locally
      // Phase 2+ will add server-side consent logging
      storeZoneConsent(zoneId);
      
      toast.success(t.delegatedConsent.continue);
      onConsent();
    } catch (err) {
      console.error('[ZoneConsentGate] Error storing consent:', err);
      toast.error('Failed to record consent');
    } finally {
      setIsSubmitting(false);
    }
  }, [agreed, zoneId, onConsent, t]);

  const handleDecline = useCallback(() => {
    onDecline();
  }, [onDecline]);

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4 relative">
      {/* Theme and Language controls */}
      <div className="absolute top-4 right-4 flex items-center gap-2">
        <LanguageSwitcher />
        <ThemeToggle />
      </div>
      
      <Card className="w-full max-w-lg">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
            <Shield className="h-8 w-8 text-primary" />
          </div>
          <CardTitle className="text-xl">
            {t.delegatedConsent.title}
          </CardTitle>
          <CardDescription className="text-base">
            {t.delegatedConsent.summary}
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-6">
          {/* Zone name indicator */}
          <div className="bg-muted/50 rounded-lg p-3 text-center">
            <p className="text-sm text-muted-foreground">Zone:</p>
            <p className="font-medium">{zoneName}</p>
          </div>

          {/* Link to full policy */}
          <div className="text-center">
            <Button asChild variant="link" className="text-primary">
              <Link to="/policy/delegated-zone-confidentiality" target="_blank">
                {t.delegatedConsent.readFull}
                <ExternalLink className="ml-1 h-3 w-3" />
              </Link>
            </Button>
          </div>

          {/* Agreement checkbox */}
          <div className="flex items-start gap-3 p-4 border rounded-lg bg-card">
            <Checkbox
              id="consent-checkbox"
              checked={agreed}
              onCheckedChange={(checked) => setAgreed(checked === true)}
              className="mt-0.5"
            />
            <Label 
              htmlFor="consent-checkbox" 
              className="text-sm leading-relaxed cursor-pointer"
            >
              {t.delegatedConsent.checkbox}
            </Label>
          </div>

          {/* Action buttons */}
          <div className="flex flex-col sm:flex-row gap-3">
            <Button
              variant="outline"
              className="flex-1"
              onClick={handleDecline}
              disabled={isSubmitting}
            >
              {t.delegatedConsent.decline}
            </Button>
            <Button
              className="flex-1"
              onClick={handleContinue}
              disabled={!agreed || isSubmitting}
            >
              {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t.delegatedConsent.continue}
            </Button>
          </div>

          {/* Policy version */}
          <p className="text-xs text-center text-muted-foreground">
            {t.delegatedConsent.policyVersion}: {POLICY_VERSION}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
