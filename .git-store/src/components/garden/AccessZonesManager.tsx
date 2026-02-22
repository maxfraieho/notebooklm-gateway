// Access Zones Manager
// Lists active zones with actions: copy links, QR, revoke

import { useEffect, useState } from 'react';
import { 
  Plus, 
  Copy, 
  QrCode, 
  Trash2, 
  Globe, 
  Link2,
  AlertCircle,
  Loader2,
  Download,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { toast } from 'sonner';
import { useLocale, interpolate } from '@/hooks/useLocale';
import { useAccessZones, type AccessZone, type CreateZoneParams } from '@/hooks/useAccessZones';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { ZoneCreationDialog } from './ZoneCreationDialog';
import { ZoneQRDialog } from './ZoneQRDialog';
import { ExpirationIndicator } from './ExpirationIndicator';
import { NotebookLMStatusBadge } from '@/components/zones/NotebookLMStatusBadge';
import { NotebookLMSetupPanel } from '@/components/zones/NotebookLMSetupPanel';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { downloadZoneNotes } from '@/lib/api/mcpGatewayClient';

export function AccessZonesManager() {
  const { t } = useLocale();
  const { isAuthenticated } = useOwnerAuth();
  const { 
    zones, 
    isLoading, 
    error, 
    fetchZones, 
    createZone, 
    revokeZone,
    getTimeRemaining,
    isExpired,
  } = useAccessZones();

  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [zoneToRevoke, setZoneToRevoke] = useState<AccessZone | null>(null);
  const [qrZone, setQrZone] = useState<AccessZone | null>(null);
  const [setupZone, setSetupZone] = useState<AccessZone | null>(null);

  useEffect(() => {
    fetchZones();
  }, [fetchZones]);

  const handleCreateZone = async (params: CreateZoneParams) => {
    setIsCreating(true);
    const zone = await createZone(params);
    setIsCreating(false);
    if (zone) {
      setIsCreateDialogOpen(false);
      if (zone.notebooklm) {
        setSetupZone(zone);
      }
    }
  };

  const handleRevoke = async () => {
    if (!zoneToRevoke) return;
    await revokeZone(zoneToRevoke.id);
    setZoneToRevoke(null);
  };

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`${label} ${t.zones.copied}`);
    } catch {
      toast.error(t.export.copyError);
    }
  };

  const getAccessTypeIcon = (type: string) => {
    switch (type) {
      case 'web': return Globe;
      case 'mcp': return Link2;
      default: return Link2;
    }
  };

  const getAccessTypeLabel = (type: string) => {
    switch (type) {
      case 'web': return t.zones.webOnly;
      case 'mcp': return t.zones.mcpOnly;
      case 'both': return t.zones.webAndMcp;
      default: return type;
    }
  };

  // Filter out expired zones
  const activeZones = zones.filter(z => !isExpired(z.expiresAt));

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">{t.zones.title}</h2>
          <p className="text-sm text-muted-foreground">{t.zones.description}</p>
        </div>
        <Button onClick={() => setIsCreateDialogOpen(true)} size="sm">
          <Plus className="w-4 h-4 mr-2" />
          {t.zones.createNew}
        </Button>
      </div>

      {/* Error State */}
      {error && (
        <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-3 rounded-lg">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Loading State */}
      {isLoading && zones.length === 0 && (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {/* Empty State */}
      {!isLoading && activeZones.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-8 text-center">
            <Link2 className="w-10 h-10 text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground mb-4">
              {t.zones.noZones}
            </p>
            <Button variant="outline" size="sm" onClick={() => setIsCreateDialogOpen(true)}>
              <Plus className="w-4 h-4 mr-2" />
              {t.zones.createFirst}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Zones List */}
      {activeZones.length > 0 && (
        <div className="space-y-3">
          {activeZones.map(zone => {
            const AccessIcon = getAccessTypeIcon(zone.accessType);
            
            return (
              <Card key={zone.id} className="overflow-hidden">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <CardTitle className="text-base truncate">{zone.name}</CardTitle>
                      {zone.description && (
                        <CardDescription className="truncate">{zone.description}</CardDescription>
                      )}
                    </div>
                    <div className="ml-2 flex-shrink-0 flex flex-col items-end gap-2">
                      <Badge variant="outline" className="w-fit">
                        <AccessIcon className="w-3 h-3 mr-1" />
                        {getAccessTypeLabel(zone.accessType)}
                      </Badge>
                      <NotebookLMStatusBadge zoneId={zone.id} />
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* Stats */}
                  <div className="flex items-center gap-4 text-sm text-muted-foreground">
                    <span>📁 {zone.folders.length} {t.export.folders}</span>
                    <span>📝 {zone.noteCount} {t.common.notes}</span>
                    <ExpirationIndicator 
                      expiresAt={zone.expiresAt}
                      createdAt={zone.createdAt}
                    />
                  </div>

                  {/* Actions */}
                  <div className="flex flex-wrap gap-2">
                    {zone.accessCode && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(zone.accessCode!, 'Access Code')}
                      >
                        <Copy className="w-3.5 h-3.5 mr-1" />
                        Access Code
                      </Button>
                    )}
                    {zone.webUrl && (
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => copyToClipboard(zone.webUrl!, 'Web URL')}
                      >
                        <Copy className="w-3.5 h-3.5 mr-1" />
                        Web URL
                      </Button>
                    )}
                    {zone.mcpUrl && (
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => copyToClipboard(zone.mcpUrl!, 'MCP URL')}
                      >
                        <Copy className="w-3.5 h-3.5 mr-1" />
                        MCP URL
                      </Button>
                    )}
                    {zone.webUrl && (
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => setQrZone(zone)}
                      >
                        <QrCode className="w-3.5 h-3.5 mr-1" />
                        QR
                      </Button>
                    )}

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={async () => {
                        try {
                          await downloadZoneNotes(zone.id, zone.name);
                          toast.success('Download started');
                        } catch (err) {
                          toast.error('Download failed');
                          console.error(err);
                        }
                      }}
                    >
                      <Download className="w-3.5 h-3.5 mr-1" />
                      .md
                    </Button>
                    {zone.notebooklm && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSetupZone(zone)}
                      >
                        NotebookLM
                      </Button>
                    )}
                    <Button 
                      variant="ghost" 
                      size="sm"
                      className="text-destructive hover:text-destructive hover:bg-destructive/10"
                      onClick={() => setZoneToRevoke(zone)}
                    >
                      <Trash2 className="w-3.5 h-3.5 mr-1" />
                      {t.zones.revoke}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Create Dialog */}
      <ZoneCreationDialog
        open={isCreateDialogOpen}
        onOpenChange={setIsCreateDialogOpen}
        onCreateZone={handleCreateZone}
        isCreating={isCreating}
      />

      {/* QR Dialog */}
      {qrZone && (
        <ZoneQRDialog
          zone={qrZone}
          open={!!qrZone}
          onOpenChange={(open) => !open && setQrZone(null)}
        />
      )}

      {/* NotebookLM Setup */}
      <Dialog open={!!setupZone} onOpenChange={(open) => !open && setSetupZone(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>NotebookLM setup</DialogTitle>
            <DialogDescription>
              Track import progress. Retry is available in owner mode.
            </DialogDescription>
          </DialogHeader>
          {setupZone && (
            <NotebookLMSetupPanel
              zoneId={setupZone.id}
              initialNotebooklm={setupZone.notebooklm ?? null}
              isOwner={isAuthenticated}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Revoke Confirmation */}
      <AlertDialog open={!!zoneToRevoke} onOpenChange={(open) => !open && setZoneToRevoke(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.zones.revokeConfirmTitle}</AlertDialogTitle>
            <AlertDialogDescription>
              {interpolate(t.zones.revokeConfirmDescription, { name: zoneToRevoke?.name || '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.export.cancel}</AlertDialogCancel>
            <AlertDialogAction 
              onClick={handleRevoke}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {t.zones.revoke}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
