// Zone QR Code Dialog
// Displays QR code for zone access URL with download option

import { useEffect, useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Copy, Download, QrCode } from 'lucide-react';
import { toast } from 'sonner';
import { useLocale } from '@/hooks/useLocale';
import type { AccessZone } from '@/hooks/useAccessZones';

interface ZoneQRDialogProps {
  zone: AccessZone;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

// Simple QR code generator using external API
function generateQRCode(text: string, size: number = 200): string {
  return `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(text)}&format=svg`;
}

export function ZoneQRDialog({ zone, open, onOpenChange }: ZoneQRDialogProps) {
  const { t } = useLocale();
  const [qrUrl, setQrUrl] = useState<string>('');

  useEffect(() => {
    if (zone.webUrl) {
      setQrUrl(generateQRCode(zone.webUrl, 256));
    }
  }, [zone.webUrl]);

  const copyUrl = async () => {
    if (!zone.webUrl) return;
    try {
      await navigator.clipboard.writeText(zone.webUrl);
      toast.success(t.zones.urlCopied);
    } catch {
      toast.error(t.export.copyError);
    }
  };

  const downloadQR = async () => {
    if (!qrUrl) return;
    
    try {
      const response = await fetch(qrUrl);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      
      const a = document.createElement('a');
      a.href = url;
      a.download = `zone-${zone.id}-qr.svg`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      toast.success(t.zones.qrDownloaded);
    } catch {
      toast.error(t.zones.qrDownloadError);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <QrCode className="w-5 h-5" />
            {t.zones.qrTitle}
          </DialogTitle>
          <DialogDescription>
            {zone.name}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col items-center gap-4 py-4">
          {/* QR Code */}
          <div className="bg-white p-4 rounded-lg">
            {qrUrl ? (
              <img 
                src={qrUrl} 
                alt="QR Code" 
                className="w-64 h-64"
              />
            ) : (
              <div className="w-64 h-64 flex items-center justify-center bg-muted rounded">
                <QrCode className="w-16 h-16 text-muted-foreground" />
              </div>
            )}
          </div>

          {/* URL Display */}
          <div className="w-full">
            <div className="text-xs text-muted-foreground mb-1">{t.zones.accessUrl}</div>
            <div className="text-sm font-mono bg-muted p-2 rounded truncate">
              {zone.webUrl}
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-2 w-full">
            <Button variant="outline" className="flex-1" onClick={copyUrl}>
              <Copy className="w-4 h-4 mr-2" />
              {t.export.copy}
            </Button>
            <Button variant="outline" className="flex-1" onClick={downloadQR}>
              <Download className="w-4 h-4 mr-2" />
              {t.zones.downloadQR}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
