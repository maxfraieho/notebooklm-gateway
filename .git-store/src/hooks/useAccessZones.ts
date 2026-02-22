// Access Zones Hook
// Manages delegated access zones with TTL, folder restrictions, and access types

import { useState, useCallback } from 'react';
import { toast } from 'sonner';
import { getOwnerToken } from './useOwnerAuth';
import type { AccessType, NotebookLMMapping } from '@/types/mcpGateway';
import {
  createZone as apiCreateZone,
  listZones as apiListZones,
  revokeZone as apiRevokeZone,
  getGatewayBaseUrl,
} from '@/lib/api/mcpGatewayClient';

type MaybeApiError = {
  message?: string;
  code?: string;
  httpStatus?: number;
  details?: unknown;
};

function getErrorMessage(err: unknown, fallback: string) {
  if (err instanceof Error && err.message) return err.message;
  if (err && typeof err === 'object' && 'message' in err) {
    const m = (err as MaybeApiError).message;
    if (typeof m === 'string' && m.trim()) return m;
  }
  return fallback;
}

function getErrorCode(err: unknown) {
  if (err && typeof err === 'object' && 'code' in err) {
    const code = (err as MaybeApiError).code;
    return typeof code === 'string' && code.trim() ? code : undefined;
  }
  return undefined;
}

function getErrorZoneId(err: unknown): string | undefined {
  if (!err || typeof err !== 'object') return undefined;
  const details = (err as MaybeApiError).details as any;
  const zoneId = details?.zoneId;
  return typeof zoneId === 'string' && zoneId.trim() ? zoneId : undefined;
}

export interface AccessZone {
  id: string;
  name: string;
  description?: string;
  folders: string[];
  noteCount: number;
  accessType: AccessType;
  createdAt: number;
  expiresAt: number;
  accessCode?: string;
  webUrl?: string;
  mcpUrl?: string;
  notebooklm?: NotebookLMMapping | null;
  consentRequired?: boolean;
}

export interface CreateZoneParams {
  name: string;
  description?: string;
  folders: string[];
  noteCount: number;
  accessType: AccessType;
  ttlMinutes: number;
  notes?: { slug: string; title: string; content: string; tags: string[] }[];
  createNotebookLM?: boolean;
  notebookTitle?: string;
  notebookShareEmails?: string[];
  notebookSourceMode?: 'minio' | 'url';
  consentRequired?: boolean;
}

const MCP_GATEWAY_URL = getGatewayBaseUrl();
const APP_BASE_URL = typeof window !== 'undefined' ? window.location.origin : '';

/**
 * Generate URLs for a zone based on its accessCode and accessType
 */
function generateZoneUrls(zone: any): AccessZone {
  return {
    ...zone,
    webUrl: zone.accessType !== 'mcp' && zone.accessCode
      ? `${APP_BASE_URL}/zone/${zone.id}?code=${zone.accessCode}`
      : undefined,
    mcpUrl: zone.accessType !== 'web' && zone.id
      ? `${MCP_GATEWAY_URL}/mcp/${zone.id}`
      : undefined,
  };
}

export function useAccessZones() {
  const [zones, setZones] = useState<AccessZone[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const listZones = useCallback(async (): Promise<AccessZone[]> => {
    const token = getOwnerToken();
    if (!token) return [];

    const data = await apiListZones();
    return (data.zones || []).map(generateZoneUrls);
  }, []);

  const fetchZones = useCallback(async () => {
    const token = getOwnerToken();
    if (!token) return;

    setIsLoading(true);
    setError(null);

    try {
      const zonesWithUrls = await listZones();
      setZones(zonesWithUrls);
    } catch (err) {
      console.error('[AccessZones] Fetch error:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch zones');
    } finally {
      setIsLoading(false);
    }
  }, [listZones]);

  const createZone = useCallback(async (params: CreateZoneParams): Promise<AccessZone | null> => {
    const token = getOwnerToken();
    if (!token) {
      toast.error('Authentication required');
      return null;
    }

    setIsLoading(true);
    setError(null);

    try {
      const data = await apiCreateZone({
        name: params.name,
        description: params.description,
        allowedPaths: params.folders,
        accessType: params.accessType,
        ttlMinutes: params.ttlMinutes,
        notes: params.notes,
        createNotebookLM: params.createNotebookLM,
        notebookTitle: params.notebookTitle,
        notebookShareEmails: params.notebookShareEmails,
        notebookSourceMode: params.notebookSourceMode,
        consentRequired: params.consentRequired ?? true,
      });
      
      const newZone: AccessZone = {
        id: data.zoneId,
        name: params.name,
        description: params.description,
        folders: params.folders,
        noteCount: params.noteCount,
        accessType: params.accessType,
        createdAt: Date.now(),
        expiresAt: Date.now() + params.ttlMinutes * 60 * 1000,
        accessCode: data.accessCode,
        webUrl: params.accessType !== 'mcp' 
          ? `${APP_BASE_URL}/zone/${data.zoneId}?code=${data.accessCode}`
          : undefined,
        mcpUrl: params.accessType !== 'web'
          ? `${MCP_GATEWAY_URL}/mcp/${data.zoneId}`
          : undefined,
        notebooklm: data.notebooklm ?? null,
        consentRequired: params.consentRequired ?? true,
      };

      setZones(prev => [newZone, ...prev]);
      toast.success('Access zone created');
      return newZone;
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to create zone');
      const code = getErrorCode(err);
      const description = code ? `[${code}] ${message}` : message;

      const zoneId = getErrorZoneId(err);
      if (zoneId) {
        try {
          const refreshed = await listZones();
          setZones(refreshed);
          const created = refreshed.find((z) => z.id === zoneId) ?? null;

          toast.error('NotebookLM step failed (zone created)', { description });
          setError(description);
          return created;
        } catch {
          // Fall through to generic error
        }
      }

      setError(description);
      toast.error('Failed to create zone', { description });
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const revokeZone = useCallback(async (zoneId: string): Promise<boolean> => {
    const token = getOwnerToken();
    if (!token) {
      toast.error('Authentication required');
      return false;
    }

    setIsLoading(true);

    try {
      await apiRevokeZone(zoneId);

      setZones(prev => prev.filter(z => z.id !== zoneId));
      toast.success('Access zone revoked');
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message :
        (err && typeof err === 'object' && 'message' in err) ? (err as any).message : 'Failed to revoke zone';
      toast.error('Failed to revoke zone', { description: message });
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const getTimeRemaining = useCallback((expiresAt: number): string => {
    const now = Date.now();
    const remaining = expiresAt - now;
    
    if (remaining <= 0) return 'Expired';
    
    const minutes = Math.floor(remaining / (60 * 1000));
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    return `${minutes}m`;
  }, []);

  const isExpired = useCallback((expiresAt: number): boolean => {
    return Date.now() > expiresAt;
  }, []);

  return {
    zones,
    isLoading,
    error,
    fetchZones,
    createZone,
    revokeZone,
    getTimeRemaining,
    isExpired,
  };
}
