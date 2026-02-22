// Zone Validation Hook
// Validates zone access and fetches zone data for guest view

import { useState, useEffect, useCallback } from 'react';
import {
  validateZone as apiValidateZone,
  getZoneNotebookLMStatus,
} from '@/lib/api/mcpGatewayClient';
import type { NotebookLMMapping } from '@/types/mcpGateway';

export interface ZoneNote {
  slug: string;
  title: string;
  content: string;
  tags: string[];
}

export interface ZoneData {
  id: string;
  name: string;
  description?: string;
  folders: string[];
  noteCount: number;
  notes: ZoneNote[];
  expiresAt: number;
  accessType: 'web' | 'mcp' | 'both';
  notebooklm?: NotebookLMMapping | null;
  consentRequired?: boolean;
}

interface ZoneValidationState {
  isLoading: boolean;
  isValid: boolean;
  isExpired: boolean;
  error: string | null;
  zone: ZoneData | null;
}

export function useZoneValidation(zoneId: string | undefined, accessCode: string | null) {
  const [state, setState] = useState<ZoneValidationState>({
    isLoading: true,
    isValid: false,
    isExpired: false,
    error: null,
    zone: null,
  });

  const validateZone = useCallback(async () => {
    if (!zoneId) {
      setState({
        isLoading: false,
        isValid: false,
        isExpired: false,
        error: 'Zone ID is required',
        zone: null,
      });
      return;
    }

    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const data = await apiValidateZone(zoneId, accessCode);
      
      // Check for expired response
      if (data.expired) {
        setState({
          isLoading: false,
          isValid: false,
          isExpired: true,
          error: 'This access zone has expired',
          zone: null,
        });
        return;
      }
      
      let notebooklmData: NotebookLMMapping | null = data.notebooklm ?? null;
      
      // If notebooklm not in response, fetch it separately
      if (!notebooklmData) {
        try {
          const nlmData = await getZoneNotebookLMStatus(zoneId);
          if (nlmData.notebooklm) {
            notebooklmData = nlmData.notebooklm;
          }
        } catch {
          // NotebookLM fetch failed - continue without it
          console.warn('Failed to fetch NotebookLM status');
        }
      }
      
      const zoneData: ZoneData = {
        id: data.id || data.zoneId,
        name: data.name || 'Access Zone',
        description: data.description,
        folders: data.folders || data.allowedPaths || [],
        noteCount: data.noteCount || 0,
        notes: data.notes || [],
        expiresAt: data.expiresAt,
        accessType: data.accessType || 'both',
        notebooklm: notebooklmData,
        consentRequired: data.consentRequired ?? true,
      };
      
      // Check if expired based on expiresAt
      const isExpired = Date.now() > zoneData.expiresAt;
      
      if (isExpired) {
        setState({
          isLoading: false,
          isValid: false,
          isExpired: true,
          error: 'This access zone has expired',
          zone: null,
        });
        return;
      }

      setState({
        isLoading: false,
        isValid: true,
        isExpired: false,
        error: null,
        zone: zoneData,
      });
    } catch (err) {
      // Check for expired error from gateway
      const errObj = err as any;
      if (errObj?.code === 'ZONE_EXPIRED' || errObj?.httpStatus === 410) {
        setState({
          isLoading: false,
          isValid: false,
          isExpired: true,
          error: 'This access zone has expired',
          zone: null,
        });
        return;
      }

      setState({
        isLoading: false,
        isValid: false,
        isExpired: false,
        error: errObj?.message || (err instanceof Error ? err.message : 'Failed to validate zone'),
        zone: null,
      });
    }
  }, [zoneId, accessCode]);

  useEffect(() => {
    validateZone();
  }, [validateZone]);

  // Check expiration periodically
  useEffect(() => {
    if (!state.zone) return;

    const checkExpiration = () => {
      if (Date.now() > state.zone!.expiresAt) {
        setState(prev => ({
          ...prev,
          isValid: false,
          isExpired: true,
          error: 'This access zone has expired',
        }));
      }
    };

    const interval = setInterval(checkExpiration, 30000);
    return () => clearInterval(interval);
  }, [state.zone]);

  const getTimeRemaining = useCallback((): string => {
    if (!state.zone) return '';
    
    const remaining = state.zone.expiresAt - Date.now();
    if (remaining <= 0) return 'Expired';
    
    const minutes = Math.floor(remaining / (60 * 1000));
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    return `${minutes}m`;
  }, [state.zone]);

  return {
    ...state,
    validateZone,
    getTimeRemaining,
  };
}
