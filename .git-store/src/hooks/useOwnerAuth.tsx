// Owner Authentication Hook
// Architecture: Browser → mcpGatewayClient.authRequest → Cloudflare Worker (validation)
// Features: JWT auto-refresh before expiration

import { useState, useEffect, useCallback, useRef, createContext, useContext, ReactNode } from 'react';
import { toast } from 'sonner';
import { authRequest as gatewayAuthRequest } from '@/lib/api/mcpGatewayClient';

interface OwnerAuthState {
  isAuthenticated: boolean;
  isInitialized: boolean;
  isLoading: boolean;
  /**
   * True when MCP gateway (Cloudflare Worker) is reachable.
   * If false, app should run in public/read-only mode.
   */
  gatewayAvailable: boolean;
  error: string | null;
}

interface OwnerAuthContextValue extends OwnerAuthState {
  login: (password: string) => Promise<boolean>;
  logout: () => void;
  setupPassword: (password: string) => Promise<boolean>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<boolean>;
  checkInitialized: () => Promise<void>;
  refreshToken: () => Promise<boolean>;
}

interface JWTPayload {
  role: string;
  exp: number;
  iat: number;
}

const OwnerAuthContext = createContext<OwnerAuthContextValue | null>(null);

const STORAGE_KEY = 'owner-session-token';

// Refresh token 5 minutes before expiration
const REFRESH_THRESHOLD_MS = 5 * 60 * 1000;
// Check token every minute
const TOKEN_CHECK_INTERVAL_MS = 60 * 1000;

/**
 * Decode JWT payload without verification (verification happens server-side)
 */
function decodeJWTPayload(token: string): JWTPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const payload = JSON.parse(
      atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))
    );

    return payload as JWTPayload;
  } catch {
    return null;
  }
}

/**
 * Check if token needs refresh (expires within threshold)
 */
function shouldRefreshToken(token: string): boolean {
  const payload = decodeJWTPayload(token);
  if (!payload) return true;

  const expiresAt = payload.exp;
  const now = Date.now();

  // Token expires within threshold
  return (expiresAt - now) < REFRESH_THRESHOLD_MS;
}

/**
 * Check if token is expired
 */
function isTokenExpired(token: string): boolean {
  const payload = decodeJWTPayload(token);
  if (!payload) return true;

  return payload.exp < Date.now();
}

function getStoredToken(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function storeToken(token: string): void {
  localStorage.setItem(STORAGE_KEY, token);
}

function clearToken(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export function OwnerAuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<OwnerAuthState>({
    isAuthenticated: false,
    isInitialized: false,
    isLoading: true,
    gatewayAvailable: true,
    error: null,
  });

  const checkInitialized = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const initResponse = await gatewayAuthRequest('/auth/status', {});

      if (!initResponse.ok) {
        throw new Error('Failed to check auth status');
      }

      const { initialized } = await initResponse.json();

      const token = getStoredToken();
      let isAuthenticated = false;

      if (token && initialized) {
        const validateResponse = await gatewayAuthRequest('/auth/validate', { token });
        if (validateResponse.ok) {
          const { valid } = await validateResponse.json();
          isAuthenticated = valid;
        }

        if (!isAuthenticated) {
          clearToken();
        }
      }

      setState({
        isAuthenticated,
        isInitialized: initialized,
        isLoading: false,
        gatewayAvailable: true,
        error: null,
      });
    } catch (error) {
      // If worker is unreachable, show site normally (owner features disabled)
      console.warn('[OwnerAuth] Worker unreachable, running in public mode');
      setState({
        isAuthenticated: false,
        isInitialized: true, // Allow site to load
        isLoading: false,
        gatewayAvailable: false,
        error: null,
      });
    }
  }, []);

  useEffect(() => {
    checkInitialized();
  }, [checkInitialized]);

  const setupPassword = useCallback(async (password: string): Promise<boolean> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      if (password.length < 8) {
        throw new Error('Password must be at least 8 characters');
      }
      
      const response = await gatewayAuthRequest('/auth/setup', { password });
      
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Setup failed');
      }
      
      const { token } = await response.json();
      storeToken(token);
      
      setState(prev => ({
        ...prev,
        isAuthenticated: true,
        isInitialized: true,
        isLoading: false,
        gatewayAvailable: true,
        error: null,
      }));
      
      toast.success('Master password configured');
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Setup failed';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      toast.error('Setup failed', { description: message });
      return false;
    }
  }, []);

  const login = useCallback(async (password: string): Promise<boolean> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      const response = await gatewayAuthRequest('/auth/login', { password });
      
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Invalid password');
      }
      
      const { token } = await response.json();
      storeToken(token);
      
      setState(prev => ({
        ...prev,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      }));
      
      toast.success('Owner mode activated');
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Login failed';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      toast.error('Access denied', { description: message });
      return false;
    }
  }, []);

  const logout = useCallback(() => {
    clearToken();
    setState(prev => ({
      ...prev,
      isAuthenticated: false,
      error: null,
    }));
    toast.info('Owner mode deactivated');
  }, []);

  // 🔄 Refresh token function
  const refreshToken = useCallback(async (): Promise<boolean> => {
    const token = getStoredToken();
    if (!token) return false;
    
    // Don't refresh if token is already expired
    if (isTokenExpired(token)) {
      clearToken();
      setState(prev => ({
        ...prev,
        isAuthenticated: false,
        error: 'Session expired. Please login again.',
      }));
      return false;
    }
    
    try {
      const response = await gatewayAuthRequest('/auth/refresh', {}, token);
      
      if (!response.ok) {
        throw new Error('Token refresh failed');
      }
      
      const { token: newToken } = await response.json();
      storeToken(newToken);
      
      console.log('[OwnerAuth] Token refreshed successfully');
      return true;
    } catch (error) {
      console.warn('[OwnerAuth] Token refresh failed:', error);
      // Don't logout on refresh failure - token might still be valid
      return false;
    }
  }, []);

  // 🔄 Auto-refresh effect
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);
  
  useEffect(() => {
    if (!state.isAuthenticated) {
      // Clear interval when not authenticated
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
        refreshIntervalRef.current = null;
      }
      return;
    }
    
    // Check token periodically
    const checkAndRefresh = async () => {
      const token = getStoredToken();
      if (!token) return;
      
      if (isTokenExpired(token)) {
        // Token expired - logout
        clearToken();
        setState(prev => ({
          ...prev,
          isAuthenticated: false,
          error: 'Session expired',
        }));
        toast.warning('Session expired. Please login again.');
        return;
      }
      
      if (shouldRefreshToken(token)) {
        // Token expiring soon - refresh
        console.log('[OwnerAuth] Token expiring soon, refreshing...');
        await refreshToken();
      }
    };
    
    // Initial check
    checkAndRefresh();
    
    // Set up interval
    refreshIntervalRef.current = setInterval(checkAndRefresh, TOKEN_CHECK_INTERVAL_MS);
    
    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
        refreshIntervalRef.current = null;
      }
    };
  }, [state.isAuthenticated, refreshToken]);

  const changePassword = useCallback(async (
    currentPassword: string,
    newPassword: string
  ): Promise<boolean> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      if (newPassword.length < 8) {
        throw new Error('New password must be at least 8 characters');
      }
      
      const token = getStoredToken();
      const response = await gatewayAuthRequest('/auth/change-password', {
        currentPassword,
        newPassword,
      }, token || undefined);
      
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Password change failed');
      }
      
      const { token: newToken } = await response.json();
      storeToken(newToken);
      
      setState(prev => ({ ...prev, isLoading: false, error: null }));
      toast.success('Password changed successfully');
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Password change failed';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      toast.error('Failed to change password', { description: message });
      return false;
    }
  }, []);

  const value: OwnerAuthContextValue = {
    ...state,
    login,
    logout,
    setupPassword,
    changePassword,
    checkInitialized,
    refreshToken,
  };

  return (
    <OwnerAuthContext.Provider value={value}>
      {children}
    </OwnerAuthContext.Provider>
  );
}

export function useOwnerAuth() {
  const context = useContext(OwnerAuthContext);
  if (!context) {
    throw new Error('useOwnerAuth must be used within OwnerAuthProvider');
  }
  return context;
}

export function getOwnerToken(): string | null {
  return getStoredToken();
}
