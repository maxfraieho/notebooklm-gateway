import { useCallback, useEffect, useSyncExternalStore } from "react";

function subscribe(callback: () => void) {
  window.addEventListener("online", callback);
  window.addEventListener("offline", callback);
  return () => {
    window.removeEventListener("online", callback);
    window.removeEventListener("offline", callback);
  };
}

function getSnapshot() {
  return navigator.onLine;
}

function getServerSnapshot() {
  return true; // SSR always assumes online
}

/**
 * Hook to track browser online/offline status.
 * Automatically updates when connection changes.
 */
export function useOnlineStatus() {
  const isOnline = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  return { isOnline };
}

/**
 * Hook for managing connection-aware fetch operations with retry.
 */
export function useConnectionAwareFetch() {
  const { isOnline } = useOnlineStatus();

  const wrapWithRetry = useCallback(
    async <T>(
      fetchFn: () => Promise<T>,
      options?: { maxRetries?: number; retryDelayMs?: number }
    ): Promise<T> => {
      const maxRetries = options?.maxRetries ?? 3;
      const retryDelayMs = options?.retryDelayMs ?? 1000;
      let lastError: unknown;

      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        if (!navigator.onLine) {
          throw new Error("OFFLINE");
        }

        try {
          return await fetchFn();
        } catch (err) {
          lastError = err;

          // Don't retry non-retryable errors
          if (
            err &&
            typeof err === "object" &&
            "retryable" in err &&
            !(err as any).retryable
          ) {
            throw err;
          }

          // Last attempt, throw
          if (attempt === maxRetries) {
            throw err;
          }

          // Wait before retry
          await new Promise((resolve) => setTimeout(resolve, retryDelayMs * (attempt + 1)));
        }
      }

      throw lastError;
    },
    []
  );

  return { isOnline, wrapWithRetry };
}
