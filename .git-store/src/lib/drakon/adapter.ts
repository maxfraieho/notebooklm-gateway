// src/lib/drakon/adapter.ts

import type { DrakonWidget } from '@/types/drakonwidget';

let loadPromise: Promise<void> | null = null;

/**
 * Dynamically loads drakonwidget.js script
 * Returns when createDrakonWidget is available on window
 */
export function loadDrakonWidget(): Promise<void> {
  if (window.createDrakonWidget) {
    return Promise.resolve();
  }

  if (loadPromise) {
    return loadPromise;
  }

  loadPromise = new Promise<void>((resolve, reject) => {
    const script = document.createElement('script');
    script.src = '/libs/drakonwidget.js';
    script.async = true;

    script.onload = () => {
      if (window.createDrakonWidget) {
        resolve();
      } else {
        reject(new Error('DrakonWidget script loaded but createDrakonWidget not found'));
      }
    };

    script.onerror = () => {
      loadPromise = null;
      reject(new Error('Failed to load drakonwidget.js'));
    };

    document.head.appendChild(script);
  });

  return loadPromise;
}

/**
 * Creates a new DrakonWidget instance
 * Must call loadDrakonWidget() first
 */
export function createWidget(): DrakonWidget {
  if (!window.createDrakonWidget) {
    throw new Error('DrakonWidget not loaded. Call loadDrakonWidget() first.');
  }
  return window.createDrakonWidget();
}
