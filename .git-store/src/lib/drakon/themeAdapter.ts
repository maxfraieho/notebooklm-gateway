// src/lib/drakon/themeAdapter.ts

import type { DrakonConfigTheme } from '@/types/drakonwidget';

/**
 * Maps garden-bloom theme (dark/light) to DrakonWidget theme
 */
export function getGardenDrakonTheme(isDark: boolean): DrakonConfigTheme {
  if (isDark) {
    return {
      background: '#1e293b',
      iconBack: '#334155',
      iconBorder: '#64748b',
      color: '#f1f5f9',
      lines: '#94a3b8',
      lineWidth: 1,
      shadowColor: 'rgba(0, 0, 0, 0.4)',
      shadowBlur: 4,
      scrollBar: 'rgba(255, 255, 255, 0.2)',
      scrollBarHover: 'rgba(255, 255, 255, 0.5)',
      backText: '#cbd5e1',
    };
  }

  return {
    background: '#f8fafc',
    iconBack: 'white',
    iconBorder: '#94a3b8',
    color: '#1e293b',
    lines: '#475569',
    lineWidth: 1,
    shadowColor: 'rgba(0, 0, 0, 0.12)',
    shadowBlur: 4,
    scrollBar: 'rgba(0, 0, 0, 0.15)',
    scrollBarHover: 'rgba(0, 0, 0, 0.4)',
    backText: '#475569',
  };
}
