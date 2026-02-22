// Locale context and hook for i18n

import { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { 
  type Locale, 
  type Translations, 
  DEFAULT_LOCALE,
  uk, en, fr, de, it 
} from '@/lib/i18n';

const LOCALE_STORAGE_KEY = 'digital-garden-locale';

const translations: Record<Locale, Translations> = {
  uk,
  en,
  fr,
  de,
  it,
};

interface LocaleContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: Translations;
}

const LocaleContext = createContext<LocaleContextValue | null>(null);

function getStoredLocale(): Locale {
  if (typeof window === 'undefined') return DEFAULT_LOCALE;
  
  const stored = localStorage.getItem(LOCALE_STORAGE_KEY);
  if (stored && isValidLocale(stored)) {
    return stored as Locale;
  }
  
  return DEFAULT_LOCALE;
}

function isValidLocale(value: string): value is Locale {
  return ['uk', 'en', 'fr', 'de', 'it'].includes(value);
}

interface LocaleProviderProps {
  children: ReactNode;
}

export function LocaleProvider({ children }: LocaleProviderProps) {
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);
  
  // Load stored locale on mount
  useEffect(() => {
    const stored = getStoredLocale();
    setLocaleState(stored);
  }, []);
  
  const setLocale = useCallback((newLocale: Locale) => {
    setLocaleState(newLocale);
    localStorage.setItem(LOCALE_STORAGE_KEY, newLocale);
  }, []);
  
  const t = translations[locale];
  
  return (
    <LocaleContext.Provider value={{ locale, setLocale, t }}>
      {children}
    </LocaleContext.Provider>
  );
}

export function useLocale(): LocaleContextValue {
  const context = useContext(LocaleContext);
  
  if (!context) {
    throw new Error('useLocale must be used within a LocaleProvider');
  }
  
  return context;
}

// Helper to interpolate strings with variables
export function interpolate(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (_, key) => {
    return values[key]?.toString() ?? `{${key}}`;
  });
}
