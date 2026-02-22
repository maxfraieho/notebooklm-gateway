// Language switcher component with flags

import { useLocale } from '@/hooks/useLocale';
import { SUPPORTED_LOCALES, type Locale } from '@/lib/i18n';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

const FLAGS: Record<Locale, string> = {
  uk: '🇺🇦',
  en: '🇬🇧',
  fr: '🇫🇷',
  de: '🇩🇪',
  it: '🇮🇹',
};

export function LanguageSwitcher() {
  const { locale, setLocale } = useLocale();
  
  const currentFlag = FLAGS[locale];
  const currentLocale = SUPPORTED_LOCALES.find(l => l.code === locale);
  
  return (
    <Select value={locale} onValueChange={(value) => setLocale(value as Locale)}>
      <SelectTrigger className="w-auto h-8 text-sm gap-1 px-2 sm:px-3">
        <SelectValue>
          <span className="flex items-center gap-1.5">
            <span className="text-base">{currentFlag}</span>
            <span className="hidden sm:inline">{currentLocale?.nativeName}</span>
          </span>
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        {SUPPORTED_LOCALES.map((loc) => (
          <SelectItem key={loc.code} value={loc.code}>
            <span className="flex items-center gap-2">
              <span className="text-base">{FLAGS[loc.code]}</span>
              <span>{loc.nativeName}</span>
            </span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
