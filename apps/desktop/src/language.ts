import { FALLBACK_LOCALE, SUPPORTED_LOCALES, translate, type SupportedLocale } from './i18n.ts';

export const DEFAULT_LOCALE = FALLBACK_LOCALE;
export { SUPPORTED_LOCALES };
export type { SupportedLocale };

export function getSkeletonCopy(locale: SupportedLocale) {
  return {
    status: locale === 'zh-CN' ? '桌面基础已就绪' : 'Desktop foundation is ready',
    detail: translate(locale, 'shell.subtitle'),
    languageLabel: translate(locale, 'preferences.languageLabel'),
  };
}
