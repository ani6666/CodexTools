import { detectSystemLocale, type MessageKey, type SupportedLocale } from './i18n.ts';

export type NavigationDestination = 'overview' | 'status-lab' | 'preferences';
export type DisplayState = 'ready' | 'empty' | 'loading' | 'error' | 'cancelled' | 'duplicate' | 'compatibility_protected';
export type NotificationTone = 'info' | 'success' | 'warning' | 'danger';
export type LocalePreference = 'system' | SupportedLocale;
export const LOCALE_PREFERENCE_KEY = 'codextools.locale-preference';

export interface ShellNotification { id: number; tone: NotificationTone; messageKey: MessageKey }
export interface ShellState {
  navigation: NavigationDestination;
  locale: SupportedLocale;
  localePreference: LocalePreference;
  notification: ShellNotification | null;
  displayState: DisplayState;
}

export type ShellAction =
  | { type: 'navigate'; destination: NavigationDestination }
  | { type: 'set-locale-preference'; preference: LocalePreference; systemLanguages?: readonly string[] }
  | { type: 'system-locale-changed'; languages: readonly string[] }
  | { type: 'notify'; tone: NotificationTone; messageKey: MessageKey }
  | { type: 'dismiss-notification' }
  | { type: 'show-display-state'; displayState: DisplayState };

let nextNotificationId = 1;

export function initializeLocalePreference(storedValue: string | null): { preference: LocalePreference; persisted: boolean } {
  if (storedValue === 'zh-CN' || storedValue === 'en') return { preference: storedValue, persisted: true };
  return { preference: 'system', persisted: false };
}

export function resolveLocale(preference: LocalePreference, languages?: readonly string[]): SupportedLocale {
  return preference === 'system' ? detectSystemLocale(languages) : preference;
}

interface PreferenceStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface LocalePreferenceReadResult {
  preference: LocalePreference;
  persisted: boolean;
  storageSucceeded: boolean;
}

export interface LocalePreferenceWriteResult { succeeded: boolean }

export function readLocalePreference(storage: PreferenceStorage): LocalePreferenceReadResult {
  let storedValue: string | null;
  try {
    storedValue = storage.getItem(LOCALE_PREFERENCE_KEY);
  } catch {
    return { preference: 'system', persisted: false, storageSucceeded: false };
  }

  const initialized = initializeLocalePreference(storedValue);
  if (storedValue === null || initialized.persisted) return { ...initialized, storageSucceeded: true };

  try {
    storage.removeItem(LOCALE_PREFERENCE_KEY);
    return { ...initialized, storageSucceeded: true };
  } catch {
    return { ...initialized, storageSucceeded: false };
  }
}

export function persistLocalePreference(preference: LocalePreference, storage: PreferenceStorage): LocalePreferenceWriteResult {
  try {
    if (preference === 'system') storage.removeItem(LOCALE_PREFERENCE_KEY);
    else storage.setItem(LOCALE_PREFERENCE_KEY, preference);
    return { succeeded: true };
  } catch {
    return { succeeded: false };
  }
}

export function updateLocalePreferenceForSession(
  preference: LocalePreference,
  systemLanguages: readonly string[],
  storage: PreferenceStorage,
  dispatch: (action: ShellAction) => void,
): LocalePreferenceWriteResult {
  dispatch({ type: 'set-locale-preference', preference, systemLanguages });
  return persistLocalePreference(preference, storage);
}

export function createInitialShellState(languages?: readonly string[], storedPreference: string | null = null): ShellState {
  const { preference } = initializeLocalePreference(storedPreference);
  return { navigation: 'overview', locale: resolveLocale(preference, languages), localePreference: preference, notification: null, displayState: 'ready' };
}

export function shellReducer(state: ShellState, action: ShellAction): ShellState {
  switch (action.type) {
    case 'navigate': return { ...state, navigation: action.destination };
    case 'set-locale-preference': return { ...state, localePreference: action.preference, locale: resolveLocale(action.preference, action.systemLanguages) };
    case 'system-locale-changed': return state.localePreference === 'system' ? { ...state, locale: resolveLocale('system', action.languages) } : state;
    case 'notify': return { ...state, notification: { id: nextNotificationId++, tone: action.tone, messageKey: action.messageKey } };
    case 'dismiss-notification': return { ...state, notification: null };
    case 'show-display-state': return { ...state, displayState: action.displayState };
  }
}
