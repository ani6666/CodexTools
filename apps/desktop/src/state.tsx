import { createContext, useContext, useEffect, useMemo, useReducer, type Dispatch, type ReactNode } from 'react';
import { translate } from './i18n';
import { createInitialShellState, readLocalePreference, shellReducer, updateLocalePreferenceForSession, type LocalePreference, type ShellAction, type ShellState } from './shell-state';

interface ShellContextValue { state: ShellState; dispatch: Dispatch<ShellAction>; setLocalePreference: (preference: LocalePreference) => void; t: (key: string) => string }
const ShellContext = createContext<ShellContextValue | null>(null);

export function ShellProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(shellReducer, undefined, () => {
    const { preference } = readLocalePreference(window.localStorage);
    return createInitialShellState(window.navigator.languages, preference);
  });
  useEffect(() => {
    document.documentElement.lang = state.locale;
  }, [state.locale]);
  useEffect(() => {
    const updateSystemLocale = () => dispatch({ type: 'system-locale-changed', languages: window.navigator.languages });
    window.addEventListener('languagechange', updateSystemLocale);
    return () => window.removeEventListener('languagechange', updateSystemLocale);
  }, []);
  const setLocalePreference = (preference: LocalePreference) => {
    updateLocalePreferenceForSession(preference, window.navigator.languages, window.localStorage, dispatch);
  };
  const value = useMemo(() => ({ state, dispatch, setLocalePreference, t: (key: string) => translate(state.locale, key) }), [state]);
  return <ShellContext.Provider value={value}>{children}</ShellContext.Provider>;
}

export function useShell(): ShellContextValue {
  const value = useContext(ShellContext);
  if (!value) throw new Error('ShellProvider is required');
  return value;
}

export { createInitialShellState, shellReducer } from './shell-state';
