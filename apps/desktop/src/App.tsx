import { Button } from './components/Button';
import { Card } from './components/Card';
import { StatusFeedback } from './components/StatusFeedback';
import { SUPPORTED_LOCALES, type SupportedLocale } from './i18n';
import { type DisplayState, type LocalePreference, type NavigationDestination } from './shell-state';
import { useShell } from './state';
import './styles.css';

const destinations: NavigationDestination[] = ['overview', 'status-lab', 'preferences'];
const displayStates: DisplayState[] = ['ready', 'empty', 'loading', 'error', 'cancelled', 'duplicate', 'compatibility_protected'];

export function App() {
  const { state, dispatch, setLocalePreference, t } = useShell();
  const navigate = (destination: NavigationDestination) => dispatch({ type: 'navigate', destination });

  return <div className="app-shell">
    <a className="skip-link" href="#main-content">{t('a11y.skipToContent')}</a>
    <header className="topbar">
      <div className="brand"><span className="brand__mark" aria-hidden="true">CT</span><strong>{t('app.name')}</strong></div>
      <span className="stage-label">{t('shell.stage')}</span>
    </header>
    <aside className="sidebar">
      <nav aria-label={t('nav.label')}>
        {destinations.map((destination) => <button key={destination} className="nav-item" aria-current={state.navigation === destination ? 'page' : undefined} onClick={() => navigate(destination)}>{t(`nav.${destination === 'status-lab' ? 'statusLab' : destination}`)}</button>)}
      </nav>
      <p className="sidebar__boundary">{t('footer.boundary')}</p>
    </aside>
    <main id="main-content" tabIndex={-1}>
      <div className="page-heading"><p>{t('shell.eyebrow')}</p><h1>{t('shell.title')}</h1><span>{t('shell.subtitle')}</span></div>
      {state.navigation === 'overview' && <section aria-labelledby="overview-title"><div className="section-heading"><h2 id="overview-title">{t('overview.title')}</h2><p>{t('overview.description')}</p></div><div className="card-grid"><Card title={t('overview.boundaryTitle')}>{t('overview.boundaryBody')}</Card><Card title={t('overview.languageTitle')}>{t('overview.languageBody')}</Card><Card title={t('overview.contractTitle')}>{t('overview.contractBody')}</Card></div></section>}
      {state.navigation === 'status-lab' && <section aria-labelledby="status-title"><div className="section-heading"><h2 id="status-title">{t('status.title')}</h2><p>{t('status.description')}</p></div><fieldset className="segmented"><legend>{t('status.selectorLabel')}</legend>{displayStates.map((value) => <button key={value} type="button" aria-pressed={state.displayState === value} onClick={() => dispatch({ type: 'show-display-state', displayState: value })}>{t(`state.${value}.title`)}</button>)}</fieldset><StatusFeedback state={state.displayState} title={t(`state.${state.displayState}.title`)} body={t(`state.${state.displayState}.body`)} /></section>}
      {state.navigation === 'preferences' && <section aria-labelledby="preferences-title"><div className="section-heading"><h2 id="preferences-title">{t('preferences.title')}</h2><p>{t('preferences.description')}</p></div><div className="settings-row"><label htmlFor="locale-select"><strong>{t('preferences.languageLabel')}</strong><span>{t('preferences.languageHint')}</span></label><select id="locale-select" value={state.localePreference} onChange={(event) => setLocalePreference(event.target.value as LocalePreference)}><option value="system">{t('locale.system')}</option>{SUPPORTED_LOCALES.map((locale: SupportedLocale) => <option key={locale} value={locale}>{t(locale === 'zh-CN' ? 'locale.zhCN' : 'locale.en')}</option>)}</select></div><Button variant="primary" onClick={() => dispatch({ type: 'notify', tone: 'info', messageKey: 'notification.fixture' })}>{t('action.previewNotification')}</Button></section>}
    </main>
    <div className="notification-region" aria-live="polite" aria-label={t('notification.region')}>{state.notification && <div className={`notification notification--${state.notification.tone}`}><span>{t(state.notification.messageKey)}</span><Button variant="quiet" onClick={() => dispatch({ type: 'dismiss-notification' })}>{t('action.dismiss')}</Button></div>}</div>
  </div>;
}
