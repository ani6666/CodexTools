import { Button } from './Button';
import type { M33State } from '../m33-state';

interface Props { scan: M33State['scan']; busy: boolean; t: (key: string) => string; onScan: () => void; onImport: () => void }

export function LocalCandidate({ scan, busy, t, onScan, onImport }: Props) {
  const canImport = scan.status === 'candidate' && scan.candidate;
  return <section id="local-candidate" className="work-panel" aria-labelledby="candidate-title" aria-busy={scan.status === 'scanning'}>
    <div className="work-panel__heading"><div><h2 id="candidate-title">{t('m33.candidate.title')}</h2><p>{t('m33.candidate.description')}</p></div><Button onClick={onScan} disabled={busy}>{scan.status === 'scanning' ? t('m33.action.scanning') : t('m33.action.scan')}</Button></div>
    <div className={`business-status business-status--${scan.status}`} role="status" aria-live="polite" aria-atomic="true">
      <strong>{t(`m33.scan.${scan.status}.title`)}</strong>
      <span>{t(`m33.scan.${scan.status}.body`)}</span>
      {scan.candidate && <span className="metadata-line">{t('m33.candidate.authMode')}: {t(`m33.auth.${scan.candidate.authMode}`)}</span>}
    </div>
    {canImport && <div className="confirmation-row"><p>{t('m33.import.confirmation')}</p><Button variant="primary" onClick={onImport} disabled={busy}>{t('m33.action.import')}</Button></div>}
  </section>;
}
