import { useState } from 'react';
import type { EndpointPolicy, IdentitySummary, ModelCandidate } from '../ipc';
import type { M35State } from '../m35-state';
import { Button } from './Button';

interface Props {
  identity: IdentitySummary | null; state: M35State; busy: boolean; t: (key: string) => string;
  onProbe: (policy: EndpointPolicy) => void; onDiscover: (policy: EndpointPolicy) => void;
  onCancel: () => void; onUseModel: (model: ModelCandidate) => Promise<void>;
}

export function ConnectionDiscovery({ identity, state, busy, t, onProbe, onDiscover, onCancel, onUseModel }: Props) {
  const [policy, setPolicy] = useState<EndpointPolicy>('public_https');
  const active = state.status === 'probing' || state.status === 'discovering' || state.status === 'cancelling';
  return <section className="work-panel connection-discovery" aria-labelledby="connection-title" aria-busy={active}>
    <div className="work-panel__heading"><div><h2 id="connection-title">{t('m35.connection.title')}</h2><p>{t('m35.connection.description')}</p></div></div>
    {!identity ? <p className="empty-copy" role="status">{t('m35.connection.chooseIdentity')}</p> : <>
      <label htmlFor="endpoint-policy">{t('m35.connection.policy')}</label>
      <select id="endpoint-policy" value={policy} disabled={busy || active} onChange={(event) => setPolicy(event.target.value as EndpointPolicy)}>
        <option value="public_https">{t('m35.connection.publicHttps')}</option>
        <option value="loopback_development">{t('m35.connection.loopback')}</option>
      </select>
      {policy === 'loopback_development' && <p className="business-status business-status--compatibility_protected" role="alert">{t('m35.connection.loopbackWarning')}</p>}
      <div className="switch-actions">
        <Button type="button" variant="secondary" disabled={busy || active} onClick={() => onProbe(policy)}>{t('m35.action.probe')}</Button>
        <Button type="button" variant="primary" disabled={busy || active} onClick={() => onDiscover(policy)}>{t('m35.action.discover')}</Button>
        {active && <Button type="button" variant="quiet" onClick={onCancel}>{t('m35.action.cancel')}</Button>}
      </div>
      <div className="business-status" role={state.status === 'error' ? 'alert' : 'status'} aria-live="polite" aria-atomic="true">
        <strong>{t(`m35.status.${state.status}`)}</strong>
        {state.errorCode && <span>{t(`m35.error.${state.errorCode}`)}{state.retryable ? ` ${t('m35.error.retryable')}` : ''}</span>}
      </div>
      {state.models.length > 0 && <ul className="model-candidates" aria-label={t('m35.models.label')}>
        {state.models.map((model) => <li key={model.modelId}><span><strong>{model.displayName ?? model.modelId}</strong><small>{model.modelId}</small></span><Button type="button" variant="secondary" disabled={busy} onClick={() => onUseModel(model)}>{t('m35.action.useModel')}</Button></li>)}
      </ul>}
    </>}
  </section>;
}
