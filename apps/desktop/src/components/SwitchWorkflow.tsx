import { useEffect, useState } from 'react';
import type { M34State } from '../m34-state';
import type { IdentitySummary, PresetSummary, SwitchRecovery } from '../ipc';
import { Button } from './Button';

type Translate = (key: string) => string;

interface SwitchWorkflowProps {
  identity: IdentitySummary | null;
  preset: PresetSummary | null;
  state: M34State;
  busy: boolean;
  t: Translate;
  onPreview: () => void;
  onExecute: () => void;
  onCancel: () => void;
  onReset: () => void;
  onRecover: (recoveryId: string) => void;
}

function RecoveryItem({ item, busy, t, onRecover }: { item: SwitchRecovery; busy: boolean; t: Translate; onRecover: (id: string) => void }) {
  const [confirmed, setConfirmed] = useState(false);
  return <li className="recovery-item">
    <div><strong>{t('m34.recovery.itemTitle')}</strong><span>{t('m34.recovery.itemBody')}</span></div>
    <label className="confirmation-check"><input type="checkbox" checked={confirmed} disabled={busy} onChange={(event) => setConfirmed(event.target.checked)} /><span>{t('m34.recovery.confirmation')}</span></label>
    <Button variant="secondary" disabled={!confirmed || busy} onClick={() => onRecover(item.recoveryId)}>{t('m34.action.recover')}</Button>
  </li>;
}

export function SwitchWorkflow({ identity, preset, state, busy, t, onPreview, onExecute, onCancel, onReset, onRecover }: SwitchWorkflowProps) {
  const [confirmed, setConfirmed] = useState(false);
  useEffect(() => { setConfirmed(false); }, [state.preview?.planId]);
  const running = ['executing', 'cancelling', 'cancel_too_late'].includes(state.status);
  const terminal = ['completed', 'cancelled', 'plan_stale', 'conflict', 'recovery_required', 'failed'].includes(state.status);
  const progressValue = state.status === 'completed' ? 2 : state.progressStage === 'committing' || state.progressStage === 'entering_critical' ? 1 : 0;

  return <section className="work-panel switch-workflow" aria-labelledby="identity-switch-title" aria-busy={busy || undefined}>
    <div className="work-panel__heading">
      <div><h2 id="identity-switch-title">{t('m34.title')}</h2><p>{t('m34.description')}</p></div>
      <Button variant="secondary" disabled={!identity || !preset || busy || running} onClick={onPreview}>{state.status === 'previewing' ? t('m34.action.previewing') : t('m34.action.preview')}</Button>
    </div>

    {!identity || !preset ? <p className="empty-copy" role="status">{t('m34.empty')}</p> : null}

    {state.preview && <div className="switch-preview" aria-labelledby="switch-preview-title">
      <div className="switch-preview__heading"><h3 id="switch-preview-title">{t('m34.preview.title')}</h3><span className="status-chip">{t('m34.preview.ready')}</span></div>
      <dl className="preview-summary">
        <div><dt>{t('m34.preview.identity')}</dt><dd>{state.preview.identity.name}</dd></div>
        <div><dt>{t('m34.preview.preset')}</dt><dd>{state.preview.preset.name}</dd></div>
        <div><dt>{t('m34.preview.model')}</dt><dd>{state.preview.preset.modelId}</dd></div>
        <div><dt>{t('m34.preview.affected')}</dt><dd>{state.preview.affectedItems}</dd></div>
      </dl>
      <ul className="switch-warnings" aria-label={t('m34.preview.warningsLabel')}>
        <li>{t('m34.warning.localStateChanges')}</li>
        <li>{t('m34.warning.cancellationBoundary')}</li>
      </ul>
      <label className="confirmation-check"><input type="checkbox" checked={confirmed} disabled={busy || running} onChange={(event) => setConfirmed(event.target.checked)} /><span>{t('m34.confirmation')}</span></label>
      <div className="switch-actions">
        <Button variant="primary" disabled={!confirmed || busy || running || state.status !== 'preview_ready'} onClick={onExecute}>{t('m34.action.execute')}</Button>
        {running && <Button variant="secondary" disabled={state.status === 'cancelling' || state.status === 'cancel_too_late'} onClick={onCancel}>{state.status === 'cancelling' ? t('m34.action.cancelling') : t('m34.action.cancel')}</Button>}
        {terminal && <Button variant="quiet" onClick={onReset}>{t('m34.action.reset')}</Button>}
      </div>
    </div>}

    {state.status !== 'idle' && <div className={`switch-progress switch-progress--${state.status}`} role="status" aria-live="polite" aria-atomic="true">
      <strong>{t(`m34.status.${state.status}.title`)}</strong>
      <span>{t(`m34.status.${state.status}.body`)}</span>
      {running && <progress max={2} value={progressValue} aria-label={t('m34.progress.label')} />}
      {state.progressStage && <small>{t(`m34.stage.${state.progressStage}`)}</small>}
    </div>}

    {state.recoveries.length > 0 && <div className="recovery-block">
      <div><h3>{t('m34.recovery.title')}</h3><p>{t('m34.recovery.description')}</p></div>
      <ul>{state.recoveries.map((item) => <RecoveryItem key={item.recoveryId} item={item} busy={busy} t={t} onRecover={onRecover} />)}</ul>
    </div>}
  </section>;
}
