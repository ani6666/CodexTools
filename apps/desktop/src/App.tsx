import { useEffect, useReducer, useRef, useState } from 'react';
import { Button } from './components/Button';
import { ConnectionDiscovery } from './components/ConnectionDiscovery';
import { Card } from './components/Card';
import { IdentityManager } from './components/IdentityManager';
import { LocalCandidate } from './components/LocalCandidate';
import { PresetManager } from './components/PresetManager';
import { StatusFeedback } from './components/StatusFeedback';
import { SwitchWorkflow } from './components/SwitchWorkflow';
import { superviseOperationStatusListener } from './event-channel';
import { SUPPORTED_LOCALES, type SupportedLocale } from './i18n';
import { cancelOperation, createPresetAndBind, discoverModels, executeSwitch, importCandidate, listIdentities, listSwitchRecoveries, listenOperationStatus, listPresets, operationId, previewSwitch, probeConnection, querySwitchOperation, recoverSwitch, renameIdentity, requestAppExit, SafeIpcError, scanDefaultCodex, updatePresetAndBind, type EndpointPolicy, type IdentitySummary, type PresetSummary } from './ipc';
import { createInitialM33State, m33Reducer } from './m33-state';
import { createInitialM34State, m34Reducer, persistPendingSwitchOperation, readPendingSwitchOperation } from './m34-state';
import { bindCandidateIfCurrent, createInitialM35State, identityProvenance, m35Reducer, type OperationProvenance, type ProvenancedModelCandidate } from './m35-state';
import { type DisplayState, type LocalePreference, type NavigationDestination } from './shell-state';
import { useShell } from './state';
import './styles.css';

const destinations: NavigationDestination[] = ['overview', 'status-lab', 'preferences'];
const displayStates: DisplayState[] = ['ready', 'empty', 'loading', 'error', 'cancelled', 'duplicate', 'compatibility_protected'];

export function App() {
  const { state, dispatch, setLocalePreference, t } = useShell();
  const [m33, dispatchM33] = useReducer(m33Reducer, undefined, createInitialM33State);
  const [m34, dispatchM34] = useReducer(m34Reducer, undefined, createInitialM34State);
  const [m35, dispatchM35] = useReducer(m35Reducer, undefined, createInitialM35State);
  const [selectedIdentityId, setSelectedIdentityId] = useState<string | null>(null);
  const [connectionPolicy, setConnectionPolicy] = useState<EndpointPolicy>('public_https');
  const [mutating, setMutating] = useState(false);
  const [exitState, setExitState] = useState<'idle' | 'requesting' | 'draining'>('idle');
  const requestToken = useRef(0);
  const switchRequestToken = useRef(0);
  const mounted = useRef(true);
  const connectionRequestToken = useRef(0);
  const connectionOperation = useRef<string | null>(null);
  const selectedIdentityIdRef = useRef<string | null>(null);
  const selectedIdentityRef = useRef<IdentitySummary | null>(null);
  const connectionPolicyRef = useRef<EndpointPolicy>('public_https');
  const connectionSourceRef = useRef<{ requestToken: number; provenance: OperationProvenance | null }>({ requestToken: 0, provenance: null });
  const navigate = (destination: NavigationDestination) => dispatch({ type: 'navigate', destination });
  const selectedIdentity = m33.identities.items.find((item) => item.identityId === selectedIdentityId) ?? null;
  const selectedPreset = m33.presets.items.find((item) => item.isDefault) ?? null;

  const rotateConnectionSource = (identity: IdentitySummary | null, policy: EndpointPolicy) => {
    const token = ++connectionRequestToken.current;
    const provenance: OperationProvenance | null = identity ? { ...identityProvenance(identity), endpointPolicy: policy } : null;
    connectionSourceRef.current = { requestToken: token, provenance };
    const previousOperation = connectionOperation.current;
    connectionOperation.current = null;
    dispatchM35({ type: 'source-changed', requestToken: token, provenance });
    if (previousOperation) void cancelOperation(previousOperation).catch(() => undefined);
  };

  const selectIdentity = (identityId: string) => {
    const identity = m33.identities.items.find((item) => item.identityId === identityId) ?? null;
    selectedIdentityIdRef.current = identity?.identityId ?? null;
    selectedIdentityRef.current = identity;
    rotateConnectionSource(identity, connectionPolicyRef.current);
    setSelectedIdentityId(identity?.identityId ?? null);
  };

  const changeConnectionPolicy = (policy: EndpointPolicy) => {
    connectionPolicyRef.current = policy;
    setConnectionPolicy(policy);
    rotateConnectionSource(selectedIdentityRef.current, policy);
  };

  const fail = (token: number, error: unknown) => {
    if (!mounted.current) return;
    dispatchM33({ type: 'request-failed', requestToken: token, code: error instanceof SafeIpcError ? error.code : 'internal' });
  };
  const refreshIdentities = async () => {
    const token = ++requestToken.current;
    dispatchM33({ type: 'identities-started', requestToken: token });
    try {
      const items = await listIdentities();
      if (!mounted.current) return;
      dispatchM33({ type: 'identities-finished', requestToken: token, items });
      const current = selectedIdentityIdRef.current;
      const nextId = items.some((item) => item.identityId === current) ? current : items[0]?.identityId ?? null;
      const nextIdentity = items.find((item) => item.identityId === nextId) ?? null;
      selectedIdentityIdRef.current = nextId;
      selectedIdentityRef.current = nextIdentity;
      rotateConnectionSource(nextIdentity, connectionPolicyRef.current);
      setSelectedIdentityId(nextId);
    } catch (error) { fail(token, error); }
  };
  const loadPresets = async (identityId: string) => {
    const token = ++requestToken.current;
    dispatchM33({ type: 'presets-started', requestToken: token, identityId });
    try {
      const items = await listPresets(identityId);
      if (mounted.current) dispatchM33({ type: 'presets-finished', requestToken: token, identityId, items });
    } catch (error) { fail(token, error); }
  };
  useEffect(() => {
    mounted.current = true;
    void refreshIdentities();
    const disposeEventChannel = superviseOperationStatusListener(
      () => listenOperationStatus((event) => dispatchM34({ type: 'progress-received', operationId: event.operation_id, stage: event.stage })),
      (channelState) => dispatchM33({ type: channelState === 'ready' ? 'event-channel-ready' : 'event-channel-unavailable' }),
    );
    void listSwitchRecoveries().then((recoveries) => {
      if (mounted.current) dispatchM34({ type: 'recoveries-finished', recoveries });
    }).catch(() => undefined);
    const pendingOperation = readPendingSwitchOperation(window.localStorage);
    if (pendingOperation) {
      void querySwitchOperation(pendingOperation).then((operation) => {
        if (!mounted.current) return;
        dispatchM34({ type: 'query-finished', operationId: operation.operationId, status: operation.state });
        if (['completed', 'cancelled', 'conflict', 'failed'].includes(operation.state)) persistPendingSwitchOperation(window.localStorage, null);
      }).catch(() => persistPendingSwitchOperation(window.localStorage, null));
    }
    return () => {
      mounted.current = false;
      connectionSourceRef.current = { requestToken: Number.MAX_SAFE_INTEGER, provenance: null };
      dispatchM35({ type: 'unmounted' });
      if (connectionOperation.current) void cancelOperation(connectionOperation.current).catch(() => undefined);
      disposeEventChannel();
    };
  }, []);
  useEffect(() => { dispatchM33({ type: 'locale-changed' }); }, [state.locale]);
  useEffect(() => { if (selectedIdentityId) void loadPresets(selectedIdentityId); }, [selectedIdentityId]);

  const runScan = async () => {
    const token = ++requestToken.current;
    dispatchM33({ type: 'scan-started', requestToken: token });
    try { const result = await scanDefaultCodex(); if (mounted.current) dispatchM33({ type: 'scan-finished', requestToken: token, result }); }
    catch (error) { fail(token, error); }
  };
  const runImport = async () => {
    if (!m33.scan.candidate || mutating) return;
    setMutating(true);
    try { await importCandidate(m33.scan.candidate.scanId); await refreshIdentities(); dispatch({ type: 'notify', tone: 'success', messageKey: 'm33.notification.imported' }); }
    catch (error) { fail(m33.requestToken, error); }
    finally { if (mounted.current) setMutating(false); }
  };
  const runRename = async (identity: IdentitySummary, name: string) => {
    if (mutating) return;
    setMutating(true);
    try { await renameIdentity(identity, name); await refreshIdentities(); dispatch({ type: 'notify', tone: 'success', messageKey: 'm33.notification.renamed' }); }
    catch (error) { fail(m33.requestToken, error); }
    finally { if (mounted.current) setMutating(false); }
  };
  const savePreset = async (identity: IdentitySummary, preset: PresetSummary | null, name: string, modelId: string) => {
    if (mutating) return;
    setMutating(true);
    try {
      if (preset) await updatePresetAndBind(identity, preset, name, modelId); else await createPresetAndBind(identity, name, modelId);
      await refreshIdentities();
      if (selectedIdentityIdRef.current === identity.identityId) await loadPresets(identity.identityId);
      dispatch({ type: 'notify', tone: 'success', messageKey: 'm33.notification.presetSaved' });
    } catch (error) { fail(m33.requestToken, error); }
    finally { if (mounted.current) setMutating(false); }
  };
  const failConnection = (token: number, provenance: OperationProvenance, currentOperation: string, error: unknown) => {
    if (connectionOperation.current === currentOperation) connectionOperation.current = null;
    if (!mounted.current) return;
    const safe = error instanceof SafeIpcError ? error : new SafeIpcError('internal');
    dispatchM35({ type: 'request-failed', requestToken: token, provenance, code: safe.code, retryable: safe.retryable });
  };
  const runProbe = async (policy: EndpointPolicy) => {
    const identity = selectedIdentityRef.current;
    if (!identity || policy !== connectionPolicyRef.current) return;
    const baseProvenance = identityProvenance(identity);
    const provenance: OperationProvenance = { ...baseProvenance, endpointPolicy: policy };
    const token = ++connectionRequestToken.current;
    const currentOperation = operationId();
    connectionSourceRef.current = { requestToken: token, provenance };
    const previousOperation = connectionOperation.current;
    connectionOperation.current = currentOperation;
    if (previousOperation) void cancelOperation(previousOperation).catch(() => undefined);
    dispatchM35({ type: 'probe-started', requestToken: token, operationId: currentOperation, provenance });
    try {
      await probeConnection(identity, policy, currentOperation);
      if (mounted.current) dispatchM35({ type: 'probe-finished', requestToken: token, provenance });
      if (connectionOperation.current === currentOperation) connectionOperation.current = null;
    } catch (error) { failConnection(token, provenance, currentOperation, error); }
  };
  const runDiscovery = async (policy: EndpointPolicy) => {
    const identity = selectedIdentityRef.current;
    if (!identity || policy !== connectionPolicyRef.current) return;
    const baseProvenance = identityProvenance(identity);
    const provenance: OperationProvenance = { ...baseProvenance, endpointPolicy: policy };
    const token = ++connectionRequestToken.current;
    const currentOperation = operationId();
    connectionSourceRef.current = { requestToken: token, provenance };
    const previousOperation = connectionOperation.current;
    connectionOperation.current = currentOperation;
    if (previousOperation) void cancelOperation(previousOperation).catch(() => undefined);
    dispatchM35({ type: 'discovery-started', requestToken: token, operationId: currentOperation, provenance });
    try {
      const models = await discoverModels(identity, policy, currentOperation);
      if (mounted.current) dispatchM35({ type: 'discovery-finished', requestToken: token, provenance, models });
      if (connectionOperation.current === currentOperation) connectionOperation.current = null;
    } catch (error) { failConnection(token, provenance, currentOperation, error); }
  };
  const cancelConnection = async () => {
    const currentOperation = connectionOperation.current;
    const { provenance, requestToken: token } = connectionSourceRef.current;
    if (!currentOperation || !provenance) return;
    try { dispatchM35({ type: 'cancel-finished', requestToken: token, provenance, outcome: await cancelOperation(currentOperation) }); }
    catch (error) {
      failConnection(token, provenance, currentOperation, error);
    }
  };
  const useCandidate = async (model: ProvenancedModelCandidate) => {
    if (mutating) return;
    const saved = await bindCandidateIfCurrent(
      model,
      () => ({ identity: selectedIdentityRef.current, ...connectionSourceRef.current }),
      async (identity, candidate) => savePreset(identity, null, candidate.displayName ?? candidate.modelId, candidate.modelId),
    );
    if (!saved) {
      rotateConnectionSource(selectedIdentityRef.current, connectionPolicyRef.current);
      dispatch({ type: 'notify', tone: 'info', messageKey: 'm35.provenanceMismatch' });
    }
  };
  const exitApplication = async () => {
    if (exitState === 'requesting') return;
    setExitState('requesting');
    try { await requestAppExit(); }
    catch { if (mounted.current) { setExitState('draining'); dispatch({ type: 'notify', tone: 'info', messageKey: 'm35.exit.busy' }); } }
  };
  const failSwitch = (token: number, error: unknown) => {
    if (!mounted.current) return;
    dispatchM34({ type: 'request-failed', requestToken: token, code: error instanceof SafeIpcError ? error.code : 'internal' });
  };
  const runSwitchPreview = async () => {
    if (!selectedIdentity || !selectedPreset) return;
    const token = ++switchRequestToken.current;
    dispatchM34({ type: 'preview-started', requestToken: token });
    try {
      const preview = await previewSwitch(selectedIdentity, selectedPreset);
      if (mounted.current) dispatchM34({ type: 'preview-finished', requestToken: token, preview });
    } catch (error) { failSwitch(token, error); }
  };
  const runSwitchExecute = async () => {
    if (!m34.preview) return;
    const token = ++switchRequestToken.current;
    const operationId = m34.preview.operationId;
    dispatchM34({ type: 'execute-started', requestToken: token, operationId });
    persistPendingSwitchOperation(window.localStorage, operationId);
    try {
      const result = await executeSwitch(m34.preview);
      if (!mounted.current) return;
      dispatchM34({ type: 'execute-finished', requestToken: token, operationId: result.operation.operationId, status: result.status });
      persistPendingSwitchOperation(window.localStorage, null);
      dispatch({ type: 'notify', tone: 'success', messageKey: 'm34.notification.completed' });
    } catch (error) { failSwitch(token, error); }
  };
  const runSwitchCancel = async () => {
    if (!m34.operationId) return;
    try {
      const outcome = await cancelOperation(m34.operationId);
      if (mounted.current) dispatchM34({ type: 'cancel-finished', outcome });
    } catch (error) { failSwitch(m34.requestToken, error); }
  };
  const runSwitchRecovery = async (recoveryId: string) => {
    const token = ++switchRequestToken.current;
    dispatchM34({ type: 'execute-started', requestToken: token, operationId: recoveryId });
    try {
      const operation = await recoverSwitch(recoveryId);
      if (!mounted.current) return;
      dispatchM34({ type: 'query-finished', operationId: operation.operationId, status: operation.state });
      const recoveries = await listSwitchRecoveries();
      if (mounted.current) dispatchM34({ type: 'recoveries-finished', recoveries });
    } catch (error) { failSwitch(token, error); }
  };
  const exiting = exitState !== 'idle';
  const busy = exiting || mutating || m33.scan.status === 'scanning' || m33.identities.status === 'loading' || m33.presets.status === 'loading';
  const switchBusy = exiting || ['previewing', 'executing', 'cancelling', 'cancel_too_late'].includes(m34.status);

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
      <div className="sidebar__footer"><p className="sidebar__boundary">{t('footer.boundary')}</p><Button type="button" variant="quiet" disabled={exitState === 'requesting'} onClick={exitApplication}>{t(exitState === 'idle' ? 'm35.exit.action' : exitState === 'requesting' ? 'm35.exit.waiting' : 'm35.exit.retry')}</Button></div>
    </aside>
    <main id="main-content" tabIndex={-1}>
      <div className="page-heading"><h1>{t('shell.title')}</h1><span>{t('shell.subtitle')}</span></div>
      {state.navigation === 'overview' && <div className="workspace-flow"><section aria-labelledby="overview-title"><div className="section-heading"><h2 id="overview-title">{t('overview.title')}</h2><p>{t('overview.description')}</p></div><div className="boundary-strip"><Card title={t('overview.boundaryTitle')}>{t('overview.boundaryBody')}</Card><Card title={t('overview.contractTitle')}>{t('overview.contractBody')}</Card></div></section>{m33.eventChannel === 'unavailable' && <div className="event-channel-status" role="status" aria-live="polite" aria-atomic="true">{t('m33.eventChannel.unavailable')}</div>}{m33.errorCode && <div className="business-error" role="alert" aria-live="assertive">{t(`m33.error.${m33.errorCode}`)}</div>}<LocalCandidate scan={m33.scan} busy={busy} t={t} onScan={runScan} onImport={runImport} /><IdentityManager identities={m33.identities.items} selectedId={selectedIdentityId} loading={m33.identities.status === 'loading'} busy={busy} t={t} onRefresh={refreshIdentities} onSelect={selectIdentity} onRename={runRename} /><ConnectionDiscovery identity={selectedIdentity} state={m35} busy={busy} t={t} policy={connectionPolicy} onPolicyChange={changeConnectionPolicy} onProbe={runProbe} onDiscover={runDiscovery} onCancel={cancelConnection} onUseModel={useCandidate} /><PresetManager identity={selectedIdentity} presets={m33.presets.items} loading={m33.presets.status === 'loading'} busy={busy} t={t} onSave={savePreset} /><SwitchWorkflow identity={selectedIdentity} preset={selectedPreset} state={m34} busy={switchBusy} t={t} onPreview={runSwitchPreview} onExecute={runSwitchExecute} onCancel={runSwitchCancel} onReset={() => { dispatchM34({ type: 'reset' }); persistPendingSwitchOperation(window.localStorage, null); }} onRecover={runSwitchRecovery} /></div>}
      {state.navigation === 'status-lab' && <section aria-labelledby="status-title"><div className="section-heading"><h2 id="status-title">{t('status.title')}</h2><p>{t('status.description')}</p></div><fieldset className="segmented"><legend>{t('status.selectorLabel')}</legend>{displayStates.map((value) => <button key={value} type="button" aria-pressed={state.displayState === value} onClick={() => dispatch({ type: 'show-display-state', displayState: value })}>{t(`state.${value}.title`)}</button>)}</fieldset><StatusFeedback state={state.displayState} title={t(`state.${state.displayState}.title`)} body={t(`state.${state.displayState}.body`)} /></section>}
      {state.navigation === 'preferences' && <section aria-labelledby="preferences-title"><div className="section-heading"><h2 id="preferences-title">{t('preferences.title')}</h2><p>{t('preferences.description')}</p></div><div className="settings-row"><label htmlFor="locale-select"><strong>{t('preferences.languageLabel')}</strong><span>{t('preferences.languageHint')}</span></label><select id="locale-select" value={state.localePreference} onChange={(event) => setLocalePreference(event.target.value as LocalePreference)}><option value="system">{t('locale.system')}</option>{SUPPORTED_LOCALES.map((locale: SupportedLocale) => <option key={locale} value={locale}>{t(locale === 'zh-CN' ? 'locale.zhCN' : 'locale.en')}</option>)}</select></div><Button variant="primary" onClick={() => dispatch({ type: 'notify', tone: 'info', messageKey: 'notification.fixture' })}>{t('action.previewNotification')}</Button></section>}
    </main>
    <div className="notification-region" aria-live="polite" aria-label={t('notification.region')}>{state.notification && <div className={`notification notification--${state.notification.tone}`}><span>{t(state.notification.messageKey)}</span><Button variant="quiet" onClick={() => dispatch({ type: 'dismiss-notification' })}>{t('action.dismiss')}</Button></div>}</div>
  </div>;
}
