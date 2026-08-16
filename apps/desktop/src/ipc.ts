import { invoke } from '@tauri-apps/api/core';
import { listen, type Event, type UnlistenFn } from '@tauri-apps/api/event';

const schemaVersion = 1;
const root = 'default_codex' as const;

export type SafeErrorCode = 'validation' | 'not_found' | 'conflict' | 'plan_stale' | 'compatibility_protected' | 'cancelled' | 'recovery_required' | 'unavailable' | 'auth_required' | 'forbidden' | 'rate_limited' | 'timeout' | 'tls_failure' | 'network_unavailable' | 'invalid_response' | 'response_too_large' | 'internal';
export type ScanStatus = 'not_found' | 'candidate' | 'duplicate' | 'compatibility_protected' | 'conflict' | 'recovery_required' | 'error';
export interface ScanCandidate { scanId: string; authMode: 'api_key' | 'o_auth' }
export interface ScanResult { status: ScanStatus; candidate: ScanCandidate | null; existingIdentityId: string | null }
export interface IdentitySummary { identityId: string; credentialRefId: string; name: string; providerName: string; authMode: 'api_key' | 'o_auth'; status: string; defaultPresetId: string | null; version: number }
export type EndpointPolicy = 'public_https' | 'loopback_development';
export interface ModelCandidate { modelId: string; displayName: string | null }
export interface PresetSummary { presetId: string; name: string; modelId: string; version: number; isDefault: boolean }
export type SwitchProgressStage = 'accepted' | 'queued' | 'preparing' | 'validated' | 'entering_critical' | 'committing' | 'completed' | 'cancelled' | 'conflict' | 'recovery_required' | 'failed';
export type SwitchOperationState = 'queued' | 'preparing' | 'validated' | 'entering_critical' | 'committing' | 'completed' | 'cancelled' | 'conflict' | 'recovery_required' | 'failed';
export interface OperationStatusEvent { schema_version: number; operation_id: string; correlation_id: string; stage: SwitchProgressStage; status: 'running' | 'succeeded' | 'failed' | 'cancelled'; completed_items: number; total_items: number | null; summary_code: string | null }
export interface SwitchPreview { planId: string; planVersion: number; operationId: string; identity: IdentitySummary; preset: PresetSummary; affectedCategories: Array<'configuration' | 'authentication'>; affectedItems: number; warnings: string[]; compatibility: 'ready' | 'compatibility_protected' }
export interface SwitchOperation { operationId: string; state: SwitchOperationState; completedItems: number; totalItems: number }
export interface SwitchRecovery { recoveryId: string; state: SwitchOperationState; affectedItems: number }
export type CancellationOutcome = 'requested' | 'already_requested' | 'unknown_operation' | 'too_late' | 'already_completed';

interface ErrorEnvelope { code?: string; retryable?: boolean }
interface ScanResponse { status: ScanStatus; candidate: { scan_id: string; auth_mode: 'api_key' | 'o_auth' } | null; existing_identity_id: string | null }
interface IdentityResponse { identities: Array<{ identity_id: string; credential_ref_id: string; name: string; provider_name: string; auth_mode: 'api_key' | 'o_auth'; status: string; default_preset_id: string | null; version: number }> }
interface PresetResponse { presets: Array<{ preset_id: string; name: string; model_id: string; version: number; is_default: boolean }> }
interface SwitchPreviewResponse { preview: { plan_id: string; plan_version: number; operation_id: string; identity: IdentityResponse['identities'][number]; preset: PresetResponse['presets'][number]; affected_categories: Array<'configuration' | 'authentication'>; affected_items: number; warning_codes: string[]; compatibility: 'ready' | 'compatibility_protected' } }
interface SwitchOperationResponse { operation: { operation_id: string; state: SwitchOperationState; completed_items: number; total_items: number } }

export class SafeIpcError extends Error {
  readonly code: SafeErrorCode;
  readonly retryable: boolean;
  constructor(code: SafeErrorCode, retryable = false) { super(code); this.code = code; this.retryable = retryable; }
}

function correlationId(): string { return crypto.randomUUID(); }
export function operationId(): string { return crypto.randomUUID(); }

function safeError(error: unknown): never {
  const candidate = typeof error === 'object' && error !== null ? (error as ErrorEnvelope).code : undefined;
  const allowed: SafeErrorCode[] = ['validation', 'not_found', 'conflict', 'plan_stale', 'compatibility_protected', 'cancelled', 'recovery_required', 'unavailable', 'auth_required', 'forbidden', 'rate_limited', 'timeout', 'tls_failure', 'network_unavailable', 'invalid_response', 'response_too_large', 'internal'];
  throw new SafeIpcError(allowed.includes(candidate as SafeErrorCode) ? candidate as SafeErrorCode : 'internal', Boolean(typeof error === 'object' && error !== null && (error as ErrorEnvelope).retryable));
}

export async function scanDefaultCodex(): Promise<ScanResult> {
  try {
    const response = await invoke<ScanResponse>('scan_default_codex_v1', { request: { schema_version: schemaVersion, correlation_id: correlationId(), root } });
    return {
      status: response.status,
      candidate: response.candidate ? { scanId: response.candidate.scan_id, authMode: response.candidate.auth_mode } : null,
      existingIdentityId: response.existing_identity_id,
    };
  } catch (error) { return safeError(error); }
}

export async function importCandidate(scanId: string): Promise<void> {
  try {
    await invoke('import_candidate_v1', { request: { schema_version: schemaVersion, operation_id: operationId(), correlation_id: correlationId(), root, scan_id: scanId } });
  } catch (error) { safeError(error); }
}

export async function listIdentities(): Promise<IdentitySummary[]> {
  try {
    const response = await invoke<IdentityResponse>('list_identities_v1', { request: { schema_version: schemaVersion, correlation_id: correlationId() } });
    return response.identities.map(identityFromWire);
  } catch (error) { return safeError(error); }
}

export async function renameIdentity(identity: IdentitySummary, name: string): Promise<IdentitySummary> {
  try {
    const response = await invoke<{ identity: IdentityResponse['identities'][number] }>('rename_identity_v1', { request: { schema_version: schemaVersion, correlation_id: correlationId(), identity_id: identity.identityId, expected_version: identity.version, name } });
    const item = response.identity;
    return identityFromWire(item);
  } catch (error) { return safeError(error); }
}

export async function listPresets(identityId: string): Promise<PresetSummary[]> {
  try {
    const response = await invoke<PresetResponse>('list_presets_v1', { request: { schema_version: schemaVersion, correlation_id: correlationId(), identity_id: identityId } });
    return response.presets.map((item) => ({ presetId: item.preset_id, name: item.name, modelId: item.model_id, version: item.version, isDefault: item.is_default }));
  } catch (error) { return safeError(error); }
}

export async function createPresetAndBind(identity: IdentitySummary, name: string, modelId: string): Promise<void> {
  try {
    await invoke('create_preset_and_bind_v1', { request: { schema_version: schemaVersion, operation_id: operationId(), correlation_id: correlationId(), identity_id: identity.identityId, expected_identity_version: identity.version, preset_id: operationId(), name, model_id: modelId } });
  } catch (error) { safeError(error); }
}

export async function updatePresetAndBind(identity: IdentitySummary, preset: PresetSummary, name: string, modelId: string): Promise<void> {
  try {
    await invoke('update_preset_and_bind_v1', { request: { schema_version: schemaVersion, operation_id: operationId(), correlation_id: correlationId(), identity_id: identity.identityId, expected_identity_version: identity.version, preset_id: preset.presetId, expected_preset_version: preset.version, name, model_id: modelId } });
  } catch (error) { safeError(error); }
}

function identityFromWire(item: IdentityResponse['identities'][number]): IdentitySummary {
  return { identityId: item.identity_id, credentialRefId: item.credential_ref_id, name: item.name, providerName: item.provider_name, authMode: item.auth_mode, status: item.status, defaultPresetId: item.default_preset_id, version: item.version };
}

function networkRequest(identity: IdentitySummary, endpointPolicy: EndpointPolicy, operationIdValue: string) {
  return { schema_version: schemaVersion, correlation_id: correlationId(), identity_id: identity.identityId, credential_ref_id: identity.credentialRefId, expected_identity_version: identity.version, endpoint_policy: endpointPolicy, operation_id: operationIdValue };
}

export async function probeConnection(identity: IdentitySummary, endpointPolicy: EndpointPolicy, operationIdValue: string): Promise<void> {
  try { await invoke('probe_connection_v1', { request: networkRequest(identity, endpointPolicy, operationIdValue) }); }
  catch (error) { safeError(error); }
}

export async function discoverModels(identity: IdentitySummary, endpointPolicy: EndpointPolicy, operationIdValue: string): Promise<ModelCandidate[]> {
  try {
    const response = await invoke<{ models: Array<{ model_id: string; display_name: string | null }> }>('discover_models_v1', { request: networkRequest(identity, endpointPolicy, operationIdValue) });
    return response.models.map((model) => ({ modelId: model.model_id, displayName: model.display_name }));
  } catch (error) { return safeError(error); }
}

export async function requestAppExit(): Promise<void> {
  try { await invoke('request_app_exit_v1', { request: { schema_version: schemaVersion, correlation_id: correlationId() } }); }
  catch (error) { safeError(error); }
}

function presetFromWire(item: PresetResponse['presets'][number]): PresetSummary {
  return { presetId: item.preset_id, name: item.name, modelId: item.model_id, version: item.version, isDefault: item.is_default };
}

function operationFromWire(item: SwitchOperationResponse['operation']): SwitchOperation {
  return { operationId: item.operation_id, state: item.state, completedItems: item.completed_items, totalItems: item.total_items };
}

export async function previewSwitch(identity: IdentitySummary, preset: PresetSummary): Promise<SwitchPreview> {
  try {
    const response = await invoke<SwitchPreviewResponse>('preview_switch_v1', { request: { schema_version: schemaVersion, correlation_id: correlationId(), identity_id: identity.identityId, expected_identity_version: identity.version, preset_id: preset.presetId, expected_preset_version: preset.version } });
    return { planId: response.preview.plan_id, planVersion: response.preview.plan_version, operationId: response.preview.operation_id, identity: identityFromWire(response.preview.identity), preset: presetFromWire(response.preview.preset), affectedCategories: response.preview.affected_categories, affectedItems: response.preview.affected_items, warnings: response.preview.warning_codes, compatibility: response.preview.compatibility };
  } catch (error) { return safeError(error); }
}

export async function executeSwitch(preview: SwitchPreview): Promise<{ status: 'applied' | 'already_applied'; operation: SwitchOperation }> {
  try {
    const response = await invoke<SwitchOperationResponse & { status: 'applied' | 'already_applied' }>('execute_switch_v1', { request: { schema_version: schemaVersion, correlation_id: correlationId(), plan_id: preview.planId, expected_plan_version: preview.planVersion, operation_id: preview.operationId } });
    return { status: response.status, operation: operationFromWire(response.operation) };
  } catch (error) { return safeError(error); }
}

export async function cancelOperation(operationIdValue: string): Promise<CancellationOutcome> {
  try {
    const response = await invoke<{ outcome: CancellationOutcome }>('cancel_operation_v1', { request: { schema_version: schemaVersion, operation_id: operationIdValue, correlation_id: correlationId() } });
    return response.outcome;
  } catch (error) { return safeError(error); }
}

export async function querySwitchOperation(operationIdValue: string): Promise<SwitchOperation> {
  try {
    const response = await invoke<SwitchOperationResponse>('query_switch_operation_v1', { request: { schema_version: schemaVersion, operation_id: operationIdValue, correlation_id: correlationId() } });
    return operationFromWire(response.operation);
  } catch (error) { return safeError(error); }
}

export async function listSwitchRecoveries(): Promise<SwitchRecovery[]> {
  try {
    const response = await invoke<{ recoveries: Array<{ recovery_id: string; state: SwitchOperationState; affected_items: number }> }>('list_switch_recoveries_v1', { request: { schema_version: schemaVersion, correlation_id: correlationId() } });
    return response.recoveries.map((item) => ({ recoveryId: item.recovery_id, state: item.state, affectedItems: item.affected_items }));
  } catch (error) { return safeError(error); }
}

export async function recoverSwitch(recoveryId: string): Promise<SwitchOperation> {
  try {
    const response = await invoke<SwitchOperationResponse>('recover_switch_v1', { request: { schema_version: schemaVersion, operation_id: recoveryId, correlation_id: correlationId(), recovery_id: recoveryId } });
    return operationFromWire(response.operation);
  } catch (error) { return safeError(error); }
}

export function notifyOperationStatus(onStatus: (event: OperationStatusEvent) => void, event: OperationStatusEvent): void {
  try { onStatus(event); } catch { /* 观察者异常不得逃逸到 Tauri event runtime。 */ }
}

export async function listenOperationStatus(onStatus: (event: OperationStatusEvent) => void): Promise<UnlistenFn> {
  const unlisten = await listen<OperationStatusEvent>('codextools://operation-status/v1', (event: Event<OperationStatusEvent>) => notifyOperationStatus(onStatus, event.payload));
  return unlisten;
}
