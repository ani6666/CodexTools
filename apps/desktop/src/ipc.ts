import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

const schemaVersion = 1;
const root = 'default_codex' as const;

export type SafeErrorCode = 'validation' | 'not_found' | 'conflict' | 'compatibility_protected' | 'cancelled' | 'recovery_required' | 'unavailable' | 'internal';
export type ScanStatus = 'not_found' | 'candidate' | 'duplicate' | 'compatibility_protected' | 'conflict' | 'recovery_required' | 'error';
export interface ScanCandidate { scanId: string; authMode: 'api_key' | 'o_auth' }
export interface ScanResult { status: ScanStatus; candidate: ScanCandidate | null; existingIdentityId: string | null }
export interface IdentitySummary { identityId: string; name: string; providerName: string; authMode: 'api_key' | 'o_auth'; status: string; defaultPresetId: string | null; version: number }
export interface PresetSummary { presetId: string; name: string; modelId: string; version: number; isDefault: boolean }

interface ErrorEnvelope { code?: string }
interface ScanResponse { status: ScanStatus; candidate: { scan_id: string; auth_mode: 'api_key' | 'o_auth' } | null; existing_identity_id: string | null }
interface IdentityResponse { identities: Array<{ identity_id: string; name: string; provider_name: string; auth_mode: 'api_key' | 'o_auth'; status: string; default_preset_id: string | null; version: number }> }
interface PresetResponse { presets: Array<{ preset_id: string; name: string; model_id: string; version: number; is_default: boolean }> }

export class SafeIpcError extends Error {
  constructor(public readonly code: SafeErrorCode) { super(code); }
}

function correlationId(): string { return crypto.randomUUID(); }
export function operationId(): string { return crypto.randomUUID(); }

function safeError(error: unknown): never {
  const candidate = typeof error === 'object' && error !== null ? (error as ErrorEnvelope).code : undefined;
  const allowed: SafeErrorCode[] = ['validation', 'not_found', 'conflict', 'compatibility_protected', 'cancelled', 'recovery_required', 'unavailable', 'internal'];
  throw new SafeIpcError(allowed.includes(candidate as SafeErrorCode) ? candidate as SafeErrorCode : 'internal');
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
    return response.identities.map((item) => ({ identityId: item.identity_id, name: item.name, providerName: item.provider_name, authMode: item.auth_mode, status: item.status, defaultPresetId: item.default_preset_id, version: item.version }));
  } catch (error) { return safeError(error); }
}

export async function renameIdentity(identity: IdentitySummary, name: string): Promise<IdentitySummary> {
  try {
    const response = await invoke<{ identity: IdentityResponse['identities'][number] }>('rename_identity_v1', { request: { schema_version: schemaVersion, correlation_id: correlationId(), identity_id: identity.identityId, expected_version: identity.version, name } });
    const item = response.identity;
    return { identityId: item.identity_id, name: item.name, providerName: item.provider_name, authMode: item.auth_mode, status: item.status, defaultPresetId: item.default_preset_id, version: item.version };
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

export async function listenOperationStatus(onStatus: () => void): Promise<UnlistenFn> {
  const unlisten = await listen('codextools://operation-status/v1', () => onStatus());
  return unlisten;
}
