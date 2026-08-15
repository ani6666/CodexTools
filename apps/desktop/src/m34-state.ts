import type {
  CancellationOutcome,
  SafeErrorCode,
  SwitchOperationState,
  SwitchPreview,
  SwitchProgressStage,
  SwitchRecovery,
} from './ipc.ts';

export type M34Status =
  | 'idle'
  | 'previewing'
  | 'preview_ready'
  | 'executing'
  | 'cancelling'
  | 'cancel_too_late'
  | 'completed'
  | 'cancelled'
  | 'plan_stale'
  | 'conflict'
  | 'recovery_required'
  | 'failed';

export interface M34State {
  mounted: boolean;
  requestToken: number;
  status: M34Status;
  preview: SwitchPreview | null;
  operationId: string | null;
  progressStage: SwitchProgressStage | null;
  errorCode: SafeErrorCode | null;
  recoveries: SwitchRecovery[];
}

export type M34Action =
  | { type: 'unmounted' }
  | { type: 'reset' }
  | { type: 'preview-started'; requestToken: number }
  | { type: 'preview-finished'; requestToken: number; preview: SwitchPreview }
  | { type: 'execute-started'; requestToken: number; operationId: string }
  | { type: 'execute-finished'; requestToken: number; operationId: string; status: 'applied' | 'already_applied' }
  | { type: 'request-failed'; requestToken: number; code: SafeErrorCode }
  | { type: 'cancel-finished'; outcome: CancellationOutcome }
  | { type: 'progress-received'; operationId: string; stage: SwitchProgressStage }
  | { type: 'query-finished'; operationId: string; status: SwitchOperationState }
  | { type: 'recoveries-finished'; recoveries: SwitchRecovery[] };

export function createInitialM34State(): M34State {
  return {
    mounted: true,
    requestToken: 0,
    status: 'idle',
    preview: null,
    operationId: null,
    progressStage: null,
    errorCode: null,
    recoveries: [],
  };
}

function stale(state: M34State, requestToken: number): boolean {
  return !state.mounted || state.requestToken !== requestToken;
}

function terminal(status: M34Status): boolean {
  return ['completed', 'cancelled', 'plan_stale', 'conflict', 'recovery_required', 'failed'].includes(status);
}

function statusFromOperation(status: SwitchOperationState): M34Status {
  switch (status) {
    case 'completed': return 'completed';
    case 'cancelled': return 'cancelled';
    case 'conflict': return 'conflict';
    case 'recovery_required': return 'recovery_required';
    case 'failed': return 'failed';
    default: return 'executing';
  }
}

function statusFromError(code: SafeErrorCode): M34Status {
  if (code === 'plan_stale') return 'plan_stale';
  if (code === 'conflict') return 'conflict';
  if (code === 'recovery_required') return 'recovery_required';
  if (code === 'cancelled') return 'cancelled';
  return 'failed';
}

export function m34Reducer(state: M34State, action: M34Action): M34State {
  switch (action.type) {
    case 'unmounted': return { ...state, mounted: false };
    case 'reset': return { ...createInitialM34State(), recoveries: state.recoveries };
    case 'preview-started': return { ...state, requestToken: action.requestToken, status: 'previewing', preview: null, operationId: null, progressStage: null, errorCode: null };
    case 'preview-finished': return stale(state, action.requestToken) ? state : { ...state, status: 'preview_ready', preview: action.preview, operationId: action.preview.operationId, progressStage: null };
    case 'execute-started': return { ...state, requestToken: action.requestToken, status: 'executing', operationId: action.operationId, progressStage: 'queued', errorCode: null };
    case 'execute-finished': return stale(state, action.requestToken) || state.operationId !== action.operationId ? state : { ...state, status: 'completed', progressStage: 'completed', errorCode: null };
    case 'request-failed': return stale(state, action.requestToken) ? state : { ...state, status: statusFromError(action.code), errorCode: action.code };
    case 'cancel-finished':
      if (action.outcome === 'requested' || action.outcome === 'already_requested') return { ...state, status: 'cancelling' };
      if (action.outcome === 'too_late') return { ...state, status: 'cancel_too_late' };
      if (action.outcome === 'already_completed') return state;
      return { ...state, status: 'conflict', errorCode: 'conflict' };
    case 'progress-received':
      if (!state.mounted || state.operationId !== action.operationId || terminal(state.status)) return state;
      if (action.stage === 'cancelled') return { ...state, status: 'cancelled', progressStage: action.stage };
      if (action.stage === 'conflict') return { ...state, status: 'conflict', progressStage: action.stage };
      if (action.stage === 'recovery_required') return { ...state, status: 'recovery_required', progressStage: action.stage };
      if (action.stage === 'failed') return { ...state, status: 'failed', progressStage: action.stage };
      if (action.stage === 'completed') return { ...state, status: 'completed', progressStage: action.stage };
      return { ...state, progressStage: action.stage };
    case 'query-finished':
      if (!state.mounted || (state.operationId !== null && state.operationId !== action.operationId)) return state;
      return { ...state, operationId: action.operationId, status: statusFromOperation(action.status), progressStage: action.status };
    case 'recoveries-finished': return state.mounted ? { ...state, recoveries: action.recoveries } : state;
  }
}

export interface SafeStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

const pendingKey = 'codextools.m34.pending-operation';
const opaqueIdentifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function readPendingSwitchOperation(storage: SafeStorage): string | null {
  try {
    const value = storage.getItem(pendingKey);
    return value && opaqueIdentifier.test(value) ? value : null;
  } catch { return null; }
}

export function persistPendingSwitchOperation(storage: SafeStorage, operationId: string | null): boolean {
  try {
    if (operationId && opaqueIdentifier.test(operationId)) storage.setItem(pendingKey, operationId);
    else storage.removeItem(pendingKey);
    return true;
  } catch { return false; }
}
