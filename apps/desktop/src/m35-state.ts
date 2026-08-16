import type { CancellationOutcome, ModelCandidate, SafeErrorCode } from './ipc.ts';

export type M35Status = 'idle' | 'probing' | 'reachable' | 'discovering' | 'ready' | 'cancelling' | 'cancelled' | 'cancel_too_late' | 'error';
export interface M35State {
  status: M35Status;
  requestToken: number;
  operationId: string | null;
  models: ModelCandidate[];
  errorCode: SafeErrorCode | null;
  retryable: boolean;
}
export type M35Action =
  | { type: 'probe-started'; requestToken: number; operationId: string }
  | { type: 'probe-finished'; requestToken: number }
  | { type: 'discovery-started'; requestToken: number; operationId: string }
  | { type: 'discovery-finished'; requestToken: number; models: ModelCandidate[] }
  | { type: 'cancel-finished'; outcome: CancellationOutcome }
  | { type: 'request-failed'; requestToken: number; code: SafeErrorCode; retryable: boolean }
  | { type: 'reset' } | { type: 'unmounted' };

export function createInitialM35State(): M35State {
  return { status: 'idle', requestToken: 0, operationId: null, models: [], errorCode: null, retryable: false };
}

export function m35Reducer(state: M35State, action: M35Action): M35State {
  switch (action.type) {
    case 'probe-started': return { ...createInitialM35State(), status: 'probing', requestToken: action.requestToken, operationId: action.operationId };
    case 'discovery-started': return { ...createInitialM35State(), status: 'discovering', requestToken: action.requestToken, operationId: action.operationId };
    case 'probe-finished': return action.requestToken === state.requestToken ? { ...state, status: 'reachable', operationId: null } : state;
    case 'discovery-finished': return action.requestToken === state.requestToken ? { ...state, status: 'ready', operationId: null, models: action.models } : state;
    case 'cancel-finished':
      if (action.outcome === 'requested' || action.outcome === 'already_requested') return { ...state, status: 'cancelling' };
      if (action.outcome === 'too_late' || action.outcome === 'already_completed') return { ...state, status: 'cancel_too_late' };
      return state;
    case 'request-failed':
      if (action.requestToken !== state.requestToken) return state;
      return { ...state, status: action.code === 'cancelled' ? 'cancelled' : 'error', operationId: null, errorCode: action.code, retryable: action.retryable };
    case 'unmounted': return { ...state, requestToken: Number.MAX_SAFE_INTEGER, operationId: null };
    case 'reset': return createInitialM35State();
  }
}
