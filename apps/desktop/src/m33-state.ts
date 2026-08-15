import type { IdentitySummary, PresetSummary, SafeErrorCode, ScanResult } from './ipc.ts';

type AsyncStatus = 'idle' | 'loading' | 'success' | 'error';
export interface M33State {
  mounted: boolean;
  requestToken: number;
  scan: { status: 'idle' | 'scanning' | ScanResult['status']; candidate: ScanResult['candidate']; existingIdentityId: string | null };
  identities: { status: AsyncStatus; items: IdentitySummary[] };
  presets: { status: AsyncStatus; identityId: string | null; items: PresetSummary[] };
  errorCode: SafeErrorCode | null;
}

export type M33Action =
  | { type: 'locale-changed' }
  | { type: 'unmounted' }
  | { type: 'scan-started'; requestToken: number }
  | { type: 'scan-finished'; requestToken: number; result: ScanResult }
  | { type: 'request-failed'; requestToken: number; code: SafeErrorCode }
  | { type: 'identities-started'; requestToken: number }
  | { type: 'identities-finished'; requestToken: number; items: IdentitySummary[] }
  | { type: 'presets-started'; requestToken: number; identityId: string }
  | { type: 'presets-finished'; requestToken: number; identityId: string; items: PresetSummary[] };

export function createInitialM33State(): M33State {
  return {
    mounted: true,
    requestToken: 0,
    scan: { status: 'idle', candidate: null, existingIdentityId: null },
    identities: { status: 'idle', items: [] },
    presets: { status: 'idle', identityId: null, items: [] },
    errorCode: null,
  };
}

function stale(state: M33State, requestToken: number): boolean {
  return !state.mounted || requestToken !== state.requestToken;
}

export function m33Reducer(state: M33State, action: M33Action): M33State {
  switch (action.type) {
    case 'locale-changed': return state;
    case 'unmounted': return { ...state, mounted: false };
    case 'scan-started': return { ...state, requestToken: action.requestToken, errorCode: null, scan: { status: 'scanning', candidate: null, existingIdentityId: null } };
    case 'scan-finished': return stale(state, action.requestToken) ? state : { ...state, scan: { status: action.result.status, candidate: action.result.candidate, existingIdentityId: action.result.existingIdentityId ?? null } };
    case 'identities-started': return { ...state, requestToken: action.requestToken, errorCode: null, identities: { ...state.identities, status: 'loading' } };
    case 'identities-finished': return stale(state, action.requestToken) ? state : { ...state, identities: { status: action.items.length ? 'success' : 'idle', items: action.items } };
    case 'presets-started': return { ...state, requestToken: action.requestToken, errorCode: null, presets: { status: 'loading', identityId: action.identityId, items: [] } };
    case 'presets-finished': return stale(state, action.requestToken) || state.presets.identityId !== action.identityId ? state : { ...state, presets: { status: action.items.length ? 'success' : 'idle', identityId: action.identityId, items: action.items } };
    case 'request-failed': return stale(state, action.requestToken) ? state : { ...state, errorCode: action.code, scan: state.scan.status === 'scanning' ? { ...state.scan, status: 'error' } : state.scan, identities: state.identities.status === 'loading' ? { ...state.identities, status: 'error' } : state.identities, presets: state.presets.status === 'loading' ? { ...state.presets, status: 'error' } : state.presets };
  }
}
