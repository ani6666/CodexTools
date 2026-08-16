import type { CancellationOutcome, EndpointPolicy, IdentitySummary, ModelCandidate, SafeErrorCode } from './ipc.ts';

export type M35Status = 'idle' | 'probing' | 'reachable' | 'discovering' | 'ready' | 'cancelling' | 'cancelled' | 'cancel_too_late' | 'error';
export interface IdentityProvenance {
  identityId: string;
  credentialRefId: string;
  identityVersion: number;
}
export interface OperationProvenance extends IdentityProvenance {
  endpointPolicy: EndpointPolicy;
}
export interface ProvenancedModelCandidate extends ModelCandidate {
  requestToken: number;
  provenance: OperationProvenance;
}
export interface CandidateSaveContext {
  identity: IdentitySummary | null;
  requestToken: number;
  provenance: OperationProvenance | null;
}
export interface M35State {
  status: M35Status;
  requestToken: number;
  operationId: string | null;
  currentProvenance: OperationProvenance | null;
  requestProvenance: OperationProvenance | null;
  models: ProvenancedModelCandidate[];
  errorCode: SafeErrorCode | null;
  retryable: boolean;
}
export type M35Action =
  | { type: 'source-changed'; requestToken: number; provenance: OperationProvenance | null }
  | { type: 'probe-started'; requestToken: number; operationId: string; provenance: OperationProvenance }
  | { type: 'probe-finished'; requestToken: number; provenance: OperationProvenance }
  | { type: 'discovery-started'; requestToken: number; operationId: string; provenance: OperationProvenance }
  | { type: 'discovery-finished'; requestToken: number; provenance: OperationProvenance; models: ModelCandidate[] }
  | { type: 'cancel-finished'; requestToken: number; provenance: OperationProvenance; outcome: CancellationOutcome }
  | { type: 'request-failed'; requestToken: number; provenance: OperationProvenance; code: SafeErrorCode; retryable: boolean }
  | { type: 'reset' } | { type: 'unmounted' };

export function identityProvenance(identity: IdentitySummary): IdentityProvenance {
  return { identityId: identity.identityId, credentialRefId: identity.credentialRefId, identityVersion: identity.version };
}

export function sameIdentityProvenance(left: IdentityProvenance | null, right: IdentityProvenance | null): boolean {
  if (!left || !right) return left === right;
  return left.identityId === right.identityId
    && left.credentialRefId === right.credentialRefId
    && left.identityVersion === right.identityVersion;
}

export function sameOperationProvenance(left: OperationProvenance | null, right: OperationProvenance | null): boolean {
  return sameIdentityProvenance(left, right) && left?.endpointPolicy === right?.endpointPolicy;
}

export function candidateSaveIdentity(context: CandidateSaveContext, candidate: ProvenancedModelCandidate): IdentitySummary | null {
  if (!context.identity
    || context.requestToken !== candidate.requestToken
    || !sameOperationProvenance(context.provenance, candidate.provenance)
    || !sameIdentityProvenance(identityProvenance(context.identity), candidate.provenance)) return null;
  return {
    ...context.identity,
    identityId: candidate.provenance.identityId,
    credentialRefId: candidate.provenance.credentialRefId,
    version: candidate.provenance.identityVersion,
  };
}

export async function bindCandidateIfCurrent(
  candidate: ProvenancedModelCandidate,
  readCurrent: () => CandidateSaveContext,
  bind: (identity: IdentitySummary, candidate: ProvenancedModelCandidate) => Promise<void>,
): Promise<boolean> {
  const identity = candidateSaveIdentity(readCurrent(), candidate);
  if (!identity) return false;
  await bind(identity, candidate);
  return true;
}

function idleState(provenance: OperationProvenance | null, requestToken: number): M35State {
  return {
    status: 'idle', requestToken, operationId: null, currentProvenance: provenance,
    requestProvenance: null, models: [], errorCode: null, retryable: false,
  };
}

export function createInitialM35State(): M35State {
  return idleState(null, 0);
}

function matchesRequest(state: M35State, requestToken: number, provenance: OperationProvenance): boolean {
  return requestToken === state.requestToken && sameOperationProvenance(provenance, state.requestProvenance);
}

export function m35Reducer(state: M35State, action: M35Action): M35State {
  switch (action.type) {
    case 'source-changed': return idleState(action.provenance, action.requestToken);
    case 'probe-started':
      if (!sameOperationProvenance(state.currentProvenance, action.provenance)) return state;
      return { ...idleState(state.currentProvenance, action.requestToken), status: 'probing', operationId: action.operationId, requestProvenance: action.provenance };
    case 'discovery-started':
      if (!sameOperationProvenance(state.currentProvenance, action.provenance)) return state;
      return { ...idleState(state.currentProvenance, action.requestToken), status: 'discovering', operationId: action.operationId, requestProvenance: action.provenance };
    case 'probe-finished':
      return matchesRequest(state, action.requestToken, action.provenance) ? { ...state, status: 'reachable', operationId: null } : state;
    case 'discovery-finished':
      return matchesRequest(state, action.requestToken, action.provenance)
        ? { ...state, status: 'ready', operationId: null, models: action.models.map((model) => ({ ...model, requestToken: action.requestToken, provenance: action.provenance })) }
        : state;
    case 'cancel-finished':
      if (!matchesRequest(state, action.requestToken, action.provenance)) return state;
      if (action.outcome === 'requested' || action.outcome === 'already_requested') return { ...state, status: 'cancelling' };
      if (action.outcome === 'too_late' || action.outcome === 'already_completed') return { ...state, status: 'cancel_too_late' };
      return state;
    case 'request-failed':
      if (!matchesRequest(state, action.requestToken, action.provenance)) return state;
      return { ...state, status: action.code === 'cancelled' ? 'cancelled' : 'error', operationId: null, errorCode: action.code, retryable: action.retryable };
    case 'unmounted': return idleState(null, Number.MAX_SAFE_INTEGER);
    case 'reset': return idleState(state.currentProvenance, state.requestToken + 1);
  }
}
