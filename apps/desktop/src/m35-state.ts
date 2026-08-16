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
  provenance: OperationProvenance;
}
export interface M35State {
  status: M35Status;
  requestToken: number;
  operationId: string | null;
  identityProvenance: IdentityProvenance | null;
  requestProvenance: OperationProvenance | null;
  models: ProvenancedModelCandidate[];
  errorCode: SafeErrorCode | null;
  retryable: boolean;
}
export type M35Action =
  | { type: 'identity-changed'; requestToken: number; provenance: IdentityProvenance | null }
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

export function candidateSaveIdentity(identity: IdentitySummary | null, candidate: ProvenancedModelCandidate): IdentitySummary | null {
  if (!identity || !sameIdentityProvenance(identityProvenance(identity), candidate.provenance)) return null;
  return {
    ...identity,
    identityId: candidate.provenance.identityId,
    credentialRefId: candidate.provenance.credentialRefId,
    version: candidate.provenance.identityVersion,
  };
}

function idleState(provenance: IdentityProvenance | null, requestToken: number): M35State {
  return {
    status: 'idle', requestToken, operationId: null, identityProvenance: provenance,
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
    case 'identity-changed': return idleState(action.provenance, action.requestToken);
    case 'probe-started':
      if (!sameIdentityProvenance(state.identityProvenance, action.provenance)) return state;
      return { ...idleState(state.identityProvenance, action.requestToken), status: 'probing', operationId: action.operationId, requestProvenance: action.provenance };
    case 'discovery-started':
      if (!sameIdentityProvenance(state.identityProvenance, action.provenance)) return state;
      return { ...idleState(state.identityProvenance, action.requestToken), status: 'discovering', operationId: action.operationId, requestProvenance: action.provenance };
    case 'probe-finished':
      return matchesRequest(state, action.requestToken, action.provenance) ? { ...state, status: 'reachable', operationId: null } : state;
    case 'discovery-finished':
      return matchesRequest(state, action.requestToken, action.provenance)
        ? { ...state, status: 'ready', operationId: null, models: action.models.map((model) => ({ ...model, provenance: action.provenance })) }
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
    case 'reset': return idleState(state.identityProvenance, state.requestToken + 1);
  }
}
