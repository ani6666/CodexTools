import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { candidateSaveIdentity, createInitialM35State, identityProvenance, m35Reducer } from '../src/m35-state.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('连接与发现只由显式动作开始且迟到结果不能覆盖新请求', () => {
  const initial = createInitialM35State();
  assert.equal(initial.status, 'idle');
  const identityA = { identityId: 'identity-a', credentialRefId: 'credential-a', version: 1, name: 'A', providerName: 'p', authMode: 'api_key', status: 'ready', defaultPresetId: null };
  const provenanceA = { ...identityProvenance(identityA), endpointPolicy: 'public_https' };
  const selected = m35Reducer(initial, { type: 'identity-changed', requestToken: 1, provenance: identityProvenance(identityA) });
  const probing = m35Reducer(selected, { type: 'probe-started', requestToken: 2, operationId: 'op-1', provenance: provenanceA });
  assert.equal(probing.status, 'probing');
  const discovering = m35Reducer(probing, { type: 'discovery-started', requestToken: 3, operationId: 'op-2', provenance: provenanceA });
  assert.deepEqual(m35Reducer(discovering, { type: 'probe-finished', requestToken: 2, provenance: provenanceA }), discovering);
});

test('取消与安全错误保持稳定语义', () => {
  const provenance = { identityId: 'identity-a', credentialRefId: 'credential-a', identityVersion: 1, endpointPolicy: 'public_https' };
  let state = m35Reducer(createInitialM35State(), { type: 'identity-changed', requestToken: 1, provenance });
  state = m35Reducer(state, { type: 'discovery-started', requestToken: 2, operationId: 'op-1', provenance });
  state = m35Reducer(state, { type: 'cancel-finished', requestToken: 2, provenance, outcome: 'requested' });
  assert.equal(state.status, 'cancelling');
  state = m35Reducer(state, { type: 'request-failed', requestToken: 2, provenance, code: 'timeout', retryable: true });
  assert.equal(state.status, 'error');
  assert.equal(state.retryable, true);
});

test('候选绑定完整身份来源且切换、轮换、删除与迟到结果全部失效', () => {
  const identityA = { identityId: 'identity-a', credentialRefId: 'credential-a', version: 1, name: 'A', providerName: 'p', authMode: 'api_key', status: 'ready', defaultPresetId: null };
  const identityB = { ...identityA, identityId: 'identity-b', credentialRefId: 'credential-b', name: 'B' };
  const operationA = { ...identityProvenance(identityA), endpointPolicy: 'public_https' };
  let state = m35Reducer(createInitialM35State(), { type: 'identity-changed', requestToken: 1, provenance: identityProvenance(identityA) });
  state = m35Reducer(state, { type: 'discovery-started', requestToken: 2, operationId: 'op-a', provenance: operationA });
  state = m35Reducer(state, { type: 'discovery-finished', requestToken: 2, provenance: operationA, models: [{ modelId: 'model-a', displayName: null }] });
  assert.equal(state.models[0].provenance.identityId, 'identity-a');
  assert.equal(candidateSaveIdentity(identityB, state.models[0]), null);
  assert.equal(candidateSaveIdentity(identityA, state.models[0])?.version, 1);

  const switched = m35Reducer(state, { type: 'identity-changed', requestToken: 3, provenance: identityProvenance(identityB) });
  assert.equal(switched.models.length, 0);
  assert.deepEqual(m35Reducer(switched, { type: 'discovery-finished', requestToken: 2, provenance: operationA, models: [{ modelId: 'late', displayName: null }] }), switched);
  assert.deepEqual(m35Reducer(switched, { type: 'request-failed', requestToken: 2, provenance: operationA, code: 'timeout', retryable: true }), switched);
  assert.deepEqual(m35Reducer(switched, { type: 'cancel-finished', requestToken: 2, provenance: operationA, outcome: 'requested' }), switched);

  for (const changed of [
    { ...identityA, version: 2 },
    { ...identityA, credentialRefId: 'credential-rotated' },
    null,
  ]) {
    const reset = m35Reducer(state, { type: 'identity-changed', requestToken: state.requestToken + 10, provenance: changed ? identityProvenance(changed) : null });
    assert.equal(reset.models.length, 0);
    assert.equal(candidateSaveIdentity(changed, state.models[0]), null);
  }
});

test('M3.5 前端无直接网络 API、秘密字段或自动联网 effect', async () => {
  const sources = await Promise.all(['src/ipc.ts', 'src/App.tsx', 'src/m35-state.ts', 'src/components/ConnectionDiscovery.tsx'].map((file) => readFile(path.join(root, file), 'utf8')));
  const joined = sources.join('\n');
  assert.doesNotMatch(joined, /\b(fetch|XMLHttpRequest|WebSocket)\b/);
  assert.doesNotMatch(joined, /authorization|apiKey|accessToken|credentialMaterial|httpBody|responseHeaders/i);
  assert.match(joined, /loopback_development/);
  assert.match(joined, /aria-live/);
});

test('根节点由 ErrorBoundary 包裹并提供安全恢复', async () => {
  const main = await readFile(path.join(root, 'src/main.tsx'), 'utf8');
  const boundary = await readFile(path.join(root, 'src/components/ErrorBoundary.tsx'), 'utf8');
  assert.match(main, /ErrorBoundary/);
  assert.match(boundary, /componentDidCatch/);
  assert.doesNotMatch(boundary, /error\.message|error\.stack/);
  assert.match(boundary, /role="alert"/);
  assert.match(boundary, /tabIndex=\{-1\}/);
  assert.match(boundary, /\.focus\(\)/);
  assert.match(boundary, /aria-live="assertive"/);
});
