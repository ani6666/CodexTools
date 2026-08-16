import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { bindCandidateIfCurrent, candidateSaveIdentity, createInitialM35State, identityProvenance, m35Reducer } from '../src/m35-state.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('连接与发现只由显式动作开始且迟到结果不能覆盖新请求', () => {
  const initial = createInitialM35State();
  assert.equal(initial.status, 'idle');
  const identityA = { identityId: 'identity-a', credentialRefId: 'credential-a', version: 1, name: 'A', providerName: 'p', authMode: 'api_key', status: 'ready', defaultPresetId: null };
  const provenanceA = { ...identityProvenance(identityA), endpointPolicy: 'public_https' };
  const selected = m35Reducer(initial, { type: 'source-changed', requestToken: 1, provenance: provenanceA });
  const probing = m35Reducer(selected, { type: 'probe-started', requestToken: 2, operationId: 'op-1', provenance: provenanceA });
  assert.equal(probing.status, 'probing');
  const discovering = m35Reducer(probing, { type: 'discovery-started', requestToken: 3, operationId: 'op-2', provenance: provenanceA });
  assert.deepEqual(m35Reducer(discovering, { type: 'probe-finished', requestToken: 2, provenance: provenanceA }), discovering);
});

test('取消与安全错误保持稳定语义', () => {
  const provenance = { identityId: 'identity-a', credentialRefId: 'credential-a', identityVersion: 1, endpointPolicy: 'public_https' };
  let state = m35Reducer(createInitialM35State(), { type: 'source-changed', requestToken: 1, provenance });
  state = m35Reducer(state, { type: 'discovery-started', requestToken: 2, operationId: 'op-1', provenance });
  state = m35Reducer(state, { type: 'cancel-finished', requestToken: 2, provenance, outcome: 'requested' });
  assert.equal(state.status, 'cancelling');
  state = m35Reducer(state, { type: 'request-failed', requestToken: 2, provenance, code: 'timeout', retryable: true });
  assert.equal(state.status, 'error');
  assert.equal(state.retryable, true);
});

test('候选绑定 request token 与完整来源且切换、轮换、删除与迟到结果全部失效', () => {
  const identityA = { identityId: 'identity-a', credentialRefId: 'credential-a', version: 1, name: 'A', providerName: 'p', authMode: 'api_key', status: 'ready', defaultPresetId: null };
  const identityB = { ...identityA, identityId: 'identity-b', credentialRefId: 'credential-b', name: 'B' };
  const operationA = { ...identityProvenance(identityA), endpointPolicy: 'public_https' };
  let state = m35Reducer(createInitialM35State(), { type: 'source-changed', requestToken: 1, provenance: operationA });
  state = m35Reducer(state, { type: 'discovery-started', requestToken: 2, operationId: 'op-a', provenance: operationA });
  state = m35Reducer(state, { type: 'discovery-finished', requestToken: 2, provenance: operationA, models: [{ modelId: 'model-a', displayName: null }] });
  assert.equal(state.models[0].provenance.identityId, 'identity-a');
  assert.equal(state.models[0].requestToken, 2);
  assert.equal(candidateSaveIdentity({ identity: identityB, requestToken: 2, provenance: operationA }, state.models[0]), null);
  assert.equal(candidateSaveIdentity({ identity: identityA, requestToken: 2, provenance: operationA }, state.models[0])?.version, 1);

  const operationB = { ...identityProvenance(identityB), endpointPolicy: 'public_https' };
  const switched = m35Reducer(state, { type: 'source-changed', requestToken: 3, provenance: operationB });
  assert.equal(switched.models.length, 0);
  assert.deepEqual(m35Reducer(switched, { type: 'discovery-finished', requestToken: 2, provenance: operationA, models: [{ modelId: 'late', displayName: null }] }), switched);
  assert.deepEqual(m35Reducer(switched, { type: 'request-failed', requestToken: 2, provenance: operationA, code: 'timeout', retryable: true }), switched);
  assert.deepEqual(m35Reducer(switched, { type: 'cancel-finished', requestToken: 2, provenance: operationA, outcome: 'requested' }), switched);

  for (const changed of [
    { ...identityA, version: 2 },
    { ...identityA, credentialRefId: 'credential-rotated' },
    null,
  ]) {
    const changedProvenance = changed ? { ...identityProvenance(changed), endpointPolicy: 'public_https' } : null;
    const reset = m35Reducer(state, { type: 'source-changed', requestToken: state.requestToken + 10, provenance: changedProvenance });
    assert.equal(reset.models.length, 0);
    assert.equal(candidateSaveIdentity({ identity: changed, requestToken: reset.requestToken, provenance: changedProvenance }, state.models[0]), null);
  }
});

test('policy 改变使旧候选 fail closed，A→B→A 仍由新 token 拒绝且 bind=0', async () => {
  const identity = { identityId: 'identity-a', credentialRefId: 'credential-a', version: 1, name: 'A', providerName: 'p', authMode: 'api_key', status: 'ready', defaultPresetId: null };
  const publicSource = { ...identityProvenance(identity), endpointPolicy: 'public_https' };
  const loopbackSource = { ...identityProvenance(identity), endpointPolicy: 'loopback_development' };
  const candidate = { modelId: 'model-a', displayName: null, requestToken: 2, provenance: publicSource };
  let bindCount = 0;
  const bind = async () => { bindCount += 1; };

  assert.equal(await bindCandidateIfCurrent(candidate, () => ({ identity, requestToken: 3, provenance: loopbackSource }), bind), false);
  assert.equal(await bindCandidateIfCurrent(candidate, () => ({ identity, requestToken: 4, provenance: publicSource }), bind), false);
  assert.equal(bindCount, 0);
});

test('相同 provenance 但 token mismatch 被拒绝，完全匹配仅调用一次原子 bind', async () => {
  const identity = { identityId: 'identity-a', credentialRefId: 'credential-a', version: 7, name: 'A', providerName: 'p', authMode: 'api_key', status: 'ready', defaultPresetId: null };
  const provenance = { ...identityProvenance(identity), endpointPolicy: 'public_https' };
  const candidate = { modelId: 'model-a', displayName: 'Model A', requestToken: 9, provenance };
  let bindCount = 0;
  let boundVersion = 0;
  const bind = async (boundIdentity) => { bindCount += 1; boundVersion = boundIdentity.version; };

  assert.equal(await bindCandidateIfCurrent(candidate, () => ({ identity, requestToken: 10, provenance }), bind), false);
  assert.equal(bindCount, 0);
  assert.equal(await bindCandidateIfCurrent(candidate, () => ({ identity, requestToken: 9, provenance }), bind), true);
  assert.equal(bindCount, 1);
  assert.equal(boundVersion, 7);
});

test('保存点击使用同步 current context，旧 React 闭包不能跨 policy 或 identity 保存', async () => {
  const identityA = { identityId: 'identity-a', credentialRefId: 'credential-a', version: 1, name: 'A', providerName: 'p', authMode: 'api_key', status: 'ready', defaultPresetId: null };
  const identityB = { ...identityA, identityId: 'identity-b', credentialRefId: 'credential-b', name: 'B' };
  const provenanceA = { ...identityProvenance(identityA), endpointPolicy: 'public_https' };
  const candidate = { modelId: 'model-a', displayName: null, requestToken: 2, provenance: provenanceA };
  let current = { identity: identityA, requestToken: 2, provenance: provenanceA };
  let bindCount = 0;
  const staleClickHandler = () => bindCandidateIfCurrent(candidate, () => current, async () => { bindCount += 1; });

  current = { identity: identityA, requestToken: 3, provenance: { ...provenanceA, endpointPolicy: 'loopback_development' } };
  assert.equal(await staleClickHandler(), false);
  current = { identity: identityB, requestToken: 4, provenance: { ...identityProvenance(identityB), endpointPolicy: 'loopback_development' } };
  assert.equal(await staleClickHandler(), false);
  assert.equal(bindCount, 0);
});

test('policy change 清状态且旧 success/error/cancel 均不落地', () => {
  const identity = { identityId: 'identity-a', credentialRefId: 'credential-a', version: 1, name: 'A', providerName: 'p', authMode: 'api_key', status: 'ready', defaultPresetId: null };
  const publicSource = { ...identityProvenance(identity), endpointPolicy: 'public_https' };
  const loopbackSource = { ...identityProvenance(identity), endpointPolicy: 'loopback_development' };
  let state = m35Reducer(createInitialM35State(), { type: 'source-changed', requestToken: 1, provenance: publicSource });
  state = m35Reducer(state, { type: 'discovery-started', requestToken: 2, operationId: 'op-a', provenance: publicSource });
  const changed = m35Reducer(state, { type: 'source-changed', requestToken: 3, provenance: loopbackSource });
  assert.equal(changed.status, 'idle');
  assert.equal(changed.models.length, 0);
  assert.deepEqual(m35Reducer(changed, { type: 'discovery-finished', requestToken: 2, provenance: publicSource, models: [{ modelId: 'late', displayName: null }] }), changed);
  assert.deepEqual(m35Reducer(changed, { type: 'request-failed', requestToken: 2, provenance: publicSource, code: 'timeout', retryable: true }), changed);
  assert.deepEqual(m35Reducer(changed, { type: 'cancel-finished', requestToken: 2, provenance: publicSource, outcome: 'requested' }), changed);
});

test('M3.5 前端无直接网络 API、秘密字段或自动联网 effect', async () => {
  const sources = await Promise.all(['src/ipc.ts', 'src/App.tsx', 'src/m35-state.ts', 'src/components/ConnectionDiscovery.tsx'].map((file) => readFile(path.join(root, file), 'utf8')));
  const joined = sources.join('\n');
  assert.doesNotMatch(joined, /\b(fetch|XMLHttpRequest|WebSocket)\b/);
  assert.doesNotMatch(joined, /authorization|apiKey|accessToken|credentialMaterial|httpBody|responseHeaders/i);
  assert.match(joined, /loopback_development/);
  assert.match(joined, /aria-live/);
  const connection = await readFile(path.join(root, 'src/components/ConnectionDiscovery.tsx'), 'utf8');
  const app = await readFile(path.join(root, 'src/App.tsx'), 'utf8');
  assert.match(connection, /onPolicyChange/);
  assert.doesNotMatch(connection, /onChange=\{[^}]*?(onProbe|onDiscover)/);
  const policyHandler = app.match(/const changeConnectionPolicy[\s\S]*?\n  };/)?.[0] ?? '';
  assert.match(policyHandler, /connectionPolicyRef\.current = policy[\s\S]*setConnectionPolicy\(policy\)[\s\S]*rotateConnectionSource/);
  assert.doesNotMatch(policyHandler, /probeConnection|discoverModels/);
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
