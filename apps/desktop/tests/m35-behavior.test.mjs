import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createInitialM35State, m35Reducer } from '../src/m35-state.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('连接与发现只由显式动作开始且迟到结果不能覆盖新请求', () => {
  const initial = createInitialM35State();
  assert.equal(initial.status, 'idle');
  const probing = m35Reducer(initial, { type: 'probe-started', requestToken: 1, operationId: 'op-1' });
  assert.equal(probing.status, 'probing');
  const discovering = m35Reducer(probing, { type: 'discovery-started', requestToken: 2, operationId: 'op-2' });
  assert.deepEqual(m35Reducer(discovering, { type: 'probe-finished', requestToken: 1 }), discovering);
});

test('取消与安全错误保持稳定语义', () => {
  let state = m35Reducer(createInitialM35State(), { type: 'discovery-started', requestToken: 1, operationId: 'op-1' });
  state = m35Reducer(state, { type: 'cancel-finished', outcome: 'requested' });
  assert.equal(state.status, 'cancelling');
  state = m35Reducer(state, { type: 'request-failed', requestToken: 1, code: 'timeout', retryable: true });
  assert.equal(state.status, 'error');
  assert.equal(state.retryable, true);
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
});
