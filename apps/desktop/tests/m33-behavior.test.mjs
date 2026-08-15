import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createInitialM33State, m33Reducer } from '../src/m33-state.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('首次扫描只由显式动作进入 scanning，初始化和语言变化不触发', () => {
  const initial = createInitialM33State();
  assert.equal(initial.scan.status, 'idle');
  assert.equal(m33Reducer(initial, { type: 'locale-changed' }).scan.status, 'idle');
  const scanning = m33Reducer(initial, { type: 'scan-started', requestToken: 1 });
  assert.equal(scanning.scan.status, 'scanning');
});

test('stale response、重复点击与卸载后的响应不会改写当前状态', () => {
  let state = m33Reducer(createInitialM33State(), { type: 'scan-started', requestToken: 2 });
  const stale = m33Reducer(state, { type: 'scan-finished', requestToken: 1, result: { status: 'not_found', candidate: null } });
  assert.deepEqual(stale, state);
  state = m33Reducer(state, { type: 'unmounted' });
  const afterUnmount = m33Reducer(state, { type: 'scan-finished', requestToken: 2, result: { status: 'candidate', candidate: { scanId: 'opaque', authMode: 'oauth' } } });
  assert.deepEqual(afterUnmount, state);
});

test('业务状态不含路径、credential material 或技术错误原文', async () => {
  const sources = await Promise.all([
    'src/ipc.ts', 'src/m33-state.ts', 'src/components/LocalCandidate.tsx',
    'src/components/IdentityManager.tsx', 'src/components/PresetManager.tsx',
  ].map((file) => readFile(path.join(root, file), 'utf8')));
  const joined = sources.join('\n');
  assert.doesNotMatch(joined, /CODEX_HOME|auth\.json|config\.toml|access[_-]?token|refresh[_-]?token|authorization|credentialMaterial|stack|rawError/i);
  assert.match(joined, /aria-busy/);
  assert.match(joined, /aria-live/);
});

test('IPC listener 生命周期显式保存并调用 unlisten', async () => {
  const ipc = await readFile(path.join(root, 'src', 'ipc.ts'), 'utf8');
  assert.match(ipc, /listenOperationStatus/);
  assert.match(ipc, /unlisten/);
  assert.match(ipc, /return\s+unlisten/);
});
