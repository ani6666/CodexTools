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

test('事件通道注册失败进入固定 unavailable 状态且不泄漏技术原文', async () => {
  const { superviseOperationStatusListener } = await import('../src/event-channel.ts');
  const states = [];
  const dispose = superviseOperationStatusListener(
    () => Promise.reject(new Error('ACL denied: private runtime detail')),
    (state) => states.push(state),
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(states, ['unavailable']);
  assert.doesNotMatch(states.join(' '), /ACL|denied|private|runtime/i);
  dispose();
});

test('事件通道失败不覆盖业务错误或伪造业务成功状态', () => {
  let state = m33Reducer(createInitialM33State(), { type: 'event-channel-unavailable' });
  assert.equal(state.eventChannel, 'unavailable');
  assert.equal(state.errorCode, null);
  state = m33Reducer(state, { type: 'request-failed', requestToken: 0, code: 'conflict' });
  assert.equal(state.eventChannel, 'unavailable');
  assert.equal(state.errorCode, 'conflict');
});

test('卸载期间迟到的 listener 注册会立即 unlisten 且不再更新状态', async () => {
  const { superviseOperationStatusListener } = await import('../src/event-channel.ts');
  let resolveRegistration;
  let releaseCount = 0;
  const states = [];
  const registration = new Promise((resolve) => { resolveRegistration = resolve; });
  const dispose = superviseOperationStatusListener(() => registration, (state) => states.push(state));
  dispose();
  resolveRegistration(async () => { releaseCount += 1; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(releaseCount, 1);
  assert.deepEqual(states, []);
});

test('unlisten 异步失败被安全吸收且不产生 unhandled rejection', async () => {
  const { superviseOperationStatusListener } = await import('../src/event-channel.ts');
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    const dispose = superviseOperationStatusListener(
      () => Promise.resolve(() => Promise.reject(new Error('unlisten runtime detail'))),
      () => undefined,
    );
    await new Promise((resolve) => setImmediate(resolve));
    dispose();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

test('事件通道不可用状态提供中英文等键与 aria-live 呈现', async () => {
  const [i18n, app] = await Promise.all([
    readFile(path.join(root, 'src', 'i18n.ts'), 'utf8'),
    readFile(path.join(root, 'src', 'App.tsx'), 'utf8'),
  ]);
  assert.equal((i18n.match(/'m33\.eventChannel\.unavailable'/g) ?? []).length, 2);
  assert.match(app, /m33\.eventChannel\.unavailable/);
  assert.match(app, /role="status"[^>]*aria-live="polite"/);
});

test('event-channel 状态观察回调抛错不会形成 unhandled rejection', async () => {
  const { superviseOperationStatusListener } = await import('../src/event-channel.ts');
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    const dispose = superviseOperationStatusListener(
      () => Promise.resolve(() => undefined),
      () => { throw new Error('observer failure detail'); },
    );
    await new Promise((resolve) => setImmediate(resolve));
    dispose();
    assert.deepEqual(unhandled, []);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

test('production IPC event 通知边界吸收业务观察回调异常', async () => {
  const { notifyOperationStatus } = await import('../src/ipc.ts');
  assert.doesNotThrow(() => notifyOperationStatus(
    () => { throw new Error('event observer failure detail'); },
    { schema_version: 1, operation_id: 'opaque-op', correlation_id: 'opaque-corr', stage: 'queued', status: 'running', completed_items: 0, total_items: 2, summary_code: null },
  ));
});
