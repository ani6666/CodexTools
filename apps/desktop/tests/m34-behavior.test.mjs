import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createInitialM34State, m34Reducer } from '../src/m34-state.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const preview = {
  planId: 'opaque-plan', planVersion: 1, operationId: 'opaque-operation',
  identity: { identityId: 'opaque-identity', name: 'Synthetic identity', providerName: 'Sample', authMode: 'api_key', status: 'ready', defaultPresetId: 'opaque-preset', version: 1 },
  preset: { presetId: 'opaque-preset', name: 'Default', modelId: 'sample-model', version: 1, isDefault: true },
  affectedCategories: ['configuration', 'authentication'], affectedItems: 2,
  warnings: ['local_state_changes', 'cancellation_ends_at_critical'], compatibility: 'ready',
};

test('切换只从显式 preview 开始，preview 后必须确认才进入 execute', () => {
  const initial = createInitialM34State();
  assert.equal(initial.status, 'idle');
  const previewing = m34Reducer(initial, { type: 'preview-started', requestToken: 1 });
  assert.equal(previewing.status, 'previewing');
  const ready = m34Reducer(previewing, { type: 'preview-finished', requestToken: 1, preview });
  assert.equal(ready.status, 'preview_ready');
  assert.equal(ready.preview?.planId, 'opaque-plan');
  const executing = m34Reducer(ready, { type: 'execute-started', requestToken: 2, operationId: preview.operationId });
  assert.equal(executing.status, 'executing');
});

test('stale promise、错误 operation event 与卸载后响应不改写状态', () => {
  let state = m34Reducer(createInitialM34State(), { type: 'preview-started', requestToken: 2 });
  assert.deepEqual(m34Reducer(state, { type: 'preview-finished', requestToken: 1, preview }), state);
  state = m34Reducer(state, { type: 'unmounted' });
  assert.deepEqual(m34Reducer(state, { type: 'preview-finished', requestToken: 2, preview }), state);
  const active = m34Reducer(m34Reducer(createInitialM34State(), { type: 'preview-started', requestToken: 3 }), { type: 'preview-finished', requestToken: 3, preview });
  assert.deepEqual(m34Reducer(active, { type: 'progress-received', operationId: 'foreign', stage: 'committing' }), active);
});

test('取消 requested 与 too_late 分离，too_late 不伪装成已取消', () => {
  let state = m34Reducer(createInitialM34State(), { type: 'preview-started', requestToken: 1 });
  state = m34Reducer(state, { type: 'preview-finished', requestToken: 1, preview });
  state = m34Reducer(state, { type: 'execute-started', requestToken: 2, operationId: preview.operationId });
  assert.equal(m34Reducer(state, { type: 'cancel-finished', outcome: 'requested' }).status, 'cancelling');
  assert.equal(m34Reducer(state, { type: 'cancel-finished', outcome: 'too_late' }).status, 'cancel_too_late');
});

test('终态查询和迟到事件以 backend 结果收敛', () => {
  let state = m34Reducer(createInitialM34State(), { type: 'query-finished', operationId: 'opaque-operation', status: 'recovery_required' });
  assert.equal(state.status, 'recovery_required');
  const late = m34Reducer(state, { type: 'progress-received', operationId: 'opaque-operation', stage: 'completed' });
  assert.deepEqual(late, state);
});

test('恢复命令以 recovery id 绑定 operation registry、事件和取消语义', async () => {
  const ipc = await readFile(path.join(root, 'src/ipc.ts'), 'utf8');
  const recoveryCommand = ipc.match(/export async function recoverSwitch[\s\S]*?\n}/)?.[0] ?? '';
  assert.match(recoveryCommand, /operation_id:\s*recoveryId/);
  assert.doesNotMatch(recoveryCommand, /operation_id:\s*operationId\(\)/);
});

test('M3.4 UI 与 IPC 不包含真实路径、秘密正文或任意变更输入', async () => {
  const sources = await Promise.all([
    'src/ipc.ts', 'src/m34-state.ts', 'src/components/SwitchWorkflow.tsx', 'src/App.tsx',
  ].map((file) => readFile(path.join(root, file), 'utf8')));
  const joined = sources.join('\n');
  assert.doesNotMatch(joined, /CODEX_HOME|auth\.json|config\.toml|credentialMaterial|targetConfig|targetAuth|rawDiff|commandText/i);
  assert.match(joined, /aria-live/);
  assert.match(joined, /aria-busy/);
  assert.match(joined, /m34\.confirmation/);
});
