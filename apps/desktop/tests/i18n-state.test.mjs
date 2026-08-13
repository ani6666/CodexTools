import assert from 'node:assert/strict';
import test from 'node:test';

import { FALLBACK_LOCALE, detectSystemLocale, translate, translateFromResources } from '../src/i18n.ts';
import { createInitialShellState, initializeLocalePreference, persistLocalePreference, readLocalePreference, resolveLocale, shellReducer, updateLocalePreferenceForSession } from '../src/shell-state.ts';

test('系统语言、用户语言与缺失键 fallback 稳定', () => {
  assert.equal(detectSystemLocale(['en-US', 'zh-CN']), 'en');
  assert.equal(detectSystemLocale(['zh-HK', 'en-US']), 'zh-CN');
  assert.equal(detectSystemLocale(['fr-FR']), FALLBACK_LOCALE);
  assert.equal(translate('en', 'shell.title'), 'Local identity workspace');
  assert.equal(translate('en', 'overview.title'), 'Workspace overview');
  assert.equal(translateFromResources({}, { fallback: '回退文案' }, 'fallback'), '回退文案');
  assert.equal(translate('en', 'missing.key'), 'missing.key');
});

test('语言 preference 生命周期区分 system 与显式用户选择', () => {
  assert.deepEqual(initializeLocalePreference(null), { preference: 'system', persisted: false });
  assert.equal(resolveLocale('system', ['en-US']), 'en');
  assert.equal(resolveLocale('system', ['zh-CN']), 'zh-CN');
  assert.deepEqual(initializeLocalePreference('invalid'), { preference: 'system', persisted: false });

  const writes = [];
  assert.deepEqual(persistLocalePreference('system', { getItem: () => null, setItem: (...args) => writes.push(args), removeItem: (...args) => writes.push(args) }), { succeeded: true });
  assert.deepEqual(writes, [['codextools.locale-preference']]);
  writes.length = 0;
  assert.deepEqual(persistLocalePreference('en', { getItem: () => null, setItem: (...args) => writes.push(args), removeItem: (...args) => writes.push(args) }), { succeeded: true });
  assert.deepEqual(writes, [['codextools.locale-preference', 'en']]);
});

test('存储读取异常与无效旧值安全降级为 system', () => {
  const readFailure = readLocalePreference({
    getItem: () => { throw new DOMException('storage-read-failed'); },
    setItem: () => {},
    removeItem: () => {},
  });
  assert.deepEqual(readFailure, { preference: 'system', persisted: false, storageSucceeded: false });
  assert.equal(createInitialShellState(['en-US'], readFailure.preference).locale, 'en');

  let cleanupAttempted = false;
  const invalidValue = readLocalePreference({
    getItem: () => 'invalid-value',
    setItem: () => {},
    removeItem: () => { cleanupAttempted = true; throw new DOMException('storage-remove-failed'); },
  });
  assert.equal(cleanupAttempted, true);
  assert.deepEqual(invalidValue, { preference: 'system', persisted: false, storageSucceeded: false });
});

test('存储写入或删除失败不阻止当前会话切换语言', () => {
  let state = createInitialShellState(['zh-CN']);
  const dispatch = (action) => { state = shellReducer(state, action); };
  const writeResult = updateLocalePreferenceForSession('en', ['zh-CN'], {
    getItem: () => null,
    setItem: () => { throw new DOMException('storage-write-failed'); },
    removeItem: () => {},
  }, dispatch);
  assert.deepEqual(writeResult, { succeeded: false });
  assert.equal(state.locale, 'en');

  const removeResult = updateLocalePreferenceForSession('system', ['zh-CN'], {
    getItem: () => 'en',
    setItem: () => {},
    removeItem: () => { throw new DOMException('storage-remove-failed'); },
  }, dispatch);
  assert.deepEqual(removeResult, { succeeded: false });
  assert.equal(state.localePreference, 'system');
  assert.equal(state.locale, 'zh-CN');
});

test('shell reducer 覆盖导航、语言、通知和全部演示状态', () => {
  let state = createInitialShellState(['en-US']);
  assert.equal(state.locale, 'en');
  state = shellReducer(state, { type: 'navigate', destination: 'status-lab' });
  state = shellReducer(state, { type: 'set-locale-preference', preference: 'zh-CN' });
  state = shellReducer(state, { type: 'notify', tone: 'info', messageKey: 'notification.fixture' });
  assert.equal(state.navigation, 'status-lab');
  assert.equal(state.locale, 'zh-CN');
  assert.equal(state.notification?.tone, 'info');

  for (const displayState of ['ready', 'empty', 'loading', 'error', 'cancelled', 'duplicate', 'compatibility_protected']) {
    state = shellReducer(state, { type: 'show-display-state', displayState });
    assert.equal(state.displayState, displayState);
  }
  assert.equal(shellReducer(state, { type: 'dismiss-notification' }).notification, null);
});
