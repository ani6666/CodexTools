import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DEFAULT_LOCALE,
  getSkeletonCopy,
  SUPPORTED_LOCALES,
} from '../src/language.ts';

test('默认语言为简体中文，同时保留英文骨架文案', () => {
  assert.equal(DEFAULT_LOCALE, 'zh-CN');
  assert.deepEqual(SUPPORTED_LOCALES, ['zh-CN', 'en']);
  assert.equal(getSkeletonCopy('zh-CN').status, '桌面基础已就绪');
  assert.equal(getSkeletonCopy('en').status, 'Desktop foundation is ready');
});
