import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function luminance(hex) {
  const channels = hex.match(/[0-9a-f]{2}/gi).map((value) => Number.parseInt(value, 16) / 255);
  const adjusted = channels.map((value) => value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return adjusted[0] * 0.2126 + adjusted[1] * 0.7152 + adjusted[2] * 0.0722;
}

function contrast(first, second) {
  const values = [luminance(first), luminance(second)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

test('shell 具备基础语义、键盘焦点和响应式约束', async () => {
  const [app, styles] = await Promise.all([
    readFile(path.join(root, 'src', 'App.tsx'), 'utf8'),
    readFile(path.join(root, 'src', 'styles.css'), 'utf8'),
  ]);
  for (const marker of ['skip-link', '<header', '<nav', '<aside', '<main', 'aria-live', 'aria-current']) {
    assert.match(app, new RegExp(marker));
  }
  assert.match(styles, /:focus-visible/);
  assert.match(styles, /prefers-reduced-motion/);
  assert.match(styles, /@media\s*\(max-width/);
  assert.match(styles, /overflow-wrap/);
});

test('基础文字与主按钮颜色达到 WCAG AA 对比度', () => {
  assert.ok(contrast('#17211d', '#ffffff') >= 4.5);
  assert.ok(contrast('#59665f', '#ffffff') >= 4.5);
  assert.ok(contrast('#ffffff', '#176b4d') >= 4.5);
});

test('StatusFeedback 精确提供原子 live region 与完整动态文本', async () => {
  const component = await readFile(path.join(root, 'src', 'components', 'StatusFeedback.tsx'), 'utf8');
  assert.match(component, /role="status"/);
  assert.match(component, /aria-live="polite"/);
  assert.match(component, /aria-atomic="true"/);
  assert.match(component, /aria-busy=\{state === 'loading'\}/);
  assert.match(component, /\{title\}/);
  assert.match(component, /\{body\}/);
});

test('暗色通知及常用控件的焦点指示达到 3:1', async () => {
  const styles = await readFile(path.join(root, 'src', 'styles.css'), 'utf8');
  assert.match(styles, /prefers-color-scheme:\s*dark[\s\S]*--color-focus:\s*#[0-9a-f]{6}/i);
  assert.ok(contrast('#1d70b7', '#263a32') < 3, '回归基线应能复现旧暗色焦点不足');
  assert.ok(contrast('#8fd8ff', '#263a32') >= 3);
  assert.ok(contrast('#8fd8ff', '#19231f') >= 3);
  assert.ok(contrast('#8fd8ff', '#24543f') >= 3);
  assert.ok(contrast('#07100c', '#79d1a8') >= 3);
  assert.match(styles, /box-shadow:\s*0 0 0 2px #07100c/);
});
