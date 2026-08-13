import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(absolute)));
    } else {
      files.push(absolute);
    }
  }
  return files;
}

test('M3.1 前端仍不建立 IPC、事件或秘密材料入口', async () => {
  const frontendSource = (
    await Promise.all((await listFiles(path.join(desktopRoot, 'src'))).map((file) => readFile(file, 'utf8')))
  ).join('\n');
  const forbidden = [
    /@tauri-apps\/api/i,
    /\binvoke\s*\(/,
    /\b(?:listen|emit)\s*\(/,
    /CODEX_HOME/i,
    /auth\.json/i,
    /config\.toml/i,
    /api[_-]?key/i,
    /access[_-]?token/i,
    /refresh[_-]?token/i,
    /authorization/i,
  ];

  for (const pattern of forbidden) {
    assert.doesNotMatch(frontendSource, pattern);
  }
});

test('M3.1 Rust 只暴露集中定义的最小 typed command adapter', async () => {
  const rustRoot = path.join(desktopRoot, 'src-tauri', 'src');
  const rustFiles = await listFiles(rustRoot);
  const commandLocations = [];
  const invokeHandlerLocations = [];
  for (const file of rustFiles) {
    const source = await readFile(file, 'utf8');
    if (source.includes('#[tauri::command]')) commandLocations.push(path.relative(rustRoot, file));
    if (source.includes('.invoke_handler(')) invokeHandlerLocations.push(path.relative(rustRoot, file));
  }
  assert.deepEqual(commandLocations, ['commands.rs']);
  assert.deepEqual(invokeHandlerLocations, ['lib.rs']);

  const commands = await readFile(path.join(rustRoot, 'commands.rs'), 'utf8');
  assert.equal((commands.match(/#\[tauri::command\]/g) ?? []).length, 2);
  assert.match(commands, /describe_contract_v1/);
  assert.match(commands, /cancel_operation_v1/);
  assert.doesNotMatch(commands, /PathBuf|&Path|Vec<u8>|api[_-]?key|access[_-]?token|authorization|cookie/i);
});
