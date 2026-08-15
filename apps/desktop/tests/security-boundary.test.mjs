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

test('M3.3 前端 IPC 仍不建立秘密材料或真实路径入口', async () => {
  const frontendSource = (
    await Promise.all((await listFiles(path.join(desktopRoot, 'src'))).map((file) => readFile(file, 'utf8')))
  ).join('\n');
  const forbidden = [
    /CODEX_HOME/i,
    /auth\.json/i,
    /config\.toml/i,
    /access[_-]?token/i,
    /refresh[_-]?token/i,
    /authorization/i,
  ];

  for (const pattern of forbidden) {
    assert.doesNotMatch(frontendSource, pattern);
  }
});

test('M3.3 Rust 只通过集中 typed command adapter 暴露必要命令', async () => {
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
  assert.equal((commands.match(/#\[tauri::command\]/g) ?? []).length, 9);
  assert.match(commands, /describe_contract_v1/);
  assert.match(commands, /cancel_operation_v1/);
  for (const command of ['scan_default_codex_v1', 'import_candidate_v1', 'list_identities_v1', 'rename_identity_v1', 'list_presets_v1', 'create_preset_and_bind_v1', 'update_preset_and_bind_v1']) assert.match(commands, new RegExp(command));
  assert.doesNotMatch(commands, /PathBuf|&Path|Vec<u8>|api[_-]?key|access[_-]?token|authorization|cookie/i);
});
