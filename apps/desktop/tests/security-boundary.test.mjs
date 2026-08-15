import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
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

test('M3.3 snapshot 与当前 M3.4 均只通过集中 typed command adapter 暴露必要命令', async () => {
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

  const m33Commands = execFileSync(
    'git',
    ['show', '446aa3b970fa5ee6e170f8fd70160c3781a65623:apps/desktop/src-tauri/src/commands.rs'],
    { cwd: path.resolve(desktopRoot, '..', '..'), encoding: 'utf8' },
  );
  assert.equal((m33Commands.match(/#\[tauri::command\]/g) ?? []).length, 9);
  for (const command of [
    'describe_contract_v1',
    'cancel_operation_v1',
    'scan_default_codex_v1',
    'import_candidate_v1',
    'list_identities_v1',
    'rename_identity_v1',
    'list_presets_v1',
    'create_preset_and_bind_v1',
    'update_preset_and_bind_v1',
  ]) assert.match(m33Commands, new RegExp(command));

  const commands = await readFile(path.join(rustRoot, 'commands.rs'), 'utf8');
  const currentCommands = [
    ...commands.matchAll(/#\[tauri::command\]\s*pub (?:async )?fn ([a-z0-9_]+)\(/g),
  ].map((match) => match[1]);
  assert.deepEqual(currentCommands, [
    'describe_contract_v1',
    'cancel_operation_v1',
    'scan_default_codex_v1',
    'import_candidate_v1',
    'list_identities_v1',
    'rename_identity_v1',
    'list_presets_v1',
    'create_preset_and_bind_v1',
    'update_preset_and_bind_v1',
    'preview_switch_v1',
    'execute_switch_v1',
    'query_switch_operation_v1',
    'list_switch_recoveries_v1',
    'recover_switch_v1',
  ]);
  assert.equal((commands.match(/#\[tauri::command\]/g) ?? []).length, 14);
  assert.doesNotMatch(commands, /PathBuf|&Path|Vec<u8>|api[_-]?key|access[_-]?token|authorization|cookie/i);
});
