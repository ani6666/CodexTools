[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$failures = [System.Collections.Generic.List[string]]::new()
$passes = 0

function Assert-True([bool]$Condition, [string]$Message) {
    if ($Condition) { $script:passes++; Write-Host "PASS: $Message" }
    else { $script:failures.Add($Message); Write-Host "FAIL: $Message" -ForegroundColor Red }
}

function Read-Repo([string]$RelativePath) {
    $path = Join-Path $root $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return '' }
    Get-Content -LiteralPath $path -Raw
}

Write-Host "M3.3 desktop identity contract: $root"
$required = @(
    'apps/desktop/src-tauri/src/application_facade/m33.rs',
    'apps/desktop/src-tauri/src/m33_backend.rs',
    'apps/desktop/src-tauri/tests/m33_contract.rs',
    'apps/desktop/src/ipc.ts',
    'apps/desktop/src/m33-state.ts',
    'apps/desktop/src/components/LocalCandidate.tsx',
    'apps/desktop/src/components/IdentityManager.tsx',
    'apps/desktop/src/components/PresetManager.tsx',
    'apps/desktop/tests/m33-behavior.test.mjs'
)
foreach ($file in $required) { Assert-True (Test-Path (Join-Path $root $file) -PathType Leaf) "存在 $file" }

$contract = Read-Repo 'apps/desktop/src-tauri/src/application_facade/m33.rs'
$backend = Read-Repo 'apps/desktop/src-tauri/src/m33_backend.rs'
$commands = Read-Repo 'apps/desktop/src-tauri/src/commands.rs'
$library = Read-Repo 'apps/desktop/src-tauri/src/lib.rs'
$app = Read-Repo 'apps/desktop/src/App.tsx'
$ipc = Read-Repo 'apps/desktop/src/ipc.ts'
$state = Read-Repo 'apps/desktop/src/m33-state.ts'
$components = (Read-Repo 'apps/desktop/src/components/LocalCandidate.tsx') + (Read-Repo 'apps/desktop/src/components/IdentityManager.tsx') + (Read-Repo 'apps/desktop/src/components/PresetManager.tsx')
$package = Read-Repo 'apps/desktop/package.json'
$capability = Read-Repo 'apps/desktop/src-tauri/capabilities/default.json'

Assert-True ($contract -match 'M33_CONTRACT_VERSION' -and $contract -match 'deny_unknown_fields') 'M3.3 typed DTO 版本化且拒绝未知字段'
Assert-True ($contract -match 'DefaultCodex' -and $contract -notmatch 'PathBuf|&Path|Vec<u8>') 'IPC 只接受受控根且无真实路径/字节类型'
foreach ($stateName in @('Idle','Scanning','NotFound','Candidate','Duplicate','CompatibilityProtected','Conflict','RecoveryRequired','Error')) {
    Assert-True ($contract -match $stateName) "扫描状态包含 $stateName"
}
Assert-True ($contract -match 'IdentitySummaryDto' -and $contract -match 'ModelPresetSummaryDto') '身份与预设 DTO 仅输出摘要'
Assert-True ($contract -notmatch '(?i)api_key|access_token|refresh_token|authorization|cookie|credential_material|fingerprint|endpoint') 'DTO 不包含 credential/endpoint/secret 字段'

Assert-True ($backend -match 'CaptureImportService' -and $backend -match 'consume_confirmed') '生产导入复用 M2.6 exact rescan 闭环'
Assert-True ($backend -match 'PresetBindingService' -and $backend -match 'create_and_bind' -and $backend -match 'update_and_bind') '生产预设复用 M2.7 组合事务服务'
Assert-True ($backend -match 'list_runtime_identities' -and $backend -match 'update_runtime_identity') '生产身份列表与 rename 走真实仓储/CAS'
Assert-True ($backend -match 'DefaultCodex' -and $backend -notmatch 'std::env::var|CODEX_HOME') 'composition root 后端解析默认受控根且不读取 CODEX_HOME'

foreach ($command in @('scan_default_codex_v1','import_candidate_v1','list_identities_v1','rename_identity_v1','list_presets_v1','create_preset_and_bind_v1','update_preset_and_bind_v1')) {
    Assert-True ($commands -match $command) "集中注册 command $command"
}
Assert-True ($commands -match 'spawn_blocking') 'SQLite/DPAPI 命令离开 UI 线程执行'
Assert-True ($library -match 'TauriEventSink' -and $library -match 'app_data_dir') 'composition root 在后端解析 app data 并提供 typed event sink'

Assert-True ($package -match '"@tauri-apps/api"\s*:\s*"2\.11\.0"') '仅新增锁定版本的官方 Tauri invoke/listen API'
Assert-True ($capability -match '"permissions"\s*:\s*\[\s*\]') '自定义 commands 不扩大 capability 权限'
Assert-True ($ipc -match "@tauri-apps/api/core" -and $ipc -match "@tauri-apps/api/event") '前端仅使用官方 invoke/listen 子模块'
Assert-True ($ipc -notmatch '(?i)access[_-]?token|refresh[_-]?token|authorization|credential[_-]?material|CODEX_HOME|auth\.json|config\.toml') '前端 IPC 层不接触秘密或真实路径'
Assert-True ($state -match 'requestToken' -and $state -match 'stale' -and $state -match 'unmounted') '状态机防止 stale response 与卸载后更新'
Assert-True ($app -notmatch '(?s)useEffect\(\(\)\s*=>\s*\{[^}]*scanDefaultCodex') '挂载/语言切换不会自动扫描'
Assert-True ($components -match 'local-candidate' -and $components -match 'saved-identities' -and $components -match 'model-presets') '信息架构明确区分候选、身份与预设'
Assert-True (($app + $components) -match 'aria-live' -and ($app + $components) -match 'aria-busy') '业务区提供 live/busy 可访问状态'

$readme = Read-Repo 'README.md'
Assert-True ($readme -match 'M3\.3' -and $readme -match 'M33DesktopIdentity.Tests.ps1') 'README 记录 M3.3 边界与验证入口'

if ($failures.Count) {
    Write-Host "M3.3 desktop identity contract failed: $($failures.Count) failed, $passes passed." -ForegroundColor Red
    exit 1
}
Write-Host "M3.3 desktop identity contract passed: $passes checks." -ForegroundColor Green
