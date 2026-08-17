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

Write-Host "M3.4 identity switch contract: $root"
$required = @(
    'apps/desktop/src-tauri/src/application_facade/m34.rs',
    'apps/desktop/src-tauri/src/m34_backend.rs',
    'apps/desktop/src-tauri/tests/m34_contract.rs',
    'apps/desktop/src/m34-state.ts',
    'apps/desktop/src/components/SwitchWorkflow.tsx',
    'apps/desktop/tests/m34-behavior.test.mjs'
)
foreach ($file in $required) { Assert-True (Test-Path (Join-Path $root $file) -PathType Leaf) "存在 $file" }

$contract = Read-Repo 'apps/desktop/src-tauri/src/application_facade/m34.rs'
$backend = Read-Repo 'apps/desktop/src-tauri/src/m34_backend.rs'
$commands = Read-Repo 'apps/desktop/src-tauri/src/commands.rs'
$events = Read-Repo 'apps/desktop/src-tauri/src/application_facade/events.rs'
$ipc = Read-Repo 'apps/desktop/src/ipc.ts'
$state = Read-Repo 'apps/desktop/src/m34-state.ts'
$component = Read-Repo 'apps/desktop/src/components/SwitchWorkflow.tsx'
$capability = Read-Repo 'apps/desktop/src-tauri/capabilities/default.json' | ConvertFrom-Json

Assert-True ($contract -match 'M34_CONTRACT_VERSION' -and $contract -match 'deny_unknown_fields') 'M3.4 DTO 版本化且拒绝未知字段'
Assert-True ($contract -match 'plan_id' -and $contract -match 'expected_plan_version' -and $contract -match 'operation_id') 'approve 只携带 opaque plan/version/operation ids'
Assert-True ($contract -notmatch '(?i)PathBuf|&Path|Vec<u8>|target_config|target_auth|credential_material|diff_text|command_text') 'IPC DTO 不含路径、秘密或变更正文'
foreach ($command in @('preview_switch_v1','execute_switch_v1','query_switch_operation_v1','list_switch_recoveries_v1','recover_switch_v1')) {
    Assert-True ($commands -match $command) "集中注册 command $command"
}
Assert-True ($backend -match 'VerticalSwitchPlanner' -and $backend -match 'preview_from_store' -and $backend -match 'execute_approved') '生产 backend 复用 M2.5 两阶段纵向服务'
Assert-True ($backend -match 'recover_root' -and $backend -match 'list_recovery_required_diagnostics') '恢复复用 M2.3 journal/recovery 服务且只输出摘要'
foreach ($stage in @('Queued','Preparing','Validated','EnteringCritical','Committing','Completed','Cancelled','Conflict','RecoveryRequired','Failed')) {
    Assert-True ($events -match $stage) "typed event 阶段包含 $stage"
}
Assert-True ($events -notmatch '(?i)PathBuf|&Path|Vec<u8>|credential_material|config_text|auth_text') 'event payload 保持 pathless/secret-free'
Assert-True ($ipc -match 'previewSwitch' -and $ipc -match 'executeSwitch' -and $ipc -match 'cancelOperation' -and $ipc -match 'querySwitchOperation') 'frontend 使用单个 typed workflow commands'
Assert-True ($state -match 'preview_ready' -and $state -match 'cancel_too_late' -and $state -match 'recovery_required') '前端状态区分 preview、TooLate 与恢复'
Assert-True ($component -match 'm34\.confirmation' -and $component -match 'aria-live' -and $component -match 'aria-busy') '确认、进度和 a11y 状态完整'

$permissions = @($capability.permissions | Sort-Object)
$expected = @('core:event:allow-listen','core:event:allow-unlisten') | Sort-Object
Assert-True ($permissions.Count -eq 2 -and (Compare-Object $expected $permissions).Count -eq 0) 'capability 仍精确为 listen/unlisten 两项'
Assert-True ($ipc -notmatch '\bemit\(') 'frontend 不调用 event emit'

$readme = Read-Repo 'README.md'
Assert-True ($readme -match 'M3\.4' -and $readme -match 'M34IdentitySwitch.Tests.ps1') 'README 记录 M3.4 边界与验证入口'

if ($failures.Count) {
    Write-Host "M3.4 identity switch contract failed: $($failures.Count) failed, $passes passed." -ForegroundColor Red
    exit 1
}
Write-Host "M3.4 identity switch contract passed: $passes checks." -ForegroundColor Green
