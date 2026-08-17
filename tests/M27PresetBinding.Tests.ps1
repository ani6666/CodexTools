$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$passed = 0
$failed = 0

function Assert-True([bool]$Condition, [string]$Message) {
    if ($Condition) { $script:passed++; Write-Host "PASS: $Message"; return }
    $script:failed++; Write-Host "FAIL: $Message" -ForegroundColor Red
}
function Read-Repo([string]$Path) {
    $full = Join-Path $root $Path
    Assert-True (Test-Path -LiteralPath $full -PathType Leaf) "存在 $Path"
    if (Test-Path -LiteralPath $full -PathType Leaf) { return Get-Content -LiteralPath $full -Raw }
    return ''
}

$application = Read-Repo 'crates/codex-application/src/preset_binding.rs'
$infrastructure = Read-Repo 'crates/local-infrastructure/src/preset_binding.rs'
$domain = Read-Repo 'crates/codex-domain/src/preset.rs'
$integration = Read-Repo 'crates/local-infrastructure/tests/m27_preset_binding.rs'
$m27Parent = 'f8b5b75011309e753a477978c68ea3b8196db13a'
$m27Snapshot = '8340690298a072048ff69a5ea9923b5dece87c8f'
$desktopDiff = & git -C $root diff "$m27Parent..$m27Snapshot" -- apps/desktop 2>&1 | Out-String

Assert-True ($application -match 'M27_SERVICE_VERSION' -and $application -match 'CreatePresetAndBindInput' -and $application -match 'UpdatePresetAndBindInput') '使用分离且带版本的 create/update 输入'
Assert-True ($application -match 'trait PresetBindingRepository' -and $application -notmatch 'Option<\s*(Create|Update)PresetAndBindInput') 'application 暴露无歧义组合仓储端口'
Assert-True ($infrastructure -match 'TransactionBehavior::Immediate' -and $infrastructure -match 'expected_identity_version' -and $infrastructure -match 'expected_preset_version' -and $infrastructure -match '\.commit\(\)') 'SQLite 组合适配器使用单个 Immediate transaction 与双 CAS'
Assert-True ($infrastructure -notmatch 'create_model_preset\(' -and $infrastructure -notmatch 'update_runtime_identity\(') '组合适配器不拼装既有单实体仓储公开方法'
Assert-True ($domain -match 'new_managed' -and $domain -match 'update_metadata') 'ModelPreset 安全创建与更新由 domain 验证'
Assert-True ($integration -match 'rejects_secret_and_path_shapes_without_echo') '固定高置信秘密与路径形态具有不回显回归'

foreach ($marker in @('AfterPresetWrite','BeforeIdentityWrite','AfterIdentityWrite','BeforeCommit','CommitOutcomeUnknown')) {
    Assert-True ($infrastructure -match [regex]::Escape($marker)) "故障切点 $marker 已实现"
}
foreach ($marker in @('fault_matrix','reopen','AlreadyApplied','foreign','concurrent')) {
    Assert-True ($integration -match [regex]::Escape($marker)) "集成矩阵包含 $marker"
}

Assert-True ([string]::IsNullOrWhiteSpace($desktopDiff)) 'M2.7 snapshot 范围不修改 apps/desktop 生产或测试代码'
Assert-True ($application -notmatch '(?i)tauri|serde|EventSink|#\[command\]' -and $infrastructure -notmatch '(?i)http|network|dpapi') 'M2.7 不引入 IPC、网络或凭据实现'

Write-Host "M27_CONTRACT_SUMMARY passed=$passed failed=$failed"
if ($failed -ne 0) {
    throw "M2.7 contract failed: $failed assertion(s)"
}
