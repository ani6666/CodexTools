[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$failures = [System.Collections.Generic.List[string]]::new()
$passes = 0

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if ($Condition) {
        $script:passes++
        Write-Host "PASS: $Message"
    } else {
        $script:failures.Add($Message)
        Write-Host "FAIL: $Message" -ForegroundColor Red
    }
}

function Read-Repo {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $root $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return ''
    }
    return Get-Content -LiteralPath $path -Raw
}

Write-Host "M3.1 application facade contract: $root"

$requiredFiles = @(
    'apps/desktop/src-tauri/src/application_facade/mod.rs',
    'apps/desktop/src-tauri/src/application_facade/cancellation.rs',
    'apps/desktop/src-tauri/src/application_facade/contract.rs',
    'apps/desktop/src-tauri/src/application_facade/error.rs',
    'apps/desktop/src-tauri/src/application_facade/events.rs',
    'apps/desktop/src-tauri/src/commands.rs',
    'apps/desktop/src-tauri/tests/m31_contract.rs'
)
foreach ($file in $requiredFiles) {
    Assert-True (Test-Path -LiteralPath (Join-Path $root $file) -PathType Leaf) "存在 $file"
}

$manifest = Read-Repo 'apps/desktop/src-tauri/Cargo.toml'
Assert-True ($manifest -match '(?m)^serde\s*=\s*\{\s*version\s*=\s*"=1\.0\.229"') '桌面边界显式锁定 serde 1.0.229'
Assert-True ($manifest -match '(?m)^serde_json\s*=\s*"=1\.0\.151"') '合同测试显式锁定 serde_json 1.0.151'

$library = Read-Repo 'apps/desktop/src-tauri/src/lib.rs'
$facade = Read-Repo 'apps/desktop/src-tauri/src/application_facade/mod.rs'
$contract = Read-Repo 'apps/desktop/src-tauri/src/application_facade/contract.rs'
$cancellation = Read-Repo 'apps/desktop/src-tauri/src/application_facade/cancellation.rs'
$errors = Read-Repo 'apps/desktop/src-tauri/src/application_facade/error.rs'
$events = Read-Repo 'apps/desktop/src-tauri/src/application_facade/events.rs'
$commands = Read-Repo 'apps/desktop/src-tauri/src/commands.rs'
$tests = Read-Repo 'apps/desktop/src-tauri/tests/m31_contract.rs'
$capability = Read-Repo 'apps/desktop/src-tauri/capabilities/default.json'

Assert-True ($library -match 'mod application_facade' -and $library -match 'mod commands') 'Tauri crate 隔离 facade 与 command adapter'
Assert-True ($library -match 'invoke_handler' -and $library -match 'commands::registered_handlers') 'Tauri 仅通过集中 adapter 注册 handler'
Assert-True ($facade -match 'pub struct ApplicationFacade') '定义可独立单测的 ApplicationFacade'
Assert-True ($facade -notmatch '(?i)tauri') 'ApplicationFacade 不依赖 Tauri 类型'

Assert-True ($contract -match 'M31_CONTRACT_VERSION') '集中定义 M3.1 contract version'
Assert-True ($contract -match 'COMMAND_DESCRIBE_CONTRACT_V1' -and $contract -match 'COMMAND_CANCEL_OPERATION_V1') 'command 名称集中定义'
Assert-True ($contract -match 'Serialize' -and $contract -match 'Deserialize') 'request/response DTO 支持 serde'
Assert-True ($contract -notmatch '(?i)PathBuf|&Path|Vec<u8>|Zeroizing|api_key|access_token|refresh_token|authorization|cookie|oauth_code|code_verifier') 'IPC DTO 不包含秘密正文或真实路径类型'
Assert-True ($contract -match 'contains_high_confidence_secret') 'SafeIdentifier 复用 M2 集中的高置信秘密检测'

foreach ($code in @(
    'Validation', 'NotFound', 'Conflict', 'PlanStale', 'CompatibilityProtected',
    'Cancelled', 'RecoveryRequired', 'Unavailable', 'Internal'
)) {
    Assert-True ($errors -match $code) "稳定错误码包含 $code"
}
Assert-True ($errors -match 'message_zh_cn' -and $errors -match 'message_key') '错误 envelope 同时提供中文消息与本地化 key'
Assert-True ($errors -match 'RepositoryError' -and $errors -match 'SwitchExecutionError' -and $errors -match 'VerticalClosureError') 'M2 错误具有显式 facade 映射'

Assert-True ($events -match 'EVENT_OPERATION_STATUS_V1' -and $events -match 'schema_version') 'typed event 名称和 schema version 集中定义'
Assert-True ($events -match 'operation_id' -and $events -match 'correlation_id') 'event payload 绑定 operation/correlation'
Assert-True ($events -match 'trait EventSink') '定义可测试的 event sink port'
Assert-True ($events -notmatch '(?i)PathBuf|&Path|Vec<u8>|api_key|access_token|refresh_token|authorization|cookie|oauth_code|code_verifier') 'event payload 不含秘密正文或真实路径类型'

foreach ($outcome in @('Requested', 'AlreadyRequested', 'UnknownOperation', 'TooLate', 'AlreadyCompleted')) {
    Assert-True ($cancellation -match $outcome) "取消结果包含 $outcome"
}
Assert-True ($cancellation -match 'enter_non_cancellable' -and $cancellation -match 'checkpoint') '取消契约区分可取消点与不可取消临界区'
Assert-True ($cancellation -notmatch '(?i)kill|terminate|process') '取消契约不使用进程强制终止'
Assert-True ($cancellation -match 'rollback_registration' -and $cancellation -match 'remove_completed') 'operation 注册失败可安全回滚且完成态可显式释放'

Assert-True ($commands -match '#\[tauri::command' -and $commands -match 'describe_contract_v1' -and $commands -match 'cancel_operation_v1') '仅注册最小 typed Tauri commands'
Assert-True ($capability -match '"permissions"\s*:\s*\[\s*\]') '自定义 app commands 保持空 capability permissions'

Assert-True ($tests -match 'CANARY' -and $tests -match 'serde_json') '合同测试覆盖固定 canary 与 JSON'
Assert-True ($tests -match 'request_response_event_error_debug_display_and_json_are_secret_free') '合同测试覆盖 DTO/event/error 的 secret-free 输出'
Assert-True ($tests -match 'cancellation_semantics_are_stable') '合同测试覆盖重复、未知、完成后和临界区取消'
Assert-True ($tests -match 'm2_error_mapping_is_exhaustive_and_stable') '合同测试覆盖 M2 错误映射'
Assert-True ($tests -match 'OPENAI_CANARY' -and $tests -match 'GITHUB_CANARY' -and $tests -match 'AWS_CANARY' -and $tests -match 'JWT_CANARY' -and $tests -match 'PRIVATE_KEY_HEADER') '合同测试覆盖高置信秘密形态与危险路径'
Assert-True ($tests -match 'event_sink_failure_rolls_back_registration_and_lifecycle_is_bounded') '合同测试覆盖事件失败重试与 operation 有界生命周期'
Assert-True ($errors -match 'OutsideWriteDetected\s*=>\s*ErrorCode::CompatibilityProtected') '隔离目录外写入映射为不可重试兼容保护'

$readme = Read-Repo 'README.md'
Assert-True ($readme -match 'M3\.1' -and $readme -match 'M31ApplicationFacade.Tests.ps1') 'README 记录 M3.1 契约与验证入口'

if ($failures.Count -gt 0) {
    Write-Host "M3.1 application facade contract failed: $($failures.Count) failed, $passes passed." -ForegroundColor Red
    exit 1
}

Write-Host "M3.1 application facade contract passed: $passes checks." -ForegroundColor Green
