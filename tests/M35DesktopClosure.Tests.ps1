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

Write-Host "M3.5 desktop closure contract: $root"
$required = @(
    'apps/desktop/src-tauri/src/application_facade/m35.rs',
    'apps/desktop/src-tauri/src/m35_backend.rs',
    'apps/desktop/src-tauri/tests/m35_contract.rs',
    'apps/desktop/src/m35-state.ts',
    'apps/desktop/src/components/ConnectionDiscovery.tsx',
    'apps/desktop/src/components/ErrorBoundary.tsx',
    'apps/desktop/tests/m35-behavior.test.mjs'
)
foreach ($file in $required) { Assert-True (Test-Path (Join-Path $root $file) -PathType Leaf) "存在 $file" }

$contract = Read-Repo 'apps/desktop/src-tauri/src/application_facade/m35.rs'
$backend = Read-Repo 'apps/desktop/src-tauri/src/m35_backend.rs'
$commands = Read-Repo 'apps/desktop/src-tauri/src/commands.rs'
$lib = Read-Repo 'apps/desktop/src-tauri/src/lib.rs'
$windowsPlatform = Read-Repo 'crates/windows-platform/src/single_instance.rs'
$rustContract = Read-Repo 'apps/desktop/src-tauri/tests/m35_contract.rs'
$lifecycle = Read-Repo 'apps/desktop/src-tauri/src/application_facade/lifecycle.rs'
$activation = Read-Repo 'apps/desktop/src-tauri/src/window_activation.rs'
$cargo = Read-Repo 'apps/desktop/src-tauri/Cargo.toml'
$ipc = Read-Repo 'apps/desktop/src/ipc.ts'
$app = Read-Repo 'apps/desktop/src/App.tsx'
$m35State = Read-Repo 'apps/desktop/src/m35-state.ts'
$connection = Read-Repo 'apps/desktop/src/components/ConnectionDiscovery.tsx'
$capability = Read-Repo 'apps/desktop/src-tauri/capabilities/default.json' | ConvertFrom-Json

Assert-True ($contract -match 'M35_CONTRACT_VERSION' -and $contract -match 'deny_unknown_fields') 'M3.5 DTO 版本化且拒绝未知字段'
Assert-True ($contract -notmatch '(?i)PathBuf|&Path|Vec<u8>|authorization|token|credential_material|http_body|header') 'M3.5 IPC DTO 不含路径、秘密与原始网络材料'
foreach ($command in @('probe_connection_v1','discover_models_v1','request_app_exit_v1')) { Assert-True ($commands -match $command) "注册 $command" }
Assert-True ($backend -match 'SafeModelDiscoveryService' -and $backend -match 'NativeHttpTransport' -and $backend -match 'SystemDnsResolver') '生产 backend 复用 M2.8 安全服务与 transport'
Assert-True ($backend -match 'MAX_ACTIVE_OPERATIONS' -and $backend -match 'CancellationController') '网络 operation registry 有界并复用 M2.8 取消控制器'
Assert-True ($lifecycle -match 'Condvar' -and $lifecycle -match 'ProcessLifecyclePhase' -and $lifecycle -match 'ExitInProgress') '进程生命周期 gate 原子 admission、draining 与无 sleep 等待'
$expectedExempt = @('describe_contract_v1', 'cancel_operation_v1', 'request_app_exit_v1')
$expectedAdmitted = @('scan_default_codex_v1', 'import_candidate_v1', 'list_identities_v1', 'rename_identity_v1', 'list_presets_v1', 'create_preset_and_bind_v1', 'update_preset_and_bind_v1', 'preview_switch_v1', 'execute_switch_v1', 'query_switch_operation_v1', 'list_switch_recoveries_v1', 'recover_switch_v1', 'probe_connection_v1', 'discover_models_v1')
$declaredExempt = [regex]::Match($commands, 'ADMISSION_EXEMPT_COMMANDS:[^=]+?=\s*\[(?<body>[\s\S]*?)\];').Groups['body'].Value
$exactExempt = @([regex]::Matches($declaredExempt, '"(?<name>[a-z0-9_]+)"') | ForEach-Object { $_.Groups['name'].Value })
$allCommands = @([regex]::Matches($commands, '#\[tauri::command\]\s*pub(?:\s+async)?\s+fn\s+(?<name>[a-z0-9_]+)') | ForEach-Object { $_.Groups['name'].Value })
$admittedBodiesMatch = $true
foreach ($name in $expectedAdmitted) {
    $body = [regex]::Match($commands, "pub\s+async\s+fn\s+$name[\s\S]*?(?=#\[tauri::command\]|pub\s+fn\s+registered_handlers)").Value
    if ($body -notmatch 'run_admitted_blocking') { $admittedBodiesMatch = $false }
}
Assert-True ((Compare-Object ($expectedExempt | Sort-Object) ($exactExempt | Sort-Object)).Count -eq 0 -and (Compare-Object (($expectedExempt + $expectedAdmitted) | Sort-Object) ($allCommands | Sort-Object)).Count -eq 0 -and $admittedBodiesMatch) 'typed command 统一 admission 且豁免 allowlist 精确'
Assert-True ($backend -match 'current_exe' -and $backend -match 'CODEXTOOLS_M35_NATIVE_CHILD') 'native harness 通过 fresh test process 驱动 production backend'
Assert-True ($cargo -match 'tauri-plugin-single-instance\s*=\s*\{\s*version\s*=\s*"=') 'single-instance 官方插件精确锁版本'
Assert-True ($lib -match 'tauri_plugin_single_instance::init' -and $lib -match 'get_webview_window\("main"\)') '第二实例仅恢复并聚焦 main 窗口'
Assert-True ($windowsPlatform -match 'CreateMutexW' -and $windowsPlatform -match 'CreateEventW' -and $windowsPlatform -match 'WaitForSingleObject') 'Windows 启动门禁以 mutex+ready event 消除主实例建窗竞态'
Assert-True ($lib -match 'InstanceStartupDisposition::Secondary' -and $lib -match 'mark_ready') '第二实例 fail closed，主实例完成 setup 后才发布 ready'
Assert-True ($rustContract -match 'real_process_gate_is_unique_barriered_and_recovers_after_crash') '单实例以真实 helper process、barrier 与 crash recovery 验证'
Assert-True ($activation -match 'activate_main_window' -and $activation -match 'show' -and $activation -match 'unminimize' -and $activation -match 'focus') '单实例窗口激活顺序可独立测试且逐步吸收失败'
Assert-True ($activation -notmatch '\bexit\s*\(' -and $lib -notmatch 'single_instance[\s\S]{0,500}\.exit\s*\(') '第二实例激活路径不能触发退出'
Assert-True ($lib -notmatch '(?i)emit.*single|argv.*emit|cwd.*emit') 'second-instance argv/cwd 不转发前端'
Assert-True ($lib -match 'CloseRequested' -and $lib -match 'prevent_close' -and $lib -match 'cancel_network_operations') '窗口关闭只隐藏并取消网络操作'
Assert-True ($contract -match 'request_app_exit_with_sink' -and $contract -match 'begin_exit' -and $contract -match 'wait_for_zero' -and $commands -match 'TauriExitSink' -and $commands -match 'request_app_exit_with_sink') '显式安全退出在 sealed gate 内通过 ExitSink 调用原生退出'
Assert-True ($ipc -match 'probeConnection' -and $ipc -match 'discoverModels') 'frontend 仅通过 typed invoke 请求连接与候选'
Assert-True (($ipc + $app) -notmatch '\b(fetch|XMLHttpRequest|WebSocket)\b') 'frontend 不直接发起网络请求'
Assert-True ($app -notmatch 'useEffect[\s\S]{0,300}(probeConnection|discoverModels)') 'mount/languagechange 不触发联网'
Assert-True ($m35State -match 'ProvenancedModelCandidate[\s\S]{0,180}requestToken' -and $m35State -match 'bindCandidateIfCurrent' -and $m35State -match 'sameOperationProvenance\(context\.provenance, candidate\.provenance\)') '候选保存精确绑定 request token 与完整 operation provenance'
$policyHandler = [regex]::Match($app, 'const changeConnectionPolicy[\s\S]*?\n  };').Value
Assert-True ($connection -match 'onPolicyChange' -and $policyHandler -match 'connectionPolicyRef\.current = policy[\s\S]*setConnectionPolicy\(policy\)[\s\S]*rotateConnectionSource' -and $policyHandler -notmatch 'probeConnection|discoverModels') 'endpoint policy 变化同步失效来源且不自动联网'
$saveHandler = [regex]::Match($app, 'const useCandidate[\s\S]*?\n  };').Value
Assert-True ($saveHandler -match 'bindCandidateIfCurrent' -and $saveHandler -match 'selectedIdentityRef\.current' -and $saveHandler -match 'connectionSourceRef\.current') '候选保存调用前从同步 current refs 重验身份、token 与 policy'

$permissions = @($capability.permissions | Sort-Object)
$expected = @('core:event:allow-listen','core:event:allow-unlisten') | Sort-Object
Assert-True ($permissions.Count -eq 2 -and (Compare-Object $expected $permissions).Count -eq 0) 'capability 仍精确为 listen/unlisten'

if ($failures.Count) {
    Write-Host "M3.5 desktop closure contract failed: $($failures.Count) failed, $passes passed." -ForegroundColor Red
    exit 1
}
Write-Host "M3.5 desktop closure contract passed: $passes checks." -ForegroundColor Green
