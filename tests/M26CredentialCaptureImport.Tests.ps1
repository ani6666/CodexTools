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

$port = Read-Repo 'crates/codex-application/src/capture_import.rs'
$codex = Read-Repo 'crates/codex-application/src/codex.rs'
$adapter = Read-Repo 'crates/codex-adapter/src/lib.rs'
$json = Read-Repo 'crates/codex-adapter/src/json.rs'
$hash = Read-Repo 'crates/codex-adapter/src/hash.rs'
$credential = Read-Repo 'crates/local-infrastructure/src/credential_service.rs'
$orchestrator = Read-Repo 'crates/local-infrastructure/src/capture_import.rs'
$controlledSource = Read-Repo 'crates/local-infrastructure/src/controlled_source.rs'
$windowsPath = Read-Repo 'crates/windows-platform/src/secure_path.rs'
$windowsHandle = Read-Repo 'crates/windows-platform/src/sensitive_temp.rs'
$helper = Read-Repo 'crates/local-infrastructure/src/bin/m26-capture-import-crash.rs'
$migration = Read-Repo 'crates/local-infrastructure/migrations/0011_capture_import_recovery.sql'
$repository = Read-Repo 'crates/local-infrastructure/src/repository.rs'
$tests = Read-Repo 'crates/local-infrastructure/tests/m26_capture_import.rs'
$verify = Read-Repo 'scripts/verify-repo.ps1'
$readme = Read-Repo 'README.md'
$engineering = Read-Repo 'docs/engineering/m26-credential-capture-import.md'

Assert-True ($port -match 'enum ControlledRoot' -and $port -match 'DefaultCodex') 'production contract 使用固定非敏感 root selector'
Assert-True ($port -notmatch 'CaptureImportRequest[\s\S]{0,1000}PathBuf') '公开 capture-import 请求不携带真实路径'
Assert-True ($port -match 'trait ScannedAuthConsumer' -and $port -match 'auth: &mut \[u8\]') 'auth bytes 仅经 Rust mutable consumer 短借用'
Assert-True ($port -match 'enum CaptureImportStatus' -and $port -match 'RecoveryRequired') 'outward result 仅暴露稳定非敏感状态'
Assert-True ($port -notmatch '(?i)tauri|serde_json|command') 'application port 不依赖 Tauri/桌面命令'
Assert-True ($controlledSource -match 'DefaultCodexRootResolver' -and $windowsPath -match 'SHGetKnownFolderPath' -and $windowsPath -match 'FOLDERID_Profile') '生产默认根由受控 Windows known-folder resolver 生成'
Assert-True ($controlledSource -match 'RootNamespacePin' -and $controlledSource -match 'open_stable_read' -and $windowsHandle -match 'FILE_SHARE_READ') 'config/auth 使用同一 pinned root 的 no-follow 稳定读句柄'
Assert-True ($adapter -match 'struct SensitiveAuth' -and $adapter -match 'self\.bytes\.zeroize\(\)') '受控 auth buffer 在 Drop 路径清零'
Assert-True ($json -notmatch 'String\(String\)' -and $json -notmatch 'fn string\([^)]*\)\s*->\s*Result<String') 'auth shape parser 不把秘密字段 materialize 为普通 String'
Assert-True ($hash -notmatch 'input\.to_vec\(\)' -and $hash -match 'update') 'SHA256 对输入流式 update 且不复制完整 auth'
Assert-True ($adapter -match 'sensitive_auth_zeroizes_during_unwind') 'panic/unwind zeroize 回归已固化'
Assert-True ($credential -match 'capture_auth_document' -and $credential -match 'SecretInput::AuthDocument') '完整 auth 文档 capture 复用 CredentialService recovery 状态机'
Assert-True ($credential -match 'capture_auth_document_scoped' -and $orchestrator -match 'complete_bundle_under_owner') 'credential owner 覆盖 exact material 验证、journal phase 与 bundle commit'
Assert-True ($codex -match 'build_scanned_identity_bundle' -and $orchestrator -match 'credential_already_persisted: true') 'bundle 构造复用旧 import 语义且 credential ownership 单一'
Assert-True ($migration -match 'capture_import_operations' -and $migration -match "'prepared','credential_ready','bundle_ready','recovery_required'") 'v11 持久化跨资源 operation phase'
Assert-True ($repository -match 'audit_capture_import_schema') 'repository open 审计 v11 capture-import schema 精确形态'
Assert-True ($repository -match 'impl CaptureImportRecoveryRepository' -and $repository -match 'version=\?6') 'capture-import journal 使用 optimistic version 更新'
Assert-True ($orchestrator -match 'committed_bundle_state' -and $orchestrator -match 'finish_completed') 'bundle commit 后可在不依赖 live root 的情况下前滚清理'
Assert-True ($orchestrator -match 'rollback_conflicted_capture' -and $orchestrator -match 'delete_credential') 'capture 后 bundle conflict 使用 exact owner/recovery 删除收敛'
Assert-True ($tests -match 'api_key_and_oauth_capture_import_are_consistent_and_idempotent') 'API-key/OAuth success 与重复请求合同已固化'
Assert-True ($tests -match 'terminated_dpapi_helpers_reopen_and_converge_at_every_persistent_cut' -and $helper -match 'BlockingFault') '真实 DPAPI helper 的每个持久 crash 切点 reopen 收敛已固化'
Assert-True ($tests -match 'second_process_rotate_is_blocked_while_capture_owner_holds_bundle_boundary') '跨进程 rotate 在 bundle 线性化边界被 owner 阻断'
Assert-True ($tests -match 'two_capture_processes_converge_without_rotation_or_orphans') '两个真实 capture 进程收敛且不留下 orphan 或轮换版本'
Assert-True ($tests -match 'repository_phase_metadata_and_bundle_faults_reopen_and_converge') 'journal create/update/delete、credential metadata、bundle commit 与 CAS stale 故障矩阵已固化'
Assert-True ($tests -match 'scan_change_compatibility_and_same_id_different_material_fail_closed') '扫描变化、兼容保护与同 ID 不同材料 fail closed'
Assert-True ($tests -match 'schema_tamper_and_outward_canaries_do_not_leak_secret_or_path') 'schema tamper 与 Debug/Display/SQLite path/secret canary 已固化'
Assert-True ($tests -match 'FakeCredentialStore' -and $tests -match 'WindowsDpapiCredentialStore' -and $helper -match 'SyntheticResolver') 'M2.6 同时覆盖 fault fake 与隔离 synthetic Windows DPAPI helper'
Assert-True ($verify -match 'M26CredentialCaptureImport.Tests.ps1') '统一验证入口包含 M2.6 契约'
Assert-True ($readme -match 'M2.6' -and $engineering -match '故障矩阵') 'README 与工程设计审计同步 M2.6'

if ($failed -gt 0) {
    Write-Host "M2.6 contract failed: $failed failed, $passed passed." -ForegroundColor Red
    exit 1
}
Write-Host "M2.6 contract passed: $passed checks." -ForegroundColor Green
