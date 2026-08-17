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
$switchPlan = Read-Repo 'crates/codex-application/src/switch.rs'
$adapter = Read-Repo 'crates/codex-adapter/src/lib.rs'
$adapterToml = Read-Repo 'crates/codex-adapter/src/toml.rs'
$adapterTests = Read-Repo 'crates/codex-adapter/tests/adapter.rs'
$json = Read-Repo 'crates/codex-adapter/src/json.rs'
$hash = Read-Repo 'crates/codex-adapter/src/hash.rs'
$credential = Read-Repo 'crates/local-infrastructure/src/credential_service.rs'
$orchestrator = Read-Repo 'crates/local-infrastructure/src/capture_import.rs'
$controlledSource = Read-Repo 'crates/local-infrastructure/src/controlled_source.rs'
$windowsPath = Read-Repo 'crates/windows-platform/src/secure_path.rs'
$windowsHandle = Read-Repo 'crates/windows-platform/src/sensitive_temp.rs'
$windowsCredentialStore = Read-Repo 'crates/windows-platform/src/credential_store.rs'
$helper = Read-Repo 'crates/local-infrastructure/src/bin/m26-capture-import-crash.rs'
$migration = Read-Repo 'crates/local-infrastructure/migrations/0011_capture_import_recovery.sql'
$repository = Read-Repo 'crates/local-infrastructure/src/repository.rs'
$tests = Read-Repo 'crates/local-infrastructure/tests/m26_capture_import.rs'
$credentialTests = Read-Repo 'crates/local-infrastructure/tests/m24_credentials.rs'
$verify = Read-Repo 'scripts/verify-repo.ps1'
$readme = Read-Repo 'README.md'
$engineering = Read-Repo 'docs/engineering/m26-credential-capture-import.md'
$rollback = Read-Repo '.tmp/rollback-m26-recovery.ps1'

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
Assert-True ($codex -match 'original_bytes:\s*Zeroizing<Vec<u8>>' -and $codex -match 'REDACTED_CONFIG_BYTES') 'ScannedConfig 原文由 Zeroizing 持有且 Debug 脱敏'
Assert-True ($adapter -match 'original_bytes:\s*Zeroizing::new\(config\.to_vec\(\)\)') 'adapter 在复制 config 后立即纳入 Zeroizing 生命周期'
Assert-True ($adapterToml -match 'text:\s*Zeroizing<String>' -and $adapterToml -match 'value:\s*Zeroizing<String>') 'TOML 原文与 assignment value 均使用 Zeroizing'
Assert-True ($adapterToml -match 'REDACTED_TOML_TEXT' -and $adapterToml -match 'REDACTED_TOML_VALUE' -and $adapterTests -match 'scanned_config_unwind_exposes_only_a_synthetic_panic_payload') 'config 正常/Debug/unwind 合同不回显原文'
Assert-True ($credential -match 'capture_auth_document' -and $credential -match 'SecretInput::AuthDocument') '完整 auth 文档 capture 复用 CredentialService recovery 状态机'
Assert-True ($credential -match 'capture_auth_document_scoped' -and $orchestrator -match 'complete_bundle_under_owner') 'credential owner 覆盖 exact material 验证、journal phase 与 bundle commit'
Assert-True ($codex -match 'build_scanned_identity_bundle' -and $orchestrator -match 'credential_already_persisted: true') 'bundle 构造复用旧 import 语义且 credential ownership 单一'
Assert-True ($migration -match 'capture_import_operations' -and $migration -match "'prepared','credential_ready','bundle_ready','recovery_required'") 'v11 持久化跨资源 operation phase'
Assert-True ($repository -match 'audit_capture_import_schema') 'repository open 审计 v11 capture-import schema 精确形态'
Assert-True ($repository -notmatch 'normalize_schema_sql|split_once\(";\\n\\nCREATE INDEX"\)' -and $repository -match 'pragma_table_xinfo' -and $repository -match 'pragma_index_xinfo' -and $repository -match 'audit_capture_constraints') 'v11 schema 使用结构 pragma、token 与事务约束矩阵，不做有损文本删除'
Assert-True ($repository -match 'trigger_mutates_capture_ledger' -and $repository -match 'tokenize_sql' -and $repository -notmatch "instr\(lower\(sql\), 'capture_import_operations'\)") 'trigger 审计忽略字面量/注释并识别真实跨表 DML'
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
Assert-True ($tests -match 'production_repository_open_accepts_the_checked_in_v11_migration_bytes' -and $tests -match 'capture_schema_rejects_cross_table_triggers_that_mutate_the_v11_ledger') 'CRLF migration 与跨表 trigger 回归已固化'
Assert-True ($tests -match 'capture_schema_rejects_semantic_changes_hidden_by_lossy_sql_normalization' -and $tests -match 'capture_schema_accepts_benign_trigger_literals_and_comments' -and $tests -match 'capture_schema_accepts_equivalent_whitespace_comments_and_statement_semicolons') 'schema collision、benign trigger 与等价格式回归已固化'
Assert-True ($credential -match 'verify_destructive_recovery_material' -and $credential -match 'planned_credential_fingerprint' -and $credential -match 'material_hash') '破坏性 recovery 删除前核对 material ref/hash 与明文 fingerprint'
Assert-True ($credentialTests -match 'destructive_create_recovery_preserves_replaced_same_binding_material_after_reopen' -and $credentialTests -match 'destructive_create_recovery_requires_exact_material_reference_and_hash') '同 binding 不同 plaintext 与 stale material 证据不误删'
Assert-True ($windowsCredentialStore -match '\(false, false\) => Err\(CredentialStoreError::NotFound\)' -and $windowsCredentialStore -match '\(true, true\) => Err\(CredentialStoreError::RecoveryRequired\)') 'delete quarantine 缺失与双重存在状态保持无歧义 fail-closed'
Assert-True ($windowsHandle -match 'namespace_chain' -and $windowsHandle -match 'local_disk_components' -and $windowsHandle -match 'FILE_FLAG_OPEN_REPARSE_POINT' -and $windowsHandle -match 'verify_parent_identity') 'root-pinned 写锁逐祖先持有 Windows no-follow handle 并核对身份'
Assert-True ($tests -match 'write_lock_rejects_an_ancestor_junction_even_when_the_final_root_is_ordinary' -and $tests -match 'write_lock_pins_each_ancestor_against_replacement_until_release' -and $tests -match 'write_lock_handle_blocks_lock_file_replacement_until_release') '祖先 junction、祖先替换与锁文件替换竞争回归已固化'
Assert-True ($codex -match 'target_bytes:\s*Zeroizing<Vec<u8>>' -and $codex -match 'impl fmt::Debug for PlannedConfig' -and $adapterToml -match 'Result<Zeroizing<Vec<u8>>, CompatibilityReason>' -and $switchPlan -match 'target_config:\s*Zeroizing<Vec<u8>>') 'PlannedConfig、TOML replacement 与 SwitchPlan config 全链路 Zeroizing 且 Debug 脱敏'
Assert-True ($tests -match 'different_roots_with_one_credential_compete_beyond_root_lock_and_converge' -and $tests -match 'same-root loser must fail at the root-lock boundary') '同根 loser 锁竞争与不同根 shared credential owner/CAS 并发语义已固化'
Assert-True ($rollback -match '\[switch\]\$Apply' -and $rollback -match 'Get-FileHash' -and $rollback -match 'm26-third-baseline' -and $rollback -notmatch 'ignored_entries=removed') 'rollback 默认 dry-run，仅按 baseline/final hash 恢复 ignored 工程资料'
Assert-True ($windowsHandle -match 'fn NtCreateFile' -and $windowsHandle -match 'root_directory' -and $windowsHandle -match 'open_relative') 'RootNamespacePin 逐组件使用 RootDirectory handle-relative no-follow 打开'
Assert-True ($windowsHandle -match 'subst_mapping_changes_between_components' -and $windowsHandle -match 'reopen_relative_identity') '真实 DOS alias 切换与父子关系回归已固化'
Assert-True ($helper -match 'OWNER_CAS_READY' -and $tests -match '64 \| 65 \| 66 \| 67') '不同根 helper 在 owner/CAS 边界握手并拒绝模糊退出状态'
Assert-True ($rollback -match 'EXPECTED_PATCH_SHA256' -and $rollback -match 'EXPECTED_MANIFEST_SHA256' -and $rollback -match 'ROLLBACK_JOURNAL' -and $rollback -match 'backup_cleanup_\$\{i\}_intent' -and $rollback -match 'comp_restore_\$\{i\}_intent' -and $rollback -match 'comp_quarantine_\$\{i\}_intent' -and $rollback -match 'comp_backup_\$\{i\}_intent' -and $rollback -match 'journal phase regression') 'rollback 固定 trust anchor 并逐文件持久化 cleanup/compensation 状态'
Assert-True ($rollback -match 'Invoke-TrustTamperCase' -and $rollback -match 'Get-FixtureDigest' -and $rollback -match 'New-EmbeddedFixtureScript' -and $rollback -match "'patch_manifest_joint'" -and $rollback -match "'manifest_entry_path'" -and $rollback -match "'manifest_entry_hash'" -and $rollback -match '\[IO\.File\]::Delete\(\$baseline\)' -and $rollback -match 'M26_SELFTEST_RESULT=') 'rollback 隔离 fixture 实际篡改 trust 资产并输出结构化证据'

$rollbackScript = Join-Path $root '.tmp/rollback-m26-recovery.ps1'
$rollbackSelfTest = @(& pwsh -NoProfile -File $rollbackScript -SelfTest 2>&1)
Assert-True ($LASTEXITCODE -eq 0) 'rollback 隔离 fixture 退出 0'
$rollbackSelfText = $rollbackSelfTest -join "`n"
foreach ($marker in @(
    'junction=blocked',
    'patch_interrupt=compensated',
    'copy_interrupt=compensated',
    'delete_interrupt=compensated'
)) {
    Assert-True ($rollbackSelfText.Contains($marker)) "rollback 隔离 fixture：$marker"
}
$trustResults = @($rollbackSelfTest | Where-Object { $_ -is [string] -and $_.StartsWith('M26_SELFTEST_RESULT=') } | ForEach-Object { $_.Substring('M26_SELFTEST_RESULT='.Length) | ConvertFrom-Json })
$expectedTrustCases = @('baseline_content', 'baseline_missing', 'manifest_entry_hash', 'manifest_entry_path', 'manifest_modified', 'patch_manifest_joint', 'patch_modified')
$actualTrustCases = @($trustResults.case | Sort-Object)
Assert-True ($trustResults.Count -eq 7 -and ($actualTrustCases -join "`n") -eq ($expectedTrustCases -join "`n")) 'rollback trust tamper 使用七个 fresh 隔离真实 Git fixture'
Assert-True (@($trustResults | Where-Object { $_.fixtureKind -ne 'real-git' -or -not $_.mutationApplied -or $_.applyExit -eq 0 -or $_.recoverExit -eq 0 -or -not $_.stateUnchanged -or $_.beforeDigest -ne $_.afterDigest }).Count -eq 0) 'rollback trust tamper 的 Apply/Recover 均拒绝且 repo byte digest 不变'
Assert-True (@($trustResults | Where-Object { $_.journalBefore -ne 0 -or $_.journalAfter -ne 0 -or $_.quarantineBefore -ne 0 -or $_.quarantineAfter -ne 0 -or $_.outsideBefore -ne $_.outsideAfter }).Count -eq 0 -and @($trustResults | Where-Object { $_.case -eq 'patch_manifest_joint' -and $_.trustAnchorKind -eq 'script-embedded' }).Count -eq 1 -and @($trustResults | Where-Object { $_.case -ne 'patch_manifest_joint' -and $_.trustAnchorKind -ne 'independent-fixture-anchor' }).Count -eq 0) 'rollback trust tamper 无 residue/outside 变化且共同替换由内嵌 anchor 阻断'

$rollbackPreview = @(& pwsh -NoProfile -File $rollbackScript 2>&1)
$rollbackExit = $LASTEXITCODE
$snapshotHead = '8340690298a072048ff69a5ea9923b5dece87c8f'
$currentHead = (& git -C $root rev-parse HEAD).Trim()
$trackedDelta = @(& git -C $root diff --name-only)
if ($currentHead -eq $snapshotHead -and $trackedDelta.Count -eq 0) {
    Assert-True ($rollbackExit -eq 0) 'rollback 精确旧 snapshot 默认 dry-run 退出 0'
    Assert-True (($rollbackPreview -join "`n").Contains('trust_anchor=exact apply=false')) 'rollback 精确旧 snapshot 完成全部 trust/path/hash 预检'
} else {
    Assert-True ($rollbackExit -ne 0) 'rollback 在 M3.3 diff/checkpoint 上 fail closed'
    Assert-True (-not ($rollbackPreview -join "`n").Contains('trust_anchor=exact apply=false')) 'rollback 不把 M3.3 状态误认作旧 snapshot trust anchor'
}
Assert-True ($tests -match 'FakeCredentialStore' -and $tests -match 'WindowsDpapiCredentialStore' -and $helper -match 'SyntheticResolver') 'M2.6 同时覆盖 fault fake 与隔离 synthetic Windows DPAPI helper'
Assert-True ($verify -match 'M26CredentialCaptureImport.Tests.ps1') '统一验证入口包含 M2.6 契约'
Assert-True ($readme -match 'M2.6' -and $engineering -match '故障矩阵') 'README 与工程设计审计同步 M2.6'

if ($failed -gt 0) {
    Write-Host "M2.6 contract failed: $failed failed, $passed passed." -ForegroundColor Red
    exit 1
}
Write-Host "M2.6 contract passed: $passed checks." -ForegroundColor Green
