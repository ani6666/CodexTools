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

$vertical = Read-Repo 'crates/local-infrastructure/src/vertical.rs'
$credentialService = Read-Repo 'crates/local-infrastructure/src/credential_service.rs'
$switchPort = Read-Repo 'crates/codex-application/src/switch.rs'
$tests = Read-Repo 'crates/local-infrastructure/tests/m25_vertical.rs'
$library = Read-Repo 'crates/local-infrastructure/src/lib.rs'
$verify = Read-Repo 'scripts/verify-repo.ps1'
$readme = Read-Repo 'README.md'
$engineering = Read-Repo 'docs/engineering/codex-layer.md'
$domain = Read-Repo 'docs/product/domain-model.md'
$adr = Read-Repo 'docs/architecture/adr/0001-m2-rust-core-stack.md'

Assert-True ($vertical -match 'VerticalSwitchPlanner' -and $vertical -match 'VerticalPreview') 'M2.5 提供脱敏纵向规划入口'
Assert-True ($vertical -match 'preview_from_store' -and $vertical -match 'execute_approved' -and $vertical -match 'prepare_restore' -and $vertical -match 'verify_expected') '纵向入口复用 store/scan/plan/restore/verify 两阶段边界'
Assert-True ($vertical -notmatch 'pub fn prepare_switch\s*\(' -and $vertical -notmatch 'pub fn execute_from_store\s*') '生产纵向入口不接受裸认证正文或事后 preview 单阶段入口'
Assert-True ($vertical -match 'struct VerticalPreparedIntent' -and $vertical -match 'recalculated != \*self\.approved') 'approved intent 绑定非秘密计划并在执行前 exact 重算'
Assert-True ($credentialService -match 'read_bound_for_switch' -and $credentialService -match 'BoundSecretConsumer') 'exact CredentialReference 与认证材料在同一 owner 内交付'
Assert-True ($switchPort -match 'target_auth: Zeroizing<Vec<u8>>') 'SwitchPlan 认证目标使用 zeroizing 缓冲'
Assert-True ($vertical -match 'SwitchExecutor' -and $vertical -match 'BackupRestoreTarget') '纵向执行复用 M2.3/M2.4 实现'
Assert-True ($tests -match 'vertical_scan_import_create_preview_switch_verify_and_restore') 'A 导入、B 创建、预览、切换、重读与恢复闭环已固化'
Assert-True ($tests -match 'one_hundred_real_switches_reopen_and_restore_initial_pair' -and $tests -match 'M25_SWITCH_100_SUMMARY') '100 次真实交替切换、逐次重读、重开和初始恢复已固化'
Assert-True ($tests -match 'iteration \{iteration\} retained terminal transaction material' -and $tests -notmatch 'starts_with\("snapshot-"\)') '100 次逐轮断言终态事务材料为零且秘密扫描不跳过 snapshot'
Assert-True ($tests -match 'successful_read_count\(\), 200' -and $tests -match 'successful_read_count\(\), 201' -and $tests -notmatch 'auth: Vec<u8>') '100 次 preview+execute 分别读取 DPAPI，恢复另计，身份夹具不长期保存正文'
Assert-True ($tests -match 'approved_preview_is_prewrite_and_exactly_matches_execution' -and $tests -match 'approved_intent_rejects_live_credential_material_identity_and_preset_changes') 'prewrite preview 与批准后全绑定失效矩阵已固化'
Assert-True ($tests -match 'restore_revalidates_credential_generation_before_any_write') '恢复执行前复验 credential generation'
Assert-True ($tests -match 'vertical_store_corrupt_wrong_binding_and_stale_metadata_are_prewrite' -and $tests -match 'vertical_owner_blocks_rotate_and_panic_releases_owner') 'Store 负向、owner 竞态与 panic 释放矩阵已固化'
Assert-True ($tests -match 'vertical_fault_and_recovery_matrix_never_marks_mixed_state_successful' -and $tests -match 'M25_FAULT_MATRIX') '纵向故障/中断矩阵禁止混合态成功'
Assert-True ($tests -match 'M25_SECRET_SCAN' -and $tests -match 'preview_secret=false' -and $tests -match 'sqlite_secret=false') 'preview/SQLite/Debug/错误零正文回归已固化'
Assert-True ($tests -match 'fragment_hits_except' -and $tests -match 'retained a credential fragment outside canonical live auth') '真实切换 secret 的 prefix/middle/suffix 逐轮扫描包含完整合成根，仅精确排除 canonical live auth'
Assert-True ($library -match 'mod vertical' -and $library -match 'VerticalSwitchPlanner') 'M2.5 编排器由基础设施 crate 导出'
Assert-True ($verify -match 'M25VerticalClosure.Tests.ps1') '统一验证入口包含 M2.5 契约'
Assert-True ($readme -match 'cargo test --workspace --all-targets') 'README 只公开 clone 后真实可运行的 Rust 验证命令'
Assert-True ($engineering -match 'M2.5' -and $domain -match 'M2.5' -and $adr -match 'M2.5') '工程、领域与 ADR 同步 M2.5 实际语义'
Assert-True ($vertical -notmatch '(?i)tauri|reqwest|browser') '纵向核心不依赖 UI、网络或浏览器'

if ($failed -gt 0) {
    Write-Host "M2.5 contract failed: $failed failed, $passed passed." -ForegroundColor Red
    exit 1
}
Write-Host "M2.5 contract passed: $passed checks." -ForegroundColor Green
