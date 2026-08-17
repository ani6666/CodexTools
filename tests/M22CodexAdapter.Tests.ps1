$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$failed = 0
$passed = 0

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

$workspace = Read-Repo 'Cargo.toml'
$adapterManifest = Read-Repo 'crates/codex-adapter/Cargo.toml'
$adapter = Read-Repo 'crates/codex-adapter/src/lib.rs'
$authParser = Read-Repo 'crates/codex-adapter/src/json.rs'
$adapterTests = Read-Repo 'crates/codex-adapter/tests/adapter.rs'
$application = Read-Repo 'crates/codex-application/src/codex.rs'
$domain = Read-Repo 'crates/codex-domain/src/managed_patch.rs'
$secretDetector = Read-Repo 'crates/codex-domain/src/value.rs'
$migration = Read-Repo 'crates/local-infrastructure/migrations/0002_managed_config_patch.sql'
$repository = Read-Repo 'crates/local-infrastructure/src/import.rs'
$repositoryMapper = Read-Repo 'crates/local-infrastructure/src/repository.rs'

Assert-True ($workspace -match 'crates/codex-adapter') 'workspace 包含只读 Codex adapter crate'
Assert-True ($adapterManifest -notmatch '(?im)^\s*(tauri|tokio|reqwest|windows-sys|toml_edit)\s*=') 'adapter 未引入 UI/网络/Windows 写入/TOML 重写依赖'
Assert-True ($adapter -match 'scan_explicit_root') 'adapter 只扫描调用方明确目录'
Assert-True ($adapter -match 'plan_config') 'adapter 提供纯内存配置计划'
Assert-True ($adapter -notmatch '(?i)write_all|rename\(|replace_file|atomic') 'adapter 不提供写入或原子替换'
Assert-True ($application -match 'CompatibilityProtected') '应用边界提供兼容保护结果'
Assert-True ($application -match 'CredentialCaptureRequired') '导入缺少凭据时返回结构化结果'
Assert-True ($application -match 'MultipleMatches') '唯一匹配显式处理 2+ 候选'
Assert-True ($domain -match 'ManagedConfigPatch') '领域层定义受管配置 patch 元数据'
Assert-True ($domain -match 'baseline_sha256') 'patch 包含不可变基线 SHA256'
Assert-True ($domain -match 'target_sha256') 'patch 包含确定性目标 SHA256'
Assert-True ($migration -match 'managed_config_patches') 'schema v2 保存非秘密 patch 元数据'
Assert-True ($repository -match 'create_identity_bundle') 'SQLite 提供原子 identity/preset/patch 导入'
Assert-True ($repository -match 'transaction') '原子导入使用 SQLite transaction'
Assert-True ($adapter -match 'RedactedDiff') '计划输出脱敏最终差异'
Assert-True ($authParser -match 'from_utf8') 'auth.json 在解析前严格验证 UTF-8'
Assert-True ($authParser -match 'hex_quad') 'auth.json 严格验证 Unicode 转义与代理项'
Assert-True ($authParser -match 'fraction_start' -and $authParser -match 'exponent_start') 'auth.json 数字遵循 JSON 小数与指数语法'
Assert-True ($authParser -match "b' ' \| b'\\t' \| b'\\n' \| b'\\r'") 'auth.json 空白只接受 JSON 允许的四种字节'
Assert-True ($adapterTests -match 'auth_json_strictly_rejects_invalid_grammar_without_echoing_input') '严格 JSON 非法语法回归已固化'
Assert-True ($adapter -match 'contains_high_confidence_secret_bytes' -and $secretDetector -match '"RSA PRIVATE KEY"' -and $secretDetector -match '"OPENSSH PRIVATE KEY"' -and $secretDetector -match '"EC PRIVATE KEY"' -and $secretDetector -match '"DSA PRIVATE KEY"') '适配器复用集中规则覆盖五类高置信私钥头'
Assert-True ($adapterTests -match 'cross_provider_planning_requires_predeclared_table_and_preserves_both_tables') '跨 Provider 预置表能力边界已固化'
Assert-True ($repository -match 'map_write_error') '原子导入复用统一 SQLite 写错误映射'
Assert-True ($repositoryMapper -match 'pub\(crate\) fn map_write_error') 'SQLite 写错误映射仅在基础设施 crate 内共享'

if ($failed -gt 0) {
    Write-Host "M2.2 contract failed: $failed failed, $passed passed." -ForegroundColor Red
    exit 1
}
Write-Host "M2.2 contract passed: $passed checks." -ForegroundColor Green
