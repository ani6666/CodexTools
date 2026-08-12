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

function Get-RepositoryText {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $root $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return ''
    }
    Get-Content -LiteralPath $path -Raw
}

Write-Host "M2.1 identity core contract: $root"

$requiredFiles = @(
    'crates/codex-application/Cargo.toml',
    'crates/codex-application/src/lib.rs',
    'crates/codex-application/tests/repository_ports.rs',
    'crates/codex-domain/tests/domain_models.rs',
    'crates/local-infrastructure/Cargo.toml',
    'crates/local-infrastructure/migrations/0001_identity_core.sql',
    'crates/local-infrastructure/src/lib.rs',
    'crates/local-infrastructure/src/migration.rs',
    'crates/local-infrastructure/src/repository.rs',
    'crates/local-infrastructure/tests/sqlite_repository.rs'
)
foreach ($relativePath in $requiredFiles) {
    Assert-True (Test-Path -LiteralPath (Join-Path $root $relativePath) -PathType Leaf) "存在 $relativePath"
}

$manifestPath = Join-Path $root 'Cargo.toml'
$metadataText = (& cargo metadata --locked --offline --format-version 1 --no-deps --manifest-path $manifestPath) -join "`n"
Assert-True ($LASTEXITCODE -eq 0) 'cargo metadata 可离线读取 M2.1 锁文件'
if ($LASTEXITCODE -eq 0) {
    $metadata = $metadataText | ConvertFrom-Json
    $packageNames = @($metadata.packages.name)
    Assert-True ($metadata.workspace_members.Count -ge 3) 'workspace 保留全部 M2.1 crate'
    Assert-True ($packageNames -contains 'codex-domain') '包含 codex-domain'
    Assert-True ($packageNames -contains 'codex-application') '包含 codex-application'
    Assert-True ($packageNames -contains 'local-infrastructure') '包含 local-infrastructure'

    $domainPackage = $metadata.packages | Where-Object name -EQ 'codex-domain' | Select-Object -First 1
    $applicationPackage = $metadata.packages | Where-Object name -EQ 'codex-application' | Select-Object -First 1
    $infrastructurePackage = $metadata.packages | Where-Object name -EQ 'local-infrastructure' | Select-Object -First 1
    Assert-True ($domainPackage.dependencies.Count -eq 0) 'codex-domain 保持零依赖'
    $applicationDependencies = @($applicationPackage.dependencies.name | Sort-Object)
    Assert-True (($applicationDependencies -join ',') -eq 'codex-domain,zeroize') 'codex-application 只依赖领域 crate 与既有 zeroize 明文生命周期边界'
    Assert-True (@($infrastructurePackage.dependencies.name) -contains 'rusqlite') '基础设施 crate 使用 rusqlite'
    $rusqlite = $infrastructurePackage.dependencies | Where-Object name -EQ 'rusqlite' | Select-Object -First 1
    Assert-True ($rusqlite.req -eq '=0.37.0') 'rusqlite 精确锁定 0.37.0'
    Assert-True (@($rusqlite.features) -contains 'bundled') 'rusqlite 启用 bundled feature'
    $binaryTargets = @($metadata.packages.targets | Where-Object kind -Contains 'bin')
    $allowedInternalBins = @('m23-lock-probe', 'm23-sensitive-temp-crash', 'm24-oauth-helper')
    Assert-True (($binaryTargets | Where-Object name -NotIn $allowedInternalBins).Count -eq 0) '不引入 UI 或面向用户的可执行程序入口；仅允许阶段内部测试探针'
}

$allManifests = @(
    Get-RepositoryText 'Cargo.toml'
    Get-RepositoryText 'crates/codex-domain/Cargo.toml'
    Get-RepositoryText 'crates/codex-application/Cargo.toml'
    Get-RepositoryText 'crates/local-infrastructure/Cargo.toml'
) -join "`n"
foreach ($forbiddenDependency in @('tauri', 'tokio', 'sqlx', 'diesel', 'reqwest', 'toml_edit', 'windows-sys')) {
    Assert-True (-not ($allManifests -match "(?m)^\s*$([regex]::Escape($forbiddenDependency))\s*=")) "未提前引入 $forbiddenDependency"
}

$domainSource = Get-RepositoryText 'crates/codex-domain/src/lib.rs'
$credentialSource = Get-RepositoryText 'crates/codex-domain/src/credential.rs'
$applicationSource = Get-RepositoryText 'crates/codex-application/src/lib.rs'
$infrastructureSource = Get-RepositoryText 'crates/local-infrastructure/src/lib.rs'
Assert-True ($domainSource -match 'M2_STAGE:\s*&str\s*=\s*"M2\.[1-9]"') '领域阶段标识不低于 M2.1'
Assert-True ($domainSource -match '#!\[forbid\(unsafe_code\)\]') '领域 crate 禁止 unsafe'
Assert-True ($applicationSource -match '#!\[forbid\(unsafe_code\)\]') '应用 crate 禁止 unsafe'
Assert-True ($infrastructureSource -match '#!\[forbid\(unsafe_code\)\]') '基础设施 crate 禁止 unsafe'
Assert-True ($credentialSource -match 'pub fn rotate\(') '凭据引用提供不泄密轮换边界'
Assert-True ($applicationSource -match 'fn update_credential_reference\(') '凭据仓储提供乐观并发更新端口'

$migration = Get-RepositoryText 'crates/local-infrastructure/migrations/0001_identity_core.sql'
foreach ($table in @('credential_references', 'runtime_identities', 'model_presets')) {
    Assert-True ($migration -match "(?i)CREATE TABLE\s+$table") "migration 创建 $table"
}
Assert-True ($migration -match '(?i)auth_mode\s+TEXT\s+GENERATED ALWAYS AS') 'credential schema 生成认证模式映射列'
Assert-True ($migration -match "(?is)WHEN\s+'api_key'\s+THEN\s+'api_key'.*WHEN\s+'oauth_bundle'\s+THEN\s+'oauth'") 'schema 显式映射 API Key 与 OAuthBundle'
Assert-True ($migration -match '(?i)UNIQUE\(id, auth_mode\)') '凭据引用提供复合外键唯一父键'
Assert-True ($migration -match '(?is)FOREIGN KEY\(credential_ref_id, auth_mode\).*REFERENCES credential_references\(id, auth_mode\)') '身份通过生成映射列强制认证类型一致'
Assert-True (-not ($migration -match '(?is)REFERENCES credential_references\(id, kind\)')) 'schema 不再直接比较 oauth 与 oauth_bundle'
Assert-True ($migration -match '(?i)UNIQUE\(provider_id, api_base_url, credential_ref_id\)') 'schema 强制身份组合唯一'
Assert-True ($migration -match '(?i)UNIQUE\(identity_id, name\)') 'schema 强制身份内预设名称唯一'
Assert-True ($migration -match '(?i)CHECK\(version >= 1\)') 'schema 强制实体版本有效'
Assert-True (-not ($migration -match '(?im)^\s*(secret|token|api_key_body|oauth_body)\s+')) 'schema 不提供秘密正文列'

$migrationSource = Get-RepositoryText 'crates/local-infrastructure/src/migration.rs'
Assert-True ($migrationSource -match '(?i)CREATE TABLE IF NOT EXISTS schema_migrations') 'migration 引导 schema_migrations'
Assert-True ($migrationSource -match 'LATEST_SCHEMA_VERSION:\s*u32\s*=\s*(?:[2-9]|[1-9][0-9]+)') '最新 schema 版本保留并演进 M2.1 基线'
Assert-True ($migrationSource -match 'FutureVersion') '未知未来 schema 版本 fail closed'

if ($failures.Count -gt 0) {
    Write-Host "M2.1 contract failed: $($failures.Count) failed, $passes passed." -ForegroundColor Red
    exit 1
}

Write-Host "M2.1 contract passed: $passes checks." -ForegroundColor Green
