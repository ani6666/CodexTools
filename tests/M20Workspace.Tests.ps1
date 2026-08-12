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

    return Get-Content -LiteralPath $path -Raw
}

Write-Host "M2.0 Rust workspace contract: $root"

$requiredFiles = @(
    'Cargo.toml',
    'Cargo.lock',
    'crates/codex-domain/Cargo.toml',
    'crates/codex-domain/src/lib.rs',
    'docs/architecture/adr/0001-m2-rust-core-stack.md',
    'scripts/m2.0/Test-SensitiveContent.ps1',
    'scripts/verify-repo.ps1',
    'tests/M20SensitiveScan.Tests.ps1'
)

foreach ($relativePath in $requiredFiles) {
    Assert-True (Test-Path -LiteralPath (Join-Path $root $relativePath) -PathType Leaf) "存在 $relativePath"
}

$workspaceManifest = Get-RepositoryText 'Cargo.toml'
Assert-True ($workspaceManifest -match '(?m)^resolver\s*=\s*"3"\s*$') 'Cargo workspace 使用 resolver 3'
Assert-True ($workspaceManifest -match '"crates/codex-domain"') 'Cargo workspace 保留核心领域 crate'

$crateManifest = Get-RepositoryText 'crates/codex-domain/Cargo.toml'
Assert-True ($crateManifest -match '(?m)^name\s*=\s*"codex-domain"\s*$') '核心 crate 名称为 codex-domain'
Assert-True ($crateManifest -match '(?m)^edition\s*=\s*"2024"\s*$') '核心 crate 使用 Rust 2024 edition'
Assert-True ($crateManifest -match '(?m)^rust-version\s*=\s*"1\.85"\s*$') '核心 crate 声明 Rust 2024 的最低工具链 1.85'

$coreSource = Get-RepositoryText 'crates/codex-domain/src/lib.rs'
Assert-True ($coreSource -match '#!\[forbid\(unsafe_code\)\]') '核心 crate 禁止 unsafe code'
Assert-True ($coreSource -match 'M2_STAGE') '核心 crate 保留可测试的阶段标识'

$verifyScript = Get-RepositoryText 'scripts/verify-repo.ps1'
foreach ($command in @(
    'cargo fmt --all -- --check',
    'cargo clippy --workspace --all-targets --all-features -- -D warnings',
    'cargo test --workspace --all-targets',
    'cargo build --workspace --all-targets',
    'VsDevCmd.bat',
    'scripts/m2.0/Test-SensitiveContent.ps1',
    'tests/M20SensitiveScan.Tests.ps1',
    'tests/M20Workspace.Tests.ps1',
    'tests/CodexFormatResearch.Tests.ps1'
)) {
    Assert-True ($verifyScript.Contains($command)) "统一验证入口包含：$command"
}
Assert-True ($verifyScript.Contains('-all') -and $verifyScript.Contains('stdarg.h') -and $verifyScript.Contains('candidateEnvironment')) '统一验证入口枚举并实检可用 MSVC 头文件环境'

$readme = Get-RepositoryText 'README.md'
Assert-True (-not ($readme -match '(?m)^\s*pwsh\s+.*scripts[\\/]verify-repo\.ps1\s*$')) 'README 不把 ignored 脚本列为公开可执行命令'
Assert-True ($readme.Contains('本地协作资料')) 'README 明确 scripts/verify-repo.ps1 属于本地协作资料'

$toolchain = (& rustc -vV 2>&1) -join "`n"
Assert-True ($LASTEXITCODE -eq 0) 'rustc -vV 执行成功'
Assert-True ($toolchain -match '(?m)^host:\s+x86_64-pc-windows-msvc\s*$') 'Rust host 为 x86_64-pc-windows-msvc'

$manifestPath = Join-Path $root 'Cargo.toml'
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    $metadataText = (& cargo metadata --locked --offline --format-version 1 --no-deps --manifest-path $manifestPath) -join "`n"
    Assert-True ($LASTEXITCODE -eq 0) 'cargo metadata 可离线读取锁定的 workspace'
    if ($LASTEXITCODE -eq 0) {
        $metadata = $metadataText | ConvertFrom-Json
        $domainPackage = $metadata.packages | Where-Object name -EQ 'codex-domain' | Select-Object -First 1
        Assert-True ($metadata.workspace_members.Count -ge 1) 'workspace 至少包含 M2.0 核心成员'
        Assert-True ($metadata.packages.Count -ge 1) 'workspace 至少包含 M2.0 核心 package'
        Assert-True ($null -ne $domainPackage) 'workspace package 包含 codex-domain'
        Assert-True ($null -ne $domainPackage -and $domainPackage.dependencies.Count -eq 0) 'codex-domain 继续保持零依赖'
        Assert-True ($null -ne $domainPackage -and ($domainPackage.targets | Where-Object kind -Contains 'bin').Count -eq 0) '核心 crate 不包含 UI 或可执行程序入口'
    }
}

if ($failures.Count -gt 0) {
    Write-Host "M2.0 contract failed: $($failures.Count) failed, $passes passed." -ForegroundColor Red
    exit 1
}

Write-Host "M2.0 contract passed: $passes checks." -ForegroundColor Green
