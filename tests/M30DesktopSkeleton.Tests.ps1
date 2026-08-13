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

Write-Host "M3.0 desktop skeleton contract: $root"

$requiredFiles = @(
    'apps/desktop/package.json',
    'apps/desktop/package-lock.json',
    'apps/desktop/tsconfig.json',
    'apps/desktop/vite.config.ts',
    'apps/desktop/index.html',
    'apps/desktop/src/main.tsx',
    'apps/desktop/src/App.tsx',
    'apps/desktop/src/language.ts',
    'apps/desktop/tests/language.test.mjs',
    'apps/desktop/src-tauri/Cargo.toml',
    'apps/desktop/src-tauri/build.rs',
    'apps/desktop/src-tauri/icons/icon.ico',
    'apps/desktop/src-tauri/icons/icon.svg',
    'apps/desktop/src-tauri/tauri.conf.json',
    'apps/desktop/src-tauri/capabilities/default.json',
    'apps/desktop/src-tauri/src/lib.rs',
    'apps/desktop/src-tauri/src/main.rs'
)
foreach ($relativePath in $requiredFiles) {
    Assert-True (Test-Path -LiteralPath (Join-Path $root $relativePath) -PathType Leaf) "存在 $relativePath"
}

$workspace = Get-RepositoryText 'Cargo.toml'
Assert-True ($workspace -match '"apps/desktop/src-tauri"') 'Cargo workspace 包含桌面 Tauri crate'

$packageText = Get-RepositoryText 'apps/desktop/package.json'
$package = if ($packageText) { $packageText | ConvertFrom-Json } else { $null }
Assert-True ($null -ne $package -and $package.private -eq $true) '前端 package 标记为 private'
Assert-True ($null -ne $package -and $package.dependencies.react -match '^19\.') 'React 锁定 19.x'
Assert-True ($null -ne $package -and $package.dependencies.'react-dom' -match '^19\.') 'React DOM 锁定 19.x'
Assert-True ($null -ne $package -and $package.devDependencies.vite -match '^8\.') 'Vite 锁定 8.x'
Assert-True ($null -ne $package -and $package.devDependencies.typescript -match '^6\.') 'TypeScript 锁定稳定 6.x'
Assert-True ($null -ne $package -and $package.devDependencies.'@tauri-apps/cli' -match '^2\.') 'Tauri CLI 锁定 2.x'
foreach ($scriptName in @('dev', 'check', 'test', 'build', 'tauri', 'tauri:info', 'tauri:build')) {
    Assert-True ($null -ne $package -and $package.scripts.PSObject.Properties.Name -contains $scriptName) "npm 提供 $scriptName 验证入口"
}
Assert-True ($packageText -notmatch '@tauri-apps/api') 'M3.0 前端不引入未使用的 Tauri API'

$packageLockText = Get-RepositoryText 'apps/desktop/package-lock.json'
$packageLock = if ($packageLockText) { $packageLockText | ConvertFrom-Json -AsHashtable } else { $null }
$registryPackages = @()
if ($null -ne $packageLock -and $packageLock.ContainsKey('packages')) {
    $registryPackages = @(
        $packageLock.packages.GetEnumerator() |
            Where-Object {
                $_.Value.ContainsKey('resolved') -and
                $_.Value.resolved -notmatch '^(?:link|file|workspace):'
            }
    )
}
$unexpectedResolved = @(
    $registryPackages |
        Where-Object { $_.Value.resolved -notmatch '^https://registry\.npmjs\.org/' }
)
$missingIntegrity = @(
    $registryPackages |
        Where-Object {
            -not $_.Value.ContainsKey('integrity') -or
            [string]::IsNullOrWhiteSpace([string]$_.Value.integrity)
        }
)
Assert-True ($registryPackages.Count -gt 0) 'package-lock 包含已解析的 registry 包'
Assert-True ($unexpectedResolved.Count -eq 0) 'package-lock 的 registry 包全部来自 registry.npmjs.org'
Assert-True ($missingIntegrity.Count -eq 0) 'package-lock 的 registry 包全部具备 integrity'

$tauriManifest = Get-RepositoryText 'apps/desktop/src-tauri/Cargo.toml'
Assert-True ($tauriManifest -match '(?m)^tauri\s*=\s*\{\s*version\s*=\s*"=2\.') 'Rust Tauri 精确锁定 2.x'
Assert-True ($tauriManifest -match 'codex-domain\s*=\s*\{\s*path\s*=\s*"\.\./\.\./\.\./crates/codex-domain"') '桌面 crate 通过 path dependency 复用 codex-domain'
Assert-True ($tauriManifest -match 'codex-application\s*=\s*\{\s*path\s*=\s*"\.\./\.\./\.\./crates/codex-application"') '桌面 crate 通过 path dependency 复用 codex-application'
Assert-True ($tauriManifest -match 'local-infrastructure\s*=\s*\{\s*path\s*=\s*"\.\./\.\./\.\./crates/local-infrastructure"') '桌面 crate 通过 path dependency 复用 local-infrastructure'
Assert-True ($tauriManifest -match 'windows-platform\s*=\s*\{\s*path\s*=\s*"\.\./\.\./\.\./crates/windows-platform"') '桌面 crate 通过 path dependency 复用 windows-platform'

$capabilityText = Get-RepositoryText 'apps/desktop/src-tauri/capabilities/default.json'
$capability = if ($capabilityText) { $capabilityText | ConvertFrom-Json } else { $null }
Assert-True ($null -ne $capability -and @($capability.windows).Count -eq 1 -and $capability.windows[0] -eq 'main') 'capability 仅绑定主窗口'
Assert-True ($null -ne $capability -and @($capability.permissions).Count -eq 0) 'M3.0 capability 权限集合为空'

$rustSource = Get-RepositoryText 'apps/desktop/src-tauri/src/lib.rs'
$commandAdapter = Get-RepositoryText 'apps/desktop/src-tauri/src/commands.rs'
Assert-True ($rustSource -match '#!\[forbid\(unsafe_code\)\]') '桌面 Rust crate 禁止 unsafe'
Assert-True ($rustSource -match 'mod commands' -and $rustSource -match 'invoke_handler') 'M3.1 通过集中 adapter 注册 command handler'
Assert-True ($commandAdapter -match '#\[tauri::command\]' -and ([regex]::Matches($commandAdapter, '#\[tauri::command\]').Count -eq 2)) 'M3.1 仅保留两个最小 command adapter'
Assert-True ($rustSource -notmatch '(?i)CODEX_HOME|auth\.json|config\.toml|secret|token|cookie|oauth') '桌面入口不读取或命名秘密与真实 Codex 材料'

$language = Get-RepositoryText 'apps/desktop/src/language.ts'
$i18n = Get-RepositoryText 'apps/desktop/src/i18n.ts'
$app = Get-RepositoryText 'apps/desktop/src/App.tsx'
Assert-True ($i18n -match "FALLBACK_LOCALE\s*=\s*'zh-CN'") '默认 fallback 界面语言为简体中文'
Assert-True ($i18n -match "SUPPORTED_LOCALES\s*=\s*\['zh-CN',\s*'en'\]") '完整语言边界支持简体中文与英文'
Assert-True ($i18n -match 'CodexTools' -and $language -match '桌面基础已就绪') '桌面壳提供完整中文资源且保留 M3.0 骨架文案'

$allDesktopSource = @(
    Get-RepositoryText 'apps/desktop/src/main.tsx'
    $app
    $language
    $i18n
    $rustSource
    $commandAdapter
) -join "`n"
Assert-True ($allDesktopSource -notmatch '(?i)invoke\(|listen\(|emit\(|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization') '前后端无直接 IPC 消费或秘密正文字段'

$readme = Get-RepositoryText 'README.md'
Assert-True ($readme -match 'M3\.0') 'README 记录 M3.0 技术栈与边界'
Assert-True ($readme -match 'M30DesktopSkeleton.Tests.ps1') 'README 提供 M3.0 公开验收命令'
Assert-True ($readme -match '许可证' -and $readme -match '体积') 'README 提供依赖许可证与体积评估'

if ($failures.Count -gt 0) {
    Write-Host "M3.0 desktop skeleton contract failed: $($failures.Count) failed, $passes passed." -ForegroundColor Red
    exit 1
}

Write-Host "M3.0 desktop skeleton contract passed: $passes checks." -ForegroundColor Green
