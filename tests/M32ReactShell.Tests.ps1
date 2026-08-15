[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$failures = [System.Collections.Generic.List[string]]::new()
$passes = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:passes++; Write-Host "PASS: $Message" }
    else { $script:failures.Add($Message); Write-Host "FAIL: $Message" -ForegroundColor Red }
}

function Read-Repo([string]$RelativePath) {
    $path = Join-Path $root $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return '' }
    Get-Content -LiteralPath $path -Raw
}

Write-Host "M3.2 React shell contract: $root"
$required = @(
    'apps/desktop/src/i18n.ts',
    'apps/desktop/src/state.tsx',
    'apps/desktop/src/components/Button.tsx',
    'apps/desktop/src/components/Card.tsx',
    'apps/desktop/src/components/StatusFeedback.tsx',
    'apps/desktop/tests/i18n-state.test.mjs',
    'apps/desktop/tests/shell-accessibility.test.mjs'
)
foreach ($file in $required) { Assert-True (Test-Path (Join-Path $root $file) -PathType Leaf) "存在 $file" }

$package = Read-Repo 'apps/desktop/package.json'
$m32Package = (& git -C $root show '8340690298a072048ff69a5ea9923b5dece87c8f:apps/desktop/package.json' 2>&1 | Out-String)
Assert-True ($m32Package -notmatch 'zustand|redux|mobx|i18next|react-intl|@tauri-apps/api') 'M3.2 snapshot 零新增生产状态/i18n/IPC 依赖'

$i18n = Read-Repo 'apps/desktop/src/i18n.ts'
Assert-True ($i18n -match "'zh-CN'" -and $i18n -match '\ben\b') '提供完整 zh-CN 与 en 资源'
Assert-True ($i18n -match 'navigator\.languages|detectSystemLocale') '默认语言跟随系统语言'
Assert-True ($i18n -match 'fallback|FALLBACK_LOCALE') '缺失键具有明确 fallback'

$state = (Read-Repo 'apps/desktop/src/state.tsx') + (Read-Repo 'apps/desktop/src/shell-state.ts')
foreach ($value in @('ready','empty','loading','error','cancelled','duplicate','compatibility_protected')) {
    Assert-True ($state -match $value) "状态模型包含 $value"
}
Assert-True ($state -match 'useReducer' -and $state -match 'notification') '使用 React useReducer 管理导航、语言与全局通知'
Assert-True ($state -match "'system'" -and $state -match 'locale-preference' -and $state -match 'persistLocalePreference') '语言偏好区分 system 与显式用户选择'
Assert-True ($state -notmatch "setItem\('codextools\.locale',\s*state\.locale") '系统推导语言不会被无条件固化为用户偏好'
$shellState = Read-Repo 'apps/desktop/src/shell-state.ts'
$providerState = Read-Repo 'apps/desktop/src/state.tsx'
Assert-True ($shellState -match 'readLocalePreference' -and $shellState -match 'storageSucceeded' -and $shellState -match 'catch') '存储读取与无效值清理通过可测试边界安全降级'
Assert-True ($shellState -match 'persistLocalePreference[\s\S]*succeeded' -and $shellState -match 'catch') '偏好写入和删除失败返回非敏感结果而不外抛'
Assert-True ($providerState -match 'readLocalePreference\(window\.localStorage\)' -and $providerState -match 'updateLocalePreferenceForSession\([^;]+window\.localStorage, dispatch\)') 'Provider 使用可测试边界安全初始化和更新当前会话'
Assert-True ($shellState -match 'updateLocalePreferenceForSession[\s\S]*dispatch\(\{ type: ''set-locale-preference''[\s\S]*return persistLocalePreference') '会话更新边界先 dispatch 再尽力持久化'

$app = Read-Repo 'apps/desktop/src/App.tsx'
Assert-True ($app -match 'skip-link' -and $app -match 'main-content') '提供跳转主内容链接'
Assert-True ($app -match '<header' -and $app -match '<nav' -and $app -match '<main' -and $app -match '<aside') '应用壳使用语义结构'
Assert-True ($app -match 'aria-live' -and $app -match 'aria-current') '通知 live region 与当前导航可访问'
Assert-True ($app -notmatch '>\s*(Overview|Settings|Loading|Cancel|Retry)\s*<') '业务组件不散落英文用户文案'

$styles = Read-Repo 'apps/desktop/src/styles.css'
Assert-True ($styles -match '--color-' -and $styles -match '--space-' -and $styles -match '--radius-') '定义颜色、间距与圆角 tokens'
Assert-True ($styles -match ':focus-visible') '定义可见键盘焦点'
Assert-True ($styles -match 'prefers-reduced-motion') '尊重 reduced-motion'
Assert-True ($styles -match 'overflow-wrap|text-overflow|minmax\(0') '长文本与溢出具有约束'
Assert-True ($styles -match '@media\s*\(max-width') '适配窄桌面窗口'
$feedback = Read-Repo 'apps/desktop/src/components/StatusFeedback.tsx'
Assert-True ($feedback -match 'role="status"' -and $feedback -match 'aria-live="polite"' -and $feedback -match 'aria-atomic="true"') 'StatusFeedback 是精确原子 polite live region'
Assert-True ($styles -match '(?s)prefers-color-scheme:\s*dark.*--color-focus:\s*#8fd8ff') '暗色主题使用高对比度焦点 token'

$capability = Read-Repo 'apps/desktop/src-tauri/capabilities/default.json'
Assert-True ($capability -match '"permissions"\s*:\s*\[\s*\]') 'M3.2 不增加 Tauri capability permission'

$readme = Read-Repo 'README.md'
Assert-True ($readme -match 'M3\.2' -and $readme -match 'M32ReactShell.Tests.ps1') 'README 记录 M3.2 边界与验证入口'

if ($failures.Count) {
    Write-Host "M3.2 React shell contract failed: $($failures.Count) failed, $passes passed." -ForegroundColor Red
    exit 1
}
Write-Host "M3.2 React shell contract passed: $passes checks." -ForegroundColor Green
