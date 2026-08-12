[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scanScript = Join-Path $root 'scripts/m2.0/Test-SensitiveContent.ps1'
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

function Invoke-SensitiveScan {
    param([switch]$ListScannedFiles)

    $arguments = @('-NoProfile', '-File', $scanScript)
    if ($ListScannedFiles) {
        $arguments += '-ListScannedFiles'
    }
    $output = @(& pwsh @arguments 2>&1 | ForEach-Object { $_.ToString() })
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Lines = $output
        Text = $output -join "`n"
    }
}

Write-Host "M2.0 sensitive scan regression: $root"

$temporaryName = "m20-sensitive-regression-$([guid]::NewGuid().ToString('N')).txt"
$temporaryPath = Join-Path $root $temporaryName
$testValue = 'sk-' + ('Z' * 24)
try {
    Set-Content -LiteralPath $temporaryPath -Value "test_value=$testValue" -Encoding utf8NoBOM
    $failureResult = Invoke-SensitiveScan
    Assert-True ($failureResult.ExitCode -ne 0) '未跟踪工程文本中的高置信测试秘密使扫描失败'
    Assert-True ($failureResult.Text.Contains($temporaryName)) '失败输出包含临时文件路径'
    Assert-True ($failureResult.Text.Contains('openai_key')) '失败输出包含规则名称'
    Assert-True (-not $failureResult.Text.Contains($testValue)) '失败输出不包含测试秘密正文'
} finally {
    Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
}

Assert-True (-not (Test-Path -LiteralPath $temporaryPath)) '临时测试秘密文件已清理'

$successResult = Invoke-SensitiveScan -ListScannedFiles
Assert-True ($successResult.ExitCode -eq 0) '清理临时文件后敏感扫描通过'
$requiredCoverage = @(
    'Cargo.toml',
    'Cargo.lock',
    'crates/codex-domain/Cargo.toml',
    'crates/codex-domain/src/lib.rs',
    'tests/M20Workspace.Tests.ps1',
    'scripts/m2.0/Test-SensitiveContent.ps1'
)
foreach ($relativePath in $requiredCoverage) {
    Assert-True ($successResult.Text.Contains("SCAN_FILE=$relativePath")) "扫描覆盖 $relativePath"
}

if ($failures.Count -gt 0) {
    Write-Host "M2.0 sensitive scan regression failed: $($failures.Count) failed, $passes passed." -ForegroundColor Red
    exit 1
}

Write-Host "M2.0 sensitive scan regression passed: $passes checks." -ForegroundColor Green
