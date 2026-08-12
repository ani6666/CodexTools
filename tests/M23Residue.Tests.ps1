$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scriptPath = Join-Path $root 'scripts/m2.3/Test-M23Residue.ps1'
if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw 'M2.3 residue gate script is missing.'
}
& pwsh -NoProfile -File $scriptPath -SelfTest
if ($LASTEXITCODE -ne 0) {
    throw "M2.3 residue gate self-test failed with exit $LASTEXITCODE"
}
Write-Host 'M2.3 residue gate contract passed: 1/1.' -ForegroundColor Green
