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

$domain = Read-Repo 'crates/codex-domain/src/network.rs'
$application = Read-Repo 'crates/codex-application/src/model_discovery.rs'
$adapter = Read-Repo 'crates/codex-adapter/src/auth.rs'
$infrastructure = Read-Repo 'crates/local-infrastructure/src/http_transport.rs'
$integration = Read-Repo 'crates/local-infrastructure/tests/m28_safe_model_discovery.rs'
$manifest = Read-Repo 'crates/local-infrastructure/Cargo.toml'

Assert-True ($domain -match 'NormalizedEndpoint' -and $domain -match 'LoopbackDevelopment' -and $domain -match 'approve_addresses') 'domain 提供版本化 URL 与逐地址 fail-closed 策略'
Assert-True ($application -match 'ProbeConnectionInput' -and $application -match 'DiscoverModelsInput' -and $application -match 'M28_SERVICE_VERSION') 'application 分离 probe/discover 且输入带版本'
Assert-True ($application -match 'trait DnsResolver' -and $application -match 'trait ApprovedHttpTransport' -and $application -match 'trait CredentialAuthorizationParser') 'DNS、固定目标 transport 与凭据解析均为显式 port'
Assert-True ($application -match 'ResponseTooLarge' -and $application -match 'RateLimited' -and $application -match 'TlsFailure' -and $application -match 'CompatibilityProtected') '错误分类稳定且 secret-free'
Assert-True ($adapter -match 'Zeroizing' -and $adapter -match 'access_token' -and $adapter -notmatch 'serde_json') '认证解析不经普通 String/serde Value 持有秘密'
Assert-True ($infrastructure -match 'ProxyMode::Disabled' -and $infrastructure -match 'RedirectMode::Disabled' -and $infrastructure -match 'connect_addr') 'HTTP adapter 禁代理/重定向并固定审批地址'
Assert-True ($infrastructure -match 'Zeroizing' -and $infrastructure -match 'Authorization: Bearer') 'Authorization 请求缓冲显式 zeroize'
Assert-True ($integration -match 'mixed_allowed_and_denied' -and $integration -match 'redirect' -and $integration -match 'chunked' -and $integration -match 'slowloris' -and $integration -match 'secret_canary') '集成测试覆盖 DNS、redirect、size/timeout 与 secret canary'
Assert-True ($manifest -match 'native-tls\s*=\s*\{[^}]*version\s*=\s*"=0\.2\.18"[^}]*default-features\s*=\s*false') 'TLS 依赖精确锁定且不启用 vendored/invalid-cert feature'

$desktopDiff = & git -C $root diff -- apps/desktop package.json package-lock.json 2>&1 | Out-String
Assert-True ([string]::IsNullOrWhiteSpace($desktopDiff)) 'M2.8 不修改 desktop、npm、Tauri 或 capability'

Write-Host "M28_CONTRACT_SUMMARY passed=$passed failed=$failed"
if ($failed -ne 0) { throw "M2.8 contract failed: $failed assertion(s)" }
