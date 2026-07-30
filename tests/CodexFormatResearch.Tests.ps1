[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $root 'tests/CodexFormatResearch.psm1') -Force
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$failures = [System.Collections.Generic.List[string]]::new()
$tests = 0

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-BytesEqual([byte[]]$Expected, [byte[]]$Actual, [string]$Message) {
    if ($Expected.Length -ne $Actual.Length) { throw "$Message（长度不同）" }
    for ($index = 0; $index -lt $Expected.Length; $index++) {
        if ($Expected[$index] -ne $Actual[$index]) { throw "$Message（偏移 $index）" }
    }
}

function Assert-Protected([scriptblock]$Body, [string]$Code, [string]$Message) {
    $caught = $null
    try {
        & $Body
    } catch {
        $caught = $_.Exception
    }
    Assert-True ($null -ne $caught) "$Message：未触发兼容保护"
    Assert-True ($caught.Data['CompatibilityCode'] -eq $Code) "$Message：错误码为 $($caught.Data['CompatibilityCode'])，预期 $Code"
}

function Invoke-Test([string]$Name, [scriptblock]$Body) {
    $script:tests++
    try {
        & $Body
        Write-Host "[ OK ] $Name"
    } catch {
        $script:failures.Add("$Name：$($_.Exception.Message)")
        Write-Host "[FAIL] $Name：$($_.Exception.Message)" -ForegroundColor Red
    }
}

function Read-FixtureBytes([string]$Generation, [string]$Name) {
    return ,[IO.File]::ReadAllBytes((Join-Path $fixtures "$Generation/$Name"))
}

function Read-FixtureText([string]$Generation, [string]$Name) {
    return [IO.File]::ReadAllText((Join-Path $fixtures "$Generation/$Name"))
}

Invoke-Test '三个固定样本 Profile 可分类' {
    $cases = @(
        @('g1-api-key', 'ApiKeyBaselineProfile'),
        @('g2-oauth', 'SyntheticOAuthProfile'),
        @('g3-current-shape', 'CurrentShapeApiKeyProfile')
    )
    foreach ($case in $cases) {
        $actual = Get-CodexFixtureProfile `
            -ConfigBytes (Read-FixtureBytes $case[0] 'config.toml') `
            -AuthJson (Read-FixtureText $case[0] 'auth.json') `
            -SessionMetadataJson (Read-FixtureText $case[0] 'session-index.jsonl')
        Assert-True ($actual -eq $case[1]) "$($case[0]) 分类错误：$actual"
    }
}

Invoke-Test '局部修改保留注释、顺序、未知字段与 Provider' {
    $input = Read-FixtureBytes 'g1-api-key' 'config.toml'
    $output = Set-CodexTomlString $input @('model') 'gpt-SAMPLE-next'
    $expectedText = ([Text.UTF8Encoding]::new($false)).GetString($input).
        Replace('model = "gpt-SAMPLE-1"', 'model = "gpt-SAMPLE-next"')
    Assert-BytesEqual ([Text.UTF8Encoding]::new($false).GetBytes($expectedText)) $output '仅目标值应变化'
    $text = [Text.Encoding]::UTF8.GetString($output)
    Assert-True $text.Contains('# 固定样本：值均为合成数据') '注释丢失'
    Assert-True $text.Contains('unknown_future_key = "KEEP_ME"') '未知字段丢失'
    Assert-True $text.Contains('[model_providers.sample]') 'Provider 表丢失'
    Assert-True ($text.IndexOf('unknown_future_key') -lt $text.IndexOf('[features]')) '字段顺序变化'
}

Invoke-Test 'CRLF 与行尾注释保持不变' {
    $input = Read-FixtureBytes 'g2-oauth' 'config.toml'
    $output = Set-CodexTomlString $input @('model_provider') 'next-provider'
    $text = [Text.UTF8Encoding]::new($false).GetString($output)
    Assert-True $text.Contains("`r`n") 'CRLF 丢失'
    Assert-True (-not [regex]::IsMatch($text, '(?<!\r)\n')) '出现单独 LF'
    Assert-True $text.Contains('model_provider = "next-provider" # 保留行尾注释') '行尾注释丢失'
}

Invoke-Test 'UTF-8 BOM 保持不变' {
    $input = Read-FixtureBytes 'g3-current-shape' 'config.toml'
    $output = Set-CodexTomlString $input @('model') 'gpt-SAMPLE-bom'
    Assert-True ($output[0] -eq 0xEF -and $output[1] -eq 0xBB -and $output[2] -eq 0xBF) 'BOM 丢失'
}

Invoke-Test 'Provider 子字段修改保留未知 Provider 选项' {
    $input = Read-FixtureBytes 'g3-current-shape' 'config.toml'
    $output = Set-CodexTomlString $input @('model_providers', 'sample', 'base_url') 'https://HOST/v2'
    $text = [Text.UTF8Encoding]::new($false).GetString($output, 3, $output.Length - 3)
    Assert-True $text.Contains('base_url = "https://HOST/v2"') '目标 Provider 字段未修改'
    Assert-True $text.Contains('env_key = "API_KEY_ENV"') 'Provider 字段丢失'
    Assert-True $text.Contains('unknown_provider_option = true') '未知 Provider 字段丢失'
}

Invoke-Test '未知关键 TOML 形态触发兼容保护' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"gpt-SAMPLE`"`nmodel_providers = { sample = {} }`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '内联 Provider'
}

Invoke-Test '混合换行触发兼容保护' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"gpt-SAMPLE`"`r`nmodel_provider = `"sample`"`n")
    $caught = $null
    try {
        Get-CodexTomlCompatibility $bytes | Out-Null
    } catch {
        $caught = $_.Exception
    }
    Assert-True ($null -ne $caught) '混合换行未被阻断'
    Assert-True ($caught.Data['CompatibilityCode'] -eq 'mixed_line_endings') '混合换行错误码不符'
}

Invoke-Test '未知认证与会话形态触发兼容保护' {
    $config = Read-FixtureBytes 'g1-api-key' 'config.toml'
    $session = Read-FixtureText 'g1-api-key' 'session-index.jsonl'
    $caught = $null
    try {
        Get-CodexFixtureProfile $config '{"credential_bundle_v99":{}}' $session | Out-Null
    } catch {
        $caught = $_.Exception
    }
    Assert-True ($null -ne $caught) '未知认证形态未被阻断'
    Assert-True ($caught.Data['CompatibilityCode'] -eq 'unknown_auth_shape') '认证错误码不符'

    $caught = $null
    try {
        Get-CodexFixtureProfile $config '{"OPENAI_API_KEY":"API_KEY_SAMPLE"}' '{"opaque":true}' | Out-Null
    } catch {
        $caught = $_.Exception
    }
    Assert-True ($null -ne $caught) '未知会话形态未被阻断'
    Assert-True ($caught.Data['CompatibilityCode'] -eq 'unknown_session_metadata_shape') '会话错误码不符'
}

Invoke-Test '损坏的未知数组字段阻断修改' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`nfuture = [broken`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '损坏未知字段'
}

Invoke-Test '字符串尾随垃圾阻断修改' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`" junk `"b`"`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_critical_shape' '尾随垃圾字符串'
}

Invoke-Test '多行字符串中的伪 Provider 不会被识别' {
    $source = @'
model = "a"
future = """
[model_providers.sample]
base_url = "https://HOST/v1"
"""
'@
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($source)
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '多行字符串'
}

Invoke-Test '重复字段触发兼容保护' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`nmodel = `"b`"`n")
    Assert-Protected { Get-CodexTomlCompatibility $bytes | Out-Null } 'duplicate_managed_field' '重复字段'
}

Invoke-Test '重复表触发兼容保护' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("[features]`napps = true`n[features]`nother = false`n")
    Assert-Protected { Get-CodexTomlCompatibility $bytes | Out-Null } 'duplicate_table' '重复表'
}

Invoke-Test '数组表 Provider 触发兼容保护' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`n[[model_providers.sample]]`nbase_url = `"https://HOST/v1`"`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '数组表 Provider'
}

Invoke-Test '无效 UTF-8 触发兼容保护' {
    $bytes = [byte[]](0x6D, 0x6F, 0x64, 0x65, 0x6C, 0x20, 0x3D, 0x20, 0x22, 0xFF, 0x22)
    Assert-Protected { Get-CodexTomlCompatibility $bytes | Out-Null } 'invalid_utf8' '无效 UTF-8'
}

Invoke-Test '缺失纳管字段触发兼容保护' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model_provider = `"sample`"`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'missing_managed_field' '缺失纳管字段'
}

Invoke-Test '合法井号与转义字符串可安全修改' {
    $source = @'
model = "a # b \"quoted\" \\ path \u0041" # 保留注释
model_provider = "sample"
'@
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($source)
    $output = Set-CodexTomlString $bytes @('model') 'next # "value"'
    $text = [Text.UTF8Encoding]::new($false).GetString($output)
    Assert-True $text.Contains('model = "next # \"value\"" # 保留注释') '合法字符串修改结果错误'
}

Invoke-Test '认证和会话关键字段类型错误触发保护' {
    $config = Read-FixtureBytes 'g1-api-key' 'config.toml'
    $session = Read-FixtureText 'g1-api-key' 'session-index.jsonl'
    Assert-Protected { Get-CodexFixtureProfile $config '{"OPENAI_API_KEY":{}}' $session | Out-Null } 'unknown_auth_shape' 'API Key 类型错误'
    Assert-Protected { Get-CodexFixtureProfile $config '{"OPENAI_API_KEY":"API_KEY_SAMPLE"}' '{"id":null,"thread_name":"SAMPLE","updated_at":"2026-01-01T00:00:00Z"}' | Out-Null } 'unknown_session_metadata_shape' '会话 id 为空'
}

Invoke-Test '有效数组也因超出安全子集而阻断' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`nfuture = [`"one`", `"two`"]`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '有效数组'
}

Invoke-Test '引用表键因超出安全子集而阻断' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`n[`"quoted.table`"]`nvalue = true`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '引用表键'
}

Invoke-Test '非法字符串转义触发兼容保护' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes('model = "bad\q"')
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_critical_shape' '非法字符串转义'
}

Invoke-Test '认证和会话顶层数组触发兼容保护' {
    $config = Read-FixtureBytes 'g1-api-key' 'config.toml'
    $session = Read-FixtureText 'g1-api-key' 'session-index.jsonl'
    Assert-Protected { Get-CodexFixtureProfile $config '[{"OPENAI_API_KEY":"API_KEY_SAMPLE"}]' $session | Out-Null } 'unknown_auth_shape' '认证顶层数组'
    Assert-Protected { Get-CodexFixtureProfile $config '{"OPENAI_API_KEY":"API_KEY_SAMPLE"}' '[{"id":"SESSION","thread_name":"SAMPLE","updated_at":"2026-01-01T00:00:00Z"}]' | Out-Null } 'unknown_session_metadata_shape' '会话顶层数组'
}

Invoke-Test '表与字段命名空间冲突触发保护' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`nowner = `"value`"`n[owner.child]`nenabled = true`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'conflicting_definition' '字段后声明子表'

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("[owner.child]`nenabled = true`n[owner]`nname = `"value`"`n")
    Assert-Protected { Get-CodexTomlCompatibility $bytes | Out-Null } 'conflicting_definition' '子表后声明父表'
}

Invoke-Test '非法 TOML 语法空白触发保护' {
    $vt = [char]0x000B
    $nbsp = [char]0x00A0
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes('model = "a"' + $vt)
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '字符串后 VT'

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes('model' + $nbsp + '=' + $nbsp + '"a"')
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' 'NBSP 语法空白'
}

Invoke-Test '注释控制字符触发保护' {
    $nul = [char]0x0000
    $vt = [char]0x000B
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes('model = "a" # x' + $nul)
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '行尾注释 NUL'

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes('# comment' + $vt + "`nmodel = `"a`"`n")
    Assert-Protected { Get-CodexTomlCompatibility $bytes | Out-Null } 'unsupported_toml_subset' '纯注释 VT'
}

Invoke-Test '孤立 CR 触发保护' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`r")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '孤立 CR'
}

Invoke-Test '非法空白-only 行触发保护' {
    $nbsp = [char]0x00A0
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`n" + $nbsp + "`n")
    Assert-Protected { Get-CodexTomlCompatibility $bytes | Out-Null } 'unsupported_toml_subset' 'NBSP-only 行'
}

Invoke-Test '整数只接受 Int64 范围' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`nfuture = 9223372036854775807`n")
    $output = Set-CodexTomlString $bytes @('model') 'next'
    Assert-True ([Text.UTF8Encoding]::new($false).GetString($output).Contains('future = 9223372036854775807')) 'Int64 最大值未保留'

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`nfuture = 9223372036854775808`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' 'Int64 溢出'
}

Invoke-Test '浮点数暂不属于安全子集' {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("model = `"a`"`nfuture = 1.0e999999`n")
    Assert-Protected { Set-CodexTomlString $bytes @('model') 'next' | Out-Null } 'unsupported_toml_subset' '极大浮点'
}

Invoke-Test 'JSON 字段名严格区分大小写' {
    $config = Read-FixtureBytes 'g1-api-key' 'config.toml'
    $auth = Read-FixtureText 'g1-api-key' 'auth.json'
    $session = Read-FixtureText 'g1-api-key' 'session-index.jsonl'
    Assert-Protected { Get-CodexFixtureProfile $config '{"openai_api_key":"API_KEY_SAMPLE"}' $session | Out-Null } 'unknown_auth_shape' 'API Key 大小写变体'
    Assert-Protected { Get-CodexFixtureProfile $config $auth '{"ID":"SESSION","THREAD_NAME":"SAMPLE","updated_at":"2026-01-01T00:00:00Z"}' | Out-Null } 'unknown_session_metadata_shape' '会话字段大小写变体'
}

Invoke-Test 'JSON 重复键触发保护' {
    $config = Read-FixtureBytes 'g1-api-key' 'config.toml'
    $session = Read-FixtureText 'g1-api-key' 'session-index.jsonl'
    Assert-Protected { Get-CodexFixtureProfile $config '{"OPENAI_API_KEY":{},"OPENAI_API_KEY":"API_KEY_SAMPLE"}' $session | Out-Null } 'unknown_auth_shape' '认证重复键'
    Assert-Protected { Get-CodexFixtureProfile $config '{"OPENAI_API_KEY":"API_KEY_SAMPLE"}' '{"id":"A","id":"B","thread_name":"SAMPLE","updated_at":"2026-01-01T00:00:00Z"}' | Out-Null } 'unknown_session_metadata_shape' '会话重复键'
}

Invoke-Test 'BOM 与 API Key 不足以命中当前结构 Profile' {
    $content = [Text.UTF8Encoding]::new($false).GetBytes("unrelated = true`n")
    $config = [byte[]]::new($content.Length + 3)
    $config[0] = 0xEF
    $config[1] = 0xBB
    $config[2] = 0xBF
    [Array]::Copy($content, 0, $config, 3, $content.Length)
    $auth = Read-FixtureText 'g1-api-key' 'auth.json'
    $session = Read-FixtureText 'g1-api-key' 'session-index.jsonl'
    Assert-Protected { Get-CodexFixtureProfile $config $auth $session | Out-Null } 'unknown_fixture_profile' '仅 BOM 的无关配置'
}

Invoke-Test '未知嵌套对象中的 JSON 重复键也触发保护' {
    $config = Read-FixtureBytes 'g1-api-key' 'config.toml'
    $session = Read-FixtureText 'g1-api-key' 'session-index.jsonl'
    $auth = '{"OPENAI_API_KEY":"API_KEY_SAMPLE","future":{"value":1,"value":2}}'
    Assert-Protected { Get-CodexFixtureProfile $config $auth $session | Out-Null } 'unknown_auth_shape' '未知嵌套重复键'
}

Invoke-Test 'Profile 必要配置路径同时校验类型' {
    $input = Read-FixtureBytes 'g1-api-key' 'config.toml'
    $text = [Text.UTF8Encoding]::new($false).GetString($input).Replace('base_url = "https://HOST/v1"', 'base_url = true')
    $config = [Text.UTF8Encoding]::new($false).GetBytes($text)
    $auth = Read-FixtureText 'g1-api-key' 'auth.json'
    $session = Read-FixtureText 'g1-api-key' 'session-index.jsonl'
    Assert-Protected { Get-CodexFixtureProfile $config $auth $session | Out-Null } 'unknown_fixture_profile' 'Provider URL 类型错误'
}

if ($failures.Count -gt 0) {
    Write-Host "测试失败：$($failures.Count) / $tests" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
    exit 1
}

Write-Host "测试通过：$tests / $tests" -ForegroundColor Green
