Set-StrictMode -Version Latest

$script:Utf8Bom = [byte[]](0xEF, 0xBB, 0xBF)
$script:StrictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)

function New-CompatibilityError {
    param(
        [Parameter(Mandatory)]
        [string]$Code,
        [Parameter(Mandatory)]
        [string]$Message
    )

    $exception = [System.InvalidOperationException]::new($Message)
    $exception.Data['CompatibilityCode'] = $Code
    return $exception
}

function ConvertFrom-CodexUtf8 {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $hasBom = $Bytes.Length -ge 3 -and
        $Bytes[0] -eq $script:Utf8Bom[0] -and
        $Bytes[1] -eq $script:Utf8Bom[1] -and
        $Bytes[2] -eq $script:Utf8Bom[2]
    $offset = if ($hasBom) { 3 } else { 0 }

    try {
        $text = $script:StrictUtf8.GetString($Bytes, $offset, $Bytes.Length - $offset)
    } catch {
        throw (New-CompatibilityError 'invalid_utf8' '配置不是有效 UTF-8。')
    }

    [pscustomobject]@{ Text = $text; HasBom = $hasBom }
}

function Trim-TomlSpace {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    return $Text.Trim([char[]]@(' ', "`t"))
}

function TrimStart-TomlSpace {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    return $Text.TrimStart([char[]]@(' ', "`t"))
}

function TrimEnd-TomlSpace {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    return $Text.TrimEnd([char[]]@(' ', "`t"))
}

function Assert-TomlComment {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Comment)

    foreach ($character in $Comment.ToCharArray()) {
        if ([char]::IsControl($character) -and $character -ne "`t") {
            throw (New-CompatibilityError 'unsupported_toml_subset' '注释包含 TOML 禁止的控制字符。')
        }
    }
}

function Split-TomlLine {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Line)

    [char]$quote = [char]0
    $escaped = $false
    for ($index = 0; $index -lt $Line.Length; $index++) {
        $character = $Line[$index]
        if ($quote -eq '"') {
            if ($escaped) {
                $escaped = $false
            } elseif ($character -eq '\') {
                $escaped = $true
            } elseif ($character -eq $quote) {
                $quote = [char]0
            }
        } elseif ($quote -ne [char]0) {
            if ($character -eq $quote) {
                $quote = [char]0
            }
        } elseif ($character -eq '"' -or $character -eq "'") {
            $quote = $character
        } elseif ($character -eq '#') {
            Assert-TomlComment $Line.Substring($index + 1)
            return [pscustomobject]@{
                Content = $Line.Substring(0, $index)
                CommentIndex = $index
            }
        } elseif ([char]::IsControl($character) -and $character -ne "`t") {
            throw (New-CompatibilityError 'unsupported_toml_subset' '语法区域包含 TOML 禁止的控制字符。')
        } elseif ([char]::IsWhiteSpace($character) -and $character -ne ' ' -and $character -ne "`t") {
            throw (New-CompatibilityError 'unsupported_toml_subset' '语法区域只允许空格和制表符作为空白。')
        }
    }
    if ($quote -ne [char]0) {
        throw (New-CompatibilityError 'unsupported_toml_subset' '发现未闭合或多行字符串；安全子集不处理该形态。')
    }
    return [pscustomobject]@{ Content = $Line; CommentIndex = -1 }
}

function Get-SignificantTomlText {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Line)

    return Trim-TomlSpace (Split-TomlLine $Line).Content
}

function Test-BareTomlKey {
    param([Parameter(Mandatory)][string]$Key)
    return $Key -match '^[A-Za-z0-9_-]+$'
}

function Get-TomlTablePath {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    if ($Text -notmatch '^\[([^\[\]]+)\]$') {
        return $null
    }
    $parts = @($Matches[1].Split('.') | ForEach-Object { Trim-TomlSpace $_ })
    if ($parts.Count -eq 0 -or @($parts | Where-Object { -not (Test-BareTomlKey $_) }).Count -gt 0) {
        return $null
    }
    return ,$parts
}

function Get-TomlAssignment {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $equal = $Text.IndexOf('=')
    if ($equal -lt 1) {
        return $null
    }
    $key = Trim-TomlSpace $Text.Substring(0, $equal)
    if (-not (Test-BareTomlKey $key)) {
        return $null
    }
    [pscustomobject]@{
        Key = $key
        Value = Trim-TomlSpace $Text.Substring($equal + 1)
    }
}

function Assert-BasicTomlString {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value.Length -lt 2 -or -not $Value.StartsWith('"') -or -not $Value.EndsWith('"') -or $Value.StartsWith('"""')) {
        throw (New-CompatibilityError 'unsupported_critical_shape' "关键字段形态未知：$Path")
    }

    $index = 1
    $end = $Value.Length - 1
    while ($index -lt $end) {
        $character = $Value[$index]
        if ($character -eq '"' -or [char]::IsControl($character)) {
            throw (New-CompatibilityError 'unsupported_critical_shape' "字符串包含非法内容：$Path")
        }
        if ($character -ne '\') {
            $index++
            continue
        }

        $index++
        if ($index -ge $end) {
            throw (New-CompatibilityError 'unsupported_critical_shape' "字符串转义未完成：$Path")
        }
        $escape = $Value[$index]
        if ('btnfr"\'.Contains($escape)) {
            $index++
            continue
        }
        if ($escape -ne 'u' -and $escape -ne 'U') {
            throw (New-CompatibilityError 'unsupported_critical_shape' "字符串包含未知转义：$Path")
        }

        $digits = if ($escape -eq 'u') { 4 } else { 8 }
        if ($index + $digits -ge $end) {
            throw (New-CompatibilityError 'unsupported_critical_shape' "Unicode 转义长度错误：$Path")
        }
        $hex = $Value.Substring($index + 1, $digits)
        if ($hex -notmatch '^[0-9A-Fa-f]+$') {
            throw (New-CompatibilityError 'unsupported_critical_shape' "Unicode 转义包含非十六进制字符：$Path")
        }
        $codePoint = [Convert]::ToUInt32($hex, 16)
        if ($codePoint -gt 0x10FFFF -or ($codePoint -ge 0xD800 -and $codePoint -le 0xDFFF)) {
            throw (New-CompatibilityError 'unsupported_critical_shape' "Unicode 转义不是有效标量：$Path")
        }
        $index += $digits + 1
    }
}

function Assert-SafeTomlValue {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value.StartsWith('"')) {
        Assert-BasicTomlString $Value $Path
        return 'BasicString'
    }
    if ($Value.StartsWith("'")) {
        if ($Value.Length -lt 2 -or -not $Value.EndsWith("'") -or $Value.StartsWith("'''") -or $Value.Substring(1, $Value.Length - 2).Contains("'")) {
            throw (New-CompatibilityError 'unsupported_toml_subset' "字面量字符串超出安全子集：$Path")
        }
        foreach ($character in $Value.Substring(1, $Value.Length - 2).ToCharArray()) {
            if ([char]::IsControl($character)) {
                throw (New-CompatibilityError 'unsupported_toml_subset' "字面量字符串包含控制字符：$Path")
            }
        }
        return 'LiteralString'
    }
    if ($Value -eq 'true' -or $Value -eq 'false') { return 'Boolean' }
    if ($Value -match '^[+-]?(0|[1-9][0-9]*)(_[0-9]+)*$') {
        $number = 0L
        $normalized = $Value.Replace('_', '')
        if ([long]::TryParse(
            $normalized,
            [System.Globalization.NumberStyles]::AllowLeadingSign,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$number)) {
            return 'Integer'
        }
    }

    throw (New-CompatibilityError 'unsupported_toml_subset' "值超出可证明安全的 TOML 子集：$Path")
}

function Get-CodexTomlCompatibility {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $decoded = ConvertFrom-CodexUtf8 $Bytes
    for ($index = 0; $index -lt $decoded.Text.Length; $index++) {
        if ($decoded.Text[$index] -eq "`r" -and
            ($index + 1 -ge $decoded.Text.Length -or $decoded.Text[$index + 1] -ne "`n")) {
            throw (New-CompatibilityError 'unsupported_toml_subset' '发现未组成 CRLF 的孤立 CR。')
        }
    }
    $hasCrLf = $decoded.Text.Contains("`r`n")
    $hasLoneLf = [regex]::IsMatch($decoded.Text, '(?<!\r)\n')
    if ($hasCrLf -and $hasLoneLf) {
        throw (New-CompatibilityError 'mixed_line_endings' '配置混用了 CRLF 与 LF。')
    }

    $currentTable = @()
    $modelCount = 0
    $providerCount = 0
    $tables = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $assignments = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $assignmentKinds = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
    foreach ($line in [regex]::Split($decoded.Text, '\r?\n')) {
        $significant = Get-SignificantTomlText $line
        if (-not $significant) { continue }
        if ($significant.StartsWith('[[')) {
            throw (New-CompatibilityError 'unsupported_toml_subset' '安全子集不处理数组表。')
        }

        $table = Get-TomlTablePath $significant
        if ($null -ne $table) {
            $currentTable = @($table)
            $tablePath = $currentTable -join '.'
            if (-not $tables.Add($tablePath)) {
                throw (New-CompatibilityError 'duplicate_table' "表重复：$tablePath")
            }
            foreach ($definedTable in $tables) {
                if ($definedTable -ne $tablePath -and $definedTable.StartsWith("$tablePath.", [System.StringComparison]::Ordinal)) {
                    throw (New-CompatibilityError 'conflicting_definition' "父表在子表之后重复声明：$tablePath")
                }
            }
            foreach ($definedValue in $assignments) {
                if ($definedValue -eq $tablePath -or
                    $tablePath.StartsWith("$definedValue.", [System.StringComparison]::Ordinal) -or
                    $definedValue.StartsWith("$tablePath.", [System.StringComparison]::Ordinal)) {
                    throw (New-CompatibilityError 'conflicting_definition' "表与字段路径冲突：$tablePath / $definedValue")
                }
            }
            if ($currentTable.Count -gt 0 -and
                $currentTable[0] -eq 'model_providers' -and
                $currentTable.Count -ne 2) {
                throw (New-CompatibilityError 'unsupported_critical_shape' "Provider 路径形态未知：$($currentTable -join '.')")
            }
            continue
        }

        if ($significant.StartsWith('[')) {
            throw (New-CompatibilityError 'unsupported_toml_subset' '表头包含引用键或无法识别的结构。')
        }

        $assignment = Get-TomlAssignment $significant
        if ($null -eq $assignment) {
            throw (New-CompatibilityError 'unsupported_toml_subset' '发现无法识别的 TOML 语句。')
        }
        $assignmentPath = @($currentTable + $assignment.Key) -join '.'
        if (-not $assignments.Add($assignmentPath)) {
            throw (New-CompatibilityError 'duplicate_managed_field' "字段重复：$assignmentPath")
        }
        foreach ($definedTable in $tables) {
            if ($definedTable -eq $assignmentPath -or $definedTable.StartsWith("$assignmentPath.", [System.StringComparison]::Ordinal)) {
                throw (New-CompatibilityError 'conflicting_definition' "字段与表路径冲突：$assignmentPath / $definedTable")
            }
        }
        $valueKind = Assert-SafeTomlValue $assignment.Value $assignmentPath
        $assignmentKinds.Add($assignmentPath, $valueKind)
        if ($currentTable.Count -eq 0 -and $assignment.Key -eq 'model_providers') {
            throw (New-CompatibilityError 'unsupported_critical_shape' 'model_providers 不支持内联形态。')
        }
        if ($currentTable.Count -eq 0 -and $assignment.Key -eq 'model') {
            $modelCount++
        }
        if ($currentTable.Count -eq 0 -and $assignment.Key -eq 'model_provider') {
            $providerCount++
        }
    }

    if ($modelCount -gt 1) {
        throw (New-CompatibilityError 'duplicate_managed_field' '纳管字段重复：model')
    }
    if ($providerCount -gt 1) {
        throw (New-CompatibilityError 'duplicate_managed_field' '纳管字段重复：model_provider')
    }

    [pscustomobject]@{
        Compatible = $true
        HasBom = $decoded.HasBom
        Newline = if ($hasCrLf) { 'CRLF' } elseif ($hasLoneLf) { 'LF' } else { 'None' }
        TablePaths = @($tables)
        AssignmentPaths = @($assignments)
        AssignmentKinds = $assignmentKinds
    }
}

function ConvertTo-TomlBasicString {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        switch ($character) {
            '\' { [void]$builder.Append('\\'); break }
            '"' { [void]$builder.Append('\"'); break }
            "`n" { [void]$builder.Append('\n'); break }
            "`r" { [void]$builder.Append('\r'); break }
            "`t" { [void]$builder.Append('\t'); break }
            default {
                if ([char]::IsControl($character)) {
                    [void]$builder.Append(('\u{0:X4}' -f [int]$character))
                } else {
                    [void]$builder.Append($character)
                }
            }
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Set-CodexTomlString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string[]]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )

    if ($Path.Count -eq 0 -or @($Path | Where-Object { -not (Test-BareTomlKey $_) }).Count -gt 0) {
        throw (New-CompatibilityError 'invalid_path' '纳管路径为空或含不支持的段。')
    }
    $compatibility = Get-CodexTomlCompatibility $Bytes
    $decoded = ConvertFrom-CodexUtf8 $Bytes
    $targetTable = @($Path[0..([Math]::Max(0, $Path.Count - 2))])
    if ($Path.Count -eq 1) { $targetTable = @() }
    $targetKey = $Path[-1]
    $displayPath = $Path -join '.'
    $currentTable = @()
    $matches = [System.Collections.Generic.List[object]]::new()

    foreach ($match in [regex]::Matches($decoded.Text, '.*?(?:\r\n|\n|$)')) {
        if ($match.Length -eq 0) { continue }
        $line = $match.Value.TrimEnd("`r", "`n")
        $significant = Get-SignificantTomlText $line
        $table = Get-TomlTablePath $significant
        if ($null -ne $table) {
            $currentTable = @($table)
            continue
        }
        if (($currentTable -join '.') -ne ($targetTable -join '.')) { continue }
        $assignment = Get-TomlAssignment $significant
        if ($null -eq $assignment -or $assignment.Key -ne $targetKey) { continue }
        Assert-BasicTomlString $assignment.Value $displayPath

        $equal = $line.IndexOf('=')
        $right = $line.Substring($equal + 1)
        $leading = $right.Length - (TrimStart-TomlSpace $right).Length
        $comment = (Split-TomlLine $right).CommentIndex
        if ($comment -lt 0) { $comment = $right.Length }
        $valueRegion = $right.Substring(0, $comment)
        $matches.Add([pscustomobject]@{
            Start = $match.Index + $equal + 1 + $leading
            End = $match.Index + $equal + 1 + (TrimEnd-TomlSpace $valueRegion).Length
        })
    }

    if ($matches.Count -eq 0) {
        throw (New-CompatibilityError 'missing_managed_field' "纳管字段不存在：$displayPath")
    }
    if ($matches.Count -gt 1) {
        throw (New-CompatibilityError 'duplicate_managed_field' "纳管字段重复：$displayPath")
    }

    $range = $matches[0]
    $patched = $decoded.Text.Substring(0, $range.Start) +
        (ConvertTo-TomlBasicString $Value) +
        $decoded.Text.Substring($range.End)
    $encoded = $script:StrictUtf8.GetBytes($patched)
    if (-not $compatibility.HasBom) {
        return ,$encoded
    }

    $output = [byte[]]::new($encoded.Length + 3)
    [Array]::Copy($script:Utf8Bom, 0, $output, 0, 3)
    [Array]::Copy($encoded, 0, $output, 3, $encoded.Length)
    return ,$output
}

function ConvertFrom-ExactJsonObject {
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][string]$ErrorCode,
        [Parameter(Mandatory)][string]$Label
    )

    try {
        $document = [System.Text.Json.JsonDocument]::Parse($Json)
    } catch {
        throw (New-CompatibilityError $ErrorCode "$Label 不是有效 JSON。")
    }
    try {
        if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {
            throw (New-CompatibilityError $ErrorCode "$Label 顶层必须是 JSON 对象。")
        }
        Assert-NoDuplicateJsonProperties $document.RootElement $ErrorCode $Label
        return ,(ConvertFrom-ExactJsonElementObject $document.RootElement $ErrorCode $Label)
    } finally {
        $document.Dispose()
    }
}

function Assert-NoDuplicateJsonProperties {
    param(
        [Parameter(Mandatory)][System.Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)][string]$ErrorCode,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw (New-CompatibilityError $ErrorCode "$Path 包含重复字段：$($property.Name)")
            }
            Assert-NoDuplicateJsonProperties $property.Value $ErrorCode "$Path.$($property.Name)"
        }
    } elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-NoDuplicateJsonProperties $item $ErrorCode "$Path[$index]"
            $index++
        }
    }
}

function ConvertFrom-ExactJsonElementObject {
    param(
        [Parameter(Mandatory)][System.Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)][string]$ErrorCode,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {
        throw (New-CompatibilityError $ErrorCode "$Label 必须是 JSON 对象。")
    }
    $properties = [System.Collections.Generic.Dictionary[string, System.Text.Json.JsonElement]]::new([System.StringComparer]::Ordinal)
    foreach ($property in $Element.EnumerateObject()) {
        if (-not $properties.TryAdd($property.Name, $property.Value.Clone())) {
            throw (New-CompatibilityError $ErrorCode "$Label 包含重复字段：$($property.Name)")
        }
    }
    return ,$properties
}

function Test-NonEmptyJsonString {
    param([Parameter(Mandatory)][System.Text.Json.JsonElement]$Element)
    return $Element.ValueKind -eq [System.Text.Json.JsonValueKind]::String -and
        -not [string]::IsNullOrWhiteSpace($Element.GetString())
}

function Test-OrdinalContains {
    param(
        [Parameter(Mandatory)][object[]]$Values,
        [Parameter(Mandatory)][string]$Expected
    )
    foreach ($value in $Values) {
        if ([string]::Equals([string]$value, $Expected, [System.StringComparison]::Ordinal)) {
            return $true
        }
    }
    return $false
}

function Get-CodexFixtureProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$ConfigBytes,
        [Parameter(Mandatory)][string]$AuthJson,
        [Parameter(Mandatory)][string]$SessionMetadataJson
    )

    $compatibility = Get-CodexTomlCompatibility $ConfigBytes
    $auth = ConvertFrom-ExactJsonObject $AuthJson 'unknown_auth_shape' '认证状态'
    $hasApiKey = $auth.ContainsKey('OPENAI_API_KEY')
    $hasTokens = $auth.ContainsKey('tokens')
    if ($hasApiKey -eq $hasTokens) {
        throw (New-CompatibilityError 'unknown_auth_shape' '认证状态关键结构未知。')
    }
    if ($hasApiKey -and -not (Test-NonEmptyJsonString $auth['OPENAI_API_KEY'])) {
        throw (New-CompatibilityError 'unknown_auth_shape' 'OPENAI_API_KEY 必须是非空字符串。')
    }
    if ($hasTokens) {
        $tokens = ConvertFrom-ExactJsonElementObject $auth['tokens'] 'unknown_auth_shape' '合成 tokens'
        foreach ($name in @('id_token', 'access_token', 'refresh_token', 'account_id')) {
            if (-not $tokens.ContainsKey($name) -or -not (Test-NonEmptyJsonString $tokens[$name])) {
                throw (New-CompatibilityError 'unknown_auth_shape' "合成 tokens.$name 必须是非空字符串。")
            }
        }
    }

    $session = ConvertFrom-ExactJsonObject $SessionMetadataJson 'unknown_session_metadata_shape' '会话元数据'
    foreach ($name in @('id', 'thread_name')) {
        if (-not $session.ContainsKey($name) -or -not (Test-NonEmptyJsonString $session[$name])) {
            throw (New-CompatibilityError 'unknown_session_metadata_shape' "$name 必须是非空字符串。")
        }
    }
    if (-not $session.ContainsKey('updated_at') -or -not (Test-NonEmptyJsonString $session['updated_at'])) {
        throw (New-CompatibilityError 'unknown_session_metadata_shape' 'updated_at 必须是非空时间字符串。')
    }

    $required = [ordered]@{
        model = 'BasicString'
        model_provider = 'BasicString'
        'model_providers.sample.name' = 'BasicString'
        'model_providers.sample.base_url' = 'BasicString'
        'model_providers.sample.env_key' = 'BasicString'
    }
    foreach ($path in $required.Keys) {
        if (-not (Test-OrdinalContains $compatibility.AssignmentPaths $path)) {
            throw (New-CompatibilityError 'unknown_fixture_profile' "固定样本缺少必要配置路径：$path")
        }
        if ($compatibility.AssignmentKinds[$path] -ne $required[$path]) {
            throw (New-CompatibilityError 'unknown_fixture_profile' "固定样本配置类型不匹配：$path")
        }
    }
    if (-not (Test-OrdinalContains $compatibility.TablePaths 'model_providers.sample')) {
        throw (New-CompatibilityError 'unknown_fixture_profile' '固定样本缺少 Provider 表。')
    }

    if ($hasTokens -and -not $compatibility.HasBom -and $compatibility.Newline -eq 'CRLF') {
        $profileKinds = [ordered]@{
            unknown_future_key = 'BasicString'
            'model_providers.sample.unknown_provider_option' = 'Boolean'
        }
        foreach ($path in $profileKinds.Keys) {
            if (-not (Test-OrdinalContains $compatibility.AssignmentPaths $path)) {
                throw (New-CompatibilityError 'unknown_fixture_profile' "合成 OAuth Profile 缺少必要路径：$path")
            }
            if ($compatibility.AssignmentKinds[$path] -ne $profileKinds[$path]) {
                throw (New-CompatibilityError 'unknown_fixture_profile' "合成 OAuth Profile 类型不匹配：$path")
            }
        }
        return 'SyntheticOAuthProfile'
    }
    if ($hasApiKey -and $compatibility.HasBom -and $compatibility.Newline -eq 'LF') {
        $profileKinds = [ordered]@{
            unknown_future_key = 'BasicString'
            'model_providers.sample.unknown_provider_option' = 'Boolean'
            'features.apps' = 'Boolean'
        }
        foreach ($path in $profileKinds.Keys) {
            if (-not (Test-OrdinalContains $compatibility.AssignmentPaths $path)) {
                throw (New-CompatibilityError 'unknown_fixture_profile' "当前结构指纹样本缺少必要路径：$path")
            }
            if ($compatibility.AssignmentKinds[$path] -ne $profileKinds[$path]) {
                throw (New-CompatibilityError 'unknown_fixture_profile' "当前结构指纹样本类型不匹配：$path")
            }
        }
        return 'CurrentShapeApiKeyProfile'
    }
    if ($hasApiKey -and -not $compatibility.HasBom -and $compatibility.Newline -eq 'LF' -and
        (Test-OrdinalContains $compatibility.AssignmentPaths 'features.apps') -and
        (Test-OrdinalContains $compatibility.AssignmentPaths 'unknown_future_key') -and
        $compatibility.AssignmentKinds['features.apps'] -eq 'Boolean' -and
        $compatibility.AssignmentKinds['unknown_future_key'] -eq 'BasicString') {
        return 'ApiKeyBaselineProfile'
    }
    throw (New-CompatibilityError 'unknown_fixture_profile' '配置、认证与格式特征不匹配任何固定样本 Profile。')
}

Export-ModuleMember -Function @(
    'Get-CodexFixtureProfile',
    'Get-CodexTomlCompatibility',
    'Set-CodexTomlString'
)
