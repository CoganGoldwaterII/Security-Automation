# ============================================================================
# NAME: MME IR Evidence Sanitizer
# AUTHORED BY:
# TYPE: Manual IR Sanitization / Post-Collection Derivative
# SCOPE: Analyst workstation / Windows only
# VARIABLES:
#   ManifestPath (optional parameter; auto-selects the only *_RTR_MANIFEST.json
#   in C:\MME\CS when omitted)
# OUTPUT TOKENS:
#   RESULT | SANITIZATION_COMPLETE | Source=<zip> Output=<zip> Tokenized=<n> Redacted=<n> Removed=<n> ReviewRequired=0
#   NO_ACTION | <reason>
#   ERROR | Stage=<stage> Error=<sanitized error>
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# LOGGING PATH:
#   C:\MME\AutoLogs\MME_IR_Evidence_Sanitizer.log
# DESCRIPTION:
#   Consumes the RTR manifest produced by MME IR Evidence RTR Audit and creates
#   a separate sanitized derivative of the original Device IR evidence ZIP.
#   The original ZIP is never modified, overwritten, or deleted. The script
#   verifies the source SHA256 against the manifest before and after processing.
#
#   Approved RTR actions are PRESERVE / TOKENIZE / REDACT / REMOVE /
#   REVIEW_REQUIRED. Script B executes the policy assigned by Script A; it does
#   not independently reclassify artifact families. REVIEW_REQUIRED fails closed.
#
#   Tokenization is stable within a run. The human-readable RTR final log in
#   C:\MME\CS records token mappings and change summaries. Secret values are
#   never written to either log. Chromium SQLite handling uses Windows-native
#   winsqlite3.dll only. No third-party tools, modules, packages, or downloads.
#
#   Known opaque binary families assigned REMOVE by Script A are omitted from
#   the sanitized ZIP. EVTX files are converted to sanitized XML derivatives so
#   event structure and correlation metadata remain useful without shipping the
#   original binary event log. Chromium SQLite working copies are securely
#   rewritten and VACUUMed before inclusion so original sensitive values are not
#   left behind in free database pages.
#
#   The script always exits 0. Expected and unexpected failures are reported by
#   the final output token and operational log.
# ============================================================================

[CmdletBinding()]
param(
    [string]$ManifestPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ============================================================
# CONSTANTS / RUN STATE
# ============================================================

$Build = '2026.10.05-v6'
$SupportedManifestSchema = '2.0'
$SupportedPolicyVersion = '2.0'
$Workspace = 'C:\MME\CS'
$LogDirectory = 'C:\MME\AutoLogs'
$OperationalLog = Join-Path $LogDirectory 'MME_IR_Evidence_Sanitizer.log'

$CurrentStage = 'Initialize'
$FinalOutput = $null
$SourceZip = $null
$Manifest = $null
$RtrLog = $null
$WorkRoot = $null
$EvidenceRoot = $null
$SanitizedZip = $null
$SourceHashBefore = $null

$script:TokenizedOccurrences = 0
$script:RedactedOccurrences = 0
$script:RemovedArtifacts = 0
$script:ModifiedArtifacts = 0
$script:EvtxConverted = 0
$script:TokenMap = @{}
$script:TokenKey = New-Object byte[] 32
$script:UserLiterals = @{}
$script:PersonLiterals = @{}
$script:UserLiteralTokens = @{}
$script:PersonLiteralTokens = @{}
$script:KnownIdentityRegex = $null
$script:RuleCounters = @{}
$script:BuiltInUsers = @{
    'administrator' = $true
    'public' = $true
    'default' = $true
    'default user' = $true
    'defaultaccount' = $true
    'guest' = $true
    'system' = $true
    'local service' = $true
    'network service' = $true
    'localservice' = $true
    'networkservice' = $true
    'wdagutilityaccount' = $true
}

$script:PassiveUserFolders = @{
    'documents' = $true
    'desktop' = $true
    'onedrive' = $true
    'pictures' = $true
    'videos' = $true
    'music' = $true
    'recent' = $true
}

$script:SecurityFileExtensions = @{
    '.exe' = $true; '.dll' = $true; '.sys' = $true; '.msi' = $true
    '.msp' = $true; '.ps1' = $true; '.psm1' = $true; '.bat' = $true
    '.cmd' = $true; '.vbs' = $true; '.js' = $true; '.jse' = $true
    '.wsf' = $true; '.hta' = $true; '.scr' = $true; '.com' = $true
    '.lnk' = $true; '.jar' = $true; '.zip' = $true; '.7z' = $true
    '.rar' = $true; '.iso' = $true; '.img' = $true
}

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($script:TokenKey) } finally { $rng.Dispose() }

# ============================================================
# REGEX CATALOG
# ============================================================

$script:EmailRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<![A-Z0-9._%+\-])[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}(?![A-Z0-9._%+\-])',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:UrlRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)https?://[^\s<>"'']+',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:UserPathRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<prefix>\\Users\\)(?<user>[^\\/:*?"<>|]+)',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:ContextIdRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<label>patient\s*(?:id|number|no\.?|#|account(?:\s*(?:id|number|no\.?|#))?)|member\s*(?:id|number|no\.?|#)|subscriber\s*(?:id|number|no\.?|#)|policyholder\s*(?:id|number|no\.?|#)|mrn|medical\s*record\s*(?:id|number|no\.?|#)|chart\s*(?:id|number|no\.?|#)|claim\s*(?:id|number|no\.?|#))\s*[:=]\s*(?<value>[^\s,;|"''<>]+)',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:ContextNameRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<label>patient\s*name|member\s*name|subscriber\s*name|policyholder\s*name|cardholder\s*name|recipient\s*name|first\s*name|last\s*name|full\s*name)\s*[:=]\s*(?<value>[^,;|<>\r\n]{2,120}?)(?=\s{2,}|[,;|<>]|\s+(?:dob|date\s*of\s*birth|phone|email|member|patient|subscriber|policyholder|account)\b\s*[:=]|$)',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:ContextUserRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<label>username|user|account\s*name)\s*[:=]\s*(?<value>[^\s,;|<>"'']{2,120})',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:ContextDobRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<label>dob|date\s*of\s*birth|birth\s*date)\s*[:=]\s*(?<value>[^,;|<>\r\n]{4,40})',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:ContextPhoneRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<label>phone|telephone|mobile|cell)\s*[:=]\s*(?<value>[^,;|<>\r\n]{5,40})',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:ContextAddressRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<label>street\s*address|mailing\s*address|home\s*address|postal\s*address)\s*[:=]\s*(?<value>[^;|<>\r\n]{4,180})',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:SecretAssignmentRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<![A-Za-z0-9_])(?<label>password(?:[-_ ]?value)?|passwd|pwd|passcode|pin(?:_?code)?|otp|one[-_ ]?time[-_ ]?password|security[-_ ]?answer|api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|auth[-_ ]?token|authorization|client[-_ ]?secret|secret[-_ ]?key|secret)\s*[:=]\s*(?<value>[^\s,;|<>\r\n]+)',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$script:BearerRegex = [System.Text.RegularExpressions.Regex]::new(
    '(?i)(?<prefix>\bBearer\s+)(?<value>[A-Z0-9._~+/=\-]{8,})',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# ============================================================
# BASIC HELPERS
# ============================================================

function Initialize-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function ConvertTo-SafeOutput {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    $Text = ([string]$Value) -replace '[\r\n|]+',' ' -replace '\s{2,}',' '
    if ($Text.Length -gt 900) { $Text = $Text.Substring(0,900) }
    return $Text.Trim()
}

function ConvertTo-AuditValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    $Text = ([string]$Value) -replace '[\r\n]+',' ' -replace '\|','¦'
    $Text = $Text.Replace('"','''')
    if ($Text.Length -gt 1200) { $Text = $Text.Substring(0,1200) + '...' }
    return $Text.Trim()
}

function Write-OperationalLog {
    param([Parameter(Mandatory)][string]$Message)
    try {
        '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message |
            Add-Content -LiteralPath $OperationalLog -Encoding UTF8
    }
    catch { }
}

function Write-RtrLog {
    param([Parameter(Mandatory)][string]$Message)
    if ([string]::IsNullOrWhiteSpace($RtrLog)) { return }
    try {
        '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message |
            Add-Content -LiteralPath $RtrLog -Encoding UTF8
    }
    catch {
        throw "Unable to write RTR log: $($_.Exception.Message)"
    }
}

function Add-RuleCount {
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [int]$Count = 1
    )
    if (-not $script:RuleCounters.ContainsKey($RuleId)) {
        $script:RuleCounters[$RuleId] = 0
    }
    $script:RuleCounters[$RuleId] = [int]$script:RuleCounters[$RuleId] + $Count
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Normalize-RelativePath {
    param([Parameter(Mandatory)][string]$Path)
    return (($Path -replace '/','\').TrimStart([char]'\'))
}

function Get-LocalEvidencePath {
    param([Parameter(Mandatory)][string]$RelativePath)
    $Relative = Normalize-RelativePath $RelativePath
    return Join-Path $EvidenceRoot $Relative
}

function Test-IsBuiltInUser {
    param([AllowNull()][string]$User)
    if ([string]::IsNullOrWhiteSpace($User)) { return $true }
    $u = $User.Trim().ToLowerInvariant()
    if ($script:BuiltInUsers.ContainsKey($u)) { return $true }
    if ($u -match '^(dwm|umfd)-\d+$') { return $true }
    return $false
}

function Test-IsAlreadyTokenized {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return $Value -match '^(?:USER|PERSON|EMAIL|ID|DOB|PHONE|ADDRESS|FILE|DIR|IDENTITY)_[0-9A-F]{16}(?:@.+)?$'
}

function Get-CanonicalTokenValue {
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return '' }

    # Deliberately preserve the exact source string, including case and
    # whitespace. Chromium uses UNIQUE/PRIMARY KEY constraints on several
    # identity-bearing fields. Collapsing values that differ only by case or
    # trailing whitespace can turn a valid database into a constraint failure.
    return [string]$Value
}

function Get-LiteralLookupKey {
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value)
    $Canonical = Get-CanonicalTokenValue $Value
    if ([string]::IsNullOrEmpty($Canonical)) { return '' }
    return $Canonical.ToLowerInvariant()
}

function Get-TokenStorageKey {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$DataClass
    )
    $Canonical = Get-CanonicalTokenValue $Value
    if ([string]::IsNullOrEmpty($Canonical)) { return '' }

    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($DataClass + "`0" + $Canonical)
        $Digest = $Sha.ComputeHash($Bytes)
    }
    finally {
        $Sha.Dispose()
    }

    $Hex = -join ($Digest | ForEach-Object { $_.ToString('X2') })
    return $DataClass + '|' + $Hex
}

function Test-IsKnownIdentityLiteral {
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value)
    $Key = Get-LiteralLookupKey $Value
    if ([string]::IsNullOrEmpty($Key)) { return $false }
    return ($script:PersonLiteralTokens.ContainsKey($Key) -or $script:UserLiteralTokens.ContainsKey($Key))
}

function Get-RtrToken {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][ValidateSet('USER','PERSON','EMAIL','ID','DOB','PHONE','ADDRESS','FILE','DIR','IDENTITY')][string]$DataClass,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$RuleId
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if (Test-IsAlreadyTokenized $Value) { return $Value }

    $Original = Get-CanonicalTokenValue $Value
    $StorageKey = Get-TokenStorageKey -Value $Original -DataClass $DataClass
    if ($script:TokenMap.ContainsKey($StorageKey)) {
        return [string]$script:TokenMap[$StorageKey]
    }

    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $script:TokenKey
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($DataClass + "`0" + $Original)
        $Hash = $hmac.ComputeHash($Bytes)
    }
    finally {
        $hmac.Dispose()
    }

    $Hex = -join ($Hash[0..7] | ForEach-Object { $_.ToString('X2') })
    $Token = '{0}_{1}' -f $DataClass,$Hex

    if ($DataClass -eq 'EMAIL') {
        $EmailCore = $Original.Trim()
        if ($EmailCore.Contains('@')) {
            $at = $EmailCore.LastIndexOf('@')
            if ($at -gt 0 -and $at -lt ($EmailCore.Length - 1)) {
                $Domain = $EmailCore.Substring($at + 1).ToLowerInvariant()
                $Token = $Token + '@' + $Domain
            }
        }
    }

    $script:TokenMap[$StorageKey] = $Token

    $LiteralKey = Get-LiteralLookupKey $Original
    if ($DataClass -eq 'USER') {
        if (-not $script:UserLiterals.ContainsKey($LiteralKey)) { $script:UserLiterals[$LiteralKey] = $Original }
        if (-not $script:UserLiteralTokens.ContainsKey($LiteralKey)) { $script:UserLiteralTokens[$LiteralKey] = $Token }
    }
    if ($DataClass -eq 'PERSON') {
        if (-not $script:PersonLiterals.ContainsKey($LiteralKey)) { $script:PersonLiterals[$LiteralKey] = $Original }
        if (-not $script:PersonLiteralTokens.ContainsKey($LiteralKey)) { $script:PersonLiteralTokens[$LiteralKey] = $Token }
    }

    Write-RtrLog ('TOKEN_MAP | Class={0} | Token={1} | Original="{2}" | FirstArtifact="{3}" | Rule={4}' -f `
        $DataClass,$Token,(ConvertTo-AuditValue $Original),(ConvertTo-AuditValue $Artifact),$RuleId)

    return $Token
}

function Register-TokenUse {
    param(
        [Parameter(Mandatory)][hashtable]$Stats,
        [Parameter(Mandatory)][string]$RuleId,
        [int]$Count = 1
    )
    $Stats.Tokenized = [int]$Stats.Tokenized + $Count
    $script:TokenizedOccurrences += $Count
    Add-RuleCount -RuleId $RuleId -Count $Count
}

function Register-Redaction {
    param(
        [Parameter(Mandatory)][hashtable]$Stats,
        [Parameter(Mandatory)][string]$RuleId,
        [int]$Count = 1
    )
    $Stats.Redacted = [int]$Stats.Redacted + $Count
    $script:RedactedOccurrences += $Count
    Add-RuleCount -RuleId $RuleId -Count $Count
}

function New-ArtifactStats {
    return @{ Tokenized = 0; Redacted = 0; Removed = 0 }
}

function Write-ArtifactStats {
    param(
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][hashtable]$Stats
    )
    if ($Stats.Tokenized -gt 0 -or $Stats.Redacted -gt 0 -or $Stats.Removed -gt 0) {
        Write-RtrLog ('ARTIFACT | Policy={0} | Tokenized={1} Redacted={2} Removed={3} | Path="{4}"' -f `
            $PolicyId,$Stats.Tokenized,$Stats.Redacted,$Stats.Removed,(ConvertTo-AuditValue $Artifact))
        $script:ModifiedArtifacts++
    }
}

# ============================================================
# STRING / CONTEXT TRANSFORMS
# ============================================================

function Convert-EmailValue {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats,
        [string]$RuleId = 'TEXT_EMAIL'
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $Token = Get-RtrToken -Value $Value -DataClass 'EMAIL' -Artifact $Artifact -RuleId $RuleId
    if ($Token -ne $Value) { Register-TokenUse -Stats $Stats -RuleId $RuleId }
    return $Token
}

function Convert-UserValue {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats,
        [string]$RuleId = 'STRUCTURED_USER_IDENTITY'
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if (Test-IsAlreadyTokenized $Value) { return $Value }
    $Trimmed = $Value.Trim()
    if (Test-IsBuiltInUser $Trimmed) { return $Value }

    if ($script:EmailRegex.IsMatch($Trimmed) -and $script:EmailRegex.Match($Trimmed).Value -eq $Trimmed) {
        return Convert-EmailValue -Value $Trimmed -Artifact $Artifact -Stats $Stats -RuleId $RuleId
    }

    if ($Trimmed -match '^(?<domain>[^\\]+)\\(?<user>[^\\]+)$') {
        $domain = $Matches.domain
        $user = $Matches.user
        if (Test-IsBuiltInUser $user) { return $Value }
        $token = Get-RtrToken -Value $user -DataClass 'USER' -Artifact $Artifact -RuleId $RuleId
        Register-TokenUse -Stats $Stats -RuleId $RuleId
        return $domain + '\' + $token
    }

    $Token = Get-RtrToken -Value $Value -DataClass 'USER' -Artifact $Artifact -RuleId $RuleId
    if ($Token -ne $Value) { Register-TokenUse -Stats $Stats -RuleId $RuleId }
    return $Token
}

function Convert-PersonValue {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats,
        [string]$RuleId = 'STRUCTURED_HUMAN_NAME'
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $Token = Get-RtrToken -Value $Value -DataClass 'PERSON' -Artifact $Artifact -RuleId $RuleId
    if ($Token -ne $Value) { Register-TokenUse -Stats $Stats -RuleId $RuleId }
    return $Token
}

function Convert-IdentityValue {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][ValidateSet('ID','DOB','PHONE','ADDRESS','IDENTITY')][string]$Class,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats,
        [Parameter(Mandatory)][string]$RuleId
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $Token = Get-RtrToken -Value $Value -DataClass $Class -Artifact $Artifact -RuleId $RuleId
    if ($Token -ne $Value) { Register-TokenUse -Stats $Stats -RuleId $RuleId }
    return $Token
}

function Replace-RegexWhole {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][System.Text.RegularExpressions.Regex]$Regex,
        [Parameter(Mandatory)][scriptblock]$Transform
    )
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $Matches = $Regex.Matches($Text)
    if ($Matches.Count -eq 0) { return $Text }
    $Result = $Text
    for ($i = $Matches.Count - 1; $i -ge 0; $i--) {
        $m = $Matches[$i]
        $Replacement = [string](& $Transform $m.Value $m)
        if ($Replacement -ne $m.Value) {
            $Result = $Result.Remove($m.Index,$m.Length).Insert($m.Index,$Replacement)
        }
    }
    return $Result
}

function Replace-RegexGroup {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][System.Text.RegularExpressions.Regex]$Regex,
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][scriptblock]$Transform
    )
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $Matches = $Regex.Matches($Text)
    if ($Matches.Count -eq 0) { return $Text }
    $Result = $Text
    for ($i = $Matches.Count - 1; $i -ge 0; $i--) {
        $m = $Matches[$i]
        $g = $m.Groups[$GroupName]
        if (-not $g.Success -or $g.Length -eq 0) { continue }
        $Replacement = [string](& $Transform $g.Value $m)
        if ($Replacement -ne $g.Value) {
            $Result = $Result.Remove($g.Index,$g.Length).Insert($g.Index,$Replacement)
        }
    }
    return $Result
}

function Build-KnownIdentityRegex {
    $Literals = New-Object System.Collections.Generic.List[string]
    foreach ($Key in $script:UserLiterals.Keys) {
        $v = [string]$script:UserLiterals[$Key]
        if ($v.Length -ge 3) { $Literals.Add($v) }
    }
    foreach ($Key in $script:PersonLiterals.Keys) {
        $v = [string]$script:PersonLiterals[$Key]
        if ($v.Length -ge 4) { $Literals.Add($v) }
    }
    if ($Literals.Count -eq 0) {
        $script:KnownIdentityRegex = $null
        return
    }

    $Unique = @($Literals | Sort-Object Length -Descending -Unique)
    $Escaped = @($Unique | ForEach-Object { [regex]::Escape($_) })
    $Pattern = '(?i)(?<![A-Z0-9])(?:' + ($Escaped -join '|') + ')(?![A-Z0-9])'
    $script:KnownIdentityRegex = [System.Text.RegularExpressions.Regex]::new(
        $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::Compiled
    )
}

function Convert-KnownIdentityLiteral {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats,
        [string]$RuleId = 'TEXT_KNOWN_IDENTITY'
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }

    $Key = Get-LiteralLookupKey $Value
    if ($script:PersonLiteralTokens.ContainsKey($Key)) {
        Register-TokenUse -Stats $Stats -RuleId $RuleId
        return [string]$script:PersonLiteralTokens[$Key]
    }
    if ($script:UserLiteralTokens.ContainsKey($Key)) {
        Register-TokenUse -Stats $Stats -RuleId $RuleId
        return [string]$script:UserLiteralTokens[$Key]
    }

    return $Value
}

function Test-UrlContextIdentityCandidate {
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $Decoded = [System.Uri]::UnescapeDataString($Value)
    if ([string]::IsNullOrWhiteSpace($Decoded)) { return $false }

    if ($script:EmailRegex.IsMatch($Decoded) -and $script:EmailRegex.Match($Decoded).Value -eq $Decoded) {
        return $true
    }

    # Static pages/routes are context, not identities.
    if ($Decoded -match '(?i)\.(?:aspx?|html?|php|jsp|js|css|json|xml|txt|pdf|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$') {
        return $false
    }

    $Lower = $Decoded.ToLowerInvariant()
    if ($Lower -in @(
        'login','logout','home','main','index','create','search','new','edit','view','list',
        'settings','profile','profiles','users','user','employees','employee','account',
        'accounts','patient','patients','member','members','subscriber','subscribers',
        'policyholder','policyholders','chart','charts','claim','claims','person','people',
        'dashboard','public','app','portal','auth','signin','signon','registration','register',
        'form','forms'
    )) {
        return $false
    }

    if ($Decoded -match '^\d{3,}$') { return $true }
    if ($Decoded -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f-]{20,}$') { return $true }
    if (
        $Decoded.Length -ge 6 -and
        $Decoded -match '[A-Za-z]' -and
        $Decoded -match '\d' -and
        $Decoded -match '^[A-Za-z0-9._~-]+$'
    ) {
        return $true
    }

    # A human-readable slug immediately following an explicit identity route may
    # itself be the identity (for example /patient/Jane-Smith). Avoid plain words.
    if ($Decoded -match '^[A-Za-z][A-Za-z._-]{2,80}$' -and $Decoded -match '[-_.]') {
        return $true
    }

    return (Test-IsKnownIdentityLiteral -Value $Decoded)
}

function Convert-SensitiveUrl {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Url,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats,
        [string]$RuleId = 'URL_CONTEXT_RTR',
        [AllowNull()][AllowEmptyString()][string]$RedactionTag
    )

    if ([string]::IsNullOrWhiteSpace($Url)) { return $Url }
    if ($Url -notmatch '^(?i)https?://') { return $Url }

    $Trailing = ''
    while ($Url.Length -gt 0 -and $Url[-1] -in @('.',',',')',']','}')) {
        $Trailing = [string]$Url[-1] + $Trailing
        $Url = $Url.Substring(0,$Url.Length - 1)
    }

    try { $Uri = [System.Uri]::new($Url) }
    catch { return $Url + $Trailing }

    $Builder = [System.UriBuilder]::new($Uri)

    $Segments = @(($Uri.AbsolutePath.TrimStart([char]'/')) -split '/')
    if ($Segments.Count -gt 0 -and -not [string]::IsNullOrEmpty($Segments[0])) {
        for ($i = 0; $i -lt $Segments.Count; $i++) {
            $Decoded = [System.Uri]::UnescapeDataString($Segments[$i])
            $NewValue = $Decoded

            if ($i -gt 0) {
                $Prev = [System.Uri]::UnescapeDataString($Segments[$i-1]).ToLowerInvariant()
                if (
                    $Prev -match '^(patient|member|subscriber|policyholder|mrn|chart|claim|account|person|user)$' -and
                    (Test-UrlContextIdentityCandidate -Value $Decoded)
                ) {
                    if ($script:EmailRegex.IsMatch($Decoded) -and $script:EmailRegex.Match($Decoded).Value -eq $Decoded) {
                        $NewValue = Convert-EmailValue -Value $Decoded -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                    }
                    elseif (Test-IsKnownIdentityLiteral -Value $Decoded) {
                        $NewValue = Convert-KnownIdentityLiteral -Value $Decoded -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                    }
                    else {
                        $NewValue = Convert-IdentityValue -Value $Decoded -Class 'ID' -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                    }
                }
            }

            if ($NewValue -eq $Decoded -and $script:EmailRegex.IsMatch($Decoded)) {
                $em = $script:EmailRegex.Match($Decoded)
                if ($em.Value -eq $Decoded) {
                    $NewValue = Convert-EmailValue -Value $Decoded -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                }
            }

            if ($NewValue -eq $Decoded) {
                if (Test-IsKnownIdentityLiteral -Value $Decoded) {
                    $NewValue = Convert-KnownIdentityLiteral -Value $Decoded -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                }
            }

            $Segments[$i] = [System.Uri]::EscapeDataString($NewValue)
        }
        $Builder.Path = '/' + ($Segments -join '/')
    }

    $QueryText = $Uri.Query.TrimStart([char]'?')
    if (-not [string]::IsNullOrEmpty($QueryText)) {
        $Pairs = New-Object System.Collections.Generic.List[string]
        foreach ($Part in @($QueryText -split '&')) {
            if ([string]::IsNullOrEmpty($Part)) { continue }
            # Do not use String.Split(separator,count) here. Windows PowerShell 5.1
            # can bind the integer count to StringSplitOptions and throw. Parse the
            # first '=' explicitly so query values containing '=' are preserved.
            $EqualsIndex = $Part.IndexOf([char]'=')
            if ($EqualsIndex -ge 0) {
                $RawKeyPart = $Part.Substring(0,$EqualsIndex)
                $RawValuePart = $Part.Substring($EqualsIndex + 1)
                $HadEquals = $true
            }
            else {
                $RawKeyPart = $Part
                $RawValuePart = ''
                $HadEquals = $false
            }
            $RawKey = [System.Uri]::UnescapeDataString($RawKeyPart)
            $RawValue = [System.Uri]::UnescapeDataString($RawValuePart)
            $KeyLower = $RawKey.ToLowerInvariant()
            $NewValue = $RawValue

            if ($KeyLower -match '^(access_?token|refresh_?token|auth(?:orization)?|session(?:id|_id|token)?|jwt|api_?key|secret)$') {
                if (-not [string]::IsNullOrEmpty($RawValue)) {
                    if ([string]::IsNullOrWhiteSpace($RedactionTag)) {
                        $NewValue = '[REDACTED]'
                    }
                    else {
                        $NewValue = '[REDACTED_' + $RedactionTag + ']'
                    }
                    Register-Redaction -Stats $Stats -RuleId 'URL_AUTH_PARAMETER'
                }
            }
            elseif ($KeyLower -match '^(?:patient|member|subscriber|policyholder|mrn|chart|claim|account|person)(?:_?(?:id|number|no|name))?$') {
                if (-not [string]::IsNullOrEmpty($RawValue)) {
                    $NewValue = Convert-IdentityValue -Value $RawValue -Class 'ID' -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                }
            }
            elseif ($KeyLower -match '^user(?:_?(?:id|name))?$') {
                if (-not [string]::IsNullOrEmpty($RawValue)) {
                    $NewValue = Convert-UserValue -Value $RawValue -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                }
            }
            elseif ($KeyLower -match '^(?:email|emailaddress)$') {
                if (-not [string]::IsNullOrEmpty($RawValue)) {
                    $NewValue = Convert-EmailValue -Value $RawValue -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                }
            }
            elseif ($KeyLower -match '^(?:dob|dateofbirth|birthdate)$') {
                if (-not [string]::IsNullOrEmpty($RawValue)) {
                    $NewValue = Convert-IdentityValue -Value $RawValue -Class 'DOB' -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                }
            }
            elseif ($KeyLower -match '^(?:phone|telephone|mobile)$') {
                if (-not [string]::IsNullOrEmpty($RawValue)) {
                    $NewValue = Convert-IdentityValue -Value $RawValue -Class 'PHONE' -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                }
            }
            elseif ($script:EmailRegex.IsMatch($RawValue) -and $script:EmailRegex.Match($RawValue).Value -eq $RawValue) {
                $NewValue = Convert-EmailValue -Value $RawValue -Artifact $Artifact -Stats $Stats -RuleId $RuleId
            }
            else {
                if (Test-IsKnownIdentityLiteral -Value $RawValue) {
                    $NewValue = Convert-KnownIdentityLiteral -Value $RawValue -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                }
            }

            $EncodedKey = [System.Uri]::EscapeDataString($RawKey)
            $EncodedValue = [System.Uri]::EscapeDataString($NewValue)
            if ($HadEquals) { $Pairs.Add($EncodedKey + '=' + $EncodedValue) }
            else { $Pairs.Add($EncodedKey) }
        }
        $Builder.Query = ($Pairs -join '&')
    }

    return $Builder.Uri.AbsoluteUri + $Trailing
}

function Convert-SensitivePath {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$PathValue,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats,
        [string]$RuleId = 'PATH_CONTEXT_RTR',
        [switch]$UserFilePolicy
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) { return $PathValue }
    $Result = $PathValue

    if ($Result -match '(?i)\\Users\\') {
        $Result = Replace-RegexGroup -Text $Result -Regex $script:UserPathRegex -GroupName 'user' -Transform {
            param($value,$match)
            if (Test-IsBuiltInUser $value) { return $value }
            return Convert-UserValue -Value $value -Artifact $Artifact -Stats $Stats -RuleId 'USER_FILE_PROFILE_SEGMENT'
        }
    }

    if ($script:KnownIdentityRegex -ne $null) {
        $Result = Replace-RegexWhole -Text $Result -Regex $script:KnownIdentityRegex -Transform {
            param($value,$match)
            return Convert-KnownIdentityLiteral -Value $value -Artifact $Artifact -Stats $Stats -RuleId 'USER_FILE_KNOWN_IDENTITY'
        }
    }

    if ($UserFilePolicy) {
        try {
            $Leaf = [System.IO.Path]::GetFileName($Result)
            $Extension = [System.IO.Path]::GetExtension($Leaf)
            $Stem = [System.IO.Path]::GetFileNameWithoutExtension($Leaf)
            $Directory = [System.IO.Path]::GetDirectoryName($Result)
            $Passive = $false
            foreach ($Folder in $script:PassiveUserFolders.Keys) {
                if ($Result -match ('(?i)[\\/]' + [regex]::Escape($Folder) + '[\\/]')) {
                    $Passive = $true
                    break
                }
            }
            if ($Passive -and -not $script:SecurityFileExtensions.ContainsKey($Extension.ToLowerInvariant()) -and -not [string]::IsNullOrWhiteSpace($Stem)) {
                $NewStem = Get-RtrToken -Value $Stem -DataClass 'FILE' -Artifact $Artifact -RuleId 'PASSIVE_USER_FILENAME'
                if ($NewStem -ne $Stem) {
                    Register-TokenUse -Stats $Stats -RuleId 'PASSIVE_USER_FILENAME'
                    $NewLeaf = $NewStem + $Extension
                    if ([string]::IsNullOrWhiteSpace($Directory)) { $Result = $NewLeaf }
                    else { $Result = Join-Path $Directory $NewLeaf }
                }
            }
        }
        catch { }
    }

    return $Result
}

function Convert-TextContext {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $Result = $Text

    # Secrets first. Values are never logged or tokenized.
    if ($Result -match '(?i)password|passwd|pwd|passcode|pin|otp|token|api.?key|authorization|secret') {
        $Result = Replace-RegexGroup -Text $Result -Regex $script:SecretAssignmentRegex -GroupName 'value' -Transform {
            param($value,$match)
            Register-Redaction -Stats $Stats -RuleId 'TEXT_SECRET_VALUE'
            return '[REDACTED]'
        }
        $Result = Replace-RegexGroup -Text $Result -Regex $script:BearerRegex -GroupName 'value' -Transform {
            param($value,$match)
            Register-Redaction -Stats $Stats -RuleId 'TEXT_SECRET_VALUE'
            return '[REDACTED]'
        }
    }

    if ($Result.Contains('@')) {
        $Result = Replace-RegexWhole -Text $Result -Regex $script:EmailRegex -Transform {
            param($value,$match)
            return Convert-EmailValue -Value $value -Artifact $Artifact -Stats $Stats -RuleId 'TEXT_EMAIL'
        }
    }

    if ($Result -match '(?i)\\Users\\') {
        $Result = Replace-RegexGroup -Text $Result -Regex $script:UserPathRegex -GroupName 'user' -Transform {
            param($value,$match)
            if (Test-IsBuiltInUser $value) { return $value }
            return Convert-UserValue -Value $value -Artifact $Artifact -Stats $Stats -RuleId 'TEXT_USER_PATH'
        }
    }

    if ($Result -match '(?i)patient|member|subscriber|policyholder|mrn|medical record|chart|claim') {
        $Result = Replace-RegexGroup -Text $Result -Regex $script:ContextIdRegex -GroupName 'value' -Transform {
            param($value,$match)
            return Convert-IdentityValue -Value $value -Class 'ID' -Artifact $Artifact -Stats $Stats -RuleId 'TEXT_CONTEXT_SENSITIVE_ID'
        }
    }

    if ($Result -match '(?i)username|\buser\s*[:=]|account\s*name') {
        $Result = Replace-RegexGroup -Text $Result -Regex $script:ContextUserRegex -GroupName 'value' -Transform {
            param($value,$match)
            return Convert-UserValue -Value $value.Trim() -Artifact $Artifact -Stats $Stats -RuleId 'TEXT_CONTEXT_IDENTITY'
        }
    }

    if ($Result -match '(?i)patient\s*name|member\s*name|subscriber\s*name|policyholder\s*name|cardholder\s*name|recipient\s*name|first\s*name|last\s*name|full\s*name') {
        $Result = Replace-RegexGroup -Text $Result -Regex $script:ContextNameRegex -GroupName 'value' -Transform {
            param($value,$match)
            return Convert-PersonValue -Value $value.Trim().Trim('"').Trim("'") -Artifact $Artifact -Stats $Stats -RuleId 'TEXT_CONTEXT_IDENTITY'
        }
    }

    if ($Result -match '(?i)dob|date\s*of\s*birth|birth\s*date') {
        $Result = Replace-RegexGroup -Text $Result -Regex $script:ContextDobRegex -GroupName 'value' -Transform {
            param($value,$match)
            return Convert-IdentityValue -Value $value.Trim() -Class 'DOB' -Artifact $Artifact -Stats $Stats -RuleId 'TEXT_CONTEXT_IDENTITY'
        }
    }

    if ($Result -match '(?i)phone|telephone|mobile|cell') {
        $Result = Replace-RegexGroup -Text $Result -Regex $script:ContextPhoneRegex -GroupName 'value' -Transform {
            param($value,$match)
            return Convert-IdentityValue -Value $value.Trim() -Class 'PHONE' -Artifact $Artifact -Stats $Stats -RuleId 'TEXT_CONTEXT_IDENTITY'
        }
    }

    if ($Result -match '(?i)street\s*address|mailing\s*address|home\s*address|postal\s*address') {
        $Result = Replace-RegexGroup -Text $Result -Regex $script:ContextAddressRegex -GroupName 'value' -Transform {
            param($value,$match)
            return Convert-IdentityValue -Value $value.Trim() -Class 'ADDRESS' -Artifact $Artifact -Stats $Stats -RuleId 'TEXT_CONTEXT_IDENTITY'
        }
    }

    if ($Result -match '(?i)https?://') {
        $Result = Replace-RegexWhole -Text $Result -Regex $script:UrlRegex -Transform {
            param($value,$match)
            return Convert-SensitiveUrl -Url $value -Artifact $Artifact -Stats $Stats -RuleId 'URL_CONTEXT_RTR'
        }
    }

    if ($script:KnownIdentityRegex -ne $null) {
        $Result = Replace-RegexWhole -Text $Result -Regex $script:KnownIdentityRegex -Transform {
            param($value,$match)
            return Convert-KnownIdentityLiteral -Value $value -Artifact $Artifact -Stats $Stats -RuleId 'TEXT_KNOWN_IDENTITY'
        }
    }

    return $Result
}

function Get-FieldDisposition {
    param(
        [AllowNull()][AllowEmptyString()][string]$FieldName,
        [Parameter(Mandatory)][string]$ArtifactPath
    )

    if ([string]::IsNullOrWhiteSpace($FieldName)) { return 'PRESERVE' }
    $n = ($FieldName -replace '[^A-Za-z0-9]','').ToLowerInvariant()
    $p = $ArtifactPath.ToLowerInvariant()

    # Password policy/status metadata is security evidence, not credential material.
    if ($n -match '^(passwordrequired|passwordlastset|passwordexpires|passwordexpired|passwordage|passwordchanged|passwordneverexpires|usermaychangepassword|mustchangepassword)$') {
        return 'PRESERVE'
    }

    if ($n -match '^(password|passwordvalue|passwd|passcode|pin|pincode|otp|onetimepassword|securityanswer|apikey|accesstoken|refreshtoken|authtoken|authorization|encryptedkey|clientsecret|secretkey|secret|cardnumber|iban|cvv|cvc)$') {
        return 'REDACT'
    }

    if ($n -match '^(email|emailaddress|mailaddress|useremail|upn)$') { return 'EMAIL' }
    if ($n -match '^(username|usernamevalue|user|useridname|accountname|runasuser|startname|owner|loggedonuser|profileuser)$' -or $n -match '(username|accountname)$') { return 'USER' }

    if ($n -match '(patient|member|subscriber|policyholder|cardholder|recipient).*(firstname|lastname|fullname|name)$' -or
        $n -match '^(firstname|lastname|fullname|givenname|familyname|middlename)$') {
        return 'PERSON'
    }

    if ($n -match '(patient|member|subscriber|policyholder|mrn|medicalrecord|chart|claim).*(id|number|no|account)$') { return 'ID' }

    if ($n -match '^(dob|dateofbirth|birthdate)$') { return 'DOB' }
    if ($n -match '^(phone|phonenumber|telephone|mobile|cell|mobilenumber)$') { return 'PHONE' }
    if ($n -match '^(streetaddress|mailingaddress|homeaddress|postaladdress|zipcode|postalcode)$') { return 'ADDRESS' }

    if ($n -match '(url|uri|href|referrer|originurl|actionurl|signonrealm)$') { return 'URL' }
    if ($n -match '(filepath|filename|fullpath|targetpath|currentpath|imagepath|commandline|executablepath|scriptpath)$') { return 'PATH' }

    if ($p -match '\\local_users\\|\\local_admins\\') {
        if ($n -in @('name','member','account')) { return 'USER' }
    }

    # A bare AccountId is not treated as identity outside explicit identity/browser context.
    if ($p -match '\\06_browser_saas_artifacts\\' -and $n -match '^(accountid|profileid|gaiaid)$') { return 'ID' }

    return 'PRESERVE'
}

function Convert-StructuredValue {
    param(
        [AllowNull()][object]$Value,
        [AllowNull()][AllowEmptyString()][string]$FieldName,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats,
        [switch]$UserFilePolicy
    )

    if ($null -eq $Value) { return $Value }
    $Text = [string]$Value
    if ([string]::IsNullOrEmpty($Text)) { return $Value }

    $Disposition = Get-FieldDisposition -FieldName $FieldName -ArtifactPath $Artifact
    switch ($Disposition) {
        'REDACT' {
            Register-Redaction -Stats $Stats -RuleId 'STRUCTURED_SECRET_VALUE'
            return '[REDACTED]'
        }
        'EMAIL' { return Convert-EmailValue -Value $Text -Artifact $Artifact -Stats $Stats -RuleId 'STRUCTURED_EMAIL' }
        'USER' { return Convert-UserValue -Value $Text -Artifact $Artifact -Stats $Stats -RuleId 'STRUCTURED_USER_IDENTITY' }
        'PERSON' { return Convert-PersonValue -Value $Text -Artifact $Artifact -Stats $Stats -RuleId 'STRUCTURED_HUMAN_NAME' }
        'ID' { return Convert-IdentityValue -Value $Text -Class 'ID' -Artifact $Artifact -Stats $Stats -RuleId 'STRUCTURED_SENSITIVE_ID' }
        'DOB' { return Convert-IdentityValue -Value $Text -Class 'DOB' -Artifact $Artifact -Stats $Stats -RuleId 'STRUCTURED_IDENTITY_VALUE' }
        'PHONE' { return Convert-IdentityValue -Value $Text -Class 'PHONE' -Artifact $Artifact -Stats $Stats -RuleId 'STRUCTURED_IDENTITY_VALUE' }
        'ADDRESS' { return Convert-IdentityValue -Value $Text -Class 'ADDRESS' -Artifact $Artifact -Stats $Stats -RuleId 'STRUCTURED_IDENTITY_VALUE' }
        'URL' { return Convert-SensitiveUrl -Url $Text -Artifact $Artifact -Stats $Stats -RuleId 'URL_CONTEXT_RTR' }
        'PATH' { $x = Convert-TextContext -Text $Text -Artifact $Artifact -Stats $Stats; return Convert-SensitivePath -PathValue $x -Artifact $Artifact -Stats $Stats -RuleId 'PATH_CONTEXT_RTR' -UserFilePolicy:$UserFilePolicy }
    }

    # Universal/contextual rules can still apply to otherwise preserved string fields.
    return Convert-TextContext -Text $Text -Artifact $Artifact -Stats $Stats
}

# ============================================================
# WINDOWS-NATIVE SQLITE WRAPPER
# ============================================================

function Initialize-WinSqlite {
    if ('MME.WinSqliteDb' -as [type]) { return }

    $Source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace MME
{
    public sealed class WinSqliteDb : IDisposable
    {
        private IntPtr db;
        private const int SQLITE_OK = 0;
        private const int SQLITE_ROW = 100;
        private const int SQLITE_DONE = 101;
        private const int SQLITE_INTEGER = 1;
        private const int SQLITE_FLOAT = 2;
        private const int SQLITE_TEXT = 3;
        private const int SQLITE_BLOB = 4;
        private const int SQLITE_NULL = 5;
        private static readonly IntPtr SQLITE_TRANSIENT = new IntPtr(-1);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        private static extern int sqlite3_open16(string filename, out IntPtr db);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_close(IntPtr db);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        private static extern int sqlite3_prepare16_v2(IntPtr db, string sql, int nByte, out IntPtr stmt, IntPtr tail);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_step(IntPtr stmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_finalize(IntPtr stmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_column_count(IntPtr stmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_column_type(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern long sqlite3_column_int64(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern double sqlite3_column_double(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_column_text16(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_column_bytes16(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_column_blob(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_column_bytes(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_column_name16(IntPtr stmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        private static extern int sqlite3_bind_text16(IntPtr stmt, int index, string value, int nBytes, IntPtr destructor);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_bind_int64(IntPtr stmt, int index, long value);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_bind_zeroblob(IntPtr stmt, int index, int n);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_errmsg16(IntPtr db);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_busy_timeout(IntPtr db, int ms);

        public WinSqliteDb(string path)
        {
            int rc = sqlite3_open16(path, out db);
            if (rc != SQLITE_OK || db == IntPtr.Zero)
                throw new InvalidOperationException("winsqlite3 open failed: " + Error());
            sqlite3_busy_timeout(db, 5000);
        }

        private string Error()
        {
            if (db == IntPtr.Zero) return "database handle unavailable";
            IntPtr p = sqlite3_errmsg16(db);
            return p == IntPtr.Zero ? "unknown sqlite error" : Marshal.PtrToStringUni(p);
        }

        private static string Q(string identifier)
        {
            return "\"" + identifier.Replace("\"", "\"\"") + "\"";
        }

        public void Execute(string sql)
        {
            IntPtr stmt = IntPtr.Zero;
            try
            {
                int rc = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
                if (rc != SQLITE_OK) throw new InvalidOperationException("sqlite prepare failed: " + Error());
                rc = sqlite3_step(stmt);
                if (rc != SQLITE_DONE && rc != SQLITE_ROW)
                    throw new InvalidOperationException("sqlite execute failed: " + Error());
                while (rc == SQLITE_ROW) rc = sqlite3_step(stmt);
                if (rc != SQLITE_DONE) throw new InvalidOperationException("sqlite execute failed: " + Error());
            }
            finally
            {
                if (stmt != IntPtr.Zero) sqlite3_finalize(stmt);
            }
        }

        public List<Dictionary<string, object>> Query(string sql)
        {
            List<Dictionary<string, object>> rows = new List<Dictionary<string, object>>();
            IntPtr stmt = IntPtr.Zero;
            try
            {
                int rc = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
                if (rc != SQLITE_OK) throw new InvalidOperationException("sqlite prepare failed: " + Error());
                int count = sqlite3_column_count(stmt);
                while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
                {
                    Dictionary<string, object> row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr np = sqlite3_column_name16(stmt, i);
                        string name = np == IntPtr.Zero ? ("Column" + i.ToString()) : Marshal.PtrToStringUni(np);
                        int type = sqlite3_column_type(stmt, i);
                        object value = null;
                        if (type == SQLITE_INTEGER) value = sqlite3_column_int64(stmt, i);
                        else if (type == SQLITE_FLOAT) value = sqlite3_column_double(stmt, i);
                        else if (type == SQLITE_TEXT)
                        {
                            IntPtr tp = sqlite3_column_text16(stmt, i);
                            int bytes = sqlite3_column_bytes16(stmt, i);
                            value = tp == IntPtr.Zero ? null : Marshal.PtrToStringUni(tp, bytes / 2);
                        }
                        else if (type == SQLITE_BLOB)
                        {
                            IntPtr bp = sqlite3_column_blob(stmt, i);
                            int bytes = sqlite3_column_bytes(stmt, i);
                            byte[] data = new byte[bytes];
                            if (bp != IntPtr.Zero && bytes > 0) Marshal.Copy(bp, data, 0, bytes);
                            value = data;
                        }
                        row[name] = value;
                    }
                    rows.Add(row);
                }
                if (rc != SQLITE_DONE) throw new InvalidOperationException("sqlite query failed: " + Error());
            }
            finally
            {
                if (stmt != IntPtr.Zero) sqlite3_finalize(stmt);
            }
            return rows;
        }

        public string[] Tables()
        {
            List<string> names = new List<string>();
            foreach (Dictionary<string, object> row in Query("SELECT name FROM sqlite_master WHERE type='table'"))
                if (row.ContainsKey("name") && row["name"] != null) names.Add(Convert.ToString(row["name"]));
            return names.ToArray();
        }

        public string[] Columns(string table)
        {
            List<string> names = new List<string>();
            string sql = "PRAGMA table_info(" + Q(table) + ")";
            foreach (Dictionary<string, object> row in Query(sql))
                if (row.ContainsKey("name") && row["name"] != null) names.Add(Convert.ToString(row["name"]));
            return names.ToArray();
        }

        public List<Dictionary<string, object>> Rows(string table, string[] columns)
        {
            string sql = "SELECT rowid AS __rowid";
            for (int i = 0; i < columns.Length; i++) sql += "," + Q(columns[i]);
            sql += " FROM " + Q(table);
            return Query(sql);
        }

        public void SetText(string table, string column, long rowid, string value)
        {
            string sql = "UPDATE " + Q(table) + " SET " + Q(column) + "=? WHERE rowid=" + rowid.ToString();
            IntPtr stmt = IntPtr.Zero;
            try
            {
                int rc = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
                if (rc != SQLITE_OK) throw new InvalidOperationException("sqlite prepare failed: " + Error());
                rc = sqlite3_bind_text16(stmt, 1, value ?? String.Empty, -1, SQLITE_TRANSIENT);
                if (rc != SQLITE_OK) throw new InvalidOperationException("sqlite bind failed: " + Error());
                rc = sqlite3_step(stmt);
                if (rc != SQLITE_DONE) throw new InvalidOperationException("sqlite update failed: " + Error());
            }
            finally { if (stmt != IntPtr.Zero) sqlite3_finalize(stmt); }
        }

        public void SetInt64(string table, string column, long rowid, long value)
        {
            string sql = "UPDATE " + Q(table) + " SET " + Q(column) + "=? WHERE rowid=" + rowid.ToString();
            IntPtr stmt = IntPtr.Zero;
            try
            {
                int rc = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
                if (rc != SQLITE_OK) throw new InvalidOperationException("sqlite prepare failed: " + Error());
                rc = sqlite3_bind_int64(stmt, 1, value);
                if (rc != SQLITE_OK) throw new InvalidOperationException("sqlite bind failed: " + Error());
                rc = sqlite3_step(stmt);
                if (rc != SQLITE_DONE) throw new InvalidOperationException("sqlite update failed: " + Error());
            }
            finally { if (stmt != IntPtr.Zero) sqlite3_finalize(stmt); }
        }

        public void SetZeroBlob(string table, string column, long rowid)
        {
            string sql = "UPDATE " + Q(table) + " SET " + Q(column) + "=? WHERE rowid=" + rowid.ToString();
            IntPtr stmt = IntPtr.Zero;
            try
            {
                int rc = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
                if (rc != SQLITE_OK) throw new InvalidOperationException("sqlite prepare failed: " + Error());
                rc = sqlite3_bind_zeroblob(stmt, 1, 0);
                if (rc != SQLITE_OK) throw new InvalidOperationException("sqlite bind failed: " + Error());
                rc = sqlite3_step(stmt);
                if (rc != SQLITE_DONE) throw new InvalidOperationException("sqlite update failed: " + Error());
            }
            finally { if (stmt != IntPtr.Zero) sqlite3_finalize(stmt); }
        }

        public string IntegrityCheck()
        {
            List<Dictionary<string, object>> rows = Query("PRAGMA integrity_check");
            if (rows.Count == 0) return "no result";
            foreach (object value in rows[0].Values) return value == null ? "null" : Convert.ToString(value);
            return "no result";
        }

        public void Dispose()
        {
            if (db != IntPtr.Zero)
            {
                sqlite3_close(db);
                db = IntPtr.Zero;
            }
        }
    }
}
'@

    Add-Type -TypeDefinition $Source -Language CSharp
}

function Test-DbTable {
    param(
        [Parameter(Mandatory)]$SqliteDatabase,
        [AllowNull()][AllowEmptyString()][string]$Table
    )
    if ([string]::IsNullOrWhiteSpace($Table)) { return $false }
    return @($SqliteDatabase.Tables()) -contains $Table
}

function Get-DbColumns {
    param(
        [Parameter(Mandatory)]$SqliteDatabase,
        [AllowNull()][AllowEmptyString()][string]$Table
    )
    if ([string]::IsNullOrWhiteSpace($Table)) { return @() }
    if (-not (Test-DbTable -SqliteDatabase $SqliteDatabase -Table $Table)) { return @() }
    return @($SqliteDatabase.Columns($Table))
}

function Test-DbHasRowId {
    param(
        [Parameter(Mandatory)]$SqliteDatabase,
        [AllowNull()][AllowEmptyString()][string]$Table
    )
    if ([string]::IsNullOrWhiteSpace($Table)) { return $false }
    if (-not (Test-DbTable -SqliteDatabase $SqliteDatabase -Table $Table)) { return $false }

    $Quoted = '"' + $Table.Replace('"','""') + '"'
    try {
        $null = $SqliteDatabase.Query('SELECT rowid FROM ' + $Quoted + ' LIMIT 1')
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-SqliteTextTransform {
    param(
        [Parameter(Mandatory)]$SqliteDatabase,
        [AllowNull()][AllowEmptyString()][string]$Table,
        [AllowNull()][AllowEmptyString()][string]$Column,
        [Parameter(Mandatory)][scriptblock]$Transform,
        [Parameter(Mandatory)][hashtable]$Stats
    )
    if ([string]::IsNullOrWhiteSpace($Table) -or [string]::IsNullOrWhiteSpace($Column)) { return }
    $Columns = Get-DbColumns -SqliteDatabase $SqliteDatabase -Table $Table
    if ($Columns -notcontains $Column) { return }
    if (-not (Test-DbHasRowId -SqliteDatabase $SqliteDatabase -Table $Table)) {
        throw "SQLite table '$Table' has no rowid; cannot safely rewrite column '$Column'."
    }
    foreach ($Row in @($SqliteDatabase.Rows($Table,[string[]]@($Column)))) {
        $Old = $Row[$Column]
        if ($null -eq $Old -or $Old -is [byte[]]) { continue }
        $OldText = [string]$Old
        if ([string]::IsNullOrEmpty($OldText)) { continue }
        $NewText = [string](& $Transform $OldText $Row)
        if ($NewText -ne $OldText) {
            $SqliteDatabase.SetText($Table,$Column,[long]$Row['__rowid'],$NewText)
        }
    }
}

function Invoke-SqliteRedactColumn {
    param(
        [Parameter(Mandatory)]$SqliteDatabase,
        [AllowNull()][AllowEmptyString()][string]$Table,
        [AllowNull()][AllowEmptyString()][string]$Column,
        [Parameter(Mandatory)][hashtable]$Stats,
        [Parameter(Mandatory)][string]$RuleId,
        [switch]$UniquePlaceholder
    )
    if ([string]::IsNullOrWhiteSpace($Table) -or [string]::IsNullOrWhiteSpace($Column)) { return }
    $Columns = Get-DbColumns -SqliteDatabase $SqliteDatabase -Table $Table
    if ($Columns -notcontains $Column) { return }
    if (-not (Test-DbHasRowId -SqliteDatabase $SqliteDatabase -Table $Table)) {
        throw "SQLite table '$Table' has no rowid; cannot safely rewrite column '$Column'."
    }
    foreach ($Row in @($SqliteDatabase.Rows($Table,[string[]]@($Column)))) {
        $Old = $Row[$Column]
        if ($null -eq $Old) { continue }
        $HasValue = $true
        if ($Old -is [byte[]]) { $HasValue = $Old.Length -gt 0 }
        elseif ([string]::IsNullOrEmpty([string]$Old)) { $HasValue = $false }
        if (-not $HasValue) { continue }

        if ($Old -is [byte[]]) {
            $SqliteDatabase.SetZeroBlob($Table,$Column,[long]$Row['__rowid'])
        }
        else {
            $Placeholder = '[REDACTED]'
            if ($UniquePlaceholder) { $Placeholder = '[REDACTED_' + [string]$Row['__rowid'] + ']' }
            $SqliteDatabase.SetText($Table,$Column,[long]$Row['__rowid'],$Placeholder)
        }
        Register-Redaction -Stats $Stats -RuleId $RuleId
    }
}

function Invoke-ParserCompatibilitySelfTest {
    # Exercises the PowerShell/.NET parsing boundaries that have historically
    # differed under Windows PowerShell 5.1. This runs before evidence extraction.
    $Stats = New-ArtifactStats
    $RedactedBefore = [int]$script:RedactedOccurrences
    $TokenizedBefore = [int]$script:TokenizedOccurrences
    $RuleSnapshot = @{}
    foreach ($Key in @($script:RuleCounters.Keys)) {
        $RuleSnapshot[$Key] = $script:RuleCounters[$Key]
    }

    try {
        $EmptyText = Convert-TextContext -Text '' -Artifact 'SELFTEST' -Stats $Stats
        if ($EmptyText -ne '') { throw 'Parser self-test failed empty-string handling.' }

        # Cover query pairs with '=', without '=', and with '=' inside the value.
        $TestUrl = 'https://example.invalid/path?plain=alpha&flag&embedded=a%3Db&access_token=SELFTESTSECRET'
        $Converted = Convert-SensitiveUrl -Url $TestUrl -Artifact 'SELFTEST' -Stats $Stats
        if ([string]::IsNullOrWhiteSpace($Converted)) {
            throw 'Parser self-test returned an empty URL.'
        }
        if ($Converted -match 'SELFTESTSECRET') {
            throw 'Parser self-test failed URL secret redaction.'
        }
        if ($Converted -notmatch 'plain=alpha') {
            throw 'Parser self-test failed ordinary query preservation.'
        }
        if ($Converted -notmatch '(?:\?|&)flag(?:&|$)') {
            throw 'Parser self-test failed flag-style query preservation.'
        }

        $StaticRoute = Convert-SensitiveUrl -Url 'https://example.invalid/Patient/Main.aspx' -Artifact 'SELFTEST' -Stats $Stats
        if ($StaticRoute -ne 'https://example.invalid/Patient/Main.aspx') {
            throw 'Parser self-test incorrectly tokenized a static patient route.'
        }

        $GenericRoute = Convert-SensitiveUrl -Url 'https://example.invalid/user/employees' -Artifact 'SELFTEST' -Stats $Stats
        if ($GenericRoute -ne 'https://example.invalid/user/employees') {
            throw 'Parser self-test incorrectly tokenized a generic route word.'
        }

        if (
            (Get-TokenStorageKey -Value 'Jorgortho' -DataClass 'USER') -eq
            (Get-TokenStorageKey -Value 'jorgortho' -DataClass 'USER')
        ) {
            throw 'Parser self-test detected case-collapsing token storage keys.'
        }

        if (
            (Get-TokenStorageKey -Value 'Katherine' -DataClass 'PERSON') -eq
            (Get-TokenStorageKey -Value 'Katherine ' -DataClass 'PERSON')
        ) {
            throw 'Parser self-test detected whitespace-collapsing token storage keys.'
        }

        $TestPath = Convert-SensitivePath -PathValue 'C:\Windows\Temp\setup.exe' -Artifact 'SELFTEST' -Stats $Stats
        if ($TestPath -ne 'C:\Windows\Temp\setup.exe') {
            throw 'Parser self-test failed safe path preservation.'
        }
    }
    finally {
        # Self-tests must never affect production token/rule counters.
        $script:RedactedOccurrences = $RedactedBefore
        $script:TokenizedOccurrences = $TokenizedBefore
        $script:RuleCounters.Clear()
        foreach ($Key in @($RuleSnapshot.Keys)) {
            $script:RuleCounters[$Key] = $RuleSnapshot[$Key]
        }
    }
}

function Invoke-NativeSqliteSelfTest {
    param([Parameter(Mandatory)][string]$TestPath)

    if (Test-Path -LiteralPath $TestPath) {
        Remove-Item -LiteralPath $TestPath -Force
    }

    $Stats = New-ArtifactStats
    $SqliteDatabase = $null
    $RedactedBefore = [int]$script:RedactedOccurrences
    $HadSelfTestRule = $script:RuleCounters.ContainsKey('SELFTEST')
    $SelfTestRuleBefore = if ($HadSelfTestRule) { [int]$script:RuleCounters['SELFTEST'] } else { 0 }

    try {
        $SqliteDatabase = [MME.WinSqliteDb]::new($TestPath)
        $SqliteDatabase.Execute('CREATE TABLE selftest (value TEXT, secret BLOB)')
        $SqliteDatabase.Execute("INSERT INTO selftest(value,secret) VALUES ('alpha',x'0102')")
        $SqliteDatabase.Execute("INSERT INTO selftest(value,secret) VALUES ('',x'')")

        # Reproduce the Chromium Login Data case-distinction requirement: two
        # records that differ only by username case must remain distinct after
        # tokenization or SQLite UNIQUE constraints will fail.
        $SqliteDatabase.Execute('CREATE TABLE unique_case_test (site TEXT NOT NULL, username TEXT NOT NULL, UNIQUE(site,username))')
        $SqliteDatabase.Execute("INSERT INTO unique_case_test(site,username) VALUES ('example','Jorgortho')")
        $SqliteDatabase.Execute("INSERT INTO unique_case_test(site,username) VALUES ('example','jorgortho')")

        # Exercise both valid and intentionally empty optional-column calls.
        Invoke-SqliteTextTransform -SqliteDatabase $SqliteDatabase -Table 'selftest' -Column '' -Stats $Stats -Transform {
            param($v,$row)
            return $v
        }
        Invoke-SqliteRedactColumn -SqliteDatabase $SqliteDatabase -Table 'selftest' -Column '' -Stats $Stats -RuleId 'SELFTEST'

        Invoke-SqliteTextTransform -SqliteDatabase $SqliteDatabase -Table 'selftest' -Column 'value' -Stats $Stats -Transform {
            param($v,$row)
            return $v.ToUpperInvariant()
        }
        Invoke-SqliteRedactColumn -SqliteDatabase $SqliteDatabase -Table 'selftest' -Column 'secret' -Stats $Stats -RuleId 'SELFTEST'

        $CaseToken1 = 'USER_' + ((Get-TokenStorageKey -Value 'Jorgortho' -DataClass 'USER').Substring(5,16))
        $CaseToken2 = 'USER_' + ((Get-TokenStorageKey -Value 'jorgortho' -DataClass 'USER').Substring(5,16))
        if ($CaseToken1 -eq $CaseToken2) {
            throw 'SQLite self-test generated identical case-distinct username tokens.'
        }
        $SqliteDatabase.SetText('unique_case_test','username',1,$CaseToken1)
        $SqliteDatabase.SetText('unique_case_test','username',2,$CaseToken2)

        $Rows = @($SqliteDatabase.Query('SELECT value, length(secret) AS secret_length FROM selftest ORDER BY rowid'))
        if ($Rows.Count -ne 2) {
            throw "SQLite self-test expected 2 rows; found $($Rows.Count)."
        }
        if ([string]($Rows[0]['value']) -ne 'ALPHA') {
            throw 'SQLite self-test text update failed.'
        }
        if ([long]($Rows[0]['secret_length']) -ne 0) {
            throw 'SQLite self-test blob redaction failed.'
        }
        if (($SqliteDatabase.IntegrityCheck()).ToLowerInvariant() -ne 'ok') {
            throw 'SQLite self-test integrity_check failed.'
        }
    }
    finally {
        $script:RedactedOccurrences = $RedactedBefore
        if ($HadSelfTestRule) {
            $script:RuleCounters['SELFTEST'] = $SelfTestRuleBefore
        }
        else {
            $script:RuleCounters.Remove('SELFTEST')
        }

        if ($null -ne $SqliteDatabase) {
            try { $SqliteDatabase.Dispose() } catch { }
        }
        if (Test-Path -LiteralPath $TestPath) {
            try { Remove-Item -LiteralPath $TestPath -Force } catch { }
        }
    }
}

function Test-ChromiumSqlitePreflight {
    param(
        [Parameter(Mandatory)]$ManifestObject
    )

    $Policies = @(
        'CHROMIUM_HISTORY_RTR',
        'CHROMIUM_LOGIN_RTR',
        'CHROMIUM_WEBDATA_RTR',
        'CHROMIUM_COOKIE_RTR'
    )

    $Checked = 0
    foreach ($ArtifactRecord in @($ManifestObject.Artifacts)) {
        $PolicyId = [string]$ArtifactRecord.PolicyId
        if ($PolicyId -notin $Policies) { continue }

        $RelativePath = Normalize-RelativePath ([string]$ArtifactRecord.Path)
        $LocalPath = Get-LocalEvidencePath -RelativePath $RelativePath
        if (-not (Test-Path -LiteralPath $LocalPath -PathType Leaf)) {
            throw "SQLite preflight artifact missing from working copy: $RelativePath"
        }

        $SqliteDatabase = $null
        try {
            $SqliteDatabase = [MME.WinSqliteDb]::new($LocalPath)
            $Integrity = $SqliteDatabase.IntegrityCheck()
            if ([string]$Integrity -ne 'ok') {
                throw "SQLite integrity_check failed before sanitization: $RelativePath Result=$Integrity"
            }

            $Tables = @($SqliteDatabase.Tables())
            switch ($PolicyId) {
                'CHROMIUM_HISTORY_RTR' {
                    if ($Tables -notcontains 'urls') {
                        throw "History database lacks expected 'urls' table: $RelativePath"
                    }
                }
                'CHROMIUM_LOGIN_RTR' {
                    if ($Tables -notcontains 'logins' -and $Tables -notcontains 'stats') {
                        throw "Login Data database lacks expected login tables: $RelativePath"
                    }
                }
                'CHROMIUM_WEBDATA_RTR' {
                    if ($Tables.Count -eq 0) {
                        throw "Web Data database contains no tables: $RelativePath"
                    }
                }
                'CHROMIUM_COOKIE_RTR' {
                    if ($Tables -notcontains 'cookies') {
                        throw "Cookies database lacks expected 'cookies' table: $RelativePath"
                    }
                }
            }

            $Checked++
        }
        finally {
            if ($null -ne $SqliteDatabase) {
                try { $SqliteDatabase.Dispose() } catch { }
            }
        }
    }

    return $Checked
}

# ============================================================
# FILE HANDLERS
# ============================================================


function Get-DetectedTextEncoding {
    param([Parameter(Mandatory)][string]$Path)

    $Default = [System.Text.Encoding]::Default
    $Stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        $Buffer = New-Object byte[] 4
        $Read = $Stream.Read($Buffer,0,$Buffer.Length)
    }
    finally {
        $Stream.Dispose()
    }

    if ($Read -ge 3 -and $Buffer[0] -eq 0xEF -and $Buffer[1] -eq 0xBB -and $Buffer[2] -eq 0xBF) {
        return [System.Text.UTF8Encoding]::new($true)
    }
    if ($Read -ge 2 -and $Buffer[0] -eq 0xFF -and $Buffer[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode
    }
    if ($Read -ge 2 -and $Buffer[0] -eq 0xFE -and $Buffer[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode
    }

    # BOM-less UTF-16 text is common in Windows logs/config. Detect the
    # alternating NUL pattern conservatively rather than decoding as ANSI.
    if ($Read -ge 4) {
        if ($Buffer[1] -eq 0 -and $Buffer[3] -eq 0 -and ($Buffer[0] -ne 0 -or $Buffer[2] -ne 0)) {
            return [System.Text.Encoding]::Unicode
        }
        if ($Buffer[0] -eq 0 -and $Buffer[2] -eq 0 -and ($Buffer[1] -ne 0 -or $Buffer[3] -ne 0)) {
            return [System.Text.Encoding]::BigEndianUnicode
        }
    }

    return $Default
}

function Invoke-TextFileHandler {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$PolicyId,
        [switch]$UserFilePolicy
    )

    $Stats = New-ArtifactStats
    $Temp = $Path + '.rtrtmp'
    if (Test-Path -LiteralPath $Temp) { Remove-Item -LiteralPath $Temp -Force }

    $DetectedEncoding = Get-DetectedTextEncoding -Path $Path
    $Reader = [System.IO.StreamReader]::new($Path,$DetectedEncoding,$true)
    $Writer = $null
    try {
        $null = $Reader.Peek()
        $Encoding = $Reader.CurrentEncoding
        $Writer = [System.IO.StreamWriter]::new($Temp,$false,$Encoding)
        while (-not $Reader.EndOfStream) {
            $Line = $Reader.ReadLine()
            $NewLine = Convert-TextContext -Text $Line -Artifact $Artifact -Stats $Stats
            $Writer.WriteLine($NewLine)
        }
    }
    finally {
        if ($null -ne $Writer) { $Writer.Dispose() }
        if ($null -ne $Reader) { $Reader.Dispose() }
    }

    Move-Item -LiteralPath $Temp -Destination $Path -Force
    Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
}

function Invoke-CsvHandler {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$PolicyId,
        [switch]$UserFilePolicy
    )

    $Stats = New-ArtifactStats
    $Rows = @(Import-Csv -LiteralPath $Path)
    foreach ($Row in $Rows) {
        foreach ($Prop in @($Row.PSObject.Properties)) {
            $Prop.Value = Convert-StructuredValue -Value $Prop.Value -FieldName $Prop.Name -Artifact $Artifact -Stats $Stats -UserFilePolicy:$UserFilePolicy
        }
    }

    $Temp = $Path + '.rtrtmp'
    if ($Rows.Count -eq 0) {
        # Preserve header-only/empty CSV byte-for-byte; no sensitive row exists.
        Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
        return
    }
    $Rows | Export-Csv -LiteralPath $Temp -NoTypeInformation -Encoding UTF8
    Move-Item -LiteralPath $Temp -Destination $Path -Force
    Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
}

function Convert-JsonNode {
    param(
        [AllowNull()]$Node,
        [string]$PropertyName,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][hashtable]$Stats,
        [string]$PropertyPath = ''
    )

    if ($null -eq $Node) { return $null }

    if ($Node -is [string]) {
        $NameForRule = if ([string]::IsNullOrWhiteSpace($PropertyName)) { 'value' } else { $PropertyName }
        $PathLower = $PropertyPath.ToLowerInvariant()
        $NameNorm = ($NameForRule -replace '[^A-Za-z0-9]','').ToLowerInvariant()

        $PasswordMetadataName = $NameNorm -match '^(passwordrequired|passwordlastset|passwordexpires|passwordexpired|passwordage|passwordchanged|passwordneverexpires|usermaychangepassword|mustchangepassword)$'
        if ((-not $PasswordMetadataName -and $NameNorm -match '^(password|passwordvalue|passwd|passcode|pincode|otp|onetimepassword|securityanswer|apikey|accesstoken|refreshtoken|authtoken|encryptedkey|clientsecret|secretkey|secret)$') -or
            $PathLower -match 'os_crypt\.encrypted_key$') {
            Register-Redaction -Stats $Stats -RuleId 'CHROMIUM_JSON_SECRET'
            return '[REDACTED]'
        }

        if ($NameNorm -match '^(email|emailaddress|username|usernamevalue|gaiaid|accountid|profileid)$') {
            if ($NameNorm -match 'email') { return Convert-EmailValue -Value $Node -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_JSON_IDENTITY' }
            if ($NameNorm -match 'username') { return Convert-UserValue -Value $Node -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_JSON_IDENTITY' }
            return Convert-IdentityValue -Value $Node -Class 'ID' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_JSON_IDENTITY'
        }

        if (($NameNorm -match '^(name|fullname|givenname|familyname)$') -and $PathLower -match '(account|profile|identity|person)') {
            return Convert-PersonValue -Value $Node -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_JSON_IDENTITY'
        }

        if ($Node -match '^(?i)https?://') {
            return Convert-SensitiveUrl -Url $Node -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_JSON_CONTEXTUAL_STRING_RTR'
        }
        if ($Node -match '(?i)(?:^[A-Z]:\\|\\Users\\|/Users/)') {
            return Convert-SensitivePath -PathValue $Node -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_JSON_CONTEXTUAL_STRING_RTR'
        }
        return Convert-TextContext -Text $Node -Artifact $Artifact -Stats $Stats
    }

    if ($Node -is [System.Collections.IList]) {
        for ($i = 0; $i -lt $Node.Count; $i++) {
            $Node[$i] = Convert-JsonNode -Node $Node[$i] -PropertyName $PropertyName -Artifact $Artifact -Stats $Stats -PropertyPath $PropertyPath
        }
        return $Node
    }

    if ($Node -is [pscustomobject] -or $Node -is [hashtable]) {
        foreach ($Prop in @($Node.PSObject.Properties)) {
            $NextPath = if ([string]::IsNullOrEmpty($PropertyPath)) { $Prop.Name } else { $PropertyPath + '.' + $Prop.Name }
            $Prop.Value = Convert-JsonNode -Node $Prop.Value -PropertyName $Prop.Name -Artifact $Artifact -Stats $Stats -PropertyPath $NextPath
        }
        return $Node
    }

    return $Node
}

function Invoke-JsonHandler {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$PolicyId
    )

    $Stats = New-ArtifactStats
    $Raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($Raw)) {
        Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
        return
    }

    try {
        $Node = $Raw | ConvertFrom-Json
    }
    catch {
        # Structured policy promised a JSON artifact. Fail closed instead of text-fallback guessing.
        throw "JSON parse failed for '$Artifact': $($_.Exception.Message)"
    }

    $Node = Convert-JsonNode -Node $Node -PropertyName '' -Artifact $Artifact -Stats $Stats
    $Temp = $Path + '.rtrtmp'
    $Node | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Temp -Encoding UTF8
    Move-Item -LiteralPath $Temp -Destination $Path -Force
    Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
}

function Invoke-XmlHandler {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$PolicyId
    )
    $Stats = New-ArtifactStats
    try { [xml]$Xml = Get-Content -LiteralPath $Path -Raw }
    catch { throw "XML parse failed for '$Artifact': $($_.Exception.Message)" }

    function Process-XmlNodeInternal {
        param([System.Xml.XmlNode]$Node)
        if ($Node.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            foreach ($Attr in @($Node.Attributes)) {
                $Attr.Value = [string](Convert-StructuredValue -Value $Attr.Value -FieldName $Attr.Name -Artifact $Artifact -Stats $Stats)
            }
            foreach ($Child in @($Node.ChildNodes)) {
                if ($Child.NodeType -in @([System.Xml.XmlNodeType]::Text,[System.Xml.XmlNodeType]::CDATA)) {
                    $Child.Value = Convert-StructuredValue -Value $Child.Value -FieldName $Node.Name -Artifact $Artifact -Stats $Stats
                }
                elseif ($Child.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                    Process-XmlNodeInternal -Node $Child
                }
            }
        }
    }

    Process-XmlNodeInternal -Node $Xml.DocumentElement
    $Temp = $Path + '.rtrtmp'
    $Xml.Save($Temp)
    Move-Item -LiteralPath $Temp -Destination $Path -Force
    Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
}

function Invoke-StructuredHandler {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$PolicyId,
        [switch]$UserFilePolicy
    )
    $Leaf = [System.IO.Path]::GetFileName($Path).ToLowerInvariant()
    $Ext = [System.IO.Path]::GetExtension($Leaf).ToLowerInvariant()
    if ($Ext -eq '.csv') {
        Invoke-CsvHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId -UserFilePolicy:$UserFilePolicy
    }
    elseif ($Ext -eq '.json' -or $Leaf -in @('preferences','secure preferences','local state','bookmarks')) {
        Invoke-JsonHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId
    }
    elseif ($Ext -eq '.xml') {
        Invoke-XmlHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId
    }
    else {
        Invoke-TextFileHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId -UserFilePolicy:$UserFilePolicy
    }
}

function Invoke-ChromiumHistoryHandler {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$PolicyId
    )

    $Stats = New-ArtifactStats
    $Db = [MME.WinSqliteDb]::new($Path)
    try {
        $Db.Execute('PRAGMA journal_mode=DELETE')
        $Db.Execute('PRAGMA secure_delete=ON')
        $Db.Execute('BEGIN IMMEDIATE')
        try {
            foreach ($Spec in @(
                @{T='urls'; C='url'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'},
                @{T='urls'; C='title'; Kind='TEXT'; Rule='CHROMIUM_HISTORY_TITLE_CONTEXT'},
                @{T='keyword_search_terms'; C='term'; Kind='TEXT'; Rule='CHROMIUM_SEARCH_TERM_CONTEXT'},
                @{T='keyword_search_terms'; C='normalized_term'; Kind='TEXT'; Rule='CHROMIUM_SEARCH_TERM_CONTEXT'},
                @{T='downloads'; C='current_path'; Kind='PATH'; Rule='CHROMIUM_DOWNLOAD_PATH_RTR'},
                @{T='downloads'; C='target_path'; Kind='PATH'; Rule='CHROMIUM_DOWNLOAD_PATH_RTR'},
                @{T='downloads'; C='referrer'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'},
                @{T='downloads'; C='site_url'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'},
                @{T='downloads'; C='tab_url'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'},
                @{T='downloads'; C='tab_referrer_url'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'},
                @{T='downloads_url_chains'; C='url'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'},
                @{T='segments'; C='name'; Kind='TEXT'; Rule='CHROMIUM_HISTORY_TITLE_CONTEXT'},
                @{T='content_annotations'; C='alternative_title'; Kind='TEXT'; Rule='CHROMIUM_HISTORY_TITLE_CONTEXT'},
                @{T='content_annotations'; C='related_searches'; Kind='TEXT'; Rule='CHROMIUM_SEARCH_TERM_CONTEXT'},
                @{T='content_annotations'; C='search_terms'; Kind='TEXT'; Rule='CHROMIUM_SEARCH_TERM_CONTEXT'},
                @{T='content_annotations'; C='search_normalized_url'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'},
                @{T='edge_downloads'; C='protected_download_url'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'},
                @{T='edge_favicons'; C='url'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'},
                @{T='visited_links'; C='frame_url'; Kind='URL'; Rule='CHROMIUM_HISTORY_URL_RTR'}
            )) {
                $Table = [string]$Spec.T
                $Column = [string]$Spec.C
                if ([string]::IsNullOrWhiteSpace($Table) -or [string]::IsNullOrWhiteSpace($Column)) { continue }

                $Kind = [string]$Spec.Kind
                $RuleId = [string]$Spec.Rule

                switch ($Kind) {
                    'URL' {
                        Invoke-SqliteTextTransform -SqliteDatabase $Db -Table $Table -Column $Column -Stats $Stats -Transform {
                            param($v,$row)
                            Convert-SensitiveUrl -Url $v -Artifact $Artifact -Stats $Stats -RuleId $RuleId
                        }
                    }
                    'PATH' {
                        Invoke-SqliteTextTransform -SqliteDatabase $Db -Table $Table -Column $Column -Stats $Stats -Transform {
                            param($v,$row)
                            Convert-SensitivePath -PathValue $v -Artifact $Artifact -Stats $Stats -RuleId $RuleId -UserFilePolicy
                        }
                    }
                    default {
                        Invoke-SqliteTextTransform -SqliteDatabase $Db -Table $Table -Column $Column -Stats $Stats -Transform {
                            param($v,$row)
                            Convert-TextContext -Text $v -Artifact $Artifact -Stats $Stats
                        }
                    }
                }
            }

            $Db.Execute('COMMIT')
        }
        catch {
            try { $Db.Execute('ROLLBACK') } catch { }
            throw
        }

        $Db.Execute('VACUUM')
        if (($Db.IntegrityCheck()).ToLowerInvariant() -ne 'ok') {
            throw 'SQLite integrity_check failed after History sanitization.'
        }
    }
    finally {
        $Db.Dispose()
    }

    Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
}

function Invoke-ChromiumLoginHandler {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$PolicyId
    )

    $Stats = New-ArtifactStats
    $Db = [MME.WinSqliteDb]::new($Path)

    # Chromium Login Data contains structural form-field names such as
    # username_element and password_element. Those are evidence and are NOT
    # usernames/passwords. Only these explicit value-bearing columns are RTR'd.
    $UserColumns = @('usernamevalue','username','sanitizedusername')
    $EmailColumns = @('senderemail')
    $PersonColumns = @('sendername','displayname')
    $UrlColumns = @(
        'originurl','actionurl','signonrealm','federationurl','iconurl',
        'profileimageurl','senderprofileimageurl','url'
    )
    $SecretColumns = @('passwordvalue','passwordencrypted','encryptedpassword','possibleusernamepairs')

    try {
        $Db.Execute('PRAGMA journal_mode=DELETE')
        $Db.Execute('PRAGMA secure_delete=ON')
        $Db.Execute('BEGIN IMMEDIATE')

        try {
            foreach ($TableValue in @($Db.Tables())) {
                $Table = [string]$TableValue
                if ([string]::IsNullOrWhiteSpace($Table)) { continue }

                $Columns = @(Get-DbColumns -SqliteDatabase $Db -Table $Table)
                foreach ($ColumnValue in $Columns) {
                    $Column = [string]$ColumnValue
                    if ([string]::IsNullOrWhiteSpace($Column)) { continue }

                    $n = ($Column -replace '[^A-Za-z0-9]','').ToLowerInvariant()
                    $TableN = ($Table -replace '[^A-Za-z0-9]','').ToLowerInvariant()

                    if (
                        $n -in $SecretColumns -or
                        ($TableN -eq 'passwordnotes' -and $n -eq 'value')
                    ) {
                        Invoke-SqliteRedactColumn -SqliteDatabase $Db -Table $Table -Column $Column -Stats $Stats -RuleId 'CHROMIUM_LOGIN_SECRET_MATERIAL'
                    }
                    elseif ($n -in $EmailColumns) {
                        Invoke-SqliteTextTransform -SqliteDatabase $Db -Table $Table -Column $Column -Stats $Stats -Transform {
                            param($v,$row)
                            Convert-EmailValue -Value $v -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_LOGIN_IDENTITY'
                        }
                    }
                    elseif ($n -in $PersonColumns) {
                        Invoke-SqliteTextTransform -SqliteDatabase $Db -Table $Table -Column $Column -Stats $Stats -Transform {
                            param($v,$row)
                            Convert-PersonValue -Value $v -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_LOGIN_IDENTITY'
                        }
                    }
                    elseif ($n -in $UserColumns) {
                        Invoke-SqliteTextTransform -SqliteDatabase $Db -Table $Table -Column $Column -Stats $Stats -Transform {
                            param($v,$row)
                            Convert-UserValue -Value $v -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_LOGIN_USERNAME'
                        }
                    }
                    elseif ($n -in $UrlColumns) {
                        Invoke-SqliteTextTransform -SqliteDatabase $Db -Table $Table -Column $Column -Stats $Stats -Transform {
                            param($v,$row)
                            # A row-specific redaction marker prevents two distinct
                            # secret-bearing URLs from collapsing into the same UNIQUE
                            # key after their secret values are removed.
                            Convert-SensitiveUrl -Url $v -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_LOGIN_URL_RTR' -RedactionTag ([string]$row['__rowid'])
                        }
                    }
                    elseif ($n -match '^(passwordnickname|nickname)$') {
                        Invoke-SqliteTextTransform -SqliteDatabase $Db -Table $Table -Column $Column -Stats $Stats -Transform {
                            param($v,$row)
                            Convert-TextContext -Text $v -Artifact $Artifact -Stats $Stats
                        }
                    }
                }
            }

            $Db.Execute('COMMIT')
        }
        catch {
            try { $Db.Execute('ROLLBACK') } catch { }
            throw
        }

        $Db.Execute('VACUUM')
        if (($Db.IntegrityCheck()).ToLowerInvariant() -ne 'ok') {
            throw 'SQLite integrity_check failed after Login Data sanitization.'
        }
    }
    finally {
        $Db.Dispose()
    }

    Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
}

function Get-AutofillValueClass {
    param([AllowNull()][AllowEmptyString()][string]$FieldName)
    if ([string]::IsNullOrWhiteSpace($FieldName)) { return 'UNKNOWN' }
    $n = ($FieldName -replace '[^A-Za-z0-9]','').ToLowerInvariant()
    if ($n -match '(password|passwd|passcode|pincode|otp|onetimepassword|securityanswer|authtoken|accesstoken|refreshtoken|secret)') { return 'REDACT' }
    if ($n -match '(cardnumber|ccnumber|creditcard|iban|cvv|cvc|expiration|expiry|expmonth|expyear|lastfour)') { return 'PAYMENT' }
    if ($n -match '(firstname|lastname|fullname|patientname|membername|subscribername|policyholdername|cardholdername|recipientname)') { return 'PERSON' }
    if ($n -match 'email') { return 'EMAIL' }
    if ($n -match '(dob|dateofbirth|birthdate)') { return 'DOB' }
    if ($n -match '(phone|telephone|mobile|cell)') { return 'PHONE' }
    if ($n -match '(streetaddress|mailingaddress|homeaddress|postaladdress|zipcode|postalcode)') { return 'ADDRESS' }
    if ($n -match '(patient|member|subscriber|policyholder|mrn|medicalrecord|chart|claim|account).*(id|number|no|#)?$') { return 'ID' }
    return 'UNKNOWN'
}

function Invoke-ChromiumWebDataHandler {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$PolicyId
    )

    $Stats = New-ArtifactStats
    $SqliteDatabase = [MME.WinSqliteDb]::new($Path)

    try {
        $SqliteDatabase.Execute('PRAGMA journal_mode=DELETE')
        $SqliteDatabase.Execute('PRAGMA secure_delete=ON')
        $SqliteDatabase.Execute('BEGIN IMMEDIATE')

        try {
            # ------------------------------------------------------------
            # Standard Chromium name/value autofill stores.
            # ------------------------------------------------------------
            foreach ($Table in @('autofill','autocomplete','autofill_edge_extended')) {
                if (-not (Test-DbTable -SqliteDatabase $SqliteDatabase -Table $Table)) { continue }

                $Cols = @(Get-DbColumns -SqliteDatabase $SqliteDatabase -Table $Table)
                if ($Cols -notcontains 'name' -or $Cols -notcontains 'value') { continue }

                $ReadCols = New-Object System.Collections.Generic.List[string]
                $ReadCols.Add('name')
                $ReadCols.Add('value')
                if ($Cols -contains 'value_lower') { $ReadCols.Add('value_lower') }

                foreach ($Row in @($SqliteDatabase.Rows($Table,$ReadCols.ToArray()))) {
                    $Name = [string]$Row['name']
                    $Value = [string]$Row['value']
                    if ([string]::IsNullOrEmpty($Value)) { continue }

                    $Class = Get-AutofillValueClass -FieldName $Name
                    $NewValue = $Value

                    switch ($Class) {
                        'REDACT' {
                            $NewValue = '[REDACTED_' + [string]$Row['__rowid'] + ']'
                            Register-Redaction -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_SECRET'
                        }
                        'PAYMENT' {
                            $NewValue = '[REDACTED_' + [string]$Row['__rowid'] + ']'
                            Register-Redaction -Stats $Stats -RuleId 'CHROMIUM_PAYMENT_DATA'
                        }
                        'PERSON' {
                            $NewValue = Convert-PersonValue -Value $Value -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_PERSON'
                        }
                        'EMAIL' {
                            $NewValue = Convert-EmailValue -Value $Value -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                        }
                        'DOB' {
                            $NewValue = Convert-IdentityValue -Value $Value -Class 'DOB' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                        }
                        'PHONE' {
                            $NewValue = Convert-IdentityValue -Value $Value -Class 'PHONE' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                        }
                        'ADDRESS' {
                            $NewValue = Convert-IdentityValue -Value $Value -Class 'ADDRESS' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                        }
                        'ID' {
                            $NewValue = Convert-IdentityValue -Value $Value -Class 'ID' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_SENSITIVE_ID'
                        }
                        default {
                            $NewValue = Convert-TextContext -Text $Value -Artifact $Artifact -Stats $Stats
                        }
                    }

                    if ($NewValue -ne $Value) {
                        $SqliteDatabase.SetText($Table,'value',[long]$Row['__rowid'],$NewValue)
                        if ($Cols -contains 'value_lower') {
                            $SqliteDatabase.SetText($Table,'value_lower',[long]$Row['__rowid'],$NewValue.ToLowerInvariant())
                        }
                    }
                }
            }

            # ------------------------------------------------------------
            # Edge field-value store. The value table itself only has a
            # field_id, so join the client-info table to recover the field
            # label and make the RTR decision context-aware.
            # ------------------------------------------------------------
            if (
                (Test-DbTable -SqliteDatabase $SqliteDatabase -Table 'autofill_edge_field_values') -and
                (Test-DbTable -SqliteDatabase $SqliteDatabase -Table 'autofill_edge_field_client_info')
            ) {
                $ValueCols = @(Get-DbColumns -SqliteDatabase $SqliteDatabase -Table 'autofill_edge_field_values')
                $InfoCols = @(Get-DbColumns -SqliteDatabase $SqliteDatabase -Table 'autofill_edge_field_client_info')

                if (
                    $ValueCols -contains 'field_id' -and
                    $ValueCols -contains 'value' -and
                    $InfoCols -contains 'field_id' -and
                    $InfoCols -contains 'label'
                ) {
                    $MaskedSelect = if ($ValueCols -contains 'is_masked') { 'v."is_masked" AS is_masked' } else { '0 AS is_masked' }
                    $Sql = @"
SELECT
    v.rowid AS __rowid,
    v."value" AS value,
    $MaskedSelect,
    i."label" AS label
FROM "autofill_edge_field_values" v
LEFT JOIN "autofill_edge_field_client_info" i
    ON i."field_id" = v."field_id"
"@

                    foreach ($Row in @($SqliteDatabase.Query($Sql))) {
                        $Value = [string]$Row['value']
                        if ([string]::IsNullOrEmpty($Value)) { continue }

                        $Label = [string]$Row['label']
                        $Class = Get-AutofillValueClass -FieldName $Label
                        $NewValue = $Value
                        $IsMasked = $false
                        try { $IsMasked = ([long]$Row['is_masked'] -ne 0) } catch { }

                        if ($IsMasked -or $Class -eq 'REDACT') {
                            $NewValue = '[REDACTED_' + [string]$Row['__rowid'] + ']'
                            Register-Redaction -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_SECRET'
                        }
                        elseif ($Class -eq 'PAYMENT') {
                            $NewValue = '[REDACTED_' + [string]$Row['__rowid'] + ']'
                            Register-Redaction -Stats $Stats -RuleId 'CHROMIUM_PAYMENT_DATA'
                        }
                        elseif ($Class -eq 'PERSON') {
                            $NewValue = Convert-PersonValue -Value $Value -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_PERSON'
                        }
                        elseif ($Class -eq 'EMAIL') {
                            $NewValue = Convert-EmailValue -Value $Value -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                        }
                        elseif ($Class -eq 'DOB') {
                            $NewValue = Convert-IdentityValue -Value $Value -Class 'DOB' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                        }
                        elseif ($Class -eq 'PHONE') {
                            $NewValue = Convert-IdentityValue -Value $Value -Class 'PHONE' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                        }
                        elseif ($Class -eq 'ADDRESS') {
                            $NewValue = Convert-IdentityValue -Value $Value -Class 'ADDRESS' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                        }
                        elseif ($Class -eq 'ID') {
                            $NewValue = Convert-IdentityValue -Value $Value -Class 'ID' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_SENSITIVE_ID'
                        }
                        else {
                            $NewValue = Convert-TextContext -Text $Value -Artifact $Artifact -Stats $Stats
                        }

                        if ($NewValue -ne $Value) {
                            $SqliteDatabase.SetText(
                                'autofill_edge_field_values',
                                'value',
                                [long]$Row['__rowid'],
                                $NewValue
                            )
                        }
                    }
                }
            }

            # ------------------------------------------------------------
            # Address-profile token tables. The table context tells us the
            # stored values are identity/address material, even when the
            # numeric field type is version-specific.
            # ------------------------------------------------------------
            foreach ($Table in @('address_type_tokens','edge_server_addresses_type_tokens')) {
                Invoke-SqliteTextTransform -SqliteDatabase $SqliteDatabase -Table $Table -Column 'value' -Stats $Stats -Transform {
                    param($v,$row)
                    Convert-IdentityValue -Value $v -Class 'IDENTITY' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                }
            }

            # ------------------------------------------------------------
            # Explicit profile/contact columns across Chromium versions.
            # Missing tables/columns are ignored safely.
            # ------------------------------------------------------------
            $ProfileMap = @{
                'autofill_profile_names' = @{
                    'first_name'='PERSON'; 'middle_name'='PERSON'; 'last_name'='PERSON'; 'full_name'='PERSON'
                    'honorific_prefix'='PERSON'; 'first_last_name'='PERSON'; 'conjunction_last_name'='PERSON'; 'second_last_name'='PERSON'
                }
                'autofill_profile_emails' = @{ 'email'='EMAIL' }
                'autofill_profile_phones' = @{ 'number'='PHONE' }
                'autofill_profiles' = @{
                    'company_name'='IDENTITY'; 'street_address'='ADDRESS'; 'dependent_locality'='ADDRESS'; 'city'='ADDRESS'
                    'state'='ADDRESS'; 'zipcode'='ADDRESS'; 'zip_code'='ADDRESS'; 'sorting_code'='ADDRESS'
                }
                'autofill_profile_addresses' = @{
                    'street_address'='ADDRESS'; 'street_name'='ADDRESS'; 'dependent_street_name'='ADDRESS'; 'house_number'='ADDRESS'
                    'subpremise'='ADDRESS'; 'premise_name'='ADDRESS'; 'dependent_locality'='ADDRESS'; 'city'='ADDRESS'
                    'state'='ADDRESS'; 'zip_code'='ADDRESS'; 'sorting_code'='ADDRESS'
                }
                'server_addresses' = @{
                    'company_name'='IDENTITY'; 'street_address'='ADDRESS'; 'address_1'='ADDRESS'; 'address_2'='ADDRESS'
                    'address_3'='ADDRESS'; 'address_4'='ADDRESS'; 'postal_code'='ADDRESS'; 'sorting_code'='ADDRESS'
                    'recipient_name'='PERSON'; 'phone_number'='PHONE'
                }
            }

            foreach ($Table in $ProfileMap.Keys) {
                if (-not (Test-DbTable -SqliteDatabase $SqliteDatabase -Table $Table)) { continue }

                foreach ($ColumnName in $ProfileMap[$Table].Keys) {
                    $Column = [string]$ColumnName
                    $Class = [string]$ProfileMap[$Table][$ColumnName]

                    Invoke-SqliteTextTransform -SqliteDatabase $SqliteDatabase -Table ([string]$Table) -Column $Column -Stats $Stats -Transform {
                        param($v,$row)
                        switch ($Class) {
                            'PERSON' {
                                Convert-PersonValue -Value $v -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_PERSON'
                            }
                            'EMAIL' {
                                Convert-EmailValue -Value $v -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                            }
                            'PHONE' {
                                Convert-IdentityValue -Value $v -Class 'PHONE' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                            }
                            'ADDRESS' {
                                Convert-IdentityValue -Value $v -Class 'ADDRESS' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                            }
                            default {
                                Convert-IdentityValue -Value $v -Class 'IDENTITY' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                            }
                        }
                    }
                }
            }

            # ------------------------------------------------------------
            # DOB extensions. Text DOBs can be tokenized. Split numeric
            # day/month/year fields cannot safely hold a string token, so
            # those specific values are redacted to zero.
            # ------------------------------------------------------------
            Invoke-SqliteTextTransform -SqliteDatabase $SqliteDatabase -Table 'autofill_profile_edge_extended' -Column 'date_of_birth' -Stats $Stats -Transform {
                param($v,$row)
                Convert-IdentityValue -Value $v -Class 'DOB' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
            }

            foreach ($Column in @('date_of_birth_day','date_of_birth_month','date_of_birth_year')) {
                $Cols = @(Get-DbColumns -SqliteDatabase $SqliteDatabase -Table 'autofill_profile_edge_extended')
                if ($Cols -notcontains $Column) { continue }

                foreach ($Row in @($SqliteDatabase.Rows('autofill_profile_edge_extended',[string[]]@($Column)))) {
                    if ($null -eq $Row[$Column]) { continue }

                    $Numeric = 0L
                    try { $Numeric = [long]$Row[$Column] } catch { continue }
                    if ($Numeric -ne 0) {
                        $SqliteDatabase.SetInt64('autofill_profile_edge_extended',$Column,[long]$Row['__rowid'],0)
                        Register-Redaction -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                    }
                }
            }

            # ------------------------------------------------------------
            # Payment/card/bank material. No source payment value is logged.
            # ------------------------------------------------------------
            foreach ($Spec in @(
                @{T='credit_cards'; Person=@('name_on_card'); Blob=@('card_number_encrypted'); Int=@('expiration_month','expiration_year')},
                @{T='masked_credit_cards'; Person=@('name_on_card'); SecretText=@('last_four'); Int=@('exp_month','exp_year')},
                @{T='unmasked_credit_cards'; Blob=@('card_number_encrypted')},
                @{T='server_credit_cards'; Blob=@('card_number_encrypted')},
                @{T='token_service'; Blob=@('encrypted_token','binding_key')},
                @{T='payments_customer_data'; SecretText=@('customer_id')},
                @{T='payments_upi_vpa'; SecretText=@('vpa')},
                @{T='server_card_cloud_token_data'; SecretText=@('suffix','instrument_token'); Int=@('exp_month','exp_year')},
                @{T='local_ibans'; Blob=@('value_encrypted')},
                @{T='local_stored_cvc'; Blob=@('value_encrypted')},
                @{T='server_stored_cvc'; Blob=@('value_encrypted')},
                @{T='generic_payment_instruments'; Blob=@('serialized_value_encrypted')},
                @{T='payment_instrument_creation_options'; Blob=@('serialized_value_encrypted')},
                @{T='masked_ibans'; SecretText=@('prefix','suffix')},
                @{T='masked_bank_accounts'; SecretText=@('account_number_suffix')},
                @{T='virtual_card_usage_data'; SecretText=@('last_four')},
                @{T='edge_tokenized_credit_cards'; SecretText=@('last_four','token_id'); Int=@('exp_month','exp_year')}
            )) {
                $Table = [string]$Spec.T
                if ([string]::IsNullOrWhiteSpace($Table)) { continue }
                if (-not (Test-DbTable -SqliteDatabase $SqliteDatabase -Table $Table)) { continue }

                foreach ($ColumnValue in @($Spec.Person | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
                    $Column = [string]$ColumnValue
                    Invoke-SqliteTextTransform -SqliteDatabase $SqliteDatabase -Table $Table -Column $Column -Stats $Stats -Transform {
                        param($v,$row)
                        Convert-PersonValue -Value $v -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_CARDHOLDER_NAME'
                    }
                }

                foreach ($ColumnValue in @($Spec.SecretText | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
                    $Column = [string]$ColumnValue
                    Invoke-SqliteRedactColumn -SqliteDatabase $SqliteDatabase -Table $Table -Column $Column -Stats $Stats -RuleId 'CHROMIUM_PAYMENT_DATA' -UniquePlaceholder
                }

                foreach ($ColumnValue in @($Spec.Blob | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
                    $Column = [string]$ColumnValue
                    Invoke-SqliteRedactColumn -SqliteDatabase $SqliteDatabase -Table $Table -Column $Column -Stats $Stats -RuleId 'CHROMIUM_PAYMENT_DATA'
                }

                foreach ($ColumnValue in @($Spec.Int | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
                    $Column = [string]$ColumnValue
                    $Cols = @(Get-DbColumns -SqliteDatabase $SqliteDatabase -Table $Table)
                    if ($Cols -notcontains $Column) { continue }

                    foreach ($Row in @($SqliteDatabase.Rows($Table,[string[]]@($Column)))) {
                        if ($null -eq $Row[$Column]) { continue }

                        $Numeric = 0L
                        try { $Numeric = [long]$Row[$Column] } catch { continue }
                        if ($Numeric -ne 0) {
                            $SqliteDatabase.SetInt64($Table,$Column,[long]$Row['__rowid'],0)
                            Register-Redaction -Stats $Stats -RuleId 'CHROMIUM_PAYMENT_DATA'
                        }
                    }
                }
            }

            # Loyalty-card numbers are identity-linked account identifiers.
            Invoke-SqliteTextTransform -SqliteDatabase $SqliteDatabase -Table 'loyalty_cards' -Column 'loyalty_card_number' -Stats $Stats -Transform {
                param($v,$row)
                Convert-IdentityValue -Value $v -Class 'ID' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_SENSITIVE_ID'
            }

            # Plus-address values are email aliases when syntactically valid.
            Invoke-SqliteTextTransform -SqliteDatabase $SqliteDatabase -Table 'plus_addresses' -Column 'plus_address' -Stats $Stats -Transform {
                param($v,$row)
                if ($script:EmailRegex.IsMatch($v) -and $script:EmailRegex.Match($v).Value -eq $v) {
                    Convert-EmailValue -Value $v -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                }
                else {
                    Convert-IdentityValue -Value $v -Class 'IDENTITY' -Artifact $Artifact -Stats $Stats -RuleId 'CHROMIUM_AUTOFILL_IDENTITY'
                }
            }

            # Search-engine/template URLs can carry account/search context.
            foreach ($Column in @('url','suggest_url','originating_url','favicon_url','image_url')) {
                Invoke-SqliteTextTransform -SqliteDatabase $SqliteDatabase -Table 'keywords' -Column $Column -Stats $Stats -Transform {
                    param($v,$row)
                    Convert-SensitiveUrl -Url $v -Artifact $Artifact -Stats $Stats -RuleId 'URL_CONTEXT_RTR'
                }
            }

            $SqliteDatabase.Execute('COMMIT')
        }
        catch {
            try { $SqliteDatabase.Execute('ROLLBACK') } catch { }
            throw
        }

        $SqliteDatabase.Execute('VACUUM')
        if (($SqliteDatabase.IntegrityCheck()).ToLowerInvariant() -ne 'ok') {
            throw 'SQLite integrity_check failed after Web Data sanitization.'
        }
    }
    finally {
        $SqliteDatabase.Dispose()
    }

    Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
}

function Invoke-ChromiumCookieHandler {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Artifact,[Parameter(Mandatory)][string]$PolicyId)
    $Stats = New-ArtifactStats
    $Db = [MME.WinSqliteDb]::new($Path)
    try {
        $Db.Execute('PRAGMA journal_mode=DELETE')
        $Db.Execute('PRAGMA secure_delete=ON')
        $Db.Execute('BEGIN IMMEDIATE')
        try {
            Invoke-SqliteRedactColumn -SqliteDatabase $Db -Table 'cookies' -Column 'value' -Stats $Stats -RuleId 'CHROMIUM_COOKIE_VALUE'
            Invoke-SqliteRedactColumn -SqliteDatabase $Db -Table 'cookies' -Column 'encrypted_value' -Stats $Stats -RuleId 'CHROMIUM_COOKIE_VALUE'
            $Db.Execute('COMMIT')
        }
        catch {
            try { $Db.Execute('ROLLBACK') } catch { }
            throw
        }
        $Db.Execute('VACUUM')
        if (($Db.IntegrityCheck()).ToLowerInvariant() -ne 'ok') { throw 'SQLite integrity_check failed after Cookie sanitization.' }
    }
    finally { $Db.Dispose() }
    Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
}

function Invoke-EvtxHandler {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Artifact,[Parameter(Mandatory)][string]$PolicyId)
    $Stats = New-ArtifactStats
    $OutputPath = $Path + '.sanitized.xml'
    $Settings = New-Object System.Xml.XmlWriterSettings
    $Settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $Settings.Indent = $false
    $Writer = [System.Xml.XmlWriter]::Create($OutputPath,$Settings)
    try {
        $Writer.WriteStartDocument()
        $Writer.WriteStartElement('Events')
        Get-WinEvent -Path $Path -Oldest -ErrorAction Stop | ForEach-Object {
            $Event = $_
            [xml]$EventXml = $Event.ToXml()

            $EventDataNodes = @($EventXml.SelectNodes('//*[local-name()="EventData"]/*[local-name()="Data"]'))
            foreach ($Node in $EventDataNodes) {
                $Name = if ($Node.Attributes['Name']) { [string]$Node.Attributes['Name'].Value } else { 'Data' }
                $Node.InnerText = [string](Convert-StructuredValue -Value $Node.InnerText -FieldName $Name -Artifact $Artifact -Stats $Stats)
            }

            $UserDataTextNodes = @($EventXml.SelectNodes('//*[local-name()="UserData"]//*[text()]'))
            foreach ($Node in $UserDataTextNodes) {
                if ($Node.ChildNodes.Count -eq 1 -and $Node.FirstChild.NodeType -eq [System.Xml.XmlNodeType]::Text) {
                    $Node.InnerText = [string](Convert-StructuredValue -Value $Node.InnerText -FieldName $Node.LocalName -Artifact $Artifact -Stats $Stats)
                }
            }

            # System/UserID is a SID and remains untouched by design.
            $EventXml.DocumentElement.WriteTo($Writer)
        }
        $Writer.WriteEndElement()
        $Writer.WriteEndDocument()
    }
    finally {
        if ($null -ne $Writer) { $Writer.Dispose() }
    }

    Remove-Item -LiteralPath $Path -Force
    $script:EvtxConverted++
    Write-RtrLog ('EVTX_EXPORT | Source="{0}" | Sanitized="{1}" | Tokenized={2} Redacted={3}' -f `
        (ConvertTo-AuditValue $Artifact),(ConvertTo-AuditValue ([System.IO.Path]::GetFileName($OutputPath))),$Stats.Tokenized,$Stats.Redacted)
    Write-ArtifactStats -Artifact $Artifact -PolicyId $PolicyId -Stats $Stats
}

# ============================================================
# ARCHIVE / PATH HELPERS
# ============================================================

function Seed-StructuralUsersFromManifest {
    param([Parameter(Mandatory)]$ManifestObject)
    foreach ($Artifact in @($ManifestObject.Artifacts)) {
        $Path = Normalize-RelativePath ([string]$Artifact.Path)
        foreach ($Pattern in @(
            '(?i)\\Collected_Files\\(?<user>[^\\]+)\\',
            '(?i)\\User_Hives\\(?<user>[^\\]+)\\',
            '(?i)\\(?:AutomaticDestinations|CustomDestinations)\\(?<user>[^\\]+)\\'
        )) {
            $m = [regex]::Match($Path,$Pattern)
            if ($m.Success) {
                $User = $m.Groups['user'].Value
                if (-not (Test-IsBuiltInUser $User) -and $User -notmatch '^(Root|Default|Profile\s+\d+)$') {
                    $dummy = New-ArtifactStats
                    $null = Get-RtrToken -Value $User -DataClass 'USER' -Artifact $Path -RuleId 'STRUCTURAL_PROFILE_USER'
                }
            }
        }
    }
}

function Convert-ArchiveRelativePath {
    param([Parameter(Mandatory)][string]$RelativePath)

    $Segments = @((($RelativePath -replace '/','\')) -split '\\')
    for ($i = 0; $i -lt $Segments.Count; $i++) {
        $Segment = [string]$Segments[$i]
        $Key = Get-LiteralLookupKey $Segment
        if ($script:UserLiteralTokens.ContainsKey($Key)) {
            $Segments[$i] = [string]$script:UserLiteralTokens[$Key]
        }
    }

    if ($Segments.Count -gt 0) {
        $LeafIndex = $Segments.Count - 1
        $Leaf = [string]$Segments[$LeafIndex]

        foreach ($Key in @($script:UserLiterals.Keys)) {
            $Original = [string]$script:UserLiterals[$Key]
            if (
                $Original.Length -ge 3 -and
                $Leaf.IndexOf($Original,[System.StringComparison]::OrdinalIgnoreCase) -ge 0
            ) {
                $Token = [string]$script:UserLiteralTokens[$Key]
                $Leaf = [regex]::Replace(
                    $Leaf,
                    [regex]::Escape($Original),
                    [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $Token },
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                )
            }
        }

        $Segments[$LeafIndex] = $Leaf
    }

    return ($Segments -join '/')
}

function Expand-EvidenceZipSafely {
    param([Parameter(Mandatory)][string]$ZipPath,[Parameter(Mandatory)][string]$Destination,[Parameter(Mandatory)]$ManifestObject)

    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    Initialize-Directory $Destination

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $Expected = @{}
    foreach ($a in @($ManifestObject.Artifacts)) {
        $p = Normalize-RelativePath ([string]$a.Path)
        if ($Expected.ContainsKey($p)) { throw "Duplicate artifact path in manifest: $p" }
        $Expected[$p] = $a
    }

    $Seen = @{}
    $Zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($Entry in $Zip.Entries) {
            if ([string]::IsNullOrEmpty($Entry.Name)) { continue }
            $Rel = Normalize-RelativePath $Entry.FullName
            if ($Rel -match '(^|\\)\.\.(\\|$)' -or [System.IO.Path]::IsPathRooted($Rel)) {
                throw "Unsafe ZIP path rejected: $Rel"
            }
            if (-not $Expected.ContainsKey($Rel)) { throw "ZIP contains file not present in RTR manifest: $Rel" }
            if ([long]$Expected[$Rel].Length -ne [long]$Entry.Length) { throw "ZIP artifact length differs from manifest: $Rel" }
            $Seen[$Rel] = $true

            $DestPath = Join-Path $Destination $Rel
            $Parent = Split-Path -Parent $DestPath
            Initialize-Directory $Parent
            $In = $Entry.Open()
            $Out = [System.IO.FileStream]::new($DestPath,[System.IO.FileMode]::Create,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
            try { $In.CopyTo($Out) } finally { $Out.Dispose(); $In.Dispose() }
        }
    }
    finally { $Zip.Dispose() }

    if ($Seen.Count -ne $Expected.Count) {
        $Missing = @($Expected.Keys | Where-Object { -not $Seen.ContainsKey($_) })
        throw "RTR manifest/ZIP mismatch. Missing artifacts: $($Missing.Count)"
    }
}

function New-SanitizedZip {
    param([Parameter(Mandatory)][string]$SourceDirectory,[Parameter(Mandatory)][string]$OutputZip)
    if (Test-Path -LiteralPath $OutputZip) { Remove-Item -LiteralPath $OutputZip -Force }
    $Archive = [System.IO.Compression.ZipFile]::Open($OutputZip,[System.IO.Compression.ZipArchiveMode]::Create)
    $Names = @{}
    try {
        $RootFull = (Get-Item -LiteralPath $SourceDirectory).FullName.TrimEnd([char]'\')
        foreach ($File in @(Get-ChildItem -LiteralPath $SourceDirectory -Recurse -File)) {
            $Rel = $File.FullName.Substring($RootFull.Length).TrimStart([char]'\')
            $EntryName = Convert-ArchiveRelativePath -RelativePath $Rel
            if ($Names.ContainsKey($EntryName)) { throw "Sanitized archive path collision: $EntryName" }
            $Names[$EntryName] = $true

            $Entry = $Archive.CreateEntry($EntryName,[System.IO.Compression.CompressionLevel]::Optimal)
            $EntryStream = $Entry.Open()
            $FileStream = [System.IO.FileStream]::new($File.FullName,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::Read)
            try { $FileStream.CopyTo($EntryStream) } finally { $FileStream.Dispose(); $EntryStream.Dispose() }
        }
    }
    finally { $Archive.Dispose() }
}

# ============================================================
# MANIFEST VALIDATION / DISPATCH
# ============================================================

function Resolve-ManifestPath {
    param([string]$Requested)
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        if (-not (Test-Path -LiteralPath $Requested -PathType Leaf)) { throw "Manifest not found: $Requested" }
        return (Get-Item -LiteralPath $Requested).FullName
    }

    $Candidates = @(Get-ChildItem -LiteralPath $Workspace -Filter '*_RTR_MANIFEST.json' -File)
    if ($Candidates.Count -eq 0) { throw "No *_RTR_MANIFEST.json found in $Workspace" }
    if ($Candidates.Count -gt 1) { throw "Multiple RTR manifests found in $Workspace. Supply -ManifestPath explicitly." }
    return $Candidates[0].FullName
}

function Test-ManifestContract {
    param([Parameter(Mandatory)]$ManifestObject)
    if ([string]$ManifestObject.SchemaVersion -ne $SupportedManifestSchema) {
        throw "Unsupported RTR manifest schema '$($ManifestObject.SchemaVersion)'; expected '$SupportedManifestSchema'."
    }
    if ([string]$ManifestObject.PolicyVersion -ne $SupportedPolicyVersion) {
        throw "Unsupported RTR policy version '$($ManifestObject.PolicyVersion)'; expected '$SupportedPolicyVersion'."
    }
    if (-not [bool]$ManifestObject.ExecutionRules.OriginalEvidenceImmutable) { throw 'Manifest does not require immutable original evidence.' }
    if (-not [bool]$ManifestObject.ExecutionRules.WindowsNativeOnly) { throw 'Manifest is not marked WindowsNativeOnly.' }
    if ([bool]$ManifestObject.ExecutionRules.ExternalDependenciesAllowed) { throw 'Manifest permits external dependencies; this sanitizer does not.' }
    if ([string]$ManifestObject.ExecutionRules.SQLiteProvider -ne 'winsqlite3.dll') { throw 'Manifest SQLite provider is not winsqlite3.dll.' }
    if ([int]$ManifestObject.Summary.ReviewRequired -ne 0 -or @($ManifestObject.ReviewItems).Count -ne 0) {
        throw 'Manifest contains REVIEW_REQUIRED items. Sanitization fails closed until Script A resolves them.'
    }

    $Approved = @($ManifestObject.ApprovedActions)
    foreach ($Required in @('PRESERVE','TOKENIZE','REDACT','REMOVE','REVIEW_REQUIRED')) {
        if ($Approved -notcontains $Required) { throw "Manifest approved-action set is missing $Required." }
    }

    foreach ($Artifact in @($ManifestObject.Artifacts)) {
        $PolicyId = [string]$Artifact.PolicyId
        if ($null -eq $ManifestObject.Policies.$PolicyId) { throw "Artifact references missing policy '$PolicyId'." }
        foreach ($Rule in @($ManifestObject.Policies.$PolicyId.Rules)) {
            if ($Approved -notcontains [string]$Rule.Action) { throw "Policy '$PolicyId' contains unapproved action '$($Rule.Action)'." }
            if ([string]$Rule.Action -eq 'REVIEW_REQUIRED') { throw "Policy '$PolicyId' requires review. Sanitization fails closed." }
        }
    }
}

function Invoke-ArtifactPolicy {
    param([Parameter(Mandatory)]$ArtifactRecord)
    $Artifact = Normalize-RelativePath ([string]$ArtifactRecord.Path)
    $PolicyId = [string]$ArtifactRecord.PolicyId
    $Path = Get-LocalEvidencePath -RelativePath $Artifact

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Working artifact missing: $Artifact" }

    switch ($PolicyId) {
        'PRESERVE_SECURITY_ARTIFACT' { return }

        'REMOVE_RAW_PREFETCH' { Remove-Item -LiteralPath $Path -Force; $script:RemovedArtifacts++; Add-RuleCount 'RAW_PREFETCH_BINARY'; return }
        'REMOVE_RAW_JUMPLIST' { Remove-Item -LiteralPath $Path -Force; $script:RemovedArtifacts++; Add-RuleCount 'RAW_JUMPLIST_BINARY'; return }
        'REMOVE_RAW_SRUM' { Remove-Item -LiteralPath $Path -Force; $script:RemovedArtifacts++; Add-RuleCount 'RAW_SRUM_DATABASE'; return }
        'REMOVE_RAW_USER_HIVE' { Remove-Item -LiteralPath $Path -Force; $script:RemovedArtifacts++; Add-RuleCount 'RAW_USER_REGISTRY_HIVE'; return }
        'REMOVE_RAW_AMCACHE' { Remove-Item -LiteralPath $Path -Force; $script:RemovedArtifacts++; Add-RuleCount 'RAW_AMCACHE_HIVE'; return }
        'REMOVE_CHROMIUM_SESSION' { Remove-Item -LiteralPath $Path -Force; $script:RemovedArtifacts++; Add-RuleCount 'RAW_CHROMIUM_SESSION_BINARY'; return }

        'GENERIC_TEXT_RTR' { Invoke-TextFileHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId; return }
        'GENERIC_STRUCTURED_RTR' { Invoke-StructuredHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId; return }
        'USER_FILE_METADATA_RTR' { Invoke-StructuredHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId -UserFilePolicy; return }
        'CHROMIUM_JSON_RTR' { Invoke-JsonHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId; return }
        'CHROMIUM_HISTORY_RTR' { Invoke-ChromiumHistoryHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId; return }
        'CHROMIUM_LOGIN_RTR' { Invoke-ChromiumLoginHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId; return }
        'CHROMIUM_WEBDATA_RTR' { Invoke-ChromiumWebDataHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId; return }
        'CHROMIUM_COOKIE_RTR' { Invoke-ChromiumCookieHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId; return }
        'EVTX_RTR' { Invoke-EvtxHandler -Path $Path -Artifact $Artifact -PolicyId $PolicyId; return }
        default { throw "Unsupported manifest policy encountered: $PolicyId" }
    }
}

function Test-IsSeedArtifact {
    param([Parameter(Mandatory)]$ArtifactRecord)
    $Policy = [string]$ArtifactRecord.PolicyId
    $Path = Normalize-RelativePath ([string]$ArtifactRecord.Path)
    if ($Policy -in @('CHROMIUM_WEBDATA_RTR','CHROMIUM_LOGIN_RTR','CHROMIUM_JSON_RTR')) { return $true }
    if ($Path -match '(?i)\\Local_Users\\|\\Local_Admins\\') { return $true }
    return $false
}

# ============================================================
# MAIN
# ============================================================

try {
    Initialize-Directory $Workspace
    Initialize-Directory $LogDirectory

    Write-OperationalLog "START MME IR Evidence Sanitizer Build=$Build"

    $CurrentStage = 'PlatformValidation'
    if ($env:OS -ne 'Windows_NT') { throw 'MME IR Evidence Sanitizer is Windows-only.' }
    if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'Windows PowerShell 5.1 or later is required.' }
    $WinSqlitePath = Join-Path $env:SystemRoot 'System32\winsqlite3.dll'
    if (-not (Test-Path -LiteralPath $WinSqlitePath -PathType Leaf)) { throw "Windows-native winsqlite3.dll was not found at $WinSqlitePath" }

    $CurrentStage = 'ResolveManifest'
    $ManifestPath = Resolve-ManifestPath -Requested $ManifestPath
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    Test-ManifestContract -ManifestObject $Manifest

    $CurrentStage = 'ResolveSource'
    $ManifestDirectory = Split-Path -Parent $ManifestPath
    $SourceZip = Join-Path $ManifestDirectory ([string]$Manifest.Source.FileName)
    if (-not (Test-Path -LiteralPath $SourceZip -PathType Leaf)) { throw "Source ZIP named by manifest was not found: $SourceZip" }

    $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($SourceZip)
    $RtrLog = Join-Path $Workspace ($BaseName + '_RTR_FINAL.log')
    $WorkRoot = Join-Path $Workspace ($BaseName + '_SANITIZER_WORK')
    $EvidenceRoot = Join-Path $WorkRoot 'Evidence'
    $SanitizedZip = Join-Path $Workspace ($BaseName + '_SANITIZED.zip')

    if (Test-Path -LiteralPath $RtrLog) { Remove-Item -LiteralPath $RtrLog -Force }
    Write-RtrLog 'MME DEVICE IR SANITIZATION / FINAL RTR LOG'
    Write-RtrLog "Build=$Build | ManifestSchema=$($Manifest.SchemaVersion) | Policy=$($Manifest.PolicyVersion)"
    Write-RtrLog ('Source="{0}"' -f (ConvertTo-AuditValue $SourceZip))
    Write-RtrLog 'NOTE | Token mappings may contain sensitive identity data by design. Secret values are never logged.'
    Write-RtrLog ('-' * 76)

    $CurrentStage = 'ValidateSourceHash'
    $SourceHashBefore = Get-FileSha256 -Path $SourceZip
    $ExpectedHash = ([string]$Manifest.Source.SHA256).ToUpperInvariant()
    if ($SourceHashBefore -ne $ExpectedHash) {
        throw "Source SHA256 does not match RTR manifest. Expected=$ExpectedHash Actual=$SourceHashBefore"
    }
    if ((Get-Item -LiteralPath $SourceZip).Length -ne [long]$Manifest.Source.Length) {
        throw 'Source ZIP length does not match RTR manifest.'
    }
    Write-OperationalLog "SOURCE File=$([System.IO.Path]::GetFileName($SourceZip)) Size=$((Get-Item $SourceZip).Length) SHA256=$SourceHashBefore"

    $CurrentStage = 'ParserCompatibilitySelfTest'
    Invoke-ParserCompatibilitySelfTest
    Write-OperationalLog 'PARSER_SELFTEST PASS'

    $CurrentStage = 'InitializeNativeSQLite'
    Initialize-WinSqlite

    $CurrentStage = 'NativeSQLiteSelfTest'
    $SqliteSelfTestPath = Join-Path $Workspace ("MME_RTR_SQLITE_SELFTEST_{0}.db" -f $PID)
    Invoke-NativeSqliteSelfTest -TestPath $SqliteSelfTestPath
    Write-OperationalLog 'SQLITE_SELFTEST PASS'

    $CurrentStage = 'SeedStructuralIdentity'
    Seed-StructuralUsersFromManifest -ManifestObject $Manifest

    $CurrentStage = 'ExtractEvidenceCopy'
    if (Test-Path -LiteralPath $WorkRoot) { Remove-Item -LiteralPath $WorkRoot -Recurse -Force }
    Initialize-Directory $WorkRoot
    Expand-EvidenceZipSafely -ZipPath $SourceZip -Destination $EvidenceRoot -ManifestObject $Manifest
    Write-OperationalLog "EXTRACT_COMPLETE Artifacts=$($Manifest.Summary.Artifacts)"

    $CurrentStage = 'ChromiumSQLitePreflight'
    $SqlitePreflightCount = Test-ChromiumSqlitePreflight -ManifestObject $Manifest
    Write-OperationalLog "SQLITE_PREFLIGHT PASS Databases=$SqlitePreflightCount"

    $Processed = @{}

    $CurrentStage = 'SeedIdentityArtifacts'
    foreach ($Artifact in @($Manifest.Artifacts)) {
        if (Test-IsSeedArtifact -ArtifactRecord $Artifact) {
            $Rel = Normalize-RelativePath ([string]$Artifact.Path)
            Invoke-ArtifactPolicy -ArtifactRecord $Artifact
            $Processed[$Rel] = $true
        }
    }
    Build-KnownIdentityRegex
    Write-OperationalLog "IDENTITY_SEED_COMPLETE Tokens=$($script:TokenMap.Count)"

    $CurrentStage = 'SanitizeArtifacts'
    foreach ($Artifact in @($Manifest.Artifacts)) {
        $Rel = Normalize-RelativePath ([string]$Artifact.Path)
        if ($Processed.ContainsKey($Rel)) { continue }
        Invoke-ArtifactPolicy -ArtifactRecord $Artifact
        $Processed[$Rel] = $true
    }

    $CurrentStage = 'WriteRemovalSummary'
    foreach ($PolicyId in @('REMOVE_RAW_PREFETCH','REMOVE_RAW_JUMPLIST','REMOVE_RAW_SRUM','REMOVE_RAW_USER_HIVE','REMOVE_RAW_AMCACHE','REMOVE_CHROMIUM_SESSION')) {
        $Count = @($Manifest.Artifacts | Where-Object { [string]$_.PolicyId -eq $PolicyId }).Count
        if ($Count -gt 0) {
            Write-RtrLog "REMOVE_SUMMARY | Policy=$PolicyId | Artifacts=$Count"
        }
    }

    $CurrentStage = 'BuildSanitizedZip'
    New-SanitizedZip -SourceDirectory $EvidenceRoot -OutputZip $SanitizedZip
    $SanitizedHash = Get-FileSha256 -Path $SanitizedZip

    $CurrentStage = 'VerifyOriginalIntegrity'
    $SourceHashAfter = Get-FileSha256 -Path $SourceZip
    if ($SourceHashAfter -ne $SourceHashBefore) {
        if (Test-Path -LiteralPath $SanitizedZip) { Remove-Item -LiteralPath $SanitizedZip -Force }
        throw "Original evidence SHA256 changed during sanitization. Before=$SourceHashBefore After=$SourceHashAfter"
    }

    $CurrentStage = 'FinalizeAudit'
    Write-RtrLog ('-' * 76)
    foreach ($RuleId in @($script:RuleCounters.Keys | Sort-Object)) {
        Write-RtrLog "RULE_SUMMARY | Rule=$RuleId | Count=$($script:RuleCounters[$RuleId])"
    }
    Write-RtrLog ('-' * 76)
    Write-RtrLog "SUMMARY | TokenMappings=$($script:TokenMap.Count) TokenizedOccurrences=$($script:TokenizedOccurrences) RedactedOccurrences=$($script:RedactedOccurrences) RemovedArtifacts=$($script:RemovedArtifacts) EvtxConverted=$($script:EvtxConverted)"
    Write-RtrLog "OUTPUT | ZIP=$SanitizedZip | SHA256=$SanitizedHash"
    Write-RtrLog "SOURCE_INTEGRITY | PASS | SHA256=$SourceHashAfter"

    Write-OperationalLog "SOURCE_INTEGRITY PASS SHA256=$SourceHashAfter"
    Write-OperationalLog "RESULT SANITIZATION_COMPLETE Source=$([System.IO.Path]::GetFileName($SourceZip)) Output=$SanitizedZip Tokenized=$($script:TokenizedOccurrences) Redacted=$($script:RedactedOccurrences) Removed=$($script:RemovedArtifacts) ReviewRequired=0"

    $FinalOutput = "RESULT | SANITIZATION_COMPLETE | Source=$([System.IO.Path]::GetFileName($SourceZip)) Output=$SanitizedZip Tokenized=$($script:TokenizedOccurrences) Redacted=$($script:RedactedOccurrences) Removed=$($script:RemovedArtifacts) ReviewRequired=0"
}
catch {
    $SafeError = ConvertTo-SafeOutput $_.Exception.Message
    Write-OperationalLog "ERROR Stage=$CurrentStage Error=$SafeError"
    if (-not [string]::IsNullOrWhiteSpace($RtrLog)) {
        try { Write-RtrLog "ERROR | Stage=$CurrentStage | Error=$SafeError" } catch { }
    }
    if (-not [string]::IsNullOrWhiteSpace($SanitizedZip) -and (Test-Path -LiteralPath $SanitizedZip)) {
        try { Remove-Item -LiteralPath $SanitizedZip -Force } catch { }
    }
    $FinalOutput = "ERROR | Stage=$CurrentStage | Error=$SafeError"
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($WorkRoot) -and (Test-Path -LiteralPath $WorkRoot)) {
        try {
            Remove-Item -LiteralPath $WorkRoot -Recurse -Force
            Write-OperationalLog "CLEANUP Removed working directory Path=$WorkRoot"
        }
        catch {
            Write-OperationalLog "WARN CleanupFailed Path=$WorkRoot Error=$(ConvertTo-SafeOutput $_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($FinalOutput)) {
        $FinalOutput = 'ERROR | Stage=Finalize | Error=No final output was produced'
        Write-OperationalLog 'ERROR Stage=Finalize Error=No final output was produced'
    }

    Write-Output $FinalOutput
    exit 0
}