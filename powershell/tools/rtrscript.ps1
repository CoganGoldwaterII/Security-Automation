# ============================================================================
# NAME: MME IR Evidence RTR Audit
# AUTHORED BY: Cogan Goldwater
# TYPE: Manual IR Utility / Read-Only RTR Policy Audit
# SCOPE: Analyst workstation / Windows / Device IR evidence ZIP
# VARIABLES:
#   Optional parameter: -EvidenceZip <full path to source Device IR ZIP>
#   Default input/workspace: C:\MME\CS
# OUTPUT TOKENS:
#   RESULT | RTR_AUDIT_COMPLETE | Source=<zip> Artifacts=<#> ReviewRequired=<#> Manifest=<path> Audit=<path>
#   NO_ACTION | No eligible Device IR ZIP found in C:\MME\CS
#   ERROR | Stage=<stage> Error=<sanitized error>
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# LOGGING PATH:
#   C:\MME\AutoLogs\MME_IR_Evidence_RTR_Audit.log
# DESCRIPTION:
#   Manual post-collection RTR policy audit for Device IR evidence. The source
#   ZIP is never modified, overwritten, or deleted. The script fingerprints the
#   source before and after the audit, inventories every artifact, identifies
#   artifact context, validates known binary signatures where practical, and
#   assigns a deterministic RTR policy for Script B.
#
#   Script A deliberately does NOT scan every log line, event record, SQLite row,
#   or structured value. That work belongs to Script B, which executes only the
#   approved rules contained in this manifest and writes the detailed final RTR
#   log of values actually tokenized/redacted/removed. This keeps the audit fast
#   while preserving the two-script separation of duties.
#
#   Approved RTR actions remain exclusively:
#       PRESERVE / TOKENIZE / REDACT / REMOVE / REVIEW_REQUIRED
#   No secondary rewrite/omit/deferred classification layer is used.
#
#   Browser SQLite artifacts are validated by their SQLite file signature only.
#   Script B must use Windows-native winsqlite3.dll for record access. No external
#   SQLite executable, module, package, download, or Tools folder is permitted.
#
#   Known opaque raw artifacts with safer corroborating evidence are assigned a
#   deterministic REMOVE policy, including raw Prefetch, Jump Lists, SRUM, raw
#   user/Amcache hives, recent-file shortcuts, and Chromium session/tab
#   state. Unknown binary artifacts are REVIEW_REQUIRED. REVIEW_REQUIRED is therefore reserved for a genuine
#   unresolved artifact decision, not a parser backlog.
#
#   Outputs are written to C:\MME\CS. Normal operational logging is written to
#   C:\MME\AutoLogs. This script always exits 0.
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$EvidenceZip
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ============================================================
# CONSTANTS / STATE
# ============================================================

$WorkspaceRoot = 'C:\MME\CS'
$LogDirectory  = 'C:\MME\AutoLogs'
$LogPath       = Join-Path $LogDirectory 'MME_IR_Evidence_RTR_Audit.log'

$PolicyVersion = '2.0'
$ScriptBuild   = '2026.10.29-v5'

$CurrentStage = 'Initialize'
$FinalOutput  = $null
$ZipArchive   = $null
$AuditPath    = $null
$ManifestPath = $null
$SourceHashBefore = $null
$SourceHashAfter  = $null

$Artifacts = New-Object 'System.Collections.Generic.List[object]'
$ReviewItems = New-Object 'System.Collections.Generic.List[object]'

$Stats = [ordered]@{
    Artifacts      = 0
    PreserveRules  = 0
    TokenizeRules  = 0
    RedactRules    = 0
    RemoveRules    = 0
    ReviewRequired = 0
}

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
    if ($Text.Length -gt 700) {
        $Text = $Text.Substring(0,700)
    }
    return $Text.Trim()
}

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)

    try {
        '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (ConvertTo-SafeOutput $Message) |
            Add-Content -LiteralPath $LogPath -Encoding UTF8
    }
    catch {
        # Logging must never alter the audit result.
    }
}

function Write-Audit {
    param([Parameter(Mandatory)][string]$Message)

    if ([string]::IsNullOrWhiteSpace($AuditPath)) { return }

    try {
        '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message |
            Add-Content -LiteralPath $AuditPath -Encoding UTF8
    }
    catch {
        throw "Unable to write RTR audit log: $($_.Exception.Message)"
    }
}

function Get-Sha256File {
    param([Parameter(Mandatory)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Normalize-ZipPath {
    param([Parameter(Mandatory)][string]$Path)

    return ($Path -replace '/','\').TrimStart('\')
}

function Get-ZipLeafName {
    param([Parameter(Mandatory)][string]$Path)

    $Normalized = Normalize-ZipPath $Path
    if ($Normalized.EndsWith('\')) { return '' }

    $Index = $Normalized.LastIndexOf('\')
    if ($Index -lt 0) { return $Normalized }
    return $Normalized.Substring($Index + 1)
}

function Get-ZipEntryPrefix {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][int]$Length
    )

    if ($Entry.Length -eq 0) {
        return [byte[]]@()
    }

    $Stream = $Entry.Open()
    try {
        $Count = [Math]::Min($Length,[int]$Entry.Length)
        $Buffer = New-Object byte[] $Count
        $Read = $Stream.Read($Buffer,0,$Count)
        if ($Read -eq $Count) {
            return $Buffer
        }
        if ($Read -le 0) {
            return [byte[]]@()
        }
        $Trimmed = New-Object byte[] $Read
        [Array]::Copy($Buffer,$Trimmed,$Read)
        return $Trimmed
    }
    finally {
        $Stream.Dispose()
    }
}

function Test-ZipEntryAsciiPrefix {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string]$Expected
    )

    $Bytes = Get-ZipEntryPrefix -Entry $Entry -Length ([System.Text.Encoding]::ASCII.GetByteCount($Expected))
    if ($Bytes.Length -eq 0) { return $false }
    $Actual = [System.Text.Encoding]::ASCII.GetString($Bytes)
    return $Actual -eq $Expected
}

# ============================================================
# RTR POLICY CATALOG
# ============================================================

# NOTE:
# - Policy rules are declarative. Script A decides which fixed policy applies.
# - Script B executes these rules and logs the exact values changed.
# - There is no second action/disposition layer.

$PolicyCatalog = [ordered]@{}

$PolicyCatalog['PRESERVE_SECURITY_ARTIFACT'] = [ordered]@{
    Handler = 'Preserve'
    Rules = @(
        [ordered]@{ Selector='*'; Action='PRESERVE'; RuleId='SECURITY_ARTIFACT_PRESERVE'; DataClass='SECURITY_EVIDENCE' }
    )
}

$PolicyCatalog['GENERIC_STRUCTURED_RTR'] = [ordered]@{
    Handler = 'StructuredContext'
    Rules = @(
        [ordered]@{ Selector='Security identifiers, timestamps, hashes, process/service/task/network metadata'; Action='PRESERVE'; RuleId='STRUCTURED_SECURITY_CONTEXT'; DataClass='SECURITY_EVIDENCE' },
        [ordered]@{ Selector='Human/local username fields'; Action='TOKENIZE'; RuleId='STRUCTURED_USER_IDENTITY'; DataClass='USER' },
        [ordered]@{ Selector='Human-name fields in identity context'; Action='TOKENIZE'; RuleId='STRUCTURED_HUMAN_NAME'; DataClass='PERSON' },
        [ordered]@{ Selector='Email fields'; Action='TOKENIZE'; RuleId='STRUCTURED_EMAIL'; DataClass='EMAIL' },
        [ordered]@{ Selector='Patient/member/subscriber/policyholder/account/chart/claim/MRN identifiers in identity context'; Action='TOKENIZE'; RuleId='STRUCTURED_SENSITIVE_ID'; DataClass='ID' },
        [ordered]@{ Selector='DOB/phone/address fields in identity context'; Action='TOKENIZE'; RuleId='STRUCTURED_IDENTITY_VALUE'; DataClass='IDENTITY' },
        [ordered]@{ Selector='Password/PIN/OTP/passcode/security-answer/auth/API/session/token values'; Action='REDACT'; RuleId='STRUCTURED_SECRET_VALUE'; DataClass='SECRET' },
        [ordered]@{ Selector='URLs'; Action='TOKENIZE'; RuleId='URL_CONTEXT_RTR'; DataClass='URL_COMPONENT' },
        [ordered]@{ Selector='File/path values'; Action='TOKENIZE'; RuleId='PATH_CONTEXT_RTR'; DataClass='PATH_COMPONENT' }
    )
}

$PolicyCatalog['GENERIC_TEXT_RTR'] = [ordered]@{
    Handler = 'TextContext'
    Rules = @(
        [ordered]@{ Selector='Unmatched text'; Action='PRESERVE'; RuleId='TEXT_DEFAULT_PRESERVE'; DataClass='TEXT' },
        [ordered]@{ Selector='Known user/person identities'; Action='TOKENIZE'; RuleId='TEXT_KNOWN_IDENTITY'; DataClass='IDENTITY' },
        [ordered]@{ Selector='Email addresses'; Action='TOKENIZE'; RuleId='TEXT_EMAIL'; DataClass='EMAIL' },
        [ordered]@{ Selector='Context-labeled patient/member/subscriber/policyholder/account/chart/claim/MRN IDs'; Action='TOKENIZE'; RuleId='TEXT_CONTEXT_SENSITIVE_ID'; DataClass='ID' },
        [ordered]@{ Selector='Context-labeled human names, DOBs, phones, addresses'; Action='TOKENIZE'; RuleId='TEXT_CONTEXT_IDENTITY'; DataClass='IDENTITY' },
        [ordered]@{ Selector='Windows user-profile path segment'; Action='TOKENIZE'; RuleId='TEXT_USER_PATH'; DataClass='USER' },
        [ordered]@{ Selector='URL sensitive path/query identifiers'; Action='TOKENIZE'; RuleId='URL_CONTEXT_RTR'; DataClass='URL_COMPONENT' },
        [ordered]@{ Selector='Password/PIN/OTP/passcode/auth/API/session/token/secret values'; Action='REDACT'; RuleId='TEXT_SECRET_VALUE'; DataClass='SECRET' }
    )
}

$PolicyCatalog['EVTX_RTR'] = [ordered]@{
    Handler = 'WindowsEventLog'
    Rules = @(
        [ordered]@{ Selector='System metadata: provider, channel, EventID, RecordID, level, timestamps, process/thread IDs'; Action='PRESERVE'; RuleId='EVTX_SYSTEM_METADATA'; DataClass='SECURITY_EVIDENCE' },
        [ordered]@{ Selector='SIDs and security correlation identifiers'; Action='PRESERVE'; RuleId='EVTX_SECURITY_IDENTIFIER'; DataClass='SECURITY_EVIDENCE' },
        [ordered]@{ Selector='Human/local username or account-name values'; Action='TOKENIZE'; RuleId='EVTX_USER_IDENTITY'; DataClass='USER' },
        [ordered]@{ Selector='Email/context-labeled human identity or sensitive IDs'; Action='TOKENIZE'; RuleId='EVTX_CONTEXT_IDENTITY'; DataClass='IDENTITY' },
        [ordered]@{ Selector='Command lines, paths and URLs'; Action='TOKENIZE'; RuleId='EVTX_CONTEXTUAL_STRING_RTR'; DataClass='CONTEXTUAL_STRING' },
        [ordered]@{ Selector='Credential/auth/session/token values'; Action='REDACT'; RuleId='EVTX_SECRET_VALUE'; DataClass='SECRET' }
    )
}

$PolicyCatalog['CHROMIUM_HISTORY_RTR'] = [ordered]@{
    Handler = 'ChromiumHistory'
    NativeRequirement = 'winsqlite3.dll'
    Rules = @(
        [ordered]@{ Selector='urls.id, visit_count, typed_count, timestamps, transition/referrer relationships'; Action='PRESERVE'; RuleId='CHROMIUM_HISTORY_SECURITY_CONTEXT'; DataClass='SECURITY_EVIDENCE' },
        [ordered]@{ Selector='urls.url'; Action='TOKENIZE'; RuleId='CHROMIUM_HISTORY_URL_RTR'; DataClass='URL_COMPONENT' },
        [ordered]@{ Selector='urls.title'; Action='TOKENIZE'; RuleId='CHROMIUM_HISTORY_TITLE_CONTEXT'; DataClass='IDENTITY_CONTEXT' },
        [ordered]@{ Selector='keyword_search_terms.term'; Action='TOKENIZE'; RuleId='CHROMIUM_SEARCH_TERM_CONTEXT'; DataClass='IDENTITY_CONTEXT' },
        [ordered]@{ Selector='downloads target/current path'; Action='TOKENIZE'; RuleId='CHROMIUM_DOWNLOAD_PATH_RTR'; DataClass='PATH_COMPONENT' },
        [ordered]@{ Selector='Auth/session/token values encountered in URLs'; Action='REDACT'; RuleId='URL_AUTH_PARAMETER'; DataClass='SECRET' }
    )
}

$PolicyCatalog['CHROMIUM_LOGIN_RTR'] = [ordered]@{
    Handler = 'ChromiumLoginData'
    NativeRequirement = 'winsqlite3.dll'
    Rules = @(
        [ordered]@{ Selector='origin/action/signon URL and timestamps/usage metadata'; Action='PRESERVE'; RuleId='CHROMIUM_LOGIN_METADATA'; DataClass='SECURITY_EVIDENCE' },
        [ordered]@{ Selector='URL sensitive components'; Action='TOKENIZE'; RuleId='CHROMIUM_LOGIN_URL_RTR'; DataClass='URL_COMPONENT' },
        [ordered]@{ Selector='username_value'; Action='TOKENIZE'; RuleId='CHROMIUM_LOGIN_USERNAME'; DataClass='USER' },
        [ordered]@{ Selector='sender name/email and other explicit identity fields'; Action='TOKENIZE'; RuleId='CHROMIUM_LOGIN_IDENTITY'; DataClass='IDENTITY' },
        [ordered]@{ Selector='password_value and secret/auth material'; Action='REDACT'; RuleId='CHROMIUM_LOGIN_SECRET_MATERIAL'; DataClass='SECRET' }
    )
}

$PolicyCatalog['CHROMIUM_WEBDATA_RTR'] = [ordered]@{
    Handler = 'ChromiumWebData'
    NativeRequirement = 'winsqlite3.dll'
    Rules = @(
        [ordered]@{ Selector='Autofill metadata: timestamps/counts/field labels'; Action='PRESERVE'; RuleId='CHROMIUM_AUTOFILL_METADATA'; DataClass='SECURITY_CONTEXT' },
        [ordered]@{ Selector='Explicit human-name fields'; Action='TOKENIZE'; RuleId='CHROMIUM_AUTOFILL_PERSON'; DataClass='PERSON' },
        [ordered]@{ Selector='Explicit email/phone/address/DOB fields'; Action='TOKENIZE'; RuleId='CHROMIUM_AUTOFILL_IDENTITY'; DataClass='IDENTITY' },
        [ordered]@{ Selector='Patient/member/subscriber/policyholder/account/chart/claim/MRN ID fields'; Action='TOKENIZE'; RuleId='CHROMIUM_AUTOFILL_SENSITIVE_ID'; DataClass='ID' },
        [ordered]@{ Selector='Unknown/vague autofill field values'; Action='PRESERVE'; RuleId='CHROMIUM_AUTOFILL_UNKNOWN_CONTEXT'; DataClass='FORM_VALUE'; Note='Still subject to known-value, universal email, URL and secret rules during Script B execution.' },
        [ordered]@{ Selector='Password/PIN/OTP/passcode/security-answer/auth/token fields'; Action='REDACT'; RuleId='CHROMIUM_AUTOFILL_SECRET'; DataClass='SECRET' },
        [ordered]@{ Selector='Card/account payment numbers, last-four, expiration, IBAN'; Action='REDACT'; RuleId='CHROMIUM_PAYMENT_DATA'; DataClass='PAYMENT_DATA' },
        [ordered]@{ Selector='Cardholder name'; Action='TOKENIZE'; RuleId='CHROMIUM_CARDHOLDER_NAME'; DataClass='PERSON' }
    )
}

$PolicyCatalog['CHROMIUM_COOKIE_RTR'] = [ordered]@{
    Handler = 'ChromiumCookies'
    NativeRequirement = 'winsqlite3.dll'
    Rules = @(
        [ordered]@{ Selector='host_key, name, path, timestamps, security flags'; Action='PRESERVE'; RuleId='CHROMIUM_COOKIE_METADATA'; DataClass='SECURITY_EVIDENCE' },
        [ordered]@{ Selector='value/encrypted_value and session material'; Action='REDACT'; RuleId='CHROMIUM_COOKIE_VALUE'; DataClass='SESSION_DATA' }
    )
}

$PolicyCatalog['CHROMIUM_JSON_RTR'] = [ordered]@{
    Handler = 'ChromiumJson'
    Rules = @(
        [ordered]@{ Selector='Browser/extension/policy/security configuration'; Action='PRESERVE'; RuleId='CHROMIUM_JSON_SECURITY_CONTEXT'; DataClass='SECURITY_EVIDENCE' },
        [ordered]@{ Selector='Account/profile names, emails, usernames, GAIA/profile identity values'; Action='TOKENIZE'; RuleId='CHROMIUM_JSON_IDENTITY'; DataClass='IDENTITY' },
        [ordered]@{ Selector='URLs and file paths'; Action='TOKENIZE'; RuleId='CHROMIUM_JSON_CONTEXTUAL_STRING_RTR'; DataClass='CONTEXTUAL_STRING' },
        [ordered]@{ Selector='Auth/session/password/token/encryption-key material'; Action='REDACT'; RuleId='CHROMIUM_JSON_SECRET'; DataClass='SECRET' }
    )
}

$PolicyCatalog['USER_FILE_METADATA_RTR'] = [ordered]@{
    Handler = 'UserFileMetadata'
    Rules = @(
        [ordered]@{ Selector='Timestamps, size, hash, extension, location category'; Action='PRESERVE'; RuleId='USER_FILE_SECURITY_METADATA'; DataClass='SECURITY_EVIDENCE' },
        [ordered]@{ Selector='Windows user-profile segment'; Action='TOKENIZE'; RuleId='USER_FILE_PROFILE_SEGMENT'; DataClass='USER' },
        [ordered]@{ Selector='Known identity component in filename/path'; Action='TOKENIZE'; RuleId='USER_FILE_KNOWN_IDENTITY'; DataClass='IDENTITY' },
        [ordered]@{ Selector='Passive Documents/Desktop/OneDrive/Pictures/Videos/Music/Recent filename stem when identity cannot be safely separated'; Action='TOKENIZE'; RuleId='PASSIVE_USER_FILENAME'; DataClass='FILE' },
        [ordered]@{ Selector='Security-relevant executable/script/installer filename, especially Downloads/Temp/AppData'; Action='PRESERVE'; RuleId='SECURITY_FILENAME_PRESERVE'; DataClass='SECURITY_EVIDENCE' },
        [ordered]@{ Selector='Credential/token embedded in filename/path'; Action='REDACT'; RuleId='PATH_SECRET_VALUE'; DataClass='SECRET' }
    )
}

$PolicyCatalog['REMOVE_RAW_PREFETCH'] = [ordered]@{
    Handler = 'Remove'
    Rules = @(
        [ordered]@{ Selector='*'; Action='REMOVE'; RuleId='RAW_PREFETCH_BINARY'; DataClass='OPAQUE_BINARY' }
    )
}

$PolicyCatalog['REMOVE_RAW_SHORTCUT'] = [ordered]@{
    Handler = 'Remove'
    Rules = @(
        [ordered]@{ Selector='*'; Action='REMOVE'; RuleId='RAW_WINDOWS_SHORTCUT_BINARY'; DataClass='OPAQUE_BINARY' }
    )
}

$PolicyCatalog['REMOVE_RAW_JUMPLIST'] = [ordered]@{
    Handler = 'Remove'
    Rules = @(
        [ordered]@{ Selector='*'; Action='REMOVE'; RuleId='RAW_JUMPLIST_BINARY'; DataClass='OPAQUE_BINARY' }
    )
}

$PolicyCatalog['REMOVE_RAW_SRUM'] = [ordered]@{
    Handler = 'Remove'
    Rules = @(
        [ordered]@{ Selector='*'; Action='REMOVE'; RuleId='RAW_SRUM_DATABASE'; DataClass='OPAQUE_BINARY' }
    )
}

$PolicyCatalog['REMOVE_RAW_USER_HIVE'] = [ordered]@{
    Handler = 'Remove'
    Rules = @(
        [ordered]@{ Selector='*'; Action='REMOVE'; RuleId='RAW_USER_REGISTRY_HIVE'; DataClass='OPAQUE_BINARY' }
    )
}

$PolicyCatalog['REMOVE_RAW_AMCACHE'] = [ordered]@{
    Handler = 'Remove'
    Rules = @(
        [ordered]@{ Selector='*'; Action='REMOVE'; RuleId='RAW_AMCACHE_HIVE'; DataClass='OPAQUE_BINARY' }
    )
}

$PolicyCatalog['REMOVE_CHROMIUM_SESSION'] = [ordered]@{
    Handler = 'Remove'
    Rules = @(
        [ordered]@{ Selector='*'; Action='REMOVE'; RuleId='RAW_CHROMIUM_SESSION_BINARY'; DataClass='OPAQUE_BINARY' }
    )
}

$PolicyCatalog['REVIEW_UNKNOWN_BINARY'] = [ordered]@{
    Handler = 'Review'
    Rules = @(
        [ordered]@{ Selector='*'; Action='REVIEW_REQUIRED'; RuleId='UNKNOWN_ARTIFACT'; DataClass='UNKNOWN' }
    )
}

$PolicyCatalog['REVIEW_FIREFOX_SQLITE'] = [ordered]@{
    Handler = 'Review'
    Rules = @(
        [ordered]@{ Selector='*'; Action='REVIEW_REQUIRED'; RuleId='FIREFOX_SQLITE_POLICY_REQUIRED'; DataClass='UNKNOWN_STRUCTURED_DATABASE' }
    )
}

# ============================================================
# ARTIFACT IDENTIFICATION
# ============================================================

function Get-ArtifactDescriptor {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Entry
    )

    $P = Normalize-ZipPath $Path
    $Leaf = Get-ZipLeafName $P
    $LeafLower = $Leaf.ToLowerInvariant()
    $Extension = [System.IO.Path]::GetExtension($LeafLower)

    if ($Entry.Length -eq 0) {
        return [pscustomobject]@{ Type='EmptyArtifact'; PolicyId='PRESERVE_SECURITY_ARTIFACT'; Validation='EMPTY' }
    }

    # Windows event logs.
    if ($Extension -eq '.evtx') {
        if (-not (Test-ZipEntryAsciiPrefix -Entry $Entry -Expected "ElfFile`0")) {
            return [pscustomobject]@{ Type='WindowsEventLog'; PolicyId='REVIEW_UNKNOWN_BINARY'; Validation='EVTX_SIGNATURE_FAILED' }
        }
        return [pscustomobject]@{ Type='WindowsEventLog'; PolicyId='EVTX_RTR'; Validation='EVTX_SIGNATURE_OK' }
    }

    # Known opaque forensic families deliberately excluded from sanitized output.
    if ($P -match '(?i)\\Prefetch\\Collected_Prefetch_Files\\' -and $Extension -eq '.pf') {
        return [pscustomobject]@{ Type='RawPrefetch'; PolicyId='REMOVE_RAW_PREFETCH'; Validation='PATH_AND_EXTENSION' }
    }

    if ($Extension -in @('.automaticdestinations-ms','.customdestinations-ms')) {
        return [pscustomobject]@{ Type='RawJumpList'; PolicyId='REMOVE_RAW_JUMPLIST'; Validation='EXTENSION' }
    }

    # Temporary CustomDestinations files are raw Jump List binaries too.
    # Restrict this disposition to the collector's Jump Lists directory.
    if ($P -match '(?i)(?:^|\\)05_Execution_Access_Artifacts\\Jump_Lists\\CustomDestinations\\' -and
        $Extension -in @('.tmp','.temp')) {
        return [pscustomobject]@{ Type='RawJumpListTemporary'; PolicyId='REMOVE_RAW_JUMPLIST'; Validation='PATH_AND_EXTENSION' }
    }

    # Raw shell shortcuts contain target paths, usernames, arguments and other
    # identity-bearing data. The Recent_Files inventory supplies safer metadata.
    if ($P -match '(?i)(?:^|\\)05_Execution_Access_Artifacts\\Collected_Recent_Files\\' -and $Extension -eq '.lnk') {
        $Signature = Get-ZipEntryPrefix -Entry $Entry -Length 20
        if ([BitConverter]::ToString([byte[]]$Signature) -ne '4C-00-00-00-01-14-02-00-00-00-00-00-C0-00-00-00-00-00-00-46') {
            return [pscustomobject]@{ Type='WindowsShellLink'; PolicyId='REVIEW_UNKNOWN_BINARY'; Validation='LNK_SIGNATURE_FAILED' }
        }
        return [pscustomobject]@{ Type='WindowsShellLink'; PolicyId='REMOVE_RAW_SHORTCUT'; Validation='LNK_SIGNATURE_OK' }
    }

    # Internet shortcuts are INI-style text, not opaque Windows Shell Links.
    if ($P -match '(?i)(?:^|\\)05_Execution_Access_Artifacts\\Collected_Recent_Files\\' -and $Extension -eq '.url') {
        return [pscustomobject]@{ Type='InternetShortcut'; PolicyId='GENERIC_TEXT_RTR'; Validation='PATH_AND_EXTENSION' }
    }

    if ($P -match '(?i)\\SRUM\\SRUDB\.dat$') {
        return [pscustomobject]@{ Type='RawSRUM'; PolicyId='REMOVE_RAW_SRUM'; Validation='PATH_AND_NAME' }
    }

    if ($P -match '(?i)\\User_Hives\\.*\\(NTUSER\.DAT|UsrClass\.dat)$') {
        return [pscustomobject]@{ Type='RawUserRegistryHive'; PolicyId='REMOVE_RAW_USER_HIVE'; Validation='PATH_AND_NAME' }
    }

    if ($P -match '(?i)\\Amcache\\Amcache\.hve$') {
        return [pscustomobject]@{ Type='RawAmcacheHive'; PolicyId='REMOVE_RAW_AMCACHE'; Validation='PATH_AND_NAME' }
    }

    # Transient Amcache registry hive copies. Validate the registry header;
    # non-registry content stays REVIEW_REQUIRED instead of being assumed safe.
    if ($P -match '(?i)(?:^|\\)05_Execution_Access_Artifacts\\Amcache\\Amcache\.hve(?:\.tmp)+$') {
        if (-not (Test-ZipEntryAsciiPrefix -Entry $Entry -Expected 'regf')) {
            return [pscustomobject]@{ Type='AmcacheTemporaryHive'; PolicyId='REVIEW_UNKNOWN_BINARY'; Validation='AMCACHE_TEMP_HIVE_SIGNATURE_FAILED' }
        }
        return [pscustomobject]@{ Type='AmcacheTemporaryHive'; PolicyId='REMOVE_RAW_AMCACHE'; Validation='PATH_AND_REGF_SIGNATURE' }
    }

    # Windows Kernel Transaction Manager backing files for the Amcache hive.
    # These are opaque raw registry transaction artifacts, not value-level
    # sanitizer inputs. Restrict removal to the collector's Amcache directory
    # and conventional GUID-qualified transaction filenames. The filename is
    # the classifier; these formats have no generic 'regf' hive header.
    if ($P -match '(?i)(?:^|\\)05_Execution_Access_Artifacts\\Amcache\\Amcache\.hve\{[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}\.TM\.blf$') {
        return [pscustomobject]@{ Type='AmcacheTransactionManagerLog'; PolicyId='REMOVE_RAW_AMCACHE'; Validation='PATH_AND_TRANSACTION_FILENAME' }
    }

    if ($P -match '(?i)(?:^|\\)05_Execution_Access_Artifacts\\Amcache\\Amcache\.hve\{[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}\.TMContainer[0-9]+\.regtrans-ms$') {
        return [pscustomobject]@{ Type='AmcacheTransactionManagerLog'; PolicyId='REMOVE_RAW_AMCACHE'; Validation='PATH_AND_TRANSACTION_FILENAME' }
    }

    # Amcache temporary registry hives / transaction logs. Reject unexpected
    # signatures instead of presuming every similarly named file is safe.
    if ($P -match '(?i)\\Amcache\\Amcache\.hve(?:\.tmp)+\.LOG[12]$') {
        if (-not ((Test-ZipEntryAsciiPrefix -Entry $Entry -Expected 'regf') -or
                   (Test-ZipEntryAsciiPrefix -Entry $Entry -Expected 'HvLE'))) {
            return [pscustomobject]@{ Type='AmcacheTransactionLog'; PolicyId='REVIEW_UNKNOWN_BINARY'; Validation='AMCACHE_LOG_SIGNATURE_FAILED' }
        }
        return [pscustomobject]@{ Type='AmcacheTransactionLog'; PolicyId='REMOVE_RAW_AMCACHE'; Validation='PATH_AND_SIGNATURE' }
    }

    # Some collector runs place an extra registry hive directly under User_Hives,
    # without a conventional NTUSER.DAT/UsrClass.dat filename.
    if ($P -match '(?i)(?:^|\\)05_Execution_Access_Artifacts\\User_Hives\\[^\\]+$' -and
        (Test-ZipEntryAsciiPrefix -Entry $Entry -Expected 'regf')) {
        return [pscustomobject]@{ Type='RawUserRegistryHive'; PolicyId='REMOVE_RAW_USER_HIVE'; Validation='PATH_AND_REGF_SIGNATURE' }
    }

    # Chromium browser artifacts.
    if ($P -match '(?i)(?:^|\\)06_Browser_SaaS_Artifacts\\(Chrome|Edge)\\Collected_Files\\') {
        if ($LeafLower -in @('current session','last session','current tabs','last tabs') -or $LeafLower -match '^sessions_(session|tabs|apps)_') {
            return [pscustomobject]@{ Type='ChromiumSessionState'; PolicyId='REMOVE_CHROMIUM_SESSION'; Validation='PATH_AND_NAME' }
        }

        if ($LeafLower -in @('history','login data','web data','cookies','network_cookies')) {
            if (-not (Test-ZipEntryAsciiPrefix -Entry $Entry -Expected "SQLite format 3`0")) {
                return [pscustomobject]@{ Type='ChromiumSQLite'; PolicyId='REVIEW_UNKNOWN_BINARY'; Validation='SQLITE_SIGNATURE_FAILED' }
            }

            switch ($LeafLower) {
                'history'         { return [pscustomobject]@{ Type='ChromiumHistory'; PolicyId='CHROMIUM_HISTORY_RTR'; Validation='SQLITE_SIGNATURE_OK' } }
                'login data'      { return [pscustomobject]@{ Type='ChromiumLoginData'; PolicyId='CHROMIUM_LOGIN_RTR'; Validation='SQLITE_SIGNATURE_OK' } }
                'web data'        { return [pscustomobject]@{ Type='ChromiumWebData'; PolicyId='CHROMIUM_WEBDATA_RTR'; Validation='SQLITE_SIGNATURE_OK' } }
                'cookies'         { return [pscustomobject]@{ Type='ChromiumCookies'; PolicyId='CHROMIUM_COOKIE_RTR'; Validation='SQLITE_SIGNATURE_OK' } }
                'network_cookies' { return [pscustomobject]@{ Type='ChromiumCookies'; PolicyId='CHROMIUM_COOKIE_RTR'; Validation='SQLITE_SIGNATURE_OK' } }
            }
        }

        if ($LeafLower -in @('preferences','secure preferences','local state','bookmarks')) {
            return [pscustomobject]@{ Type='ChromiumJson'; PolicyId='CHROMIUM_JSON_RTR'; Validation='PATH_AND_NAME' }
        }
    }

    # Firefox support is intentionally fail-closed until a complete policy is
    # designed. This is a genuine review condition, not parser deferral.
    if ($P -match '(?i)(?:^|\\)06_Browser_SaaS_Artifacts\\Firefox\\Collected_Files\\') {
        if ($LeafLower -in @('places.sqlite','formhistory.sqlite','cookies.sqlite','permissions.sqlite')) {
            return [pscustomobject]@{ Type='FirefoxSQLite'; PolicyId='REVIEW_FIREFOX_SQLITE'; Validation='PATH_AND_NAME' }
        }
        if ($LeafLower -eq 'logins.json') {
            return [pscustomobject]@{ Type='FirefoxLoginsJson'; PolicyId='GENERIC_STRUCTURED_RTR'; Validation='PATH_AND_NAME' }
        }
    }

    # User-file metadata gets a dedicated filename/path policy because privacy
    # and forensic value differ sharply by location and extension.
    if (
        $P -match '(?i)(?:^|\\)05_Execution_Access_Artifacts\\' -and
        $LeafLower -match '(file|recent|download|desktop|document|temp|inventory|metadata)' -and
        $Extension -in @('.csv','.json','.txt')
    ) {
        return [pscustomobject]@{ Type='UserFileMetadata'; PolicyId='USER_FILE_METADATA_RTR'; Validation='PATH_AND_EXTENSION' }
    }

    # Structured/text families. Script B applies field-aware policy; Script A
    # does not rescan all content merely to rediscover the same rule per value.
    if ($Extension -eq '.csv') {
        return [pscustomobject]@{ Type='StructuredCsv'; PolicyId='GENERIC_STRUCTURED_RTR'; Validation='EXTENSION' }
    }

    if ($Extension -eq '.json' -or $LeafLower -in @('bookmarks','preferences','secure preferences','local state')) {
        return [pscustomobject]@{ Type='StructuredJson'; PolicyId='GENERIC_STRUCTURED_RTR'; Validation='EXTENSION_OR_KNOWN_NAME' }
    }

    if ($Extension -eq '.xml') {
        return [pscustomobject]@{ Type='StructuredXml'; PolicyId='GENERIC_STRUCTURED_RTR'; Validation='EXTENSION' }
    }

    if ($Extension -in @('.txt','.log','.config','.ini','.bat','.cmd','.ps1','.psm1','.psd1','.reg')) {
        return [pscustomobject]@{ Type='TextArtifact'; PolicyId='GENERIC_TEXT_RTR'; Validation='EXTENSION' }
    }

    # Remaining known inventory/hash/status files without a conventional
    # extension are preserved only when their path identifies them as collector
    # metadata rather than unrecognized binary evidence.
    if ($P -match '(?i)(?:^|\\)08_Manifest_Hashes\\') {
        return [pscustomobject]@{ Type='ManifestOrHash'; PolicyId='PRESERVE_SECURITY_ARTIFACT'; Validation='COLLECTOR_PATH' }
    }

    return [pscustomobject]@{ Type='UnknownBinary'; PolicyId='REVIEW_UNKNOWN_BINARY'; Validation='UNRECOGNIZED' }
}

# ============================================================
# MANIFEST HELPERS
# ============================================================

function Add-ArtifactRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ArtifactType,
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][string]$Validation,
        [long]$Length = 0,
        [long]$CompressedLength = 0
    )

    if (-not $PolicyCatalog.Contains($PolicyId)) {
        throw "Unknown policy ID '$PolicyId' for artifact '$Path'."
    }

    $Record = [pscustomobject][ordered]@{
        Path             = $Path
        ArtifactType     = $ArtifactType
        PolicyId         = $PolicyId
        Validation       = $Validation
        Length           = $Length
        CompressedLength = $CompressedLength
    }

    $Artifacts.Add($Record)
    $Stats.Artifacts++

    $Policy = $PolicyCatalog[$PolicyId]
    foreach ($Rule in $Policy.Rules) {
        switch ([string]$Rule.Action) {
            'PRESERVE'        { $Stats.PreserveRules++ }
            'TOKENIZE'        { $Stats.TokenizeRules++ }
            'REDACT'          { $Stats.RedactRules++ }
            'REMOVE'          { $Stats.RemoveRules++ }
            'REVIEW_REQUIRED' { $Stats.ReviewRequired++ }
        }
    }

    if ($PolicyId -in @('REVIEW_UNKNOWN_BINARY','REVIEW_FIREFOX_SQLITE')) {
        $ReviewItems.Add([pscustomobject][ordered]@{
            Path       = $Path
            ArtifactType = $ArtifactType
            PolicyId   = $PolicyId
            Validation = $Validation
        })
    }
}

function Get-PolicyUsageSummary {
    $Groups = $Artifacts | Group-Object PolicyId | Sort-Object Name
    $Summary = @()
    foreach ($Group in $Groups) {
        $TotalBytes = [long](($Group.Group | Measure-Object Length -Sum).Sum)
        $Summary += [pscustomobject][ordered]@{
            PolicyId = $Group.Name
            Artifacts = $Group.Count
            Bytes = $TotalBytes
        }
    }
    return $Summary
}

# ============================================================
# SOURCE RESOLUTION
# ============================================================

function Resolve-EvidenceZip {
    param([AllowNull()][string]$RequestedPath)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $Resolved = [Environment]::ExpandEnvironmentVariables($RequestedPath.Trim('"'))
        if (-not (Test-Path -LiteralPath $Resolved -PathType Leaf)) {
            throw "Evidence ZIP not found: $Resolved"
        }
        if ([System.IO.Path]::GetExtension($Resolved) -ne '.zip') {
            throw "Evidence source must be a .zip file: $Resolved"
        }
        return (Get-Item -LiteralPath $Resolved).FullName
    }

    $Candidates = @(
        Get-ChildItem -LiteralPath $WorkspaceRoot -Filter '*.zip' -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -notmatch '(?i)_SANITIZED\.zip$' -and
                $_.Name -notmatch '(?i)_RTR_.*\.zip$'
            }
    )

    if ($Candidates.Count -eq 0) {
        return $null
    }

    if ($Candidates.Count -gt 1) {
        $Names = ($Candidates.Name | Sort-Object) -join ', '
        throw "Multiple eligible ZIP files found in $WorkspaceRoot. Specify -EvidenceZip. Files=$Names"
    }

    return $Candidates[0].FullName
}

# ============================================================
# MAIN
# ============================================================

try {
    Initialize-Directory $WorkspaceRoot
    Initialize-Directory $LogDirectory

    Write-Log "START | MME IR Evidence RTR Audit | Build=$ScriptBuild Policy=$PolicyVersion"

    $CurrentStage = 'ResolveEvidenceZip'
    $EvidenceZip = Resolve-EvidenceZip -RequestedPath $EvidenceZip

    if ([string]::IsNullOrWhiteSpace($EvidenceZip)) {
        $FinalOutput = "NO_ACTION | No eligible Device IR ZIP found in $WorkspaceRoot"
        Write-Log $FinalOutput
    }
    else {
        $SourceName = [System.IO.Path]::GetFileNameWithoutExtension($EvidenceZip)
        $ManifestPath = Join-Path $WorkspaceRoot ($SourceName + '_RTR_MANIFEST.json')
        $AuditPath    = Join-Path $WorkspaceRoot ($SourceName + '_RTR_AUDIT.log')

        Remove-Item -LiteralPath $ManifestPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $AuditPath -Force -ErrorAction SilentlyContinue

        $CurrentStage = 'FingerprintSourceBefore'
        $SourceHashBefore = Get-Sha256File $EvidenceZip
        $SourceInfo = Get-Item -LiteralPath $EvidenceZip

        Write-Audit 'MME DEVICE IR RTR POLICY AUDIT'
        Write-Audit ("Build={0} | Policy={1}" -f $ScriptBuild,$PolicyVersion)
        Write-Audit ("Source={0}" -f $EvidenceZip)
        Write-Audit ("SourceSHA256={0}" -f $SourceHashBefore)
        Write-Audit 'NOTE | Script A assigns deterministic RTR policies. Script B performs value-level RTR and writes the detailed final change log.'
        Write-Audit '----------------------------------------------------------------------------'

        Write-Log "SOURCE | File=$($SourceInfo.Name) Size=$($SourceInfo.Length) SHA256=$SourceHashBefore"

        $CurrentStage = 'OpenZip'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $ZipArchive = [System.IO.Compression.ZipFile]::OpenRead($EvidenceZip)

        $CurrentStage = 'ClassifyArtifacts'
        foreach ($Entry in $ZipArchive.Entries) {
            $RawName = [string]$Entry.FullName
            if ($RawName.EndsWith('/') -or $RawName.EndsWith('\')) { continue }

            $Path = Normalize-ZipPath $RawName
            $Descriptor = Get-ArtifactDescriptor -Path $Path -Entry $Entry

            Add-ArtifactRecord `
                -Path $Path `
                -ArtifactType $Descriptor.Type `
                -PolicyId $Descriptor.PolicyId `
                -Validation $Descriptor.Validation `
                -Length $Entry.Length `
                -CompressedLength $Entry.CompressedLength
        }

        $CurrentStage = 'BuildManifest'
        $PolicyUsage = @(Get-PolicyUsageSummary)

        $UsedPolicyIds = @($PolicyUsage.PolicyId | Sort-Object -Unique)
        $UsedPolicies = [ordered]@{}
        foreach ($PolicyId in $UsedPolicyIds) {
            $UsedPolicies[$PolicyId] = $PolicyCatalog[$PolicyId]
        }

        $CurrentStage = 'BuildManifestObject'
        $Manifest = [ordered]@{
            SchemaVersion = '2.0'
            PolicyVersion = $PolicyVersion
            ScriptBuild   = $ScriptBuild
            GeneratedUtc  = (Get-Date).ToUniversalTime().ToString('o')
            Source = [ordered]@{
                FileName = [System.IO.Path]::GetFileName($EvidenceZip)
                FullPath = $EvidenceZip
                Length   = $SourceInfo.Length
                SHA256   = $SourceHashBefore
            }
            ApprovedActions = @('PRESERVE','TOKENIZE','REDACT','REMOVE','REVIEW_REQUIRED')
            ExecutionRules = [ordered]@{
                OriginalEvidenceImmutable = $true
                WindowsNativeOnly = $true
                SQLiteProvider = 'winsqlite3.dll'
                ExternalDependenciesAllowed = $false
                DetailedValueLogProducedBy = 'ScriptB'
                ReviewRequiredFailClosed = $true
            }
            Summary = [ordered]@{
                Artifacts = $Stats.Artifacts
                ReviewRequired = $ReviewItems.Count
                PoliciesUsed = $UsedPolicyIds.Count
            }
            PolicyUsage = @($PolicyUsage)
            Policies = $UsedPolicies
            Artifacts = $Artifacts.ToArray()
            ReviewItems = $ReviewItems.ToArray()
        }

        $CurrentStage = 'SerializeManifest'
        $ManifestJson = $Manifest | ConvertTo-Json -Depth 12

        $CurrentStage = 'WriteManifest'
        Set-Content -LiteralPath $ManifestPath -Value $ManifestJson -Encoding UTF8

        foreach ($Usage in $PolicyUsage) {
            Write-Audit (
                'POLICY | {0} | Artifacts={1} | Bytes={2}' -f
                $Usage.PolicyId,
                $Usage.Artifacts,
                $Usage.Bytes
            )
        }

        if ($ReviewItems.Count -gt 0) {
            Write-Audit '----------------------------------------------------------------------------'
            Write-Audit ("REVIEW_REQUIRED | Count=$($ReviewItems.Count)")
            foreach ($Item in $ReviewItems) {
                Write-Audit (
                    'REVIEW_REQUIRED | Artifact={0} | Type={1} | Policy={2} | Validation={3}' -f
                    $Item.Path,
                    $Item.ArtifactType,
                    $Item.PolicyId,
                    $Item.Validation
                )
            }
        }

        Write-Audit '----------------------------------------------------------------------------'
        Write-Audit (
            'SUMMARY | Artifacts={0} PoliciesUsed={1} ReviewRequired={2}' -f
            $Stats.Artifacts,
            $UsedPolicyIds.Count,
            $ReviewItems.Count
        )
        Write-Audit ("MANIFEST | $ManifestPath")

        $CurrentStage = 'VerifySourceUnchanged'
        if ($null -ne $ZipArchive) {
            $ZipArchive.Dispose()
            $ZipArchive = $null
        }

        $SourceHashAfter = Get-Sha256File $EvidenceZip
        if ($SourceHashAfter -ne $SourceHashBefore) {
            throw "Source evidence hash changed during audit. Before=$SourceHashBefore After=$SourceHashAfter"
        }

        Write-Audit ("SOURCE_INTEGRITY | PASS | SHA256=$SourceHashAfter")
        Write-Log "SOURCE_INTEGRITY | PASS | SHA256=$SourceHashAfter"

        $FinalOutput = (
            'RESULT | RTR_AUDIT_COMPLETE | Source={0} Artifacts={1} ReviewRequired={2} Manifest={3} Audit={4}' -f
            ([System.IO.Path]::GetFileName($EvidenceZip)),
            $Stats.Artifacts,
            $ReviewItems.Count,
            $ManifestPath,
            $AuditPath
        )

        Write-Log $FinalOutput
    }
}
catch {
    $SafeError = ConvertTo-SafeOutput $_.Exception.Message
    $FinalOutput = "ERROR | Stage=$CurrentStage Error=$SafeError"
    Write-Log $FinalOutput

    if (-not [string]::IsNullOrWhiteSpace($AuditPath)) {
        try {
            Write-Audit ("ERROR | Stage={0} | Error={1}" -f $CurrentStage,$SafeError)
        }
        catch {
        }
    }
}
finally {
    if ($null -ne $ZipArchive) {
        try { $ZipArchive.Dispose() } catch {}
    }

    if ([string]::IsNullOrWhiteSpace($FinalOutput)) {
        $FinalOutput = 'ERROR | Stage=Finalize Error=No final result was produced.'
    }

    Write-Output $FinalOutput
    exit 0
}