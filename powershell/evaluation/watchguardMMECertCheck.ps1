<#
# ============================================================================
# NAME: EVALUATION - WatchGuard Certificate Rotation Evidence (Global Read-Only)
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation / Read-only
# SCOPE: Windows / NinjaOne broker 9800 / All Subscriber accounts (delegated skipped)
# VARIABLES: None
# FILE TRANSFERS: None (1Password PFX retrieved at run time)
# OUTPUT TOKENS:
#   RESULT | Read-only audit completed without API/evaluation failures
#   ERROR  | One or more account audits or checks failed
# CUSTOM FIELDS:
#   Reads: opServiceAccountToken
#   Writes: None
# LOGGING PATH:
#   C:\MME\AutoLogs\WatchGuard_Certificate_Rotation_Global_ReadOnly_Audit.log
# MANIFEST PATH:
#   C:\MME\CS\WatchGuard_Certificate_Rotation_Global_ReadOnly_Audit_Manifest.json
# DESCRIPTION:
#   Collects pre-rotation evidence for the CURRENT certificate package from
#   1Password. The source PFX is a fingerprint reference, NOT an instruction
#   to install that package or select it as a device Web Server certificate.
#
#   - Discovers all Subscriber accounts, skips delegated relationships, and
#     audits every cloud-managed Firebox for each eligible Subscriber.
#   - Retains explicit delegated-account skip records in the manifest.
#   - Discovery of cloud configuration device IDs uses the existing tested
#     firewall-policy index; policy-free devices may not appear in that index.
#   - Inventories source-package presence, non-source MME-named certificates,
#     individual certificate aliases, and reciprocal account/device references.
#   - Separately records whether certificates are expired, not expired, or
#     have an unknown expiration; non-source does NOT mean expired.
#   - Records per-certificate origin evidence: ACCOUNT_LINK_RECIPROCAL,
#     DEVICE_DIRECT_IMPORT_PATTERN, ACCOUNT_LINK_PARTIAL, ACCOUNT_LINK_CONFLICT,
#     or ORIGIN_UNRESOLVED (and NOT_APPLICABLE for unrelated/native certificates).
#   - Reads Web Server selection as a factual state (DefaultFirebox/ThirdParty/
#     Unknown), NOT a compliance success/failure.
#   - Preserves all certificate and Web Server identity/reference evidence,
#     including partial source packages and mixed origins on one Firebox.
#
# SAFETY:
#   - READ-ONLY. NO uploads, deletes, deployments, or configuration changes.
#   - Matching fingerprints alone do NOT establish inheritance or origin.
#   - DEVICE_DIRECT_IMPORT_PATTERN is a bench-validated evidence pattern,
#     NOT blanket proof of origin and NEVER authorization to delete.
#   - Account relationships do not by themselves prove deletion cascade.
#   - NON_SOURCE_MME_CERTIFICATE means a different fingerprint with an MME-
#     matching name. It does NOT imply expiration or authorize deletion.
#   - Review flags are observations; NO automatic remediation decisions.
#   - Certificate changes do not require deployment; changing Web Server
#     assignment is a separate operation that can require deployment.
#   - Always exits 0 for NinjaOne.
#   - GLOBAL READ-ONLY evaluation only; no destructive actions are permitted.
#   - Web Server DefaultFirebox state and current references must be verified
#     before any future certificate removal.
#   - Read-only API requests use lightweight pacing and retry HTTP 429/500/
#     502/503/504 with bounded backoff; this is NOT a write-retry helper.
# ============================================================================
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ============================================================
# CONFIGURATION
# ============================================================

$OnePasswordVault = 'MME Automation'
$WatchGuardItemName = 'WatchGuard'
$CertificateItemName = 'MME SSL Certificate'
$CertificatePasswordField = 'password'

$NonSourceMMECertificateNamePattern = 'connectwithmme'

$LogRoot = 'C:\MME\AutoLogs'
$WorkRoot = 'C:\MME\CS'

$LogPath = Join-Path $LogRoot 'WatchGuard_Certificate_Rotation_Global_ReadOnly_Audit.log'
$ManifestPath = Join-Path $WorkRoot 'WatchGuard_Certificate_Rotation_Global_ReadOnly_Audit_Manifest.json'
$TempPfxPath = Join-Path $WorkRoot ('MME_SSL_Certificate_Source_{0}.pfx' -f [guid]::NewGuid().ToString('N'))

$TransientRetryStatusCodes = @(429, 500, 502, 503, 504)
$TransientRetryMaxAttempts = 5
$TransientRetryDelaysSeconds = @(2, 5, 10, 20)
$ApiRequestSpacingMilliseconds = 100  # Reduce API burst pressure in global audits.

# ============================================================
# STATE
# ============================================================

$CurrentStage = 'Initialize'
$AuditTimestampUtc = [DateTimeOffset]::UtcNow

$ProviderToken = $null
$ProviderTokenIssuedAt = $null

$ServiceAccountToken = $null
$WatchGuardItem = $null
$CertificateItem = $null

$ApiKey = $null
$ReadOnlyAccessId = $null
$ReadOnlyPassword = $null
$ProviderAccountId = $null
$AuthenticationUrl = $null
$BaseApiUrl = $null

$OpExe = $null
$PfxPassword = $null
$PfxCollection = $null

$ExpectedCertificates = @()
$ExpectedFingerprintsNormalized = @()
$ExpectedCertificateCount = 0
$DesiredLeafFingerprintNormalized = $null
$DesiredLeafFingerprint = $null

$AccountResults = [System.Collections.Generic.List[object]]::new()

$ErrorCount = 0
$FailureCount = 0

$AccountsWithReviewFlagsCount = 0
$DevicesWithReviewFlagsCount = 0
$DirectImportPatternCount = 0
$ReciprocalAccountLinkCount = 0
$WebServerSourceLeafSelectionCount = 0
$NonSourceMMEAccountCertificateCount = 0
$ExpiredNonSourceMMEAccountCertificateCount = 0
$NonSourceMMEDeviceCertificateCount = 0
$ExpiredNonSourceMMEDeviceCertificateCount = 0

$TotalActiveDevices = 0
$TotalCloudManaged = 0
$TotalLocallyManaged = 0
$TotalManagementUnknown = 0
$AccountsDiscoveredCount = 0
$AccountsAuditedCount = 0
$DelegatedSkippedCount = 0
$EligibleSubscriberCount = 0

# ============================================================
# BASIC HELPERS
# ============================================================

function Convert-SafeOutput {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return (
        [string]$Value `
            -replace '[\r\n]+', ' ' `
            -replace '\|', '/' `
            -replace '\s{2,}', ' '
    ).Trim()
}

function Initialize-Directories {

    foreach ($Directory in @(
        $LogRoot
        $WorkRoot
    )) {
        if (-not (Test-Path -LiteralPath $Directory)) {
            New-Item `
                -ItemType Directory `
                -Path $Directory `
                -Force |
                Out-Null
        }
    }

    "WatchGuard Certificate Rotation Global Read-Only Audit - $(Get-Date -Format s)" |
        Set-Content `
            -LiteralPath $LogPath `
            -Encoding UTF8
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    try {
        $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

        "$Timestamp | $Message" |
            Add-Content `
                -LiteralPath $LogPath `
                -Encoding UTF8
    }
    catch {
    }
}

function Get-HttpErrorDetail {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $Status = 'N/A'
    $Body = $null

    try {
        if ($ErrorRecord.Exception.Response) {
            $Status = [int]$ErrorRecord.Exception.Response.StatusCode
            $Stream = $ErrorRecord.Exception.Response.GetResponseStream()

            if ($Stream) {
                $Reader = New-Object System.IO.StreamReader($Stream)

                try {
                    $Body = $Reader.ReadToEnd()
                }
                finally {
                    $Reader.Dispose()
                }
            }
        }
    }
    catch {
    }

    [PSCustomObject]@{
        httpStatus = $Status
        message = Convert-SafeOutput $ErrorRecord.Exception.Message
        responseBody = Convert-SafeOutput $Body
    }
}


function Get-HttpStatusCode {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    try {
        if ($ErrorRecord.Exception.Response) {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
    }
    catch {
    }

    return $null
}

function Invoke-WatchGuardRestMethod {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Get', 'Post')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [AllowNull()]
        [hashtable]$Headers,

        [AllowNull()]
        [object]$Body,

        [AllowNull()]
        [string]$ContentType,

        [int]$TimeoutSec = 60,

        [string]$RetryLabel = 'WatchGuardApi'
    )

    $Attempt = 0

    while ($true) {
        $Attempt++

        $InvokeParams = @{
            Method = $Method
            Uri = $Uri
            TimeoutSec = $TimeoutSec
            ErrorAction = 'Stop'
        }

        if ($null -ne $Headers) {
            $InvokeParams['Headers'] = $Headers
        }

        if ($null -ne $Body) {
            $InvokeParams['Body'] = $Body
        }

        if (-not [string]::IsNullOrWhiteSpace($ContentType)) {
            $InvokeParams['ContentType'] = $ContentType
        }

        try {
            # Global inventory is deliberately paced to reduce WatchGuard
            # rate pressure before any transient-error backoff is required.
            if ($ApiRequestSpacingMilliseconds -gt 0) {
                Start-Sleep -Milliseconds $ApiRequestSpacingMilliseconds
            }
            return Invoke-RestMethod @InvokeParams
        }
        catch {
            $StatusCode = Get-HttpStatusCode -ErrorRecord $_

            $IsTransient =
                (
                    $null -ne $StatusCode -and
                    $StatusCode -in $TransientRetryStatusCodes
                )

            if (
                -not $IsTransient -or
                $Attempt -ge $TransientRetryMaxAttempts
            ) {
                throw
            }

            $DelayIndex = [Math]::Min(
                $Attempt - 1,
                $TransientRetryDelaysSeconds.Count - 1
            )

            $DelaySeconds =
                $TransientRetryDelaysSeconds[$DelayIndex]

            Write-Log (
                'API_RETRY | Label={0} Attempt={1}/{2} HTTP={3} DelaySeconds={4}' -f
                $RetryLabel,
                $Attempt,
                $TransientRetryMaxAttempts,
                $StatusCode,
                $DelaySeconds
            )

            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Normalize-Fingerprint {
    param(
        [AllowNull()]
        [string]$Fingerprint
    )

    if ([string]::IsNullOrWhiteSpace($Fingerprint)) {
        return $null
    }

    return (
        $Fingerprint `
            -replace '[^0-9A-Fa-f]', ''
    ).ToUpperInvariant()
}

function Format-Fingerprint {
    param(
        [AllowNull()]
        [string]$Fingerprint
    )

    $Normalized = Normalize-Fingerprint $Fingerprint

    if ([string]::IsNullOrWhiteSpace($Normalized)) {
        return $null
    }

    $Parts = @()

    for ($i = 0; $i -lt $Normalized.Length; $i += 2) {
        $PartLength = [Math]::Min(
            2,
            $Normalized.Length - $i
        )

        $Parts += $Normalized.Substring(
            $i,
            $PartLength
        )
    }

    return $Parts -join ':'
}

function Convert-UnixTime {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        return (
            [DateTimeOffset]::FromUnixTimeSeconds(
                [int64]$Value
            )
        ).UtcDateTime.ToString(
            'yyyy-MM-ddTHH:mm:ssZ'
        )
    }
    catch {
        return $null
    }
}

# Record expiry independently of whether a certificate is in the source
# package. An invalid/missing Unix timestamp is UNKNOWN, never assumed safe.
function Get-CertificateExpirationStatus {
    param(
        [AllowNull()]
        [object]$UnixExpiration
    )

    if ($null -eq $UnixExpiration -or
        [string]::IsNullOrWhiteSpace([string]$UnixExpiration)) {
        return 'Unknown'
    }

    try {
        $ExpiresAt = [DateTimeOffset]::FromUnixTimeSeconds(
            [int64]$UnixExpiration
        )
        if ($ExpiresAt -le $script:AuditTimestampUtc) {
            return 'Expired'
        }
        return 'NotExpired'
    }
    catch {
        return 'Unknown'
    }
}

# ============================================================
# RESPONSE ARRAY HELPERS
# ============================================================

function Get-CertificateArray {
    param(
        [AllowNull()]
        [object]$Response
    )

    if ($null -eq $Response) {
        return @()
    }

    if ($Response -is [System.Array]) {
        return @($Response)
    }

    foreach ($PropertyName in @(
        'certificates'
        'items'
        'data'
        'results'
    )) {
        if (
            $Response.PSObject.Properties.Name -contains
            $PropertyName
        ) {
            return @($Response.$PropertyName)
        }
    }

    return @($Response)
}

function Get-InventoryArray {
    param(
        [AllowNull()]
        [object]$Response
    )

    if ($null -eq $Response) {
        return @()
    }

    if ($Response -is [System.Array]) {
        return @($Response)
    }

    foreach ($PropertyName in @(
        'items'
        'data'
        'results'
        'objects'
    )) {
        if (
            $Response.PSObject.Properties.Name -contains
            $PropertyName
        ) {
            return @($Response.$PropertyName)
        }
    }

    return @($Response)
}

# ============================================================
# 1PASSWORD HELPERS
# ============================================================

function Get-OnePasswordField {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$Label
    )

    $Field = @(
        $Item.fields |
        Where-Object {
            $_.label -eq $Label -or
            $_.id -eq $Label
        }
    ) |
        Select-Object -First 1

    if ($null -eq $Field) {
        throw "Required 1Password field not found: $Label"
    }

    $Value = [string]$Field.value

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Required 1Password field is empty: $Label"
    }

    return $Value.Trim()
}

function Get-OnePasswordAttachment {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$VaultName,

        [Parameter(Mandatory)]
        [string]$ItemName
    )

    $Candidates = [System.Collections.Generic.List[object]]::new()

    if ($Item.PSObject.Properties.Name -contains 'files') {
        foreach ($File in @($Item.files)) {
            if ($null -eq $File) {
                continue
            }

            $Name = [string]$File.name
            $Reference = [string]$File.reference

            if ([string]::IsNullOrWhiteSpace($Name)) {
                continue
            }

            if ([string]::IsNullOrWhiteSpace($Reference)) {
                $Reference = "op://$VaultName/$ItemName/$Name"
            }

            $Candidates.Add(
                [PSCustomObject]@{
                    name = $Name
                    reference = $Reference
                }
            ) | Out-Null
        }
    }

    foreach ($Field in @($Item.fields)) {
        if ($null -eq $Field) {
            continue
        }

        if ([string]$Field.type -notmatch '^FILE$') {
            continue
        }

        $Name = [string]$Field.label
        $Reference = [string]$Field.reference

        if ([string]::IsNullOrWhiteSpace($Name)) {
            continue
        }

        if ([string]::IsNullOrWhiteSpace($Reference)) {
            $Reference = "op://$VaultName/$ItemName/$Name"
        }

        $Candidates.Add(
            [PSCustomObject]@{
                name = $Name
                reference = $Reference
            }
        ) | Out-Null
    }

    $Unique = @(
        $Candidates |
        Group-Object reference |
        ForEach-Object {
            $_.Group[0]
        }
    )

    $Pfx = @(
        $Unique |
        Where-Object {
            $_.name -match '\.(pfx|p12)$'
        }
    )

    if ($Pfx.Count -eq 1) {
        return $Pfx[0]
    }

    if ($Pfx.Count -gt 1) {
        throw "Multiple PFX attachments found on '$ItemName'."
    }

    if ($Unique.Count -eq 1) {
        return $Unique[0]
    }

    throw "Unable to uniquely identify certificate PFX on '$ItemName'."
}

function Remove-TemporaryPfx {
    if (Test-Path -LiteralPath $TempPfxPath) {
        try {
            Remove-Item `
                -LiteralPath $TempPfxPath `
                -Force `
                -ErrorAction Stop
        }
        catch {
        }
    }
}

# ============================================================
# WATCHGUARD AUTH
# ============================================================

function Get-WatchGuardAccessToken {
    param(
        [Parameter(Mandatory)]
        [string]$AuthenticationUrl,

        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [string]$Password,

        [AllowNull()]
        [string]$Audience
    )

    $Pair = '{0}:{1}' -f $AccessId, $Password

    $Basic = [Convert]::ToBase64String(
        [Text.Encoding]::ASCII.GetBytes(
            $Pair
        )
    )

    $Headers = @{
        Accept = 'application/json'
        Authorization = "Basic $Basic"
    }

    $Body = @{
        grant_type = 'client_credentials'
        scope = 'api-access'
    }

    if (-not [string]::IsNullOrWhiteSpace($Audience)) {
        $Body['audience'] = $Audience
    }

    $Response =
        Invoke-WatchGuardRestMethod `
            -Method Post `
            -Uri $AuthenticationUrl `
            -Headers $Headers `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body $Body `
            -TimeoutSec 60 `
            -RetryLabel 'Authentication'

    if (
        $null -eq $Response -or
        [string]::IsNullOrWhiteSpace(
            [string]$Response.access_token
        )
    ) {
        throw 'WatchGuard authentication returned no access_token.'
    }

    return [string]$Response.access_token
}

function Refresh-ProviderToken {
    $script:ProviderToken =
        Get-WatchGuardAccessToken `
            -AuthenticationUrl $AuthenticationUrl `
            -AccessId $ReadOnlyAccessId `
            -Password $ReadOnlyPassword

    $script:ProviderTokenIssuedAt = Get-Date
}

function Get-ProviderHeaders {
    return @{
        Accept = 'application/json'
        'Content-Type' = 'application/json'
        Authorization = "Bearer $ProviderToken"
        'WatchGuard-API-Key' = $ApiKey
    }
}

# ============================================================
# ACCOUNT HELPERS
# ============================================================

function Expand-ManagedAccounts {
    param(
        [object[]]$Accounts
    )

    foreach ($Account in @($Accounts)) {
        if ($null -eq $Account) {
            continue
        }

        Write-Output $Account

        if (
            $Account.PSObject.Properties.Name -contains
            'childrenList'
        ) {
            $Children = @($Account.childrenList)

            if ($Children.Count -gt 0) {
                Expand-ManagedAccounts `
                    -Accounts $Children
            }
        }
    }
}

function Test-DelegatedAccount {
    param(
        [Parameter(Mandatory)]
        [object]$Account
    )

    return (
        [string]$Account.relationName -ieq 'Delegated' -or
        [string]$Account.relationType -ieq 'Delegated'
    )
}

# ============================================================
# CERTIFICATE HELPERS
# ============================================================

function Test-FireboxNativeCertificate {
    param(
        [AllowNull()]
        [object]$Certificate
    )

    if ($null -eq $Certificate) {
        return $false
    }

    $Text = @(
        [string]$Certificate.name
        [string]$Certificate.subject
        [string]$Certificate.issuer
    ) -join ' '

    return (
        $Text -match '(?i)fireware|watchguard'
    )
}

function Get-CertificateReferences {
    param(
        [Parameter(Mandatory)]
        [object]$Certificate
    )

    $ReferencedBy = @()

    if (
        $Certificate.PSObject.Properties.Name -contains
        'referencedBy'
    ) {
        $ReferencedBy = @($Certificate.referencedBy)
    }
    elseif (
        $Certificate.PSObject.Properties.Name -contains
        'referencedby'
    ) {
        $ReferencedBy = @($Certificate.referencedby)
    }

    return @(
        $ReferencedBy |
        ForEach-Object {
            [string]$_
        } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }
    )
}

# ============================================================
# INITIALIZE
# ============================================================

Initialize-Directories
Remove-TemporaryPfx

Write-Log 'START | WatchGuard certificate rotation evidence READ_ONLY_GLOBAL_ROTATION_EVIDENCE_AUDIT'

try {

    # ========================================================
    # NINJA -> 1PASSWORD
    # ========================================================

    $CurrentStage = 'NinjaField'

    $ServiceAccountToken =
        (
            Ninja-Property-Get `
                -Name 'opServiceAccountToken'
        ).Trim()

    if ([string]::IsNullOrWhiteSpace($ServiceAccountToken)) {
        throw 'Ninja secure custom field opServiceAccountToken was empty.'
    }

    $env:OP_SERVICE_ACCOUNT_TOKEN = $ServiceAccountToken

    # ========================================================
    # LOCATE OP
    # ========================================================

    $CurrentStage = 'OnePasswordCLI'

    $Candidates = @(
        'C:\Program Files\1Password CLI\op.exe'
        'C:\Program Files\1Password\op.exe'
    )

    foreach ($Candidate in $Candidates) {
        if (Test-Path -LiteralPath $Candidate) {
            $OpExe = $Candidate
            break
        }
    }

    if (-not $OpExe) {
        $Command =
            Get-Command `
                'op.exe' `
                -ErrorAction SilentlyContinue

        if ($Command) {
            $OpExe = $Command.Source
        }
    }

    if (-not $OpExe) {
        throw 'Unable to locate op.exe.'
    }

    $null =
        & $OpExe whoami --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw '1Password service account authentication failed.'
    }

    # ========================================================
    # WATCHGUARD ITEM
    # ========================================================

    $CurrentStage = 'WatchGuardItem'

    $WatchGuardRaw =
        & $OpExe `
            item get `
            $WatchGuardItemName `
            --vault $OnePasswordVault `
            --format json `
            2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to retrieve WatchGuard item: $($WatchGuardRaw -join ' ')"
    }

    $WatchGuardItem =
        ($WatchGuardRaw -join "`n") |
        ConvertFrom-Json

    $ApiKey =
        Get-OnePasswordField `
            -Item $WatchGuardItem `
            -Label 'credential'

    $ReadOnlyAccessId =
        Get-OnePasswordField `
            -Item $WatchGuardItem `
            -Label 'readOnlyAccessId'

    $ReadOnlyPassword =
        Get-OnePasswordField `
            -Item $WatchGuardItem `
            -Label 'readOnlyPassword'

    $ProviderAccountId =
        Get-OnePasswordField `
            -Item $WatchGuardItem `
            -Label 'accountID'

    $AuthenticationUrl =
        (
            Get-OnePasswordField `
                -Item $WatchGuardItem `
                -Label 'authenticationUrl'
        ).TrimEnd('/')

    $BaseApiUrl =
        (
            Get-OnePasswordField `
                -Item $WatchGuardItem `
                -Label 'baseApiUrl'
        ).TrimEnd('/')

    # ========================================================
    # CERTIFICATE ITEM
    # ========================================================

    $CurrentStage = 'CertificateItem'

    $CertificateRaw =
        & $OpExe `
            item get `
            $CertificateItemName `
            --vault $OnePasswordVault `
            --format json `
            2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to retrieve certificate item: $($CertificateRaw -join ' ')"
    }

    $CertificateItem =
        ($CertificateRaw -join "`n") |
        ConvertFrom-Json

    $PfxPassword =
        Get-OnePasswordField `
            -Item $CertificateItem `
            -Label $CertificatePasswordField

    $PfxAttachment =
        Get-OnePasswordAttachment `
            -Item $CertificateItem `
            -VaultName $OnePasswordVault `
            -ItemName $CertificateItemName

    # ========================================================
    # RETRIEVE PFX
    # ========================================================

    $CurrentStage = 'CertificateFile'

    Remove-TemporaryPfx

    $PfxRead =
        & $OpExe `
            read `
            --out-file $TempPfxPath `
            $PfxAttachment.reference `
            2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to retrieve PFX: $($PfxRead -join ' ')"
    }

    if (-not (Test-Path -LiteralPath $TempPfxPath)) {
        throw 'Temporary PFX was not created.'
    }

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $ServiceAccountToken = $null

    # ========================================================
    # PARSE COMPLETE PFX
    # ========================================================

    $CurrentStage = 'CertificateParse'

    $PfxCollection =
        New-Object `
            System.Security.Cryptography.X509Certificates.X509Certificate2Collection

    $Flags =
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet

    $PfxCollection.Import(
        $TempPfxPath,
        $PfxPassword,
        $Flags
    )

    if ($PfxCollection.Count -eq 0) {
        throw 'PFX contained no certificates.'
    }

    $PrivateKeyCerts =
        @(
            $PfxCollection |
            Where-Object {
                $_.HasPrivateKey
            }
        )

    if ($PrivateKeyCerts.Count -ne 1) {
        throw (
            "Expected exactly one PFX leaf/private-key certificate. Found=$($PrivateKeyCerts.Count)"
        )
    }

    $Leaf = $PrivateKeyCerts[0]

    $DesiredLeafFingerprintNormalized =
        Normalize-Fingerprint $Leaf.Thumbprint

    $DesiredLeafFingerprint =
        Format-Fingerprint $Leaf.Thumbprint

    $ExpectedList =
        [System.Collections.Generic.List[object]]::new()

    $Seen =
        [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

    foreach ($Certificate in @($PfxCollection)) {
        $Normalized =
            Normalize-Fingerprint $Certificate.Thumbprint

        if (-not $Seen.Add($Normalized)) {
            continue
        }

        $ExpectedList.Add(
            [PSCustomObject]@{
                fingerprint =
                    Format-Fingerprint $Normalized

                fingerprintNormalized =
                    $Normalized

                subject =
                    [string]$Certificate.Subject

                issuer =
                    [string]$Certificate.Issuer

                hasPrivateKey =
                    [bool]$Certificate.HasPrivateKey

                validFromUtc =
                    $Certificate.NotBefore.
                        ToUniversalTime().
                        ToString('yyyy-MM-ddTHH:mm:ssZ')

                expirationUtc =
                    $Certificate.NotAfter.
                        ToUniversalTime().
                        ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
        ) | Out-Null
    }

    $ExpectedCertificates = $ExpectedList.ToArray()
    $ExpectedCertificateCount = $ExpectedCertificates.Count

    $ExpectedFingerprintsNormalized =
        @(
            $ExpectedCertificates |
            ForEach-Object {
                $_.fingerprintNormalized
            }
        )

    if ($ExpectedCertificateCount -ne 3) {
        throw (
            "Expected authoritative PFX package count=3 but parsed=$ExpectedCertificateCount"
        )
    }

    Write-Log (
        'PFX | Certificates={0} Leaf={1}' -f
        $ExpectedCertificateCount,
        $DesiredLeafFingerprint
    )

    Remove-TemporaryPfx

    # ========================================================
    # PROVIDER AUTH
    # ========================================================

    $CurrentStage = 'ProviderAuth'

    Refresh-ProviderToken

    # ========================================================
    # ACCOUNT ENUMERATION
    # ========================================================

    $CurrentStage = 'AccountEnumeration'

    $AccountsUri =
        "$BaseApiUrl/platform/accounts/v2/accounts/$ProviderAccountId/children" +
        '?type=0&limit=-1&includeDelegatedAccounts=true'

    $ProviderHeaders = Get-ProviderHeaders

    $AccountsResponse =
        Invoke-WatchGuardRestMethod `
            -Method Get `
            -Uri $AccountsUri `
            -Headers $ProviderHeaders `
            -TimeoutSec 120 `
            -RetryLabel 'AccountEnumeration'

    $AllAccounts =
        @(
            Expand-ManagedAccounts `
                -Accounts @($AccountsResponse.items)
        )

    $SubscriberAccounts =
        @(
            $AllAccounts |
            Where-Object {
                [int]$_.type -in @(2, 4)
            } |
            Group-Object accountId |
            ForEach-Object {
                $_.Group[0]
            }
        )

    # Global scope: process every discovered Subscriber, preserving delegated
    # relationship records for explicit skips below. No fixed target and no
    # sampling/seed restrictions. Stable order aids deterministic log review.
    $SubscriberAccounts = @($SubscriberAccounts | Sort-Object accountId)
    $AccountsDiscoveredCount = $SubscriberAccounts.Count
    $EligibleSubscriberCount = @(
        $SubscriberAccounts | Where-Object { -not (Test-DelegatedAccount $_) }
    ).Count

    Write-Log (
        'GLOBAL_SCOPE | SubscribersDiscovered={0} EligibleNonDelegated={1} DelegatedToSkip={2}' -f
        $AccountsDiscoveredCount,
        $EligibleSubscriberCount,
        ($AccountsDiscoveredCount - $EligibleSubscriberCount)
    )

    # ========================================================
    # AUDIT GLOBAL SUBSCRIBER SCOPE
    # ========================================================

    $AccountIndex = 0

    foreach ($Account in $SubscriberAccounts) {
        $AccountIndex++

        $AccountId = [string]$Account.accountId
        $AccountName = Convert-SafeOutput $Account.name
        $IsDelegated = Test-DelegatedAccount $Account

        $AccountStage = 'Initialize'

        $AccountDeviceResults =
            [System.Collections.Generic.List[object]]::new()

        $AccountFailures = 0
        $AccountErrors = 0
        $AccountCloud = 0
        $AccountLocal = 0
        $AccountUnknown = 0
        $AccountDeviceReviewFlags = 0

        Write-Log (
            'ACCOUNT_START | {0}/{1} Name={2} Account={3} Delegated={4}' -f
            $AccountIndex,
            $AccountsDiscoveredCount,
            $AccountName,
            $AccountId,
            $IsDelegated
        )

        if ($IsDelegated) {
            $DelegatedSkippedCount++

            $AccountResults.Add(
                [PSCustomObject]@{
                    accountId =
                        $AccountId

                    accountName =
                        $AccountName

                    scope =
                        'Global'

                    relationName =
                        [string]$Account.relationName

                    relationType =
                        [string]$Account.relationType

                    delegated =
                        $true

                    status =
                        'SkippedDelegated'

                    reviewFlags = @()

                    summary =
                        [PSCustomObject]@{
                            devicesAllocated = 0
                            devicesActive = 0
                            devicesAllocatedInactive = 0
                            cloudManaged = 0
                            locallyManaged = 0
                            managementModeUnknown = 0
                            cloudDevicesWithReviewFlags = 0
                            failures = 0
                            errors = 0
                        }

                    devices =
                        @()

                    failures =
                        0

                    errors =
                        0
                }
            ) | Out-Null

            Write-Log (
                'ACCOUNT_SKIP | Name={0} Account={1} Reason=Delegated' -f
                $AccountName,
                $AccountId
            )

            continue
        }

        $AccountsAuditedCount++

        try {
            if (
                $null -eq $ProviderTokenIssuedAt -or
                ((Get-Date) - $ProviderTokenIssuedAt).TotalMinutes -ge 45
            ) {
                Refresh-ProviderToken
                $ProviderHeaders = Get-ProviderHeaders
            }

            # =================================================
            # AUDIENCE
            # =================================================

            $AccountStage = 'Audience'

            $AudienceResponse =
                Invoke-WatchGuardRestMethod `
                    -Method Post `
                    -Uri "$BaseApiUrl/platform/authorization/v1/audiences" `
                    -Headers $ProviderHeaders `
                    -Body (
                        @{
                            accountId = $AccountId
                        } |
                        ConvertTo-Json -Compress
                    ) `
                    -TimeoutSec 60 `
                    -RetryLabel "Audience:$AccountId"

            $Audience = [string]$AudienceResponse.audience

            if ([string]::IsNullOrWhiteSpace($Audience)) {
                throw 'No WatchGuard audience returned.'
            }

            # =================================================
            # SUBSCRIBER TOKEN
            # =================================================

            $AccountStage = 'SubscriberAuth'

            $SubscriberToken =
                Get-WatchGuardAccessToken `
                    -AuthenticationUrl $AuthenticationUrl `
                    -AccessId $ReadOnlyAccessId `
                    -Password $ReadOnlyPassword `
                    -Audience $Audience

            $SubscriberHeaders = @{
                Accept = 'application/json'
                'Content-Type' = 'application/json'
                Authorization = "Bearer $SubscriberToken"
                'WatchGuard-API-Key' = $ApiKey
            }

            # =================================================
            # ACCOUNT CERTIFICATE AUDIT
            # =================================================

            $AccountStage = 'AccountCertificates'

            $CertificateUri =
                "$BaseApiUrl/firebox/management/v1/configuration/$AccountId/system/certificates"

            $CertificateResponse =
                Invoke-WatchGuardRestMethod `
                    -Method Get `
                    -Uri $CertificateUri `
                    -Headers $SubscriberHeaders `
                    -TimeoutSec 60 `
                    -RetryLabel "AccountCertificates:$AccountId"

            $ReturnedCertificates =
                @(
                    Get-CertificateArray $CertificateResponse
                )

            $AccountCertificates =
                @(
                    $ReturnedCertificates |
                    Where-Object {
                        -not (
                            $_.PSObject.Properties.Name -contains 'device'
                        ) -or
                        [string]::IsNullOrWhiteSpace(
                            [string]$_.device
                        )
                    }
                )

            $AccountCertificateManifest =
                [System.Collections.Generic.List[object]]::new()

            $AccountSourcePresent =
                [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase
                )

            $AccountNonSourceMME =
                [System.Collections.Generic.List[object]]::new()

            # Account-object IDs and metadata for exact qualified-alias correlation.
            # This is relationship evidence only, not proof of removal behavior.
            $AccountCertIds = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            $AccountCertificatesById =
                [System.Collections.Generic.Dictionary[string,object]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase
                )
            foreach ($AccountCert in $AccountCertificates) {
                $CertId = [string]$AccountCert.id
                if (-not [string]::IsNullOrWhiteSpace($CertId)) {
                    [void]$AccountCertIds.Add($CertId)
                    $AccountCertificatesById[$CertId] = $AccountCert
                }
            }


            foreach ($Certificate in $AccountCertificates) {
                $Normalized =
                    Normalize-Fingerprint $Certificate.cert_fingerprint
                $ExpirationStatus =
                    Get-CertificateExpirationStatus $Certificate.expiration

                $Classification = 'OTHER_CERTIFICATE'

                if (
                    -not [string]::IsNullOrWhiteSpace($Normalized) -and
                    $Normalized -in $ExpectedFingerprintsNormalized
                ) {
                    $Classification = 'SOURCE_PACKAGE_MATCH'
                    [void]$AccountSourcePresent.Add($Normalized)
                }
                elseif (
                    [string]$Certificate.name -imatch
                    $NonSourceMMECertificateNamePattern
                ) {
                    $Classification =
                        'NON_SOURCE_MME_CERTIFICATE'

                    $AccountNonSourceMME.Add(
                        [PSCustomObject]@{
                            id = [string]$Certificate.id
                            name = [string]$Certificate.name
                            certType = [string]$Certificate.cert_type
                            fingerprint =
                                Format-Fingerprint $Normalized
                            expirationUtc =
                                Convert-UnixTime $Certificate.expiration
                            expirationStatus = $ExpirationStatus
                        }
                    ) | Out-Null
                    $NonSourceMMEAccountCertificateCount++
                    if ($ExpirationStatus -eq 'Expired') {
                        $ExpiredNonSourceMMEAccountCertificateCount++
                    }
                }

                $AccountCertificateManifest.Add(
                    [PSCustomObject]@{
                        id = [string]$Certificate.id
                        name = [string]$Certificate.name
                        certType = [string]$Certificate.cert_type
                        fingerprint =
                            Format-Fingerprint $Normalized
                        subject = [string]$Certificate.subject
                        issuer = [string]$Certificate.issuer
                        validFromUtc =
                            Convert-UnixTime $Certificate.valid_from
                        expirationUtc =
                            Convert-UnixTime $Certificate.expiration
                        expirationStatus = $ExpirationStatus
                        classification =
                            $Classification
                        alias = [string]$Certificate.alias
                        references = @($Certificate.references)
                        referencedBy = @(Get-CertificateReferences $Certificate)
                    }
                ) | Out-Null
            }

            $AccountSourceMissing =
                @(
                    $ExpectedCertificates |
                    Where-Object {
                        -not $AccountSourcePresent.Contains(
                            [string]$_.fingerprintNormalized
                        )
                    }
                )

            $AccountReviewFlags = [System.Collections.Generic.List[string]]::new()
            if ($AccountSourceMissing.Count -gt 0) {
                $AccountReviewFlags.Add('SOURCE_PACKAGE_INCOMPLETE') | Out-Null
            }
            if ($AccountNonSourceMME.Count -gt 0) {
                $AccountReviewFlags.Add('NON_SOURCE_MME_CERTIFICATES_PRESENT') | Out-Null
            }
            if ($AccountReviewFlags.Count -gt 0) {
                $AccountsWithReviewFlagsCount++
            }

            Write-Log (
                'ACCOUNT_CERT_RESULT | Name={0} Account={1} SourcePackage={2}/{3} Missing={4} NonSourceMME={5} ReviewFlags={6}' -f
                $AccountName, $AccountId, $AccountSourcePresent.Count,
                $ExpectedCertificateCount, $AccountSourceMissing.Count,
                $AccountNonSourceMME.Count, ($AccountReviewFlags.ToArray() -join ',')
            )

            # =================================================
            # ACTIVE ASSIGNED FIREBOX INVENTORY
            # =================================================

            $AccountStage = 'AssignedFireboxInventory'

            $InventoryUri =
                "$BaseApiUrl/platform/allocation/v2/$AccountId/assets/assigned/firebox?offset=0&limit=-1"

            $InventoryResponse =
                Invoke-WatchGuardRestMethod `
                    -Method Get `
                    -Uri $InventoryUri `
                    -Headers $SubscriberHeaders `
                    -TimeoutSec 60 `
                    -RetryLabel "AssignedFireboxInventory:$AccountId"

            $AssignedRaw =
                @(
                    Get-InventoryArray $InventoryResponse
                )

            $EvaluationUtc = [DateTimeOffset]::UtcNow

            $ActiveAssignedList =
                [System.Collections.Generic.List[object]]::new()

            $InactiveAssignedList =
                [System.Collections.Generic.List[object]]::new()

            foreach ($Firebox in $AssignedRaw) {
                $ExpiryRaw = [string]$Firebox.licenseExpiryDate

                $Active = $true
                $AllocationStatus = 'UnknownExpiry'

                if (
                    -not [string]::IsNullOrWhiteSpace(
                        $ExpiryRaw
                    )
                ) {
                    $Parsed =
                        [DateTimeOffset]::MinValue

                    if (
                        [DateTimeOffset]::TryParse(
                            $ExpiryRaw,
                            [ref]$Parsed
                        )
                    ) {
                        if ($Parsed -le $EvaluationUtc) {
                            $Active = $false
                            $AllocationStatus = 'Expired'
                        }
                        else {
                            $Active = $true
                            $AllocationStatus = 'Active'
                        }
                    }
                }

                $Decorated =
                    [PSCustomObject]@{
                        friendlyName =
                            [string]$Firebox.friendlyName

                        modelName =
                            [string]$Firebox.modelName

                        serialOrLicense =
                            [string]$Firebox.serialOrLicense

                        macAddress =
                            [string]$Firebox.macAddress

                        licenseExpiryDate =
                            $ExpiryRaw

                        allocationStatus =
                            $AllocationStatus
                    }

                if ($Active) {
                    $ActiveAssignedList.Add($Decorated) | Out-Null
                }
                else {
                    $InactiveAssignedList.Add($Decorated) | Out-Null
                }
            }

            $ActiveAssigned = $ActiveAssignedList.ToArray()
            $InactiveAssigned = $InactiveAssignedList.ToArray()

            Write-Log (
                'DEVICE_COUNT | Name={0} Account={1} Active={2} AllocatedInactive={3}' -f
                $AccountName,
                $AccountId,
                $ActiveAssigned.Count,
                $InactiveAssigned.Count
            )

            # =================================================
            # CLOUD DEVICE INDEX / MANAGEMENT MODE
            # =================================================

            $AccountStage = 'CloudDeviceIndex'

            $PolicyUri =
                "$BaseApiUrl/firebox/management/v1/configuration/$AccountId/firewall/policies?full=0"

            $PolicyResponse =
                Invoke-WatchGuardRestMethod `
                    -Method Get `
                    -Uri $PolicyUri `
                    -Headers $SubscriberHeaders `
                    -TimeoutSec 60 `
                    -RetryLabel "CloudDeviceIndex:$AccountId"

            $PolicyObjects =
                @(
                    Get-InventoryArray $PolicyResponse
                )

            $CloudDeviceIds =
                @(
                    $PolicyObjects |
                    ForEach-Object {
                        [string]$_.device
                    } |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
                )

            # Audit every cloud configuration device discovered for this
            # Subscriber. No fixed device ID or positional inventory mapping.

            $ExpectedLocalCount =
                [Math]::Max(
                    0,
                    (
                        $ActiveAssigned.Count -
                        $CloudDeviceIds.Count
                    )
                )

            $AccountCloud = $CloudDeviceIds.Count
            $AccountLocal = $ExpectedLocalCount

            $ManagedAddedDeviceCount =
                $AccountCloud +
                $AccountLocal

            $TotalActiveDevices += $ManagedAddedDeviceCount
            $TotalCloudManaged += $AccountCloud
            $TotalLocallyManaged += $AccountLocal

            Write-Log (
                'MANAGEMENT_SPLIT | Name={0} Account={1} AllocationActive={2} CloudAdded={3} LocalAdded={4} ManagedAdded={5}' -f
                $AccountName,
                $AccountId,
                $ActiveAssigned.Count,
                $AccountCloud,
                $AccountLocal,
                $ManagedAddedDeviceCount
            )

            # =================================================
            # AUDIT EACH CLOUD-MANAGED DEVICE
            # =================================================

            foreach ($DeviceId in $CloudDeviceIds) {
                $AccountStage =
                    "DeviceCertificates:$DeviceId"

                $DeviceCertificateUri =
                    '{0}?device={1}' -f
                    $CertificateUri,
                    [uri]::EscapeDataString($DeviceId)

                $DeviceCertResponse =
                    Invoke-WatchGuardRestMethod `
                        -Method Get `
                        -Uri $DeviceCertificateUri `
                        -Headers $SubscriberHeaders `
                        -TimeoutSec 60 `
                        -RetryLabel "DeviceCertificates:${AccountId}:${DeviceId}"

                $DeviceCertificates =
                    @(
                        Get-CertificateArray $DeviceCertResponse
                    )

                $SourcePresent =
                    [System.Collections.Generic.HashSet[string]]::new(
                        [System.StringComparer]::OrdinalIgnoreCase
                    )

                $NonSourceMMECertificates =
                    [System.Collections.Generic.List[object]]::new()

                $DeviceCertificateManifest =
                    [System.Collections.Generic.List[object]]::new()

                $WebServerCandidates =
                    [System.Collections.Generic.List[object]]::new()
                $DeviceHasOriginConflict = $false
                $DeviceOriginCounts = [ordered]@{
                    accountLinked = 0
                    directImportPattern = 0
                    unresolved = 0
                    conflictOrPartial = 0
                }

                foreach ($Certificate in $DeviceCertificates) {
                    $Normalized =
                        Normalize-Fingerprint `
                            $Certificate.cert_fingerprint
                    $ExpirationStatus =
                        Get-CertificateExpirationStatus $Certificate.expiration

                    $Formatted =
                        Format-Fingerprint $Normalized

                    $MatchesSourcePackage =
                        (
                            -not [string]::IsNullOrWhiteSpace(
                                $Normalized
                            ) -and
                            $Normalized -in
                            $ExpectedFingerprintsNormalized
                        )

                    $Classification = 'OTHER_CERTIFICATE'

                    if ($MatchesSourcePackage) {
                        $Classification = 'SOURCE_PACKAGE_MATCH'

                        [void]$SourcePresent.Add(
                            $Normalized
                        )
                    }
                    elseif (
                        Test-FireboxNativeCertificate `
                            $Certificate
                    ) {
                        $Classification =
                            'FIREBOX_NATIVE'
                    }
                    elseif (
                        [string]$Certificate.name -imatch
                        $NonSourceMMECertificateNamePattern
                    ) {
                        $Classification =
                            'NON_SOURCE_MME_CERTIFICATE'

                        $NonSourceMMECertificates.Add(
                            [PSCustomObject]@{
                                id =
                                    [string]$Certificate.id

                                name =
                                    [string]$Certificate.name

                                certType =
                                    [string]$Certificate.cert_type

                                fingerprint =
                                    $Formatted

                                expirationUtc =
                                    Convert-UnixTime $Certificate.expiration

                                expirationStatus =
                                    $ExpirationStatus
                            }
                        ) | Out-Null
                        $NonSourceMMEDeviceCertificateCount++
                        if ($ExpirationStatus -eq 'Expired') {
                            $ExpiredNonSourceMMEDeviceCertificateCount++
                        }
                    }

                    $ReferencedBy =
                        @(
                            Get-CertificateReferences `
                                $Certificate
                        )

                    # Correlate a qualified device alias to the exact account
                    # certificate, not to its bare ID or only its fingerprint.
                    # Verify both reference directions and the fingerprints.
                    # This establishes a corroborated account relationship,
                    # NOT yet proven inheritance/cascade behavior.
                    $DeviceAlias = ([string]$Certificate.alias).Trim()
                    $DeviceReferences = @(
                        @($Certificate.references) |
                        ForEach-Object { [string]$_ } |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                    )
                    $AliasMatchesAccountId = $false
                    $AliasAccountMatchesTarget = $false
                    $AliasTargetCertificateId = $null
                    $AliasFingerprintMatchesAccount = $false
                    $AccountReferencesDeviceCertificate = $false
                    $DeviceReferencesAccountCertificate = $false
                    $OriginEvidence = 'NOT_APPLICABLE'
                    $RelevantMME = ($MatchesSourcePackage -or
                        ([string]$Certificate.name -imatch $NonSourceMMECertificateNamePattern))

                    if ($RelevantMME) {
                        $OriginEvidence = 'ORIGIN_UNRESOLVED'
                        if (-not [string]::IsNullOrWhiteSpace($DeviceAlias)) {
                            $AliasPrefix = '{0}/' -f $AccountId
                            if ($DeviceAlias.StartsWith(
                                $AliasPrefix,
                                [System.StringComparison]::OrdinalIgnoreCase
                            )) {
                                $AliasAccountMatchesTarget = $true
                                $AliasTargetCertificateId =
                                    $DeviceAlias.Substring($AliasPrefix.Length)
                            }
                            elseif ($AccountCertIds.Contains($DeviceAlias)) {
                                # Unqualified account ID is not reciprocal evidence.
                                $AliasTargetCertificateId = $DeviceAlias
                            }

                            if (
                                -not [string]::IsNullOrWhiteSpace($AliasTargetCertificateId) -and
                                $AccountCertificatesById.ContainsKey($AliasTargetCertificateId)
                            ) {
                                $AliasMatchesAccountId = $true
                                $LinkedAccountCert =
                                    $AccountCertificatesById[$AliasTargetCertificateId]
                                $AccountFingerprint = Normalize-Fingerprint `
                                    $LinkedAccountCert.cert_fingerprint
                                $AliasFingerprintMatchesAccount = (
                                    -not [string]::IsNullOrWhiteSpace($Normalized) -and
                                    $Normalized -eq $AccountFingerprint
                                )
                                $DeviceCertificateReference =
                                    '{0}/{1}' -f $AccountId, ([string]$Certificate.id)
                                $AccountReferencesDeviceCertificate = (
                                    @(Get-CertificateReferences $LinkedAccountCert) -contains
                                        $DeviceCertificateReference
                                )
                                $DeviceReferencesAccountCertificate = (
                                    $DeviceReferences -contains $DeviceAlias
                                )
                                if (-not $AliasFingerprintMatchesAccount) {
                                    $OriginEvidence = 'ACCOUNT_LINK_CONFLICT'
                                }
                                elseif (
                                    $AliasAccountMatchesTarget -and
                                    $AccountReferencesDeviceCertificate -and
                                    $DeviceReferencesAccountCertificate
                                ) {
                                    $OriginEvidence = 'ACCOUNT_LINK_RECIPROCAL'
                                }
                                else {
                                    $OriginEvidence = 'ACCOUNT_LINK_PARTIAL'
                                }
                            }
                            else {
                                $OriginEvidence = 'ACCOUNT_LINK_CONFLICT'
                            }
                        }
                        elseif ($MatchesSourcePackage -and $DeviceReferences.Count -eq 0 -and
                                $AccountSourcePresent.Contains($Normalized)) {
                            # Negative control: directly importing the same PFX leaf
                            # produced no alias, forward or reverse account reference.
                            # Confirm reverse absence for this exact DEVICE OBJECT.
                            # This remains a pattern, not deletion authorization.
                            $DeviceCertificateReference =
                                '{0}/{1}' -f $AccountId, ([string]$Certificate.id)
                            $ReverseFound = $false
                            foreach ($PossibleAccountCert in $AccountCertificates) {
                                if ((Normalize-Fingerprint $PossibleAccountCert.cert_fingerprint) -eq
                                    $Normalized) {
                                    if (@(Get-CertificateReferences $PossibleAccountCert) -contains
                                        $DeviceCertificateReference) {
                                        $ReverseFound = $true
                                        break
                                    }
                                }
                            }
                            if ($ReverseFound) {
                                $OriginEvidence = 'ACCOUNT_LINK_CONFLICT'
                            }
                            else {
                                $OriginEvidence = 'DEVICE_DIRECT_IMPORT_PATTERN'
                            }
                        }
                    }
                    if ($OriginEvidence -eq 'ACCOUNT_LINK_RECIPROCAL') {
                        $ReciprocalAccountLinkCount++
                    }
                    elseif ($OriginEvidence -eq 'DEVICE_DIRECT_IMPORT_PATTERN') {
                        $DirectImportPatternCount++
                    }
                    elseif ($OriginEvidence -eq 'ACCOUNT_LINK_CONFLICT' -or
                            $OriginEvidence -eq 'ACCOUNT_LINK_PARTIAL') {
                        $DeviceHasOriginConflict = $true
                    }

                    if ($RelevantMME) {
                        switch ($OriginEvidence) {
                            'ACCOUNT_LINK_RECIPROCAL' { $DeviceOriginCounts.accountLinked++ }
                            'DEVICE_DIRECT_IMPORT_PATTERN' { $DeviceOriginCounts.directImportPattern++ }
                            { $_ -in @('ACCOUNT_LINK_CONFLICT','ACCOUNT_LINK_PARTIAL') } {
                                $DeviceOriginCounts.conflictOrPartial++
                            }
                            default { $DeviceOriginCounts.unresolved++ }
                        }
                    }

                    $IsWebServer =
                        (
                            [string]$Certificate.cert_type -ieq
                            'web_server'
                        )

                    $MatchesSourceLeaf =
                        (
                            -not [string]::IsNullOrWhiteSpace(
                                $Normalized
                            ) -and
                            $Normalized -eq
                            $DesiredLeafFingerprintNormalized
                        )

                    if ($IsWebServer) {
                        $WebServerCandidates.Add(
                            [PSCustomObject]@{
                                id =
                                    [string]$Certificate.id

                                name =
                                    [string]$Certificate.name

                                fingerprint =
                                    $Formatted

                                referencedBy =
                                    $ReferencedBy

                                referencedByCount =
                                    $ReferencedBy.Count

                                matchesSourceLeaf =
                                    [bool]$MatchesSourceLeaf
                            }
                        ) | Out-Null
                    }

                    $DeviceCertificateManifest.Add(
                        [PSCustomObject]@{
                            id =
                                [string]$Certificate.id

                            name =
                                [string]$Certificate.name

                            certType =
                                [string]$Certificate.cert_type

                            fingerprint =
                                $Formatted

                            subject =
                                [string]$Certificate.subject

                            issuer =
                                [string]$Certificate.issuer

                            validFromUtc =
                                Convert-UnixTime `
                                    $Certificate.valid_from

                            expirationUtc =
                                Convert-UnixTime `
                                    $Certificate.expiration

                            expirationStatus =
                                $ExpirationStatus

                            referencedBy =
                                $ReferencedBy

                            matchesSourcePackage =
                                [bool]$MatchesSourcePackage

                            matchesSourceLeaf =
                                [bool]$MatchesSourceLeaf

                            alias = $DeviceAlias
                            references = $DeviceReferences
                            originEvidence = $OriginEvidence
                            aliasMatchesAccountId = [bool]$AliasMatchesAccountId
                            aliasAccountMatchesTarget = [bool]$AliasAccountMatchesTarget
                            aliasTargetCertificateId = $AliasTargetCertificateId
                            aliasFingerprintMatchesAccount = [bool]$AliasFingerprintMatchesAccount
                            accountReferencesDeviceCertificate = [bool]$AccountReferencesDeviceCertificate
                            deviceReferencesAccountCertificate = [bool]$DeviceReferencesAccountCertificate

                            classification =
                                $Classification
                        }
                    ) | Out-Null
                    if ($MatchesSourcePackage -or $Classification -eq 'NON_SOURCE_MME_CERTIFICATE') {
                        Write-Log (
                            'CERT_ORIGIN | Account={0} Device={1} CertId={2} Fingerprint={3} Alias={4} Status={5} ReferencesCount={6} AccountIdMatch={7} FingerprintMatch={8} ReverseReference={9} ForwardReference={10}' -f
                            $AccountId, $DeviceId, ([string]$Certificate.id),
                            $Formatted, (Convert-SafeOutput $DeviceAlias),
                            $OriginEvidence, $DeviceReferences.Count,
                            $AliasMatchesAccountId, $AliasFingerprintMatchesAccount,
                            $AccountReferencesDeviceCertificate, $DeviceReferencesAccountCertificate
                        )
                    }
                }

                $MissingSourceCertificates =
                    @(
                        $ExpectedCertificates |
                        Where-Object {
                            -not $SourcePresent.Contains(
                                [string]$_.fingerprintNormalized
                            )
                        } |
                        ForEach-Object {
                            [PSCustomObject]@{
                                fingerprint =
                                    $_.fingerprint

                                subject =
                                    $_.subject

                                issuer =
                                    $_.issuer

                                hasPrivateKey =
                                    $_.hasPrivateKey
                            }
                        }
                    )

                # ---------------------------------------------
                # WEB SERVER CERTIFICATE ASSIGNMENT
                # ---------------------------------------------

                $ReferencedWebServerCandidates =
                    @(
                        $WebServerCandidates.ToArray() |
                        Where-Object {
                            $_.referencedByCount -gt 0
                        }
                    )

                $WebServerBindingDetermined = $true
                $WebServerMode = 'DefaultFirebox'
                $SelectedWebServerName = 'Default certificate signed by Firebox'
                $SelectedWebServerId = $null
                $SelectedWebServerFingerprint = $null
                $WebServerUsesSourceLeaf = $false

                if (
                    $ReferencedWebServerCandidates.Count -eq 1
                ) {
                    $Selected =
                        $ReferencedWebServerCandidates[0]

                    $WebServerMode = 'ThirdParty'
                    $SelectedWebServerName = $Selected.name
                    $SelectedWebServerId = $Selected.id
                    $SelectedWebServerFingerprint = $Selected.fingerprint
                    $WebServerUsesSourceLeaf = [bool]$Selected.matchesSourceLeaf
                }
                elseif (
                    $ReferencedWebServerCandidates.Count -gt 1
                ) {
                    $WebServerBindingDetermined = $false
                    $WebServerMode = 'Unknown'
                    $SelectedWebServerName = $null
                }

                # ---------------------------------------------
                # SAFETY REVIEW FLAGS (NOT REMEDIATION DECISIONS)
                # ---------------------------------------------

                $DeviceReviewFlags = [System.Collections.Generic.List[string]]::new()
                if ($NonSourceMMECertificates.Count -gt 0) {
                    $DeviceReviewFlags.Add('NON_SOURCE_MME_CERTIFICATES_PRESENT') | Out-Null
                }
                if ($DeviceHasOriginConflict) {
                    $DeviceReviewFlags.Add('CERTIFICATE_ORIGIN_CONFLICT_OR_PARTIAL') | Out-Null
                }
                if (-not $WebServerBindingDetermined) {
                    $DeviceReviewFlags.Add('WEB_SERVER_BINDING_UNDETERMINED') | Out-Null
                    $FailureCount++
                    $AccountFailures++
                }
                if ($DeviceReviewFlags.Count -gt 0) {
                    $DevicesWithReviewFlagsCount++
                    $AccountDeviceReviewFlags++
                }
                if ($WebServerUsesSourceLeaf) {
                    $WebServerSourceLeafSelectionCount++
                }

                $DeviceFailure = -not $WebServerBindingDetermined
                $FailureReason = $null
                if ($DeviceFailure) {
                    $DeviceStatus = 'Failure'
                    $FailureReason = 'WebServerBindingUndetermined'
                }
                elseif ($DeviceReviewFlags.Count -gt 0) {
                    $DeviceStatus = 'Review'
                }
                else {
                    $DeviceStatus = 'Audited'
                }

                $CloudResult =
                    [PSCustomObject]@{
                        deviceId = $DeviceId
                        managementMode = 'CloudManaged'
                        managementModeSource = 'FirewallPolicyDeviceIndex'
                        auditComplete = [bool]$WebServerBindingDetermined
                        failure = [bool]$DeviceFailure
                        failureReason = $FailureReason
                        status = $DeviceStatus
                        reviewFlags = $DeviceReviewFlags.ToArray()
                        sourcePackageCertificateCount = $ExpectedCertificateCount
                        sourcePackagePresentCount = $SourcePresent.Count
                        sourcePackageMissingCount = $MissingSourceCertificates.Count
                        sourcePackageMissingCertificates = $MissingSourceCertificates
                        nonSourceMMECertificateCount = $NonSourceMMECertificates.Count
                        expiredNonSourceMMECertificateCount = @(
                            $NonSourceMMECertificates.ToArray() |
                            Where-Object { $_.expirationStatus -eq 'Expired' }
                        ).Count
                        nonSourceMMECertificates = $NonSourceMMECertificates.ToArray()
                        originEvidenceCounts = [PSCustomObject]$DeviceOriginCounts
                        certificateCount = $DeviceCertificates.Count
                        certificates = $DeviceCertificateManifest.ToArray()
                        webServerCertificate = [PSCustomObject]@{
                            bindingDetermined = [bool]$WebServerBindingDetermined
                            mode = $WebServerMode
                            selectedName = $SelectedWebServerName
                            selectedId = $SelectedWebServerId
                            selectedFingerprint = $SelectedWebServerFingerprint
                            usesSourceLeaf = [bool]$WebServerUsesSourceLeaf
                            candidateCount = $WebServerCandidates.Count
                            referencedCandidateCount = $ReferencedWebServerCandidates.Count
                            candidates = $WebServerCandidates.ToArray()
                        }
                    }

                $AccountDeviceResults.Add(
                    $CloudResult
                ) | Out-Null

                Write-Log (
                    'DEVICE_RESULT | Account={0} Device={1} Management=CloudManaged SourcePackage={2}/{3} Missing={4} NonSourceMME={5} AccountLinks={6} DirectImportPatterns={7} WebServer={8} UsesSourceLeaf={9} ReviewFlags={10} Failure={11}' -f
                    $AccountId, $DeviceId, $SourcePresent.Count,
                    $ExpectedCertificateCount, $MissingSourceCertificates.Count,
                    $NonSourceMMECertificates.Count, $DeviceOriginCounts.accountLinked,
                    $DeviceOriginCounts.directImportPattern, $WebServerMode,
                    $WebServerUsesSourceLeaf, ($DeviceReviewFlags.ToArray() -join ','),
                    $DeviceFailure
                )
            }

            # =================================================
            # LOCAL-MANAGED INVENTORY REPRESENTATION
            #
            # Public allocation inventory gives friendly name /
            # serial / MAC / model but does not expose the cloud
            # configuration device ID. Therefore:
            #
            # - all-local account: every active assigned unit is
            #   safely represented as LocallyManaged.
            #
            # - mixed account: exact local count is known from
            #   ActiveAssigned - CloudDeviceIds, but individual
            #   allocation rows cannot be safely positionally
            #   matched to cloud device IDs by this API set.
            #
            # Do not infer identities.
            # =================================================

            if ($CloudDeviceIds.Count -eq 0) {
                foreach ($Device in $ActiveAssigned) {
                    $LocalResult =
                        [PSCustomObject]@{
                            deviceId = $null
                            name = $Device.friendlyName
                            serial = $Device.serialOrLicense
                            model = $Device.modelName
                            macAddress = $Device.macAddress
                            managementMode = 'LocallyManaged'
                            managementModeSource = 'NoCloudConfigurationDeviceIds'
                            auditComplete = $true
                            failure = $false
                            failureReason = $null
                            status = 'SkippedLocalManagement'
                        }

                    $AccountDeviceResults.Add(
                        $LocalResult
                    ) | Out-Null
                }
            }
            elseif (
                $CloudDeviceIds.Count -lt
                $ActiveAssigned.Count
            ) {
                # Count is authoritative for this method.
                # Exact local row identity is intentionally not
                # guessed for mixed fleets.
                for ($i = 1; $i -le $ExpectedLocalCount; $i++) {
                    $LocalResult =
                        [PSCustomObject]@{
                            deviceId = $null
                            name = $null
                            serial = $null
                            model = $null
                            macAddress = $null
                            managementMode = 'LocallyManaged'
                            managementModeSource = 'ActiveAssignedMinusCloudConfigurationCount'
                            auditComplete = $true
                            failure = $false
                            failureReason = $null
                            status = 'SkippedLocalManagement'
                            identityResolution = 'NotPositionallyInferred'
                        }

                    $AccountDeviceResults.Add(
                        $LocalResult
                    ) | Out-Null
                }
            }

            # =================================================
            # ACCOUNT RESULT
            # =================================================

            if ($AccountFailures -gt 0 -or $AccountErrors -gt 0) {
                $AccountStatus = 'Failure'
            }
            elseif ($AccountReviewFlags.Count -gt 0 -or $AccountDeviceReviewFlags -gt 0) {
                $AccountStatus = 'Review'
            }
            else {
                $AccountStatus = 'Audited'
            }

            $AccountResults.Add(
                [PSCustomObject]@{
                    accountId =
                        $AccountId

                    accountName =
                        $AccountName

                    scope =
                        'Global'

                    relationName =
                        [string]$Account.relationName

                    relationType =
                        [string]$Account.relationType

                    delegated =
                        $false

                    status =
                        $AccountStatus

                    reviewFlags = $AccountReviewFlags.ToArray()

                    accountCertificates =
                        [PSCustomObject]@{
                            sourcePackageCertificateCount = $ExpectedCertificateCount
                            sourcePackagePresentCount = $AccountSourcePresent.Count
                            sourcePackageComplete = ($AccountSourceMissing.Count -eq 0)
                            sourcePackageMissingCount = $AccountSourceMissing.Count
                            sourcePackageMissingCertificates = $AccountSourceMissing

                            nonSourceMMECertificateCount =
                                $AccountNonSourceMME.Count

                            expiredNonSourceMMECertificateCount = @(
                                $AccountNonSourceMME.ToArray() |
                                Where-Object { $_.expirationStatus -eq 'Expired' }
                            ).Count

                            nonSourceMMECertificates =
                                $AccountNonSourceMME.ToArray()

                            certificates =
                                $AccountCertificateManifest.ToArray()
                        }

                    summary =
                        [PSCustomObject]@{
                            devicesAllocated =
                                $AssignedRaw.Count

                            devicesActive =
                                $ManagedAddedDeviceCount

                            devicesAllocatedInactive =
                                $InactiveAssigned.Count

                            cloudManaged =
                                $AccountCloud

                            locallyManaged =
                                $AccountLocal

                            managementModeUnknown =
                                $AccountUnknown

                            cloudDevicesWithReviewFlags = $AccountDeviceReviewFlags

                            failures =
                                $AccountFailures

                            errors =
                                $AccountErrors
                        }

                    managementModeResolution =
                        [PSCustomObject]@{
                            source =
                                'cloud configuration device IDs plus allocation-active local remainder'

                            allocationActive =
                                $ActiveAssigned.Count

                            cloudDeviceIds =
                                @($CloudDeviceIds)

                            cloudDeviceCount =
                                $CloudDeviceIds.Count

                            localDeviceCount =
                                $ExpectedLocalCount

                            managedAddedDeviceCount =
                                $ManagedAddedDeviceCount

                            cloudExceedsAllocationActive =
                                ($CloudDeviceIds.Count -gt $ActiveAssigned.Count)

                            mixedFleetIdentityPolicy =
                                'DoNotPositionallyInfer'
                        }

                    assignedFireboxInventory =
                        @($ActiveAssigned)

                    allocatedInactiveInventory =
                        @($InactiveAssigned)

                    devices =
                        $AccountDeviceResults.ToArray()

                    failures =
                        $AccountFailures

                    errors =
                        $AccountErrors
                }
            ) | Out-Null

            Write-Log (
                'ACCOUNT_RESULT | Name={0} Account={1} ManagedAdded={2} Cloud={3} Local={4} AccountReviewFlags={5} DeviceReviewFlags={6} Failures={7} Errors={8} Status={9}' -f
                $AccountName,
                $AccountId,
                $ManagedAddedDeviceCount,
                $AccountCloud,
                $AccountLocal,
                ($AccountReviewFlags.ToArray() -join ','),
                $AccountDeviceReviewFlags,
                $AccountFailures,
                $AccountErrors,
                $AccountStatus
            )
        }
        catch {
            $ErrorCount++
            $AccountErrors++

            $Http = Get-HttpErrorDetail $_

            Write-Log (
                'ACCOUNT_ERROR | Name={0} Account={1} Stage={2} HTTP={3} Error={4}' -f
                $AccountName,
                $AccountId,
                $AccountStage,
                $Http.httpStatus,
                $Http.message
            )

            $AccountResults.Add(
                [PSCustomObject]@{
                    accountId =
                        $AccountId

                    accountName =
                        $AccountName

                    scope =
                        'Global'

                    relationName =
                        [string]$Account.relationName

                    relationType =
                        [string]$Account.relationType

                    delegated =
                        $false

                    status =
                        'Error'

                    reviewFlags = @()

                    summary =
                        [PSCustomObject]@{
                            devicesAllocated = 0
                            devicesActive = 0
                            devicesAllocatedInactive = 0
                            cloudManaged = 0
                            locallyManaged = 0
                            managementModeUnknown = 0
                            cloudDevicesWithReviewFlags = 0
                            failures = 0
                            errors = 1
                        }

                    devices =
                        @()

                    errorStage =
                        $AccountStage

                    httpStatus =
                        $Http.httpStatus

                    error =
                        $Http.message
                }
            ) | Out-Null
        }
    }

    # ========================================================
    # MANIFEST
    # ========================================================

    $CurrentStage = 'Manifest'

    $GeneratedUtc =
        [DateTime]::UtcNow.ToString(
            'yyyy-MM-ddTHH:mm:ssZ'
        )

    $GlobalScopeManifest =
        [ordered]@{
            subscriberAccountsDiscovered =
                $AccountsDiscoveredCount

            accountsAudited =
                $AccountsAuditedCount

            delegatedSkipped =
                $DelegatedSkippedCount

            includeDelegatedAccounts =
                $true

            delegatedPolicy =
                'ExplicitlySkipped'

            selectionMode =
                'AllDiscoveredSubscriberAccounts'

            eligibleSubscriberCount =
                $EligibleSubscriberCount

            cloudDeviceScope =
                'CloudManagedDevicesDiscoveredViaFirewallPolicyIndex'
        }

    $CertificatePackageManifest =
        [ordered]@{
            source =
                '1Password / MME Automation / MME SSL Certificate'

            certificateCount =
                $ExpectedCertificateCount

            leafFingerprint =
                $DesiredLeafFingerprint

            certificates =
                $ExpectedCertificates
        }

    $SummaryManifest =
        [ordered]@{
            accountsDiscovered =
                $AccountsDiscoveredCount

            accountsAudited =
                $AccountsAuditedCount

            delegatedSkipped =
                $DelegatedSkippedCount

            activeDevices =
                $TotalActiveDevices

            cloudManaged =
                $TotalCloudManaged

            locallyManaged =
                $TotalLocallyManaged

            managementModeUnknown =
                $TotalManagementUnknown

            accountsWithReviewFlags = $AccountsWithReviewFlagsCount
            cloudDevicesWithReviewFlags = $DevicesWithReviewFlagsCount
            reciprocalAccountLinks = $ReciprocalAccountLinkCount
            directImportPatterns = $DirectImportPatternCount
            webServersUsingSourceLeaf = $WebServerSourceLeafSelectionCount
            nonSourceMMEAccountCertificates = $NonSourceMMEAccountCertificateCount
            expiredNonSourceMMEAccountCertificates = $ExpiredNonSourceMMEAccountCertificateCount
            nonSourceMMEDeviceCertificates = $NonSourceMMEDeviceCertificateCount
            expiredNonSourceMMEDeviceCertificates = $ExpiredNonSourceMMEDeviceCertificateCount

            failures =
                $FailureCount

            errors =
                $ErrorCount
        }

    $Manifest =
        [ordered]@{
            schemaVersion = 6

            generatedUtc =
                $GeneratedUtc

            mode =
                'READ_ONLY_GLOBAL_ROTATION_EVIDENCE_AUDIT'

            globalScope =
                $GlobalScopeManifest

            sourceCertificatePackage =
                $CertificatePackageManifest

            summary =
                $SummaryManifest

            accounts =
                $AccountResults.ToArray()
        }

    $Manifest |
        ConvertTo-Json `
            -Depth 30 |
        Set-Content `
            -LiteralPath $ManifestPath `
            -Encoding UTF8

    Write-Log (
        'MANIFEST | Path={0} AccountsDiscovered={1} AccountsAudited={2} Cloud={3} Local={4} AccountsReview={5} DevicesReview={6} AccountLinks={7} DirectImportPatterns={8} WebServersUsingSourceLeaf={9} Failures={10} Errors={11}' -f
        $ManifestPath, $AccountsDiscoveredCount, $AccountsAuditedCount,
        $TotalCloudManaged, $TotalLocallyManaged, $AccountsWithReviewFlagsCount,
        $DevicesWithReviewFlagsCount, $ReciprocalAccountLinkCount,
        $DirectImportPatternCount, $WebServerSourceLeafSelectionCount,
        $FailureCount, $ErrorCount
    )

    # A read-only audit's success is RESULT; no action is authorized.
    $Token = if ($ErrorCount -gt 0 -or $FailureCount -gt 0) {
        'ERROR'
    } else {
        'RESULT'
    }

    Write-Output (
        '{0} | AccountsDiscovered={1} AccountsAudited={2} DelegatedSkipped={3} Devices={4} Cloud={5} Local={6} AccountsReview={7} DevicesReview={8} AccountLinks={9} DirectImportPatterns={10} WebServersUsingSourceLeaf={11} Failures={12} Errors={13} Manifest={14}' -f
        $Token, $AccountsDiscoveredCount, $AccountsAuditedCount,
        $DelegatedSkippedCount, $TotalActiveDevices, $TotalCloudManaged,
        $TotalLocallyManaged, $AccountsWithReviewFlagsCount,
        $DevicesWithReviewFlagsCount, $ReciprocalAccountLinkCount,
        $DirectImportPatternCount, $WebServerSourceLeafSelectionCount,
        $FailureCount, $ErrorCount, $ManifestPath
    )
}
catch {
    $Http = Get-HttpErrorDetail $_

    Write-Log (
        'FATAL | Stage={0} HTTP={1} Error={2}' -f
        $CurrentStage,
        $Http.httpStatus,
        $Http.message
    )

    Write-Output (
        'ERROR | Stage={0} HTTP={1} Message={2} Manifest={3}' -f
        $CurrentStage,
        $Http.httpStatus,
        $Http.message,
        $ManifestPath
    )
}
finally {
    Remove-TemporaryPfx

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null

    $ServiceAccountToken = $null
    $WatchGuardItem = $null
    $CertificateItem = $null
    $PfxPassword = $null
    $PfxCollection = $null

    $ApiKey = $null
    $ReadOnlyAccessId = $null
    $ReadOnlyPassword = $null
    $ProviderToken = $null
}

exit 0