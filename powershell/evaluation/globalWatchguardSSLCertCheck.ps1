# ============================================================================
# NAME: WatchGuard Account and Device Certificate Check
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows / Credential Broker / Global WatchGuard Subscriber Accounts
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   TRIGGER   | Account or cloud-managed Firebox remediation is required
#   NO_ACTION | No actionable remediation or account errors were identified
#   ERROR     | Fatal evaluation failure or account errors without an
#               actionable remediation finding
#
# CUSTOM FIELDS:
#   Reads: opServiceAccountToken (Secure)
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   C:\Automation\Logs\WatchGuard_Certificate_Audit.log
#
# DESCRIPTION:
#   Performs a read-only global WatchGuard certificate audit across
#   Subscriber accounts returned beneath the provider account.
#
#   Authenticates to 1Password using the NinjaOne secure custom field
#   opServiceAccountToken. Retrieves WatchGuard read-only credentials
#   and the authoritative configured certificate PFX.
#
#   Parses the PFX and requires exactly three unique certificates,
#   including one certificate with a private key.
#
#   Audits:
#     - Account-level canonical certificate package completeness.
#     - Cloud-managed Firebox certificate package completeness.
#     - Cloud-managed Firebox Web Server certificate assignments.
#     - Stale certificates matching the configured name pattern.
#     - Active assigned Firebox inventory.
#     - Cloud-managed versus locally-managed device classification.
#
#   Delegated Subscriber accounts are inventoried and skipped.
#   Locally-managed Fireboxes are inventoried but not certificate-audited.
#   Device connectivity and live reachability are not evaluated.
#
#   Writes a JSON manifest to:
#     C:\Automation\Work\WatchGuard_Certificate_Audit_Manifest.json
#
#   Temporarily retrieves the authoritative PFX to:
#     C:\Automation\Work\Certificate_Source.pfx
#
#   Attempts to remove the temporary PFX after parsing and during cleanup.
#   Does not modify WatchGuard configuration.
#   Always exits 0.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ============================================================
# CONFIGURATION
# ============================================================

$OnePasswordVault = 'YOUR_1PASSWORD_VAULT'  # CONFIGURE BEFORE USE
$WatchGuardItemName = 'WatchGuard'
$CertificateItemName = 'YOUR_CERTIFICATE_ITEM'  # CONFIGURE BEFORE USE
$CertificatePasswordField = 'password'

$StaleCertificateNamePattern = 'YOUR_STALE_CERTIFICATE_PATTERN'  # CONFIGURE BEFORE USE

$LogRoot = 'C:\Automation\Logs'
$WorkRoot = 'C:\Automation\Work'

$LogPath = Join-Path $LogRoot 'WatchGuard_Certificate_Audit.log'
$ManifestPath = Join-Path $WorkRoot 'WatchGuard_Certificate_Audit_Manifest.json'
$TempPfxPath = Join-Path $WorkRoot 'Certificate_Source.pfx'

$TransientRetryStatusCodes = @(429, 502, 503, 504)
$TransientRetryMaxAttempts = 3
$TransientRetryDelaysSeconds = @(2, 5)

# ============================================================
# STATE
# ============================================================

$CurrentStage = 'Initialize'

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

$AccountNeedsRemediationCount = 0
$DeviceNeedsRemediationCount = 0

$TotalActiveDevices = 0
$TotalCloudManaged = 0
$TotalLocallyManaged = 0
$TotalManagementUnknown = 0
$AccountsDiscoveredCount = 0
$AccountsAuditedCount = 0
$DelegatedSkippedCount = 0

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

    "WatchGuard Certificate Audit - $(Get-Date -Format s)" |
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
        [ValidateSet('Get', 'Post', 'Put', 'Delete', 'Patch')]
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

Write-Log 'START | WatchGuard certificate audit GLOBAL'

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

    if ($SubscriberAccounts.Count -eq 0) {
        throw 'No WatchGuard Subscriber accounts returned.'
    }

    $AccountsDiscoveredCount = $SubscriberAccounts.Count

    Write-Log (
        'GLOBAL_SCOPE | SubscriberAccounts={0}' -f
        $AccountsDiscoveredCount
    )

    foreach ($ScopeAccount in $SubscriberAccounts) {
        $ScopeDelegated =
            Test-DelegatedAccount $ScopeAccount

        Write-Log (
            'GLOBAL_SCOPE_ACCOUNT | Name={0} Account={1} Delegated={2}' -f
            (Convert-SafeOutput $ScopeAccount.name),
            $ScopeAccount.accountId,
            $ScopeDelegated
        )
    }

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
        $AccountDeviceNeedsRemediation = 0

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

                    remediationNeeded =
                        $false

                    remediationReasons =
                        @()

                    summary =
                        [PSCustomObject]@{
                            devicesAllocated = 0
                            devicesActive = 0
                            devicesAllocatedInactive = 0
                            cloudManaged = 0
                            locallyManaged = 0
                            managementModeUnknown = 0
                            cloudNeedsRemediation = 0
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

            $AccountPresent =
                [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase
                )

            $AccountStale =
                [System.Collections.Generic.List[object]]::new()

            foreach ($Certificate in $AccountCertificates) {
                $Normalized =
                    Normalize-Fingerprint $Certificate.cert_fingerprint

                $Classification = 'UNRELATED_PRESERVE'

                if (
                    -not [string]::IsNullOrWhiteSpace($Normalized) -and
                    $Normalized -in $ExpectedFingerprintsNormalized
                ) {
                    $Classification = 'CANONICAL_KEEP'
                    [void]$AccountPresent.Add($Normalized)
                }
                elseif (
                    [string]$Certificate.name -imatch
                    $StaleCertificateNamePattern
                ) {
                    $Classification =
                        'STALE_MME_DELETE_CANDIDATE'

                    $AccountStale.Add(
                        [PSCustomObject]@{
                            id = [string]$Certificate.id
                            name = [string]$Certificate.name
                            certType = [string]$Certificate.cert_type
                            fingerprint =
                                Format-Fingerprint $Normalized
                        }
                    ) | Out-Null
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
                        classification =
                            $Classification
                    }
                ) | Out-Null
            }

            $AccountMissing =
                @(
                    $ExpectedCertificates |
                    Where-Object {
                        -not $AccountPresent.Contains(
                            [string]$_.fingerprintNormalized
                        )
                    }
                )

            $AccountRemediationReasons =
                [System.Collections.Generic.List[string]]::new()

            if ($AccountMissing.Count -gt 0) {
                $AccountRemediationReasons.Add(
                    'MissingCanonicalCertificates'
                ) | Out-Null
            }

            if ($AccountStale.Count -gt 0) {
                $AccountRemediationReasons.Add(
                    'StaleMMECertificates'
                ) | Out-Null
            }

            $AccountRemediationNeeded =
                ($AccountRemediationReasons.Count -gt 0)

            if ($AccountRemediationNeeded) {
                $AccountNeedsRemediationCount++
            }

            Write-Log (
                'ACCOUNT_CERT_RESULT | Name={0} Account={1} Canonical={2}/{3} Missing={4} Stale={5} RemediationNeeded={6}' -f
                $AccountName,
                $AccountId,
                $AccountPresent.Count,
                $ExpectedCertificateCount,
                $AccountMissing.Count,
                $AccountStale.Count,
                $AccountRemediationNeeded
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

                $CanonicalPresent =
                    [System.Collections.Generic.HashSet[string]]::new(
                        [System.StringComparer]::OrdinalIgnoreCase
                    )

                $StaleCertificates =
                    [System.Collections.Generic.List[object]]::new()

                $DeviceCertificateManifest =
                    [System.Collections.Generic.List[object]]::new()

                $WebServerCandidates =
                    [System.Collections.Generic.List[object]]::new()

                foreach ($Certificate in $DeviceCertificates) {
                    $Normalized =
                        Normalize-Fingerprint `
                            $Certificate.cert_fingerprint

                    $Formatted =
                        Format-Fingerprint $Normalized

                    $MatchesCanonical =
                        (
                            -not [string]::IsNullOrWhiteSpace(
                                $Normalized
                            ) -and
                            $Normalized -in
                            $ExpectedFingerprintsNormalized
                        )

                    $Classification = 'UNRELATED_PRESERVE'

                    if ($MatchesCanonical) {
                        $Classification = 'CANONICAL_KEEP'

                        [void]$CanonicalPresent.Add(
                            $Normalized
                        )
                    }
                    elseif (
                        Test-FireboxNativeCertificate `
                            $Certificate
                    ) {
                        $Classification =
                            'FIREBOX_NATIVE_KEEP'
                    }
                    elseif (
                        [string]$Certificate.name -imatch
                        $StaleCertificateNamePattern
                    ) {
                        $Classification =
                            'STALE_MME_DELETE_CANDIDATE'

                        $StaleCertificates.Add(
                            [PSCustomObject]@{
                                id =
                                    [string]$Certificate.id

                                name =
                                    [string]$Certificate.name

                                certType =
                                    [string]$Certificate.cert_type

                                fingerprint =
                                    $Formatted
                            }
                        ) | Out-Null
                    }

                    $ReferencedBy =
                        @(
                            Get-CertificateReferences `
                                $Certificate
                        )

                    $IsWebServer =
                        (
                            [string]$Certificate.cert_type -ieq
                            'web_server'
                        )

                    $MatchesLeaf =
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

                                matchesCanonicalLeaf =
                                    [bool]$MatchesLeaf
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

                            referencedBy =
                                $ReferencedBy

                            matchesCanonical =
                                [bool]$MatchesCanonical

                            matchesCanonicalLeaf =
                                [bool]$MatchesLeaf

                            classification =
                                $Classification
                        }
                    ) | Out-Null
                }

                $MissingDeviceCertificates =
                    @(
                        $ExpectedCertificates |
                        Where-Object {
                            -not $CanonicalPresent.Contains(
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
                $WebServerCorrect = $false

                if (
                    $ReferencedWebServerCandidates.Count -eq 1
                ) {
                    $Selected =
                        $ReferencedWebServerCandidates[0]

                    $WebServerMode = 'ThirdParty'
                    $SelectedWebServerName = $Selected.name
                    $SelectedWebServerId = $Selected.id
                    $SelectedWebServerFingerprint = $Selected.fingerprint
                    $WebServerCorrect = [bool]$Selected.matchesCanonicalLeaf
                }
                elseif (
                    $ReferencedWebServerCandidates.Count -gt 1
                ) {
                    $WebServerBindingDetermined = $false
                    $WebServerMode = 'Unknown'
                    $SelectedWebServerName = $null
                }

                # ---------------------------------------------
                # REMEDIATION FINDINGS
                # ---------------------------------------------

                $RemediationReasons =
                    [System.Collections.Generic.List[string]]::new()

                if ($MissingDeviceCertificates.Count -gt 0) {
                    $RemediationReasons.Add(
                        'MissingCanonicalCertificates'
                    ) | Out-Null
                }

                if ($StaleCertificates.Count -gt 0) {
                    $RemediationReasons.Add(
                        'StaleMMECertificates'
                    ) | Out-Null
                }

                if (
                    $WebServerBindingDetermined -and
                    -not $WebServerCorrect
                ) {
                    $RemediationReasons.Add(
                        'WebServerCertificateMismatch'
                    ) | Out-Null
                }

                if (-not $WebServerBindingDetermined) {
                    $FailureCount++
                    $AccountFailures++
                }

                $RemediationNeeded =
                    ($RemediationReasons.Count -gt 0)

                if ($RemediationNeeded) {
                    $DeviceNeedsRemediationCount++
                    $AccountDeviceNeedsRemediation++
                }

                if (-not $WebServerBindingDetermined) {
                    $DeviceStatus = 'Failure'
                    $FailureReason = 'WebServerBindingUndetermined'
                }
                elseif ($RemediationNeeded) {
                    $DeviceStatus = 'NeedsRemediation'
                    $FailureReason = $null
                }
                else {
                    $DeviceStatus = 'Compliant'
                    $FailureReason = $null
                }

                $CloudResult =
                    [PSCustomObject]@{
                        deviceId =
                            $DeviceId

                        managementMode =
                            'CloudManaged'

                        managementModeSource =
                            'FirewallPolicyDeviceIndex'

                        auditComplete =
                            [bool]$WebServerBindingDetermined

                        failure =
                            (-not $WebServerBindingDetermined)

                        failureReason =
                            $FailureReason

                        status =
                            $DeviceStatus

                        remediationNeeded =
                            [bool]$RemediationNeeded

                        remediationReasons =
                            $RemediationReasons.ToArray()

                        expectedCanonicalCertificateCount =
                            $ExpectedCertificateCount

                        canonicalPresentCount =
                            $CanonicalPresent.Count

                        missingCanonicalCertificateCount =
                            $MissingDeviceCertificates.Count

                        missingCanonicalCertificates =
                            $MissingDeviceCertificates

                        staleMMECertificateCount =
                            $StaleCertificates.Count

                        staleMMECertificates =
                            $StaleCertificates.ToArray()

                        certificateCount =
                            $DeviceCertificates.Count

                        certificates =
                            $DeviceCertificateManifest.ToArray()

                        webServerCertificate =
                            [PSCustomObject]@{
                                bindingDetermined =
                                    [bool]$WebServerBindingDetermined

                                mode =
                                    $WebServerMode

                                selectedName =
                                    $SelectedWebServerName

                                selectedId =
                                    $SelectedWebServerId

                                selectedFingerprint =
                                    $SelectedWebServerFingerprint

                                canonicalLeafFingerprint =
                                    $DesiredLeafFingerprint

                                correct =
                                    [bool]$WebServerCorrect

                                candidateCount =
                                    $WebServerCandidates.Count

                                referencedCandidateCount =
                                    $ReferencedWebServerCandidates.Count

                                candidates =
                                    $WebServerCandidates.ToArray()
                            }
                    }

                $AccountDeviceResults.Add(
                    $CloudResult
                ) | Out-Null

                Write-Log (
                    'DEVICE_RESULT | Account={0} Device={1} Management=CloudManaged Canonical={2}/{3} Missing={4} Stale={5} WebServer={6} WebServerCorrect={7} RemediationNeeded={8} Failure={9} FailureReason={10}' -f
                    $AccountId,
                    $DeviceId,
                    $CanonicalPresent.Count,
                    $ExpectedCertificateCount,
                    $MissingDeviceCertificates.Count,
                    $StaleCertificates.Count,
                    $WebServerMode,
                    $WebServerCorrect,
                    $RemediationNeeded,
                    (-not $WebServerBindingDetermined),
                    $FailureReason
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
                            remediationNeeded = $false
                            remediationReasons = @()
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
                            remediationNeeded = $false
                            remediationReasons = @()
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

            if (
                $AccountRemediationNeeded -or
                $AccountDeviceNeedsRemediation -gt 0
            ) {
                $AccountStatus = 'NeedsRemediation'
            }
            elseif (
                $AccountFailures -gt 0 -or
                $AccountErrors -gt 0
            ) {
                $AccountStatus = 'Failure'
            }
            else {
                $AccountStatus = 'Compliant'
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

                    remediationNeeded =
                        [bool]$AccountRemediationNeeded

                    remediationReasons =
                        $AccountRemediationReasons.ToArray()

                    accountCertificates =
                        [PSCustomObject]@{
                            expectedCanonicalCertificateCount =
                                $ExpectedCertificateCount

                            canonicalPresentCount =
                                $AccountPresent.Count

                            canonicalPackageComplete =
                                ($AccountMissing.Count -eq 0)

                            missingCanonicalCertificateCount =
                                $AccountMissing.Count

                            missingCanonicalCertificates =
                                $AccountMissing

                            staleMMECertificateCount =
                                $AccountStale.Count

                            staleMMECertificates =
                                $AccountStale.ToArray()

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

                            cloudNeedsRemediation =
                                $AccountDeviceNeedsRemediation

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
                'ACCOUNT_RESULT | Name={0} Account={1} ManagedAdded={2} Cloud={3} Local={4} AccountRemediation={5} DeviceRemediation={6} Failures={7} Errors={8} Status={9}' -f
                $AccountName,
                $AccountId,
                $ManagedAddedDeviceCount,
                $AccountCloud,
                $AccountLocal,
                $AccountRemediationNeeded,
                $AccountDeviceNeedsRemediation,
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

                    remediationNeeded =
                        $false

                    remediationReasons =
                        @()

                    summary =
                        [PSCustomObject]@{
                            devicesAllocated = 0
                            devicesActive = 0
                            devicesAllocatedInactive = 0
                            cloudManaged = 0
                            locallyManaged = 0
                            managementModeUnknown = 0
                            cloudNeedsRemediation = 0
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
                'InventoriedAndSkipped'
        }

    $CertificatePackageManifest =
        [ordered]@{
            source =
                ('1Password / {0} / {1}' -f $OnePasswordVault, $CertificateItemName)

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

            accountNeedsRemediation =
                $AccountNeedsRemediationCount

            cloudDeviceNeedsRemediation =
                $DeviceNeedsRemediationCount

            failures =
                $FailureCount

            errors =
                $ErrorCount
        }

    $Manifest =
        [ordered]@{
            schemaVersion = 2

            generatedUtc =
                $GeneratedUtc

            mode =
                'READ_ONLY_GLOBAL'

            connectivityAudit =
                'NotEvaluated'

            remediationReachabilityPolicy =
                'Remediation deployment/default-Web-Server-cert step will determine live reachability.'

            globalScope =
                $GlobalScopeManifest

            authoritativeCertificatePackage =
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
        'MANIFEST | Path={0} AccountsDiscovered={1} AccountsAudited={2} DelegatedSkipped={3} ActiveDevices={4} Cloud={5} Local={6} AccountRemediation={7} DeviceRemediation={8} Failures={9} Errors={10}' -f
        $ManifestPath,
        $AccountsDiscoveredCount,
        $AccountsAuditedCount,
        $DelegatedSkippedCount,
        $TotalActiveDevices,
        $TotalCloudManaged,
        $TotalLocallyManaged,
        $AccountNeedsRemediationCount,
        $DeviceNeedsRemediationCount,
        $FailureCount,
        $ErrorCount
    )

    # ========================================================
    # FINAL TOKEN
    # ========================================================

    $HasActionableRemediation =
        (
            $AccountNeedsRemediationCount -gt 0 -or
            $DeviceNeedsRemediationCount -gt 0
        )

    if ($HasActionableRemediation) {
        $Token = 'TRIGGER'
    }
    elseif ($ErrorCount -gt 0) {
        $Token = 'ERROR'
    }
    else {
        $Token = 'NO_ACTION'
    }

    Write-Output (
        '{0} | AccountsDiscovered={1} AccountsAudited={2} DelegatedSkipped={3} Devices={4} Cloud={5} Local={6} AccountRemediation={7} DeviceRemediation={8} Failures={9} Errors={10} Manifest={11}' -f
        $Token,
        $AccountsDiscoveredCount,
        $AccountsAuditedCount,
        $DelegatedSkippedCount,
        $TotalActiveDevices,
        $TotalCloudManaged,
        $TotalLocallyManaged,
        $AccountNeedsRemediationCount,
        $DeviceNeedsRemediationCount,
        $FailureCount,
        $ErrorCount,
        $ManifestPath
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