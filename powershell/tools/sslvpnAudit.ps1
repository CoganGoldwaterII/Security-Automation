# ============================================================================
# NAME: WatchGuard Global SSLVPN Policy Audit
# AUTHORED BY: Cogan Goldwater
# TYPE: Inventory / Manual Audit
# SCOPE: Credential Broker / Device 9800 only / Global WatchGuard Cloud hierarchy
# VARIABLES: Required: None | Optional: None
# OUTPUT TOKENS: RESULT / ERROR
# CUSTOM FIELDS: Reads: opServiceAccountToken | Writes: None
# LOGGING PATH: C:\MME\AutoLogs\WatchGuard_SSLVPN_Policy_Audit.log
# DESCRIPTION: Read-only SSLVPN policy inventory across the root WatchGuard
#              account and all managed child accounts, including nested service
#              providers. Enumerates cloud-managed Fireboxes and retrieves full
#              device-local firewall policies (full=1). Detects system and
#              custom policies where traffic_types contains SSL-VPN, whether
#              enabled or disabled. Only matching devices are listed in the
#              manifest; nonmatches and skipped devices are counted/logged.
#              No changes. Always exits 0.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$OnePasswordVault = 'MME Automation'
$WatchGuardItemName = 'WatchGuard'
$BootstrapTokenField = 'opServiceAccountToken'
$ReportDirectory = 'C:\MME\CS'
$ReportPath = Join-Path $ReportDirectory 'WatchGuard_SSLVPN_Policy_Manifest.txt'
$LogDirectory = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogDirectory 'WatchGuard_SSLVPN_Policy_Audit.log'
$CurrentStage = 'Initialize'
$FinalOutput = $null
$RootAccountId = $null
$DiagnosticErrors = [System.Collections.Generic.List[string]]::new()
$ReportBuilder = [System.Text.StringBuilder]::new()

# Secret-bearing state, never included in output or report.
$ServiceAccountToken = $null
$WatchGuardItem = $null
$ApiKey = $null
$ReadOnlyAccessId = $null
$ReadOnlyPassword = $null
$AuthenticationUrl = $null
$BaseApiUrl = $null
$ProviderToken = $null

# ============================================================
# HELPERS (reused from tested Firewall Policy Collision Check)
# ============================================================

function ConvertTo-SafeOutput {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return (
        ([string]$Value) `
            -replace '[\r\n|]+', ' ' `
            -replace '\s{2,}', ' '
    ).Trim()
}

function Initialize-Directory {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item `
            -ItemType Directory `
            -Path $Path `
            -Force |
            Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    try {
        '{0} | {1}' -f `
            (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
            $Message |
            Add-Content `
                -LiteralPath $LogPath `
                -Encoding UTF8
    }
    catch {
    }
}

function Add-ReportLine {
    param(
        [AllowEmptyString()]
        [string]$Text = ''
    )

    $null = $script:ReportBuilder.AppendLine($Text)
}

function Get-HttpStatusCode {
    param(
        [AllowNull()]
        [object]$Exception
    )

    if ($null -eq $Exception) {
        return $null
    }

    try {
        if (
            $null -ne $Exception.Response -and
            $null -ne $Exception.Response.StatusCode
        ) {
            return [int]$Exception.Response.StatusCode
        }
    }
    catch {
    }

    return $null
}

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
            $_.label -eq $Label
        }
    ) | Select-Object -First 1

    if ($null -eq $Field) {
        throw "Required 1Password field not found: $Label"
    }

    $Value = [string]$Field.value

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Required 1Password field is empty: $Label"
    }

    return $Value.Trim()
}

function Get-WatchGuardAccessToken {
    param(
        [Parameter(Mandatory)]
        [string]$AuthenticationUrl,

        [Parameter(Mandatory)]
        [string]$AccessId,

        [Parameter(Mandatory)]
        [string]$Password,

        [string]$Audience
    )

    $CredentialBytes = [System.Text.Encoding]::ASCII.GetBytes(
        ('{0}:{1}' -f $AccessId, $Password)
    )

    $Headers = @{
        Accept = 'application/json'
        Authorization = 'Basic {0}' -f [Convert]::ToBase64String($CredentialBytes)
    }

    $Body = @{
        grant_type = 'client_credentials'
        scope = 'api-access'
    }

    if (-not [string]::IsNullOrWhiteSpace($Audience)) {
        $Body['audience'] = $Audience
    }

    $Response = Invoke-RestMethod `
        -Method Post `
        -Uri $AuthenticationUrl `
        -Headers $Headers `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body $Body `
        -TimeoutSec 60

    if (
        $null -eq $Response -or
        [string]::IsNullOrWhiteSpace([string]$Response.access_token)
    ) {
        throw 'WatchGuard authentication response did not contain an access token.'
    }

    return [string]$Response.access_token
}

function Get-ResponseItems {
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
        'objects'
        'items'
        'data'
        'results'
        'assets'
    )) {
        if ($Response.PSObject.Properties.Name -contains $PropertyName) {
            return @($Response.$PropertyName)
        }
    }

    return @($Response)
}

function Get-ConfigurationDeviceId {
    param(
        [Parameter(Mandatory)]
        [string]$DeviceDetailsId
    )

    if ($DeviceDetailsId -match '^FB-(\d+)$') {
        return $Matches[1]
    }

    if ($DeviceDetailsId -match '^FBCL-\d+$') {
        return $DeviceDetailsId
    }

    throw "Unsupported Firebox Device Details ID format: $DeviceDetailsId"
}

function Get-FlattenedManagedAccounts {
    param([AllowNull()][object[]]$Items)
    $Results = @()
    foreach ($Item in @($Items)) {
        if ($null -eq $Item) { continue }
        $AccountId = [string]$Item.accountId
        if (-not [string]::IsNullOrWhiteSpace($AccountId)) {
            $Results += [pscustomobject]@{
                AccountId = $AccountId
                Name = [string]$Item.name
            }
        }
        if ($Item.PSObject.Properties.Name -contains 'childrenList' -and $null -ne $Item.childrenList) {
            $Results += @(Get-FlattenedManagedAccounts -Items @($Item.childrenList))
        }
    }
    return @($Results)
}

function Get-AccountApiContext {
    param([Parameter(Mandatory)][string]$AccountId,
          [Parameter(Mandatory)][string]$RootAccountId,
          [Parameter(Mandatory)][string]$ProviderTokenForAudience,
          [Parameter(Mandatory)][string]$ApiKey,
          [Parameter(Mandatory)][string]$BaseApiUrl,
          [Parameter(Mandatory)][string]$AuthenticationUrl,
          [Parameter(Mandatory)][string]$AccessId,
          [Parameter(Mandatory)][string]$Password)
    $Token = $ProviderTokenForAudience
    if ($AccountId -cne $RootAccountId) {
        $AudienceHeaders = @{
            Accept = 'application/json'
            'Content-Type' = 'application/json'
            Authorization = "Bearer $ProviderTokenForAudience"
            'WatchGuard-API-Key' = $ApiKey
        }
        $AudienceBody = @{ accountId = $AccountId } | ConvertTo-Json -Compress
        $AudienceResponse = Invoke-RestMethod -Method Post `
            -Uri "$BaseApiUrl/platform/authorization/v1/audiences" `
            -Headers $AudienceHeaders -Body $AudienceBody -TimeoutSec 60
        $Audience = [string]$AudienceResponse.audience
        if ([string]::IsNullOrWhiteSpace($Audience)) {
            throw "WatchGuard returned no audience for managed account $AccountId."
        }
        $Token = Get-WatchGuardAccessToken -AuthenticationUrl $AuthenticationUrl `
            -AccessId $AccessId -Password $Password -Audience $Audience
    }
    return @{
        Accept = 'application/json'
        'Content-Type' = 'application/json'
        Authorization = "Bearer $Token"
        'WatchGuard-API-Key' = $ApiKey
    }
}

# ============================================================
# MAIN
# ============================================================

try {
    $CurrentStage = 'Directories'
    Initialize-Directory -Path $ReportDirectory
    Initialize-Directory -Path $LogDirectory
    Set-Content -LiteralPath $LogPath `
        -Value ('WatchGuard Global SSLVPN Policy Audit - {0}' -f (Get-Date -Format s)) `
        -Encoding UTF8

    Write-Log 'START | WatchGuard global SSLVPN policy audit'
    Add-ReportLine 'WATCHGUARD GLOBAL SSLVPN POLICY AUDIT'
    Add-ReportLine ('Generated: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Add-ReportLine 'Scope: Root WatchGuard Cloud account and nested managed accounts.'
    Add-ReportLine 'MATCHED DEVICES ONLY. Policy traffic_types includes SSL-VPN (system or custom; enabled or disabled).'
    Add-ReportLine 'ENABLED_ALLOW means an enabled allow policy, not a verified VPN session. PRESENT_NO_ENABLED_ALLOW is not a confirmed active target.'
    Add-ReportLine ''

    # --------------------------------------------------------
    # CREDENTIAL BROKER / 1PASSWORD
    # --------------------------------------------------------
    $CurrentStage = 'NinjaField'
    $ServiceAccountToken = (Ninja-Property-Get -Name $BootstrapTokenField).Trim()
    if ([string]::IsNullOrWhiteSpace($ServiceAccountToken)) {
        throw "Ninja secure custom field $BootstrapTokenField returned no value."
    }
    Write-Log "PASS | $BootstrapTokenField retrieved"

    $CurrentStage = 'OnePasswordCLI'
    $OpCommand = Get-Command 'op.exe' -ErrorAction SilentlyContinue
    if ($null -ne $OpCommand) {
        $OpExe = $OpCommand.Source
    }
    else {
        $OpExe = @(
            'C:\Program Files\1Password CLI\op.exe'
            'C:\Program Files\1Password\op.exe'
            'C:\Windows\System32\op.exe'
        ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if ([string]::IsNullOrWhiteSpace([string]$OpExe)) {
        throw '1Password CLI op.exe was not found.'
    }

    $CurrentStage = 'OnePasswordAuth'
    $env:OP_SERVICE_ACCOUNT_TOKEN = $ServiceAccountToken
    $WhoAmI = & $OpExe user get --me --format json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('1Password service account authentication failed: {0}' -f `
            (ConvertTo-SafeOutput -Value ($WhoAmI -join ' ')))
    }
    Write-Log 'PASS | 1Password service account authenticated'

    $CurrentStage = 'WatchGuardItem'
    $WatchGuardItemJson = & $OpExe `
        item get $WatchGuardItemName --vault $OnePasswordVault --format json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('1Password WatchGuard item retrieval failed: {0}' -f `
            (ConvertTo-SafeOutput -Value ($WatchGuardItemJson -join ' ')))
    }
    try { $WatchGuardItem = $WatchGuardItemJson | ConvertFrom-Json }
    catch { throw "1Password item '$WatchGuardItemName' returned invalid JSON." }

    $CurrentStage = 'WatchGuardConfig'
    $ApiKey = Get-OnePasswordField -Item $WatchGuardItem -Label 'credential'
    $ReadOnlyAccessId = Get-OnePasswordField -Item $WatchGuardItem -Label 'readOnlyAccessId'
    $ReadOnlyPassword = Get-OnePasswordField -Item $WatchGuardItem -Label 'readOnlyPassword'
    $RootAccountId = Get-OnePasswordField -Item $WatchGuardItem -Label 'accountID'
    if ($RootAccountId -notmatch '^(WGC|ACC)-') {
        throw '1Password accountID is not in the expected WatchGuard account ID format.'
    }
    $AuthenticationUrl = (
        Get-OnePasswordField -Item $WatchGuardItem -Label 'authenticationUrl'
    ).TrimEnd('/')
    $BaseApiUrl = (
        Get-OnePasswordField -Item $WatchGuardItem -Label 'baseApiUrl'
    ).TrimEnd('/')
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $ServiceAccountToken = $null
    $WatchGuardItem = $null
    Write-Log "PASS | WatchGuard read-only API configuration retrieved | RootAccount=$RootAccountId"

    $CurrentStage = 'ProviderAuth'
    $ProviderToken = Get-WatchGuardAccessToken `
        -AuthenticationUrl $AuthenticationUrl `
        -AccessId $ReadOnlyAccessId `
        -Password $ReadOnlyPassword

    $ProviderHeaders = @{
        Accept = 'application/json'
        'Content-Type' = 'application/json'
        Authorization = "Bearer $ProviderToken"
        'WatchGuard-API-Key' = $ApiKey
    }

    # Global account discovery matches the established global policy audit.
    $CurrentStage = 'AccountDiscovery'
    $AccountsUri =
        "$BaseApiUrl/platform/accounts/v2/accounts/$RootAccountId/children?limit=-1&includeDelegatedAccounts=false"
    $AccountsResponse = Invoke-RestMethod `
        -Method Get -Uri $AccountsUri -Headers $ProviderHeaders -TimeoutSec 120
    $ManagedAccounts = @()
    if ($null -ne $AccountsResponse -and
        $AccountsResponse.PSObject.Properties.Name -contains 'items') {
        $ManagedAccounts = @(
            Get-FlattenedManagedAccounts -Items @($AccountsResponse.items)
        )
    }
    $AccountRecords = @(
        [pscustomobject]@{ AccountId = $RootAccountId; Name = $RootAccountId }
    )
    $AccountRecords += @($ManagedAccounts)
    $AccountRecords = @(
        $AccountRecords |
            Group-Object AccountId |
            ForEach-Object { $_.Group | Select-Object -First 1 } |
            Sort-Object Name, AccountId
    )
    if ($AccountRecords.Count -lt 1) {
        throw 'WatchGuard account discovery returned no root or managed accounts.'
    }
    Write-Log "ACCOUNT_DISCOVERY_PASS | RootAccount=$RootAccountId Accounts=$($AccountRecords.Count)"

    $AccountsEvaluated = 0
    $DevicesDiscovered = 0
    $DevicesEvaluated = 0
    $DevicesWithPolicy = 0
    $DevicesWithEnabledAllow = 0
    $DevicesWithOnlyInactive = 0
    $DevicesWithNoPolicy = 0
    $DevicesSkipped = 0

    foreach ($Account in $AccountRecords) {
        $TargetAccountId = [string]$Account.AccountId
        $AccountName = [string]$Account.Name
        Write-Log ("ACCOUNT_START | Account={0} Name={1}" -f `
            $TargetAccountId, (ConvertTo-SafeOutput -Value $AccountName))

        try {
            $CurrentStage = "AccountAuth:$TargetAccountId"
            $Headers = Get-AccountApiContext `
                -AccountId $TargetAccountId `
                -RootAccountId $RootAccountId `
                -ProviderTokenForAudience $ProviderToken `
                -ApiKey $ApiKey `
                -BaseApiUrl $BaseApiUrl `
                -AuthenticationUrl $AuthenticationUrl `
                -AccessId $ReadOnlyAccessId `
                -Password $ReadOnlyPassword

            $CurrentStage = "DeviceDetails:$TargetAccountId"
            $DeviceDetailsUri =
                "$BaseApiUrl/firebox/management/v1/info/$TargetAccountId/devices?device_type=FB"
            $DeviceDetailsResponse = Invoke-RestMethod `
                -Method Get -Uri $DeviceDetailsUri -Headers $Headers -TimeoutSec 120
            $DeviceDetails = @(Get-ResponseItems -Response $DeviceDetailsResponse)
            $AccountsEvaluated++
        }
        catch {
            $Http = Get-HttpStatusCode -Exception $_.Exception
            if ($null -eq $Http) { $Http = 'N/A' }
            $Message = ('Account={0} Stage={1} HTTP={2} Error={3}' -f `
                $TargetAccountId, (ConvertTo-SafeOutput -Value $CurrentStage), `
                $Http, (ConvertTo-SafeOutput -Value $_.Exception.Message))
            $DiagnosticErrors.Add($Message)
            Write-Log "DIAG_ERROR | $Message"
            continue
        }


        foreach ($Device in $DeviceDetails | Sort-Object name, id) {
            $DevicesDiscovered++
            $DetailsId = [string]$Device.id
            $Name = [string]$Device.name
            $Model = [string]$Device.short_model_name
            $Serial = [string]$Device.serial_number
            $State = [string]$Device.state
            $CloudManaged = [string]$Device.cloud_managed
            $DeviceId = $null
            $SSLVPNPolicies = @()

            if ($CloudManaged -cne 'yes') {
                $DevicesSkipped++
                Write-Log "DEVICE_SKIP | Account=$TargetAccountId DetailsId=$DetailsId Reason=NotCloudManaged"
                continue
            }

            try {
                $CurrentStage = "DeviceID:${TargetAccountId}:${DetailsId}"
                $DeviceId = Get-ConfigurationDeviceId -DeviceDetailsId $DetailsId
                $CurrentStage = "Policies:${TargetAccountId}:${DeviceId}"
                $PolicyUri =
                    "$BaseApiUrl/firebox/management/v1/configuration/$TargetAccountId/firewall/policies?device=$([uri]::EscapeDataString($DeviceId))&full=1"
                $PolicyResponse = Invoke-RestMethod `
                    -Method Get -Uri $PolicyUri -Headers $Headers -TimeoutSec 120
                $Policies = @(Get-ResponseItems -Response $PolicyResponse)
                $DevicesEvaluated++
            }
            catch {
                $Http = Get-HttpStatusCode -Exception $_.Exception
                if ($null -eq $Http) { $Http = 'N/A' }
                $Message = ('Account={0} Device={1} DetailsId={2} Stage={3} HTTP={4} Error={5}' -f `
                    $TargetAccountId, (ConvertTo-SafeOutput -Value $Name), `
                    $DetailsId, (ConvertTo-SafeOutput -Value $CurrentStage), $Http, `
                    (ConvertTo-SafeOutput -Value $_.Exception.Message))
                $DiagnosticErrors.Add($Message)
                Write-Log "DIAG_ERROR | $Message"
                continue
            }

            # Match the ACTUAL WatchGuard SSL-VPN traffic type, not a policy name.
            # This catches 'WatchGuard SSLVPN' and custom 'Inbound SSLVPN'.
            # 'Allow SSLVPN-Users' alone is not an SSLVPN listener policy.
            $SSLVPNPolicies = @(
                $Policies | Where-Object {
                    $null -ne $_ -and @(
                        $_.traffic_types | Where-Object { [string]$_ -eq 'SSL-VPN' }
                    ).Count -gt 0
                }
            )

            $Status = 'ABSENT'
            if ($SSLVPNPolicies.Count -gt 0) {
                $DevicesWithPolicy++
                $EnabledAllow = @($SSLVPNPolicies | Where-Object {
                    $_.enabled -eq $true -and [string]$_.action -eq 'allow'
                })
                if ($EnabledAllow.Count -gt 0) {
                    $Status = 'ENABLED_ALLOW'
                    $DevicesWithEnabledAllow++
                }
                else {
                    $Status = 'PRESENT_NO_ENABLED_ALLOW'
                    $DevicesWithOnlyInactive++
                }
            }
            else {
                $DevicesWithNoPolicy++
            }

            # The manifest is deliberately POSITIVE-ONLY. Devices with no SSL-VPN
            # policy are logged/countable but do not appear as device entries.
            if ($SSLVPNPolicies.Count -gt 0) {
                Add-ReportLine ('DEVICE | Account={0} | Name={1} | DeviceId={2} | DetailsId={3} | Model={4} | Serial={5} | State={6} | Status={7} | Matches={8}' -f `
                    $TargetAccountId, (ConvertTo-SafeOutput -Value $Name), $DeviceId, $DetailsId, `
                    (ConvertTo-SafeOutput -Value $Model), (ConvertTo-SafeOutput -Value $Serial), `
                    (ConvertTo-SafeOutput -Value $State), $Status, $SSLVPNPolicies.Count)

                foreach ($Policy in $SSLVPNPolicies | Sort-Object name, id) {
                    $PolicyType = 'Custom'
                    if ([string]$Policy.name -ceq 'WatchGuard SSLVPN' -and $Policy.immutable -eq $true) {
                        $PolicyType = 'System'
                    }
                    $Enabled = if ($null -eq $Policy.enabled) { 'UNKNOWN' } else { [string]$Policy.enabled }
                    Add-ReportLine ('  POLICY | Name={0} | Type={1} | Enabled={2} | Action={3} | PolicyId={4} | TrafficType=SSL-VPN' -f `
                        (ConvertTo-SafeOutput -Value $Policy.name), $PolicyType, $Enabled, `
                        (ConvertTo-SafeOutput -Value $Policy.action), `
                        (ConvertTo-SafeOutput -Value $Policy.id))
                }
                Add-ReportLine ''
            }

            Write-Log ('DEVICE_DONE | Account={0} Device={1} Name={2} Status={3} MatchingPolicies={4}' -f `
                $TargetAccountId, $DeviceId, (ConvertTo-SafeOutput -Value $Name), $Status, $SSLVPNPolicies.Count)
        }

        $Headers = $null
        Write-Log "ACCOUNT_DONE | Account=$TargetAccountId"
    }

    Add-ReportLine '============================================================================'
    Add-ReportLine 'GLOBAL SUMMARY (nonmatches shown only as counts)'
    Add-ReportLine "Accounts discovered: $($AccountRecords.Count)"
    Add-ReportLine "Accounts evaluated: $AccountsEvaluated"
    Add-ReportLine "Fireboxes discovered: $DevicesDiscovered"
    Add-ReportLine "Cloud-managed Fireboxes evaluated: $DevicesEvaluated"
    Add-ReportLine "Fireboxes with SSL-VPN policies: $DevicesWithPolicy"
    Add-ReportLine "Fireboxes with enabled allow SSL-VPN policies: $DevicesWithEnabledAllow"
    Add-ReportLine "Fireboxes with policy but no enabled allow: $DevicesWithOnlyInactive"
    Add-ReportLine "Fireboxes with no matching policy: $DevicesWithNoPolicy"
    Add-ReportLine "Not-cloud-managed devices skipped: $DevicesSkipped"
    Add-ReportLine "Diagnostic errors: $($DiagnosticErrors.Count)"

    if ($DiagnosticErrors.Count -gt 0) {
        Add-ReportLine ''
        Add-ReportLine 'DIAGNOSTIC ERRORS'
        foreach ($Entry in $DiagnosticErrors) { Add-ReportLine "ERROR | $Entry" }
    }

    $ReportBuilder.ToString() | Set-Content -LiteralPath $ReportPath -Encoding UTF8

    if ($DiagnosticErrors.Count -gt 0) {
        $FinalOutput = ('ERROR | Stage=GlobalDiagnostics HTTP=N/A Errors={0} Accounts={1}/{2} Devices={3} PolicyPresent={4} File={5}' -f `
            $DiagnosticErrors.Count, $AccountsEvaluated, $AccountRecords.Count, `
            $DevicesEvaluated, $DevicesWithPolicy, $ReportPath)
    }
    else {
        $FinalOutput = ('RESULT | SSLVPN policy audit complete | Accounts={0}/{1} Devices={2} PolicyPresent={3} EnabledAllow={4} PresentNoEnabledAllow={5} File={6}' -f `
            $AccountsEvaluated, $AccountRecords.Count, $DevicesEvaluated, `
            $DevicesWithPolicy, $DevicesWithEnabledAllow, $DevicesWithOnlyInactive, $ReportPath)
    }
    Write-Log $FinalOutput
}
catch {
    $Http = Get-HttpStatusCode -Exception $_.Exception
    if ($null -eq $Http) { $Http = 'N/A' }
    $Message = ConvertTo-SafeOutput -Value $_.Exception.Message
    try {
        Add-ReportLine ''
        Add-ReportLine ('FATAL | Stage={0} HTTP={1} Error={2}' -f $CurrentStage, $Http, $Message)
        $ReportBuilder.ToString() | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    }
    catch { }
    $FinalOutput = ('ERROR | Stage={0} HTTP={1} Error={2}' -f `
        (ConvertTo-SafeOutput -Value $CurrentStage), $Http, $Message)
    Write-Log $FinalOutput
}
finally {
    try { $env:OP_SERVICE_ACCOUNT_TOKEN = $null } catch { }
    $ServiceAccountToken = $null
    $WatchGuardItem = $null
    $ApiKey = $null
    $ReadOnlyAccessId = $null
    $ReadOnlyPassword = $null
    $AuthenticationUrl = $null
    $BaseApiUrl = $null
    $ProviderToken = $null
    $Headers = $null
    $ProviderHeaders = $null
}

if ([string]::IsNullOrWhiteSpace([string]$FinalOutput)) {
    $FinalOutput = 'ERROR | Stage=Finalize HTTP=N/A Error=No final output was generated.'
}
Write-Output $FinalOutput
exit 0
