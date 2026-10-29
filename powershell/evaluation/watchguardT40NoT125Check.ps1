# ============================================================================
# NAME: WatchGuard T40 Without T125 Account Inventory Check
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation / Inventory / Read-Only
# SCOPE: Credential Broker / Device 9800 only / Global WatchGuard hierarchy
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   TRIGGER   | One or more accounts contain a T40 and no T125 Fireboxes
#   NO_ACTION | No accounts contain T40 without T125
#   ERROR     | Global inventory could not be evaluated completely
# CUSTOM FIELDS:
#   Reads: opServiceAccountToken (Secure)
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\WatchGuard_T40_Without_T125_Global_Evaluation.log
# DESCRIPTION:
#   Uses the same 1Password and WatchGuard API patterns as the proven global
#   WatchGuard firewall-policy collision evaluator. Discovers the complete
#   managed-account hierarchy, excluding delegated accounts. Retrieves Firebox
#   Device Details inventory for each account and excludes locally managed
#   devices. An account matches only if its remaining devices include at least
#   one exact T40 and zero T125s (short_model_name, case-insensitive).
#
#   Device connection state is NOT read or filtered. All matching devices count
#   whether connected, disconnected, offline, or of unknown connection status.
#   Other Firebox models in a matching account are permitted. Any cloud-managed
#   T125 excludes the entire account, regardless of its connection state.
#
#   Results include qualifying account names/IDs and T40 device names/IDs/serials.
#   T125 devices are used solely to exclude accounts, not listed as matches.
#   Writes matching accounts plus any diagnostics to:
#     C:\MME\CS\WatchGuard_T40_Without_T125_Global_Matches.txt
#
#   All API operations are read-only except authentication/audience creation.
#   Does not modify WatchGuard, NinjaOne or 1Password configuration.
#   Individual account failures are logged and do not halt the scan; if any
#   failures occur, the final status is ERROR, even if matches were found.
#   Always exits 0.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ============================================================
# CONFIGURATION / STATE
# ============================================================

$OnePasswordVault = 'MME Automation'
$WatchGuardItemName = 'WatchGuard'
$BootstrapTokenField = 'opServiceAccountToken'

$LogDirectory = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogDirectory 'WatchGuard_T40_Without_T125_Global_Evaluation.log'
$ReportDirectory = 'C:\MME\CS'
$ReportPath = Join-Path $ReportDirectory 'WatchGuard_T40_Without_T125_Global_Matches.txt'

$ProviderTokenRefreshMinutes = 50
$WatchGuardGetMaxAttempts = 4
$CurrentStage = 'Initialize'
$FinalOutput = $null
$RootAccountId = $null

$ServiceAccountToken = $null
$WatchGuardItem = $null
$ApiKey = $null
$ReadOnlyAccessId = $null
$ReadOnlyPassword = $null
$AuthenticationUrl = $null
$BaseApiUrl = $null
$ProviderToken = $null
$ProviderTokenAcquiredAt = $null

$DiagnosticErrors = [System.Collections.Generic.List[string]]::new()
$MatchingAccounts = [System.Collections.Generic.List[object]]::new()
$AccountsDiscovered = 0
$AccountsEvaluated = 0
$DevicesInventoried = 0
$DevicesLocallyManagedSkipped = 0
$DevicesUnknownManagementSkipped = 0
$DevicesCloudManaged = 0

# ============================================================
# HELPERS
# ============================================================

function ConvertTo-SafeOutput {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return (([string]$Value -replace '[\r\n|]+', ' ' -replace '\s{2,}', ' ')).Trim()
}

function Initialize-Directory {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)

    try {
        ('{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message) |
            Add-Content -LiteralPath $LogPath -Encoding UTF8
    }
    catch { }
}

function Get-HttpStatusCode {
    param([AllowNull()][object]$Exception)

    if ($null -eq $Exception) { return $null }
    try {
        if ($null -ne $Exception.Response -and
            $null -ne $Exception.Response.StatusCode) {
            return [int]$Exception.Response.StatusCode
        }
    }
    catch { }
    return $null
}

function Invoke-WatchGuardGetWithRetry {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [ValidateRange(1,600)][int]$TimeoutSec = 120,
        [ValidateRange(1,10)][int]$MaxAttempts = 4
    )

    $Attempt = 0
    $RetryDelays = @(2, 5, 10)

    while ($true) {
        $Attempt++
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers `
                -TimeoutSec $TimeoutSec
        }
        catch {
            $Status = Get-HttpStatusCode -Exception $_.Exception
            $AllowedAttempts = $MaxAttempts
            if ($Status -eq 403) {
                $AllowedAttempts = [Math]::Min(2, $MaxAttempts)
            }

            $Retryable = ($null -eq $Status -or
                $Status -in @(403,408,429,500,502,503,504))
            if (-not $Retryable -or $Attempt -ge $AllowedAttempts) {
                throw
            }

            $DelaySeconds = $RetryDelays[[Math]::Min($Attempt - 1, $RetryDelays.Count - 1)]
            Write-Log ('WARN | GET_RETRY | Attempt={0}/{1} HTTP={2} DelaySeconds={3} Uri={4}' -f `
                $Attempt, $AllowedAttempts, $(if ($null -eq $Status) {'N/A'} else {$Status}), `
                $DelaySeconds, (ConvertTo-SafeOutput $Uri))
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Get-OnePasswordField {
    param(
        [Parameter(Mandatory)][object]$Item,
        [Parameter(Mandatory)][string]$Label
    )

    $Field = @($Item.fields | Where-Object { $_.label -eq $Label }) |
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

function Get-WatchGuardAccessToken {
    param(
        [Parameter(Mandatory)][string]$AuthenticationUrl,
        [Parameter(Mandatory)][string]$AccessId,
        [Parameter(Mandatory)][string]$Password,
        [string]$Audience
    )

    $CredentialBytes = [System.Text.Encoding]::ASCII.GetBytes(
        ('{0}:{1}' -f $AccessId, $Password)
    )
    $Headers = @{
        Accept = 'application/json'
        Authorization = 'Basic {0}' -f [Convert]::ToBase64String($CredentialBytes)
    }
    $Body = @{ grant_type = 'client_credentials'; scope = 'api-access' }
    if (-not [string]::IsNullOrWhiteSpace($Audience)) {
        $Body['audience'] = $Audience
    }

    $Response = Invoke-RestMethod -Method Post -Uri $AuthenticationUrl `
        -Headers $Headers -ContentType 'application/x-www-form-urlencoded' `
        -Body $Body -TimeoutSec 60
    if ($null -eq $Response -or
        [string]::IsNullOrWhiteSpace([string]$Response.access_token)) {
        throw 'WatchGuard authentication returned no access token.'
    }
    return [string]$Response.access_token
}

function Get-ResponseItems {
    param([AllowNull()][object]$Response)

    if ($null -eq $Response) { return @() }
    if ($Response -is [System.Array]) { return @($Response) }

    foreach ($PropertyName in @('objects', 'items', 'data', 'results', 'assets')) {
        if ($Response.PSObject.Properties.Name -contains $PropertyName) {
            if ($null -eq $Response.$PropertyName) { return @() }
            return @($Response.$PropertyName)
        }
    }
    return @($Response)
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
                Type = [string]$Item.type
                ParentAccess = [string]$Item.parentAccess
                RelationName = [string]$Item.relationName
                RelationType = [string]$Item.relationType
            }
        }

        if ($Item.PSObject.Properties.Name -contains 'childrenList' -and
            $null -ne $Item.childrenList) {
            $Results += @(Get-FlattenedManagedAccounts -Items @($Item.childrenList))
        }
    }
    return @($Results)
}

function Get-AccountApiContext {
    param(
        [Parameter(Mandatory)][string]$AccountId,
        [Parameter(Mandatory)][string]$RootAccountId,
        [Parameter(Mandatory)][string]$ProviderTokenForAudience,
        [Parameter(Mandatory)][string]$OwnAccountToken,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][string]$BaseApiUrl,
        [Parameter(Mandatory)][string]$AuthenticationUrl,
        [Parameter(Mandatory)][string]$AccessId,
        [Parameter(Mandatory)][string]$Password
    )

    if ($AccountId -ceq $RootAccountId) {
        $Token = $OwnAccountToken
    }
    else {
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

    return [pscustomobject]@{
        Headers = @{
            Accept = 'application/json'
            'Content-Type' = 'application/json'
            Authorization = "Bearer $Token"
            'WatchGuard-API-Key' = $ApiKey
        }
    }
}

function Get-CloudManagementState {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return 'Unknown' }
    if ($Value -is [bool]) {
        if ($Value) { return 'Cloud' }
        return 'Local'
    }

    switch (([string]$Value).Trim().ToLowerInvariant()) {
        { $_ -in @('yes', 'true', '1') } { return 'Cloud' }
        { $_ -in @('no', 'false', '0') } { return 'Local' }
        default { return 'Unknown' }
    }
}

# ============================================================
# MAIN
# ============================================================

try {
    $CurrentStage = 'Directories'
    Initialize-Directory -Path $LogDirectory
    Initialize-Directory -Path $ReportDirectory
    Set-Content -LiteralPath $LogPath -Encoding UTF8 `
        -Value ('WatchGuard T40 Without T125 Global Evaluation - {0}' -f (Get-Date -Format s))
    Write-Log 'START | Read-only WatchGuard T40 without T125 inventory scan'

    $CurrentStage = 'NinjaField'
    $ServiceAccountToken = (Ninja-Property-Get -Name $BootstrapTokenField).Trim()
    if ([string]::IsNullOrWhiteSpace($ServiceAccountToken)) {
        throw "Ninja secure custom field $BootstrapTokenField returned no value."
    }

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
            (ConvertTo-SafeOutput ($WhoAmI -join ' ')))
    }

    $CurrentStage = 'WatchGuardItem'
    $WatchGuardItemJson = & $OpExe item get $WatchGuardItemName `
        --vault $OnePasswordVault --format json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('1Password WatchGuard item retrieval failed: {0}' -f `
            (ConvertTo-SafeOutput ($WatchGuardItemJson -join ' ')))
    }
    $WatchGuardItem = $WatchGuardItemJson | ConvertFrom-Json

    $CurrentStage = 'WatchGuardConfig'
    $ApiKey = Get-OnePasswordField -Item $WatchGuardItem -Label 'credential'
    $ReadOnlyAccessId = Get-OnePasswordField -Item $WatchGuardItem -Label 'readOnlyAccessId'
    $ReadOnlyPassword = Get-OnePasswordField -Item $WatchGuardItem -Label 'readOnlyPassword'
    $RootAccountId = Get-OnePasswordField -Item $WatchGuardItem -Label 'accountID'
    $AuthenticationUrl = (Get-OnePasswordField -Item $WatchGuardItem `
        -Label 'authenticationUrl').TrimEnd('/')
    $BaseApiUrl = (Get-OnePasswordField -Item $WatchGuardItem `
        -Label 'baseApiUrl').TrimEnd('/')
    if ($RootAccountId -notmatch '^(WGC|ACC)-') {
        throw '1Password accountID has an unexpected WatchGuard account ID format.'
    }

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $ServiceAccountToken = $null
    $WatchGuardItem = $null
    Write-Log "PASS | Broker authentication complete | RootAccount=$RootAccountId"

    $CurrentStage = 'ProviderAuth'
    $ProviderToken = Get-WatchGuardAccessToken `
        -AuthenticationUrl $AuthenticationUrl `
        -AccessId $ReadOnlyAccessId -Password $ReadOnlyPassword
    $ProviderTokenAcquiredAt = Get-Date
    $ProviderHeaders = @{
        Accept = 'application/json'
        'Content-Type' = 'application/json'
        Authorization = "Bearer $ProviderToken"
        'WatchGuard-API-Key' = $ApiKey
    }

    $CurrentStage = 'AccountDiscovery'
    $AccountsUri = "$BaseApiUrl/platform/accounts/v2/accounts/$RootAccountId/children?limit=-1&includeDelegatedAccounts=false"
    $AccountsResponse = Invoke-WatchGuardGetWithRetry -Uri $AccountsUri `
        -Headers $ProviderHeaders -MaxAttempts $WatchGuardGetMaxAttempts

    if ($null -eq $AccountsResponse -or
        -not ($AccountsResponse.PSObject.Properties.Name -contains 'items')) {
        throw 'Managed-account discovery returned an unexpected response (no items field).'
    }

    $AccountRecords = @(
        [pscustomobject]@{
            AccountId = $RootAccountId
            Name = $RootAccountId
            Type = 'ROOT'
            ParentAccess = 'True'
            RelationName = ''
            RelationType = 'Root'
        }
    )
    $AccountRecords += @(Get-FlattenedManagedAccounts -Items @($AccountsResponse.items))
    $AccountRecords = @($AccountRecords | Group-Object AccountId |
        ForEach-Object { $_.Group | Select-Object -First 1 } |
        Sort-Object Name, AccountId)
    $AccountsDiscovered = $AccountRecords.Count
    Write-Log "PASS | AccountDiscovery | Accounts=$AccountsDiscovered"

    foreach ($Account in $AccountRecords) {
        $AccountId = [string]$Account.AccountId
        $AccountName = [string]$Account.Name
        $CurrentStage = "Account:$AccountId"

        try {
            $TokenAgeMinutes = ((Get-Date) - $ProviderTokenAcquiredAt).TotalMinutes
            if ($TokenAgeMinutes -ge $ProviderTokenRefreshMinutes) {
                $CurrentStage = "ProviderRefresh:$AccountId"
                $ProviderToken = Get-WatchGuardAccessToken `
                    -AuthenticationUrl $AuthenticationUrl `
                    -AccessId $ReadOnlyAccessId -Password $ReadOnlyPassword
                $ProviderTokenAcquiredAt = Get-Date
                Write-Log "PASS | ProviderTokenRefreshed | Account=$AccountId"
            }

            $CurrentStage = "AccountAuth:$AccountId"
            try {
                $AccountContext = Get-AccountApiContext -AccountId $AccountId `
                    -RootAccountId $RootAccountId -ProviderTokenForAudience $ProviderToken `
                    -OwnAccountToken $ProviderToken -ApiKey $ApiKey `
                    -BaseApiUrl $BaseApiUrl -AuthenticationUrl $AuthenticationUrl `
                    -AccessId $ReadOnlyAccessId -Password $ReadOnlyPassword
            }
            catch {
                $Status = Get-HttpStatusCode -Exception $_.Exception
                if ($Status -notin @(401,403)) { throw }
                Write-Log "WARN | AccountAuthRetry | Account=$AccountId HTTP=$Status"
                $ProviderToken = Get-WatchGuardAccessToken `
                    -AuthenticationUrl $AuthenticationUrl `
                    -AccessId $ReadOnlyAccessId -Password $ReadOnlyPassword
                $ProviderTokenAcquiredAt = Get-Date
                $CurrentStage = "AccountAuthRetry:$AccountId"
                $AccountContext = Get-AccountApiContext -AccountId $AccountId `
                    -RootAccountId $RootAccountId -ProviderTokenForAudience $ProviderToken `
                    -OwnAccountToken $ProviderToken -ApiKey $ApiKey `
                    -BaseApiUrl $BaseApiUrl -AuthenticationUrl $AuthenticationUrl `
                    -AccessId $ReadOnlyAccessId -Password $ReadOnlyPassword
            }

            $CurrentStage = "DeviceDetails:$AccountId"
            $DeviceUri = "$BaseApiUrl/firebox/management/v1/info/$AccountId/devices?device_type=FB"
            $Response = Invoke-WatchGuardGetWithRetry -Uri $DeviceUri `
                -Headers $AccountContext.Headers -MaxAttempts $WatchGuardGetMaxAttempts
            $DeviceDetails = @(Get-ResponseItems -Response $Response)

            # Fail closed on unexpected nonempty payloads to avoid false negatives.
            foreach ($Device in $DeviceDetails) {
                if ($null -eq $Device -or
                    -not ($Device.PSObject.Properties.Name -contains 'short_model_name') -or
                    -not ($Device.PSObject.Properties.Name -contains 'cloud_managed')) {
                    throw 'Firebox Device Details returned an incomplete or unexpected device object.'
                }
            }

            $AccountsEvaluated++
            $T40 = [System.Collections.Generic.List[object]]::new()
            $T125 = [System.Collections.Generic.List[object]]::new()
            $UnknownCandidates = 0

            foreach ($Device in $DeviceDetails) {
                $DevicesInventoried++
                $Model = ([string]$Device.short_model_name).Trim()
                $Management = Get-CloudManagementState -Value $Device.cloud_managed
                if ($Management -eq 'Local') {
                    $DevicesLocallyManagedSkipped++
                    continue
                }
                if ($Management -eq 'Unknown') {
                    $DevicesUnknownManagementSkipped++
                    if ($Model -in @('T40','T125')) { $UnknownCandidates++ }
                    continue
                }
                $DevicesCloudManaged++

                $Record = [pscustomobject]@{
                    Name = [string]$Device.name
                    Id = [string]$Device.id
                    Serial = [string]$Device.serial_number
                    Model = $Model
                }
                if ($Model -ieq 'T40') { $T40.Add($Record) }
                elseif ($Model -ieq 'T125') { $T125.Add($Record) }
            }

            if ($UnknownCandidates -gt 0) {
                $Message = ('Account={0} Stage=ManagementMode UnknownTargetDevices={1}' -f `
                    $AccountId, $UnknownCandidates)
                $DiagnosticErrors.Add($Message)
                Write-Log "DIAG_ERROR | $Message"
            }

            if ($T40.Count -gt 0 -and $T125.Count -eq 0) {
                $MatchingAccounts.Add([pscustomobject]@{
                    AccountId = $AccountId
                    AccountName = $AccountName
                    T40 = @($T40.ToArray())
                    T125 = @($T125.ToArray())
                })
                Write-Log ('MATCH | Account={0} Name={1} T40={2} T125={3}' -f `
                    $AccountId, (ConvertTo-SafeOutput $AccountName), $T40.Count, $T125.Count)
            }
            else {
                Write-Log ('ACCOUNT_DONE | Account={0} Devices={1} T40={2} T125={3}' -f `
                    $AccountId, $DeviceDetails.Count, $T40.Count, $T125.Count)
            }
        }
        catch {
            $Status = Get-HttpStatusCode -Exception $_.Exception
            if ($null -eq $Status) { $Status = 'N/A' }
            $Message = ('Account={0} Name={1} Stage={2} HTTP={3} Error={4}' -f `
                $AccountId, (ConvertTo-SafeOutput $AccountName), `
                (ConvertTo-SafeOutput $CurrentStage), $Status, `
                (ConvertTo-SafeOutput $_.Exception.Message))
            $DiagnosticErrors.Add($Message)
            Write-Log "DIAG_ERROR | $Message"
            continue
        }
    }

    $CurrentStage = 'WriteReport'
    $ReportLines = [System.Collections.Generic.List[string]]::new()
    $ReportLines.Add('WATCHGUARD GLOBAL T40 WITHOUT T125 ACCOUNT INVENTORY')
    $ReportLines.Add(('Generated: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    $ReportLines.Add("Root Account: $RootAccountId")
    $ReportLines.Add('Scope: Non-delegated accounts; cloud-managed Fireboxes only; connectivity ignored')
    $ReportLines.Add('')
    $ReportLines.Add("Accounts Discovered: $AccountsDiscovered")
    $ReportLines.Add("Accounts Evaluated: $AccountsEvaluated")
    $ReportLines.Add("Devices Inventoried: $DevicesInventoried")
    $ReportLines.Add("Cloud-Managed Devices: $DevicesCloudManaged")
    $ReportLines.Add("Locally Managed Skipped: $DevicesLocallyManagedSkipped")
    $ReportLines.Add("Unknown Management Skipped: $DevicesUnknownManagementSkipped")
    $ReportLines.Add("Matching Accounts: $($MatchingAccounts.Count)")
    $ReportLines.Add("Diagnostic Errors: $($DiagnosticErrors.Count)")
    $ReportLines.Add('')

    foreach ($Match in @($MatchingAccounts.ToArray() | Sort-Object AccountName, AccountId)) {
        $ReportLines.Add(('ACCOUNT | Name={0} | AccountId={1} | T40={2} | T125={3}' -f `
            (ConvertTo-SafeOutput $Match.AccountName), $Match.AccountId, `
            $Match.T40.Count, $Match.T125.Count))
        foreach ($Device in @($Match.T40 | Sort-Object Model, Name, Id)) {
            $ReportLines.Add(('  DEVICE | Model={0} | Name={1} | Id={2} | Serial={3}' -f `
                (ConvertTo-SafeOutput $Device.Model), (ConvertTo-SafeOutput $Device.Name), `
                (ConvertTo-SafeOutput $Device.Id), (ConvertTo-SafeOutput $Device.Serial)))
        }
        $ReportLines.Add('')
    }

    if ($DiagnosticErrors.Count -gt 0) {
        $ReportLines.Add('DIAGNOSTIC ERRORS (RESULT IS INCOMPLETE)')
        foreach ($DiagnosticError in $DiagnosticErrors) {
            $ReportLines.Add(('  {0}' -f $DiagnosticError))
        }
    }
    $ReportLines | Set-Content -LiteralPath $ReportPath -Encoding UTF8

    if ($DiagnosticErrors.Count -gt 0) {
        $FinalOutput = ('ERROR | Incomplete global T40-without-T125 inventory | AccountsEvaluated={0}/{1} Matches={2} Errors={3} File={4}' -f `
            $AccountsEvaluated, $AccountsDiscovered, $MatchingAccounts.Count, $DiagnosticErrors.Count, $ReportPath)
    }
    elseif ($MatchingAccounts.Count -gt 0) {
        $FinalOutput = ('TRIGGER | Accounts with T40 and no T125 | AccountsEvaluated={0} Matches={1} DevicesInventoried={2} LocalSkipped={3} File={4}' -f `
            $AccountsEvaluated, $MatchingAccounts.Count, $DevicesInventoried, `
            $DevicesLocallyManagedSkipped, $ReportPath)
    }
    else {
        $FinalOutput = ('NO_ACTION | No accounts with T40 and no T125 | AccountsEvaluated={0} DevicesInventoried={1} LocalSkipped={2} File={3}' -f `
            $AccountsEvaluated, $DevicesInventoried, $DevicesLocallyManagedSkipped, $ReportPath)
    }
    Write-Log $FinalOutput
}
catch {
    $Status = Get-HttpStatusCode -Exception $_.Exception
    if ($null -eq $Status) { $Status = 'N/A' }
    $FinalOutput = ('ERROR | Stage={0} HTTP={1} Error={2}' -f `
        (ConvertTo-SafeOutput $CurrentStage), $Status, `
        (ConvertTo-SafeOutput $_.Exception.Message))
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
    $ProviderTokenAcquiredAt = $null
}

if ([string]::IsNullOrWhiteSpace([string]$FinalOutput)) {
    $FinalOutput = 'ERROR | Stage=Finalize Error=No final output was generated.'
}
Write-Output $FinalOutput
exit 0
