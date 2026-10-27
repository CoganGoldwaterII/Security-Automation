# ============================================================================
# NAME: EVALUATION - WatchGuard Global Firebox Template Subscription Check
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation / Read-Only
# SCOPE: Credential Broker / Device 9800 only / Global WatchGuard Cloud Subscribers
# VARIABLES:
#   None. Desired template ID is fixed below.
# FILE TRANSFERS:
#   None. The script creates only an evaluation manifest.
# OUTPUT TOKENS:
#   TRIGGER   | One or more cloud-managed Fireboxes lack the desired template ID
#   NO_ACTION | Every successfully audited cloud-managed Firebox has the ID
#   ERROR     | Incomplete inventory, invalid scope, or API/manifest failure
# CUSTOM FIELDS:
#   Reads: opServiceAccountToken (NinjaOne secure field)
#   Writes: None
# LOGGING PATH:
#   C:\MME\AutoLogs\WatchGuard_Template_Subscription_Evaluation.log
# STAGING / MANIFESTS:
#   C:\MME\CS\WatchGuard_Template_Subscriptions_Global_<Timestamp>.json
# DESCRIPTION:
#   - Preserves the proven broker -> 1Password -> WatchGuard read-only flow.
#   - Validates managed hierarchy; explicitly excludes delegated Subscribers.
#   - Enumerates all managed Subscriber accounts at runtime; no fixed scope.
#   - Skips delegated Subscribers with explicit skip records in the manifest.
#   - Reports every Firebox found, skips locally managed, and flags unknown mode.
#   - Includes offline/never-connected cloud Fireboxes, no connectivity gate.
#   - Manifest preserves every current subscription and its API response sequence.
#   - Exact desired template ID match -> NO_ACTION; absent -> TRIGGER.
#   - Errors from any account/device -> ERROR overall, never partial TRIGGER.
#   - Uses bounded retries (HTTP 408/429/500/502/503/504) for read and auth calls.
#   - Refreshes provider token before expiry for long-running global evaluations.
#   - READ ONLY: no subscription writes, deploys, or configuration changes.
#   - Single final exit 0 (Ninja-safe), one stdout result line.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ============================================================
# CONFIGURATION / STATE
# ============================================================
$DesiredTemplateId = 'tmpl_ckGsxX3ycdqw8tuYEXbQqQl'
$DesiredTemplateName = 'Third Party Remote Software Blocked -Template'
$DesiredTemplateOwnerId = 'ACC-0120546'
$OnePasswordVault = 'MME Automation'
$WatchGuardItemName = 'WatchGuard'
$BootstrapTokenField = 'opServiceAccountToken'
$LogDirectory = 'C:\MME\AutoLogs'
$StagingDirectory = 'C:\MME\CS'
$LogPath = Join-Path $LogDirectory 'WatchGuard_Template_Subscription_Evaluation.log'
$RunId = Get-Date -Format 'yyyyMMdd_HHmmss'
$ManifestPath = Join-Path $StagingDirectory "WatchGuard_Template_Subscriptions_Global_$RunId.json"
$RetryStatusCodes = @(408, 429, 500, 502, 503, 504)
$RetryDelays = @(2, 5, 10, 20)
$Stage = 'Initialize'
$ProviderAccountId = ''
$ApiKey = $null
$ReadOnlyAccessId = $null
$ReadOnlyPassword = $null
$AuthenticationUrl = $null
$BaseApiUrl = $null
$Token = $null
$ProviderToken = $null
$ProviderTokenIssuedAt = $null
$OpExe = $null
$Errors = [System.Collections.Generic.List[object]]::new()
$AccountResults = [System.Collections.Generic.List[object]]::new()
$ScopedAccountIds = @()
$EligibleAccountCount = 0
$SubscribersDiscoveredCount = 0
$DelegatedSkippedCount = 0
$Outcome = 'INCOMPLETE'
$FinalOutput = $null
$AccountsAudited = 0
$AccountsNeedingTemplate = 0
$DevicesDiscovered = 0
$CloudCount = 0
$LocalCount = 0
$UnknownCount = 0
$OfflineCount = 0
$SubscriptionCount = 0
$PresentCount = 0
$MissingCount = 0

# ============================================================
# STANDARD HELPERS
# ============================================================
function Ensure-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-Log([string]$Message) {
    try {
        '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message |
            Add-Content -LiteralPath $LogPath -Encoding UTF8
    }
    catch { }
}

function Get-HttpStatus($ErrorRecord) {
    try {
        if ($null -ne $ErrorRecord.Exception.Response) {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
    }
    catch { }
    return $null
}

function Invoke-WGApi {
    param(
        [Parameter(Mandatory)][ValidateSet('Get','Post')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [object]$Body,
        [string]$ContentType,
        [string]$Label = 'API'
    )
    for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
        $Arguments = @{
            Method = $Method
            Uri = $Uri
            TimeoutSec = 75
            ErrorAction = 'Stop'
        }
        if ($null -ne $Headers) { $Arguments.Headers = $Headers }
        if ($null -ne $Body) { $Arguments.Body = $Body }
        if ($ContentType) { $Arguments.ContentType = $ContentType }
        try {
            Start-Sleep -Milliseconds 100
            return Invoke-RestMethod @Arguments
        }
        catch {
            $Http = Get-HttpStatus $_
            if ($Attempt -eq 5 -or $null -eq $Http -or $Http -notin $RetryStatusCodes) {
                throw
            }
            $Delay = $RetryDelays[$Attempt - 1]
            Write-Log ("RETRY | Stage={0} Attempt={1}/5 HTTP={2} DelaySeconds={3}" -f $Label, $Attempt, $Http, $Delay)
            Start-Sleep -Seconds $Delay
        }
    }
}

function Get-OpField($Item, [string]$Label) {
    $Field = @($Item.fields | Where-Object { $_.label -eq $Label -or $_.id -eq $Label } | Select-Object -First 1)
    if ($Field.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$Field[0].value)) {
        throw "Required 1Password field unavailable: $Label"
    }
    return ([string]$Field[0].value).Trim()
}

function Get-WGToken([string]$AccessId, [string]$Password, [string]$Audience) {
    $Basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${AccessId}:${Password}"))
    $Body = @{ grant_type = 'client_credentials'; scope = 'api-access' }
    if ($Audience) { $Body.audience = $Audience }
    $Response = Invoke-WGApi -Method Post -Uri $AuthenticationUrl `
        -Headers @{Accept='application/json'; Authorization="Basic $Basic"} `
        -ContentType 'application/x-www-form-urlencoded' -Body $Body -Label 'Authentication'
    if ([string]::IsNullOrWhiteSpace([string]$Response.access_token)) {
        throw 'Authentication returned no access_token.'
    }
    return [string]$Response.access_token
}

function Get-WGHeaders([string]$AccessToken) {
    return @{
        Accept = 'application/json'
        'Content-Type' = 'application/json'
        Authorization = "Bearer $AccessToken"
        'WatchGuard-API-Key' = $ApiKey
    }
}

function Expand-ManagedAccounts([object[]]$Accounts) {
    foreach ($Account in @($Accounts)) {
        if ($null -eq $Account) { continue }
        Write-Output $Account
        if ($Account.PSObject.Properties.Name -contains 'childrenList') {
            $Children = @($Account.childrenList)
            if ($Children.Count -gt 0) { Expand-ManagedAccounts -Accounts $Children }
        }
    }
}

# ============================================================
# EVALUATION / MANIFEST HELPERS
# ============================================================
function Add-EvalError([string]$ErrorStage, [string]$AccountId, [string]$DeviceId, $ErrorRecord) {
    $Http = Get-HttpStatus $ErrorRecord
    $Kind = if ($null -ne $ErrorRecord) { $ErrorRecord.Exception.GetType().Name } else { 'Validation' }
    $Errors.Add([PSCustomObject]@{
        stage = $ErrorStage
        accountId = $AccountId
        deviceId = $DeviceId
        httpStatus = $Http
        errorType = $Kind
    }) | Out-Null
    Write-Log ("ERROR | Stage={0} Account={1} Device={2} HTTP={3} Type={4}" -f $ErrorStage, $AccountId, $DeviceId, $Http, $Kind)
}

function Save-AtomicJson([string]$Path, [object]$Document) {
    $Tmp = "$Path.$RunId.tmp"
    try {
        $Document | ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $Tmp -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $Tmp -Destination $Path -Force -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $Tmp) {
            Remove-Item -LiteralPath $Tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-Delegated($Account) {
    return ([string]$Account.relationName -ieq 'Delegated' -or
        [string]$Account.relationType -ieq 'Delegated')
}

function Write-Manifest {
    $Document = [ordered]@{
        schemaVersion = 2
        evaluation = 'WatchGuardTemplateSubscriptionCompliance'
        mode = 'READ_ONLY_GLOBAL'
        runId = $RunId
        capturedAtUtc = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        outcome = $Outcome
        providerAccountId = $ProviderAccountId
        target = [ordered]@{
            templateId = $DesiredTemplateId
            templateName = $DesiredTemplateName
            ownerAccountId = $DesiredTemplateOwnerId
            matchingRule = 'EXACT_TEMPLATE_ID_MEMBERSHIP_ONLY'
        }
        scope = [ordered]@{
            scopeMode = 'GLOBAL_NON_DELEGATED_SUBSCRIBERS'
            subscribersDiscovered = $SubscribersDiscoveredCount
            eligibleNonDelegatedSubscribers = $EligibleAccountCount
            delegatedSkipped = $DelegatedSkippedCount
            accountIds = @($ScopedAccountIds)
        }
        summary = [ordered]@{
            accountsInScope = @($ScopedAccountIds).Count
            delegatedSkipped = $DelegatedSkippedCount
            accountsAudited = $AccountsAudited
            accountsNeedingTemplate = $AccountsNeedingTemplate
            devicesDiscovered = $DevicesDiscovered
            cloudManaged = $CloudCount
            locallyManagedSkipped = $LocalCount
            managementUnknown = $UnknownCount
            offlineOrNeverConnectedCloudDevices = $OfflineCount
            currentSubscriptions = $SubscriptionCount
            cloudDevicesWithTarget = $PresentCount
            cloudDevicesMissingTarget = $MissingCount
            errors = $Errors.Count
        }
        accounts = @($AccountResults.ToArray())
        errors = @($Errors.ToArray())
    }
    Save-AtomicJson -Path $ManifestPath -Document $Document
}

function Refresh-ProviderToken {
    $script:ProviderToken = Get-WGToken $ReadOnlyAccessId $ReadOnlyPassword ''
    $script:ProviderTokenIssuedAt = Get-Date
}

function Invoke-AccountEvaluation([object]$Account) {
    $AccountId = [string]$Account.accountId
    $AccountName = [string]$Account.name
    $AccountStage = 'BeginAccount'
    $AccountDevices = [System.Collections.Generic.List[object]]::new()
    $AccountAvailableTemplates = @()
    $AccountDeviceCount = 0
    $AccountCloud = 0
    $AccountLocal = 0
    $AccountUnknown = 0
    $AccountOffline = 0
    $AccountSubscriptions = 0
    $AccountPresent = 0
    $AccountMissing = 0
    $ErrorStart = $Errors.Count
    $AccountStatus = 'ERROR'
    $TemplateFound = $false
    Write-Log "ACCOUNT_START | Account=$AccountId Name=$AccountName"

    try {
        if ($null -eq $ProviderTokenIssuedAt -or
            ((Get-Date) - $ProviderTokenIssuedAt).TotalMinutes -ge 45) {
            Refresh-ProviderToken
        }
        $ProviderHeaders = Get-WGHeaders $ProviderToken
        $AccountStage = 'SubscriberAudience'
        $AudienceResponse = Invoke-WGApi -Method Post `
            -Uri "$BaseApiUrl/platform/authorization/v1/audiences" `
            -Headers $ProviderHeaders `
            -Body (@{accountId=$AccountId} | ConvertTo-Json -Compress) `
            -ContentType 'application/json' -Label "$AccountStage`:$AccountId"
        if ([string]::IsNullOrWhiteSpace([string]$AudienceResponse.audience)) {
            throw 'Subscriber audience not returned.'
        }

        $AccountStage = 'SubscriberAuthentication'
        $SubscriberToken = Get-WGToken $ReadOnlyAccessId $ReadOnlyPassword ([string]$AudienceResponse.audience)
        $SubscriberHeaders = Get-WGHeaders $SubscriberToken

        $AccountStage = 'AvailableTemplates'
        $TemplatesUri = "$BaseApiUrl/firebox/management/v1/configuration/$AccountId/templates/subscribe"
        $AvailableResponse = Invoke-WGApi -Method Get -Uri $TemplatesUri -Headers $SubscriberHeaders -Label "$AccountStage`:$AccountId"
        if ($null -eq $AvailableResponse -or
            $AvailableResponse.PSObject.Properties.Name -notcontains 'templates' -or
            $null -eq $AvailableResponse.templates) {
            throw 'Account available-template inventory absent.'
        }
        $AccountAvailableTemplates = @($AvailableResponse.templates | ForEach-Object {
            [PSCustomObject]@{
                id = [string]$_.id
                name = [string]$_.name
                ownerAccountId = [string]$_.account_id
            }
        })
        if (@($AccountAvailableTemplates | Where-Object { [string]::IsNullOrWhiteSpace($_.id) }).Count -gt 0) {
            throw 'Available template entry missing ID.'
        }
        $MatchingAvailable = @($AccountAvailableTemplates | Where-Object { $_.id -ceq $DesiredTemplateId })
        if ($MatchingAvailable.Count -ne 1) {
            throw 'Target template not uniquely present in account available templates.'
        }
        if ([string]$MatchingAvailable[0].ownerAccountId -ne $DesiredTemplateOwnerId) {
            throw 'Target template owner differs from expected provider account.'
        }
        $TemplateFound = $true
        Write-Log ("AVAILABLE_TEMPLATES | Account={0} Count={1} TargetAvailable=True" -f $AccountId, $AccountAvailableTemplates.Count)

        $AccountStage = 'DeviceDetails'
        $DevicesUri = "$BaseApiUrl/firebox/management/v1/info/$AccountId/devices?device_type=FB"
        $DevicesResponse = Invoke-WGApi -Method Get -Uri $DevicesUri -Headers $SubscriberHeaders -Label "$AccountStage`:$AccountId"
        if ($null -eq $DevicesResponse -or $null -eq $DevicesResponse.data -or
            $DevicesResponse.PSObject.Properties.Name -notcontains 'count') {
            throw 'Device Details response missing count/data.'
        }
        $DeviceList = @($DevicesResponse.data)
        $AccountDeviceCount = $DeviceList.Count
        if ([int]$DevicesResponse.count -ne $AccountDeviceCount) {
            throw "Device Details count mismatch: API=$($DevicesResponse.count); data=$AccountDeviceCount."
        }
        Write-Log "DEVICES | Account=$AccountId Total=$AccountDeviceCount"

        $AccountStage = 'DeviceTemplateSubscriptions'
        foreach ($Device in @($DeviceList | Sort-Object id)) {
            $DeviceId = [string]$Device.id
            $Management = [string]$Device.cloud_managed
            $State = [string]$Device.state
            $Record = [ordered]@{
                deviceId = $DeviceId
                deviceName = [string]$Device.name
                serialNumber = [string]$Device.serial_number
                model = [string]$Device.short_model_name
                firewareVersion = [string]$Device.version
                cloudManaged = $Management
                connectionState = $State
                offlineSince = [string]$Device.offline_since
                status = 'NOT_EVALUATED'
                targetTemplateId = $DesiredTemplateId
                targetSubscribed = $null
                templateCount = 0
                subscribedTemplateIdsApiResponseOrder = @()
                subscribedTemplates = @()
            }

            if ($Management -ieq 'no') {
                $AccountLocal++
                $Record.status = 'SKIPPED_LOCALLY_MANAGED'
                $AccountDevices.Add([PSCustomObject]$Record) | Out-Null
                Write-Log "DEVICE_SKIP | Account=$AccountId Device=$DeviceId Mode=LocallyManaged"
                continue
            }
            if ($Management -ine 'yes') {
                $AccountUnknown++
                $Record.status = 'ERROR_MANAGEMENT_UNKNOWN'
                $AccountDevices.Add([PSCustomObject]$Record) | Out-Null
                Add-EvalError 'ManagementClassification' $AccountId $DeviceId $null
                continue
            }
            $AccountCloud++
            if ($State -in @('offline','never connected')) { $AccountOffline++ }
            if ($DeviceId -match '^FB-(\d+)$') {
                $QueryDeviceId = $Matches[1]
            }
            elseif ($DeviceId -match '^FBCL-\d+$') {
                $QueryDeviceId = $DeviceId
            }
            else {
                $Record.status = 'ERROR_INVALID_DEVICE_ID'
                $AccountDevices.Add([PSCustomObject]$Record) | Out-Null
                Add-EvalError 'DeviceIdValidation' $AccountId $DeviceId $null
                continue
            }

            try {
                $SubscriptionUri = "$TemplatesUri`?device=$([Uri]::EscapeDataString($QueryDeviceId))"
                $SubscriptionResponse = Invoke-WGApi -Method Get -Uri $SubscriptionUri -Headers $SubscriberHeaders `
                    -Label "Subscription:$AccountId`:$DeviceId"
                if ($null -eq $SubscriptionResponse -or
                    $SubscriptionResponse.PSObject.Properties.Name -notcontains 'templates' -or
                    $null -eq $SubscriptionResponse.templates) {
                    throw 'Device subscription result missing templates array.'
                }
                $Templates = [System.Collections.Generic.List[object]]::new()
                $Ids = [System.Collections.Generic.List[string]]::new()
                $Index = 0
                foreach ($Template in @($SubscriptionResponse.templates)) {
                    $Index++
                    $Id = [string]$Template.id
                    if ([string]::IsNullOrWhiteSpace($Id)) { throw 'Subscription entry has no template ID.' }
                    $Templates.Add([PSCustomObject]@{
                        apiResponseIndex = $Index
                        id = $Id
                        name = [string]$Template.name
                    }) | Out-Null
                    $Ids.Add($Id) | Out-Null
                }
                if (@($Ids.ToArray() | Select-Object -Unique).Count -ne $Ids.Count) {
                    throw 'Duplicate template IDs in subscription response.'
                }
                $Present = @($Ids.ToArray() | Where-Object { $_ -ceq $DesiredTemplateId }).Count -eq 1
                $Record.targetSubscribed = [bool]$Present
                $Record.status = if ($Present) { 'NO_ACTION' } else { 'TRIGGER' }
                $Record.templateCount = $Templates.Count
                $Record.subscribedTemplateIdsApiResponseOrder = @($Ids.ToArray())
                $Record.subscribedTemplates = @($Templates.ToArray())
                $AccountSubscriptions += $Templates.Count
                if ($Present) { $AccountPresent++ } else { $AccountMissing++ }
                Write-Log ("DEVICE_AUDIT | Account={0} Device={1} Name={2} State={3} Result={4} Templates={5} IDs={6}" -f `
                    $AccountId, $DeviceId, $Record.deviceName, $State, $Record.status, $Templates.Count, ($Ids.ToArray() -join ','))
            }
            catch {
                $Record.status = 'ERROR_SUBSCRIPTION_QUERY'
                Add-EvalError 'DeviceTemplateSubscriptions' $AccountId $DeviceId $_
            }
            $AccountDevices.Add([PSCustomObject]$Record) | Out-Null
        }
        if ($Errors.Count -eq $ErrorStart) {
            $AccountStatus = if ($AccountMissing -gt 0) { 'TRIGGER' } else { 'NO_ACTION' }
        }
    }
    catch {
        Add-EvalError $AccountStage $AccountId '' $_
        $AccountStatus = 'ERROR'
    }
    finally {
        if ($Errors.Count -gt $ErrorStart) { $AccountStatus = 'ERROR' }
        $script:DevicesDiscovered += $AccountDeviceCount
        $script:CloudCount += $AccountCloud
        $script:LocalCount += $AccountLocal
        $script:UnknownCount += $AccountUnknown
        $script:OfflineCount += $AccountOffline
        $script:SubscriptionCount += $AccountSubscriptions
        $script:PresentCount += $AccountPresent
        $script:MissingCount += $AccountMissing
        if ($AccountStatus -ne 'ERROR') { $script:AccountsAudited++ }
        if ($AccountStatus -eq 'TRIGGER') { $script:AccountsNeedingTemplate++ }

        $AccountResults.Add([PSCustomObject]@{
            accountId = $AccountId
            accountName = $AccountName
            relationName = [string]$Account.relationName
            status = $AccountStatus
            targetTemplateAvailable = $TemplateFound
            availableTemplates = @($AccountAvailableTemplates)
            summary = [PSCustomObject]@{
                devicesDiscovered = $AccountDeviceCount
                cloudManaged = $AccountCloud
                locallyManagedSkipped = $AccountLocal
                managementUnknown = $AccountUnknown
                offlineOrNeverConnectedCloudDevices = $AccountOffline
                currentSubscriptions = $AccountSubscriptions
                cloudDevicesWithTarget = $AccountPresent
                cloudDevicesMissingTarget = $AccountMissing
                errors = ($Errors.Count - $ErrorStart)
            }
            devices = @($AccountDevices.ToArray())
        }) | Out-Null
        Write-Log ("ACCOUNT_END | Account={0} Status={1} Devices={2} Cloud={3} LocalSkipped={4} Offline={5} Present={6} Missing={7} Errors={8}" -f `
            $AccountId, $AccountStatus, $AccountDeviceCount, $AccountCloud, $AccountLocal, $AccountOffline, `
            $AccountPresent, $AccountMissing, ($Errors.Count - $ErrorStart))
    }
}
# ============================================================
# MAIN / SCOPE INITIALIZATION
# ============================================================
try {
    Ensure-Directory $LogDirectory
    Ensure-Directory $StagingDirectory
    Write-Log "START | Mode=GlobalReadOnly Template=$DesiredTemplateId RunId=$RunId"

    $Stage = 'NinjaSecureField'
    $Token = [string](Ninja-Property-Get -Name $BootstrapTokenField)
    if ([string]::IsNullOrWhiteSpace($Token)) { throw 'Ninja secure custom field is empty.' }
    $env:OP_SERVICE_ACCOUNT_TOKEN = $Token.Trim()
    $Token = $null

    $Stage = 'OnePasswordCLI'
    foreach ($Candidate in @('C:\Program Files\1Password CLI\op.exe','C:\Program Files\1Password\op.exe')) {
        if (Test-Path -LiteralPath $Candidate) { $OpExe = $Candidate; break }
    }
    if (-not $OpExe) {
        $Command = Get-Command 'op.exe' -ErrorAction SilentlyContinue
        if ($Command) { $OpExe = $Command.Source }
    }
    if (-not $OpExe) { throw '1Password CLI not found.' }
    $null = & $OpExe whoami --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw '1Password CLI authentication failed.' }

    $Stage = 'WatchGuardCredentials'
    $Raw = & $OpExe item get $WatchGuardItemName --vault $OnePasswordVault --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Unable to retrieve WatchGuard 1Password item.' }
    $Item = ($Raw -join "`n") | ConvertFrom-Json
    $ApiKey = Get-OpField $Item 'credential'
    $ReadOnlyAccessId = Get-OpField $Item 'readOnlyAccessId'
    $ReadOnlyPassword = Get-OpField $Item 'readOnlyPassword'
    $ProviderAccountId = Get-OpField $Item 'accountID'
    $AuthenticationUrl = (Get-OpField $Item 'authenticationUrl').TrimEnd('/')
    $BaseApiUrl = (Get-OpField $Item 'baseApiUrl').TrimEnd('/')
    $Raw = $null
    $Item = $null
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null

    $Stage = 'ProviderAuthentication'
    Refresh-ProviderToken
    $ProviderHeaders = Get-WGHeaders $ProviderToken

    $Stage = 'ManagedAccountDiscovery'
    $AccountsUri = "$BaseApiUrl/platform/accounts/v2/accounts/$ProviderAccountId/children?type=0&limit=-1&includeDelegatedAccounts=true"
    $AccountResponse = Invoke-WGApi -Method Get -Uri $AccountsUri -Headers $ProviderHeaders -Label $Stage
    if ($null -eq $AccountResponse -or $null -eq $AccountResponse.items) {
        throw 'Managed-account discovery returned no items property.'
    }
    $AllSubscribers = @(Expand-ManagedAccounts -Accounts @($AccountResponse.items) |
        Where-Object { [int]$_.type -in @(2,4) } |
        Group-Object accountId | ForEach-Object { $_.Group[0] })
    $Stage = 'GlobalScopeValidation'
    if ($AllSubscribers.Count -eq 0) {
        throw 'No managed Subscriber accounts discovered; global inventory is incomplete.'
    }
    if (@($AllSubscribers | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.accountId)
    }).Count -gt 0) {
        throw 'Subscriber discovery includes an account with no account ID.'
    }

    $AllSubscribers = @($AllSubscribers | Sort-Object accountId)
    $SubscribersDiscoveredCount = $AllSubscribers.Count
    $EligibleSubscribers = @($AllSubscribers | Where-Object { -not (Test-Delegated $_) })
    $DelegatedSubscribers = @($AllSubscribers | Where-Object { Test-Delegated $_ })
    $EligibleAccountCount = $EligibleSubscribers.Count
    $DelegatedSkippedCount = $DelegatedSubscribers.Count
    $ScopedAccountIds = @($EligibleSubscribers | ForEach-Object { [string]$_.accountId })

    if ($EligibleAccountCount -eq 0 -or
        ($EligibleAccountCount + $DelegatedSkippedCount) -ne $SubscribersDiscoveredCount) {
        throw 'Global subscriber scope is empty or does not reconcile.'
    }

    Write-Log ("SCOPE | Mode=GLOBAL SubscribersDiscovered={0} Eligible={1} DelegatedSkipped={2}" -f `
        $SubscribersDiscoveredCount, $EligibleAccountCount, $DelegatedSkippedCount)

    # All discovered Subscribers are accounted for. Delegated relationships are
    # documented but never authenticated, queried, or evaluated.
    foreach ($Account in $AllSubscribers) {
        $AccountId = [string]$Account.accountId
        if (Test-Delegated $Account) {
            $AccountResults.Add([PSCustomObject]@{
                accountId = $AccountId
                accountName = [string]$Account.name
                relationName = [string]$Account.relationName
                status = 'SKIPPED_DELEGATED'
                targetTemplateAvailable = $null
                availableTemplates = @()
                summary = [PSCustomObject]@{
                    devicesDiscovered = 0
                    cloudManaged = 0
                    locallyManagedSkipped = 0
                    managementUnknown = 0
                    offlineOrNeverConnectedCloudDevices = 0
                    currentSubscriptions = 0
                    cloudDevicesWithTarget = 0
                    cloudDevicesMissingTarget = 0
                    errors = 0
                }
                devices = @()
            }) | Out-Null
            Write-Log "ACCOUNT_SKIP | Account=$AccountId Name=$($Account.name) Reason=Delegated"
            continue
        }
        $Stage = "Account:$AccountId"
        Invoke-AccountEvaluation -Account $Account
    }
    if ($Errors.Count -eq 0 -and $AccountsAudited -eq $ScopedAccountIds.Count) {
        $Outcome = if ($MissingCount -gt 0) { 'TRIGGER' } else { 'NO_ACTION' }
    }
    else {
        $Outcome = 'INCOMPLETE'
    }
}
catch {
    Add-EvalError $Stage '' '' $_
    $Outcome = 'INCOMPLETE'
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $Token = $null
    $ProviderToken = $null
    $ReadOnlyPassword = $null
    $ApiKey = $null
    try {
        Ensure-Directory $LogDirectory
        Ensure-Directory $StagingDirectory
        Write-Manifest
        Write-Log ("END | Outcome={0} AccountsAudited={1}/{2} DelegatedSkipped={3} Devices={4} Cloud={5} LocalSkipped={6} Offline={7} Present={8} Missing={9} Errors={10} Manifest={11}" -f `
            $Outcome, $AccountsAudited, $ScopedAccountIds.Count, $DelegatedSkippedCount, $DevicesDiscovered, $CloudCount, `
            $LocalCount, $OfflineCount, $PresentCount, $MissingCount, $Errors.Count, $ManifestPath)
    }
    catch {
        $Outcome = 'INCOMPLETE'
        Write-Log 'ERROR | Stage=WriteManifest; evaluation report not persisted.'
        $ManifestPath = 'NOT_WRITTEN'
    }

    if ($Outcome -eq 'TRIGGER') {
        $FinalOutput = "TRIGGER | TemplateMissing Template=$DesiredTemplateId Accounts=$($ScopedAccountIds.Count) DelegatedSkipped=$DelegatedSkippedCount AccountsNeeding=$AccountsNeedingTemplate Cloud=$CloudCount Missing=$MissingCount Present=$PresentCount LocalSkipped=$LocalCount Offline=$OfflineCount Errors=0 Manifest=$ManifestPath"
    }
    elseif ($Outcome -eq 'NO_ACTION') {
        $FinalOutput = "NO_ACTION | TemplatePresent Template=$DesiredTemplateId Accounts=$($ScopedAccountIds.Count) DelegatedSkipped=$DelegatedSkippedCount Cloud=$CloudCount Missing=0 Present=$PresentCount LocalSkipped=$LocalCount Offline=$OfflineCount Errors=0 Manifest=$ManifestPath"
    }
    else {
        $FinalOutput = "ERROR | EvaluationIncomplete Template=$DesiredTemplateId AccountsAudited=$AccountsAudited/$($ScopedAccountIds.Count) DelegatedSkipped=$DelegatedSkippedCount Cloud=$CloudCount Missing=$MissingCount Errors=$($Errors.Count) Manifest=$ManifestPath"
    }
    Write-Output $FinalOutput
    exit 0
}
