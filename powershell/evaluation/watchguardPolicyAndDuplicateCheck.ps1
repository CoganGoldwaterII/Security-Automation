# ============================================================================
# NAME: WatchGuard Firewall Policy Collision Check
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation / Inventory
# SCOPE: Windows / Authorized Credential Broker / WatchGuard Cloud Account
#
# VARIABLES:
#   Required:
#     OnePasswordVault       - 1Password vault containing API configuration
#     BootstrapTokenField   - NinjaOne secure field with 1Password token
#
#   Optional:
#     WatchGuardItemName    - 1Password API configuration item (WatchGuard)
#     LogDirectory         - Local execution log directory
#     ReportDirectory      - Local diagnostic report directory
#
#   NinjaOne calculated environment variable:
#     targetWatchguardCloudAccountId - Account ID to evaluate
#
# OUTPUT TOKENS:
#   TRIGGER   | Local/template policy collisions found | Account=<id>
#               Devices=<n> Collisions=<n> File=<path>
#   NO_ACTION | No local/template policy collisions | Account=<id>
#               Devices=<n> File=<path>
#   ERROR     | Stage=<stage> HTTP=<status> Error=<message>
#   Exit Code: Always 0 after script execution
#
# CUSTOM FIELDS:
#   Reads: Ninja secure field supplied by BootstrapTokenField
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   <LogDirectory>\WatchGuard_Firewall_Policy_Collision_Check.log
#
# DESCRIPTION:
#   Uses read-only WatchGuard API credentials obtained from 1Password to
#   inventory Fireboxes and FireClusters under one calculated account ID.
#   Retrieves device-local firewall policies and subscribed template policies,
#   then identifies exact-name collisions between local and template policies.
#
#   Reports device ID/name associations, collision details, exact policy IDs,
#   and full local firewall policy objects. Standalone FB-<id> values are
#   normalized for configuration API queries; FBCL- identifiers are retained.
#
#   No account, device, policy, or template IDs are hardcoded.
#   No WatchGuard, NinjaOne, or 1Password configuration changes are made.
#
#   SECURITY:
#     Report content generated at runtime may contain customer device names,
#     serial numbers, policy configuration, and topology information.
#     Restrict access to generated reports and diagnostic logs.
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OnePasswordVault,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BootstrapTokenField,

    [string]$WatchGuardItemName = 'WatchGuard',
    [string]$ReportDirectory = (Join-Path $env:ProgramData 'AutomationPlaybook\Reports'),
    [string]$LogDirectory = (Join-Path $env:ProgramData 'AutomationPlaybook\Logs')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ============================================================
# CONSTANTS
# ============================================================

$TargetAccountVariable = 'targetWatchguardCloudAccountId'


$ReportPath = $null

$LogPath = Join-Path $LogDirectory 'WatchGuard_Firewall_Policy_Collision_Check.log'

$CurrentStage = 'Initialize'
$FinalOutput = $null
$TargetAccountId = $null
$DiagnosticErrors = [System.Collections.Generic.List[string]]::new()

# ============================================================
# SECRET-BEARING STATE
# ============================================================

$ServiceAccountToken = $null
$WatchGuardItem = $null
$ApiKey = $null
$ReadOnlyAccessId = $null
$ReadOnlyPassword = $null
$AuthenticationUrl = $null
$BaseApiUrl = $null
$ProviderToken = $null
$AccountToken = $null
$Audience = $null

# ============================================================
# HELPERS
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

function Get-FirewallPoliciesFromGroups {
    param(
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return @()
    }

    $Policies = @()

    foreach ($Group in @(Get-ResponseItems -Response $InputObject)) {
        if (
            $null -eq $Group -or
            -not ($Group.PSObject.Properties.Name -contains 'policies')
        ) {
            continue
        }

        foreach ($PolicyEntry in @($Group.policies)) {
            if (
                $null -ne $PolicyEntry -and
                -not ($PolicyEntry -is [string]) -and
                ($PolicyEntry.PSObject.Properties.Name -contains 'id')
            ) {
                $Policies += $PolicyEntry
            }
        }
    }

    return @($Policies)
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

# ============================================================
# MAIN
# ============================================================

try {
    $CurrentStage = 'Directories'

    Initialize-Directory -Path $ReportDirectory
    Initialize-Directory -Path $LogDirectory

    $CurrentStage = 'ScriptVariable'

    $TargetAccountId = ([string]$env:targetWatchguardCloudAccountId).Trim()

    if ([string]::IsNullOrWhiteSpace($TargetAccountId)) {
        throw "Ninja calculated variable $TargetAccountVariable returned no value."
    }

    if ($TargetAccountId -notmatch '^(WGC|ACC)-') {
        throw 'targetWatchguardCloudAccountId is not in an expected WatchGuard account ID format.'
    }

    $ReportPath = Join-Path `
        $ReportDirectory `
        ("WatchGuard_Firewall_Policy_Export_{0}.txt" -f $TargetAccountId)

    Set-Content `
        -LiteralPath $LogPath `
        -Value ('WatchGuard Firewall Policy Collision Check - {0}' -f (Get-Date -Format s)) `
        -Encoding UTF8

    Write-Log 'START | WatchGuard firewall policy collision check'
    Write-Log "TARGET | Account=$TargetAccountId"

    # --------------------------------------------------------
    # CREDENTIAL BROKER / 1PASSWORD
    # --------------------------------------------------------

    $CurrentStage = 'NinjaField'

    $ServiceAccountToken = (
        Ninja-Property-Get -Name $BootstrapTokenField
    ).Trim()

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
        ) |
            Where-Object {
                Test-Path -LiteralPath $_
            } |
            Select-Object -First 1
    }

    if ([string]::IsNullOrWhiteSpace([string]$OpExe)) {
        throw '1Password CLI op.exe was not found.'
    }

    $CurrentStage = 'OnePasswordAuth'
    $env:OP_SERVICE_ACCOUNT_TOKEN = $ServiceAccountToken

    $WhoAmI = & $OpExe user get --me --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw (
            '1Password service account authentication failed: {0}' -f
            (ConvertTo-SafeOutput -Value ($WhoAmI -join ' '))
        )
    }

    Write-Log 'PASS | 1Password service account authenticated'

    $CurrentStage = 'WatchGuardItem'

    $WatchGuardItemJson = & $OpExe `
        item get `
        $WatchGuardItemName `
        --vault $OnePasswordVault `
        --format json `
        2>&1

    if ($LASTEXITCODE -ne 0) {
        throw (
            '1Password WatchGuard item retrieval failed: {0}' -f
            (ConvertTo-SafeOutput -Value ($WatchGuardItemJson -join ' '))
        )
    }

    try {
        $WatchGuardItem = $WatchGuardItemJson | ConvertFrom-Json
    }
    catch {
        throw "1Password item '$WatchGuardItemName' returned invalid JSON."
    }

    $CurrentStage = 'WatchGuardConfig'

    $ApiKey = Get-OnePasswordField -Item $WatchGuardItem -Label 'credential'
    $ReadOnlyAccessId = Get-OnePasswordField -Item $WatchGuardItem -Label 'readOnlyAccessId'
    $ReadOnlyPassword = Get-OnePasswordField -Item $WatchGuardItem -Label 'readOnlyPassword'
    $AuthenticationUrl = (
        Get-OnePasswordField -Item $WatchGuardItem -Label 'authenticationUrl'
    ).TrimEnd('/')
    $BaseApiUrl = (
        Get-OnePasswordField -Item $WatchGuardItem -Label 'baseApiUrl'
    ).TrimEnd('/')

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $ServiceAccountToken = $null
    $WatchGuardItem = $null

    Write-Log 'PASS | WatchGuard read-only API configuration retrieved'

    # --------------------------------------------------------
    # WATCHGUARD AUTH
    # --------------------------------------------------------

    $CurrentStage = 'ProviderAuth'

    $ProviderToken = Get-WatchGuardAccessToken `
        -AuthenticationUrl $AuthenticationUrl `
        -AccessId $ReadOnlyAccessId `
        -Password $ReadOnlyPassword

    $CurrentStage = 'Audience'

    $AudienceUri =
        "$BaseApiUrl/platform/authorization/v1/audiences"

    $AudienceHeaders = @{
        Accept = 'application/json'
        'Content-Type' = 'application/json'
        Authorization = "Bearer $ProviderToken"
        'WatchGuard-API-Key' = $ApiKey
    }

    $AudienceBody = @{
        accountId = $TargetAccountId
    } | ConvertTo-Json -Compress

    $AudienceResponse = Invoke-RestMethod `
        -Method Post `
        -Uri $AudienceUri `
        -Headers $AudienceHeaders `
        -Body $AudienceBody `
        -TimeoutSec 60

    $Audience = [string]$AudienceResponse.audience

    if ([string]::IsNullOrWhiteSpace($Audience)) {
        throw 'WatchGuard returned no audience for the target account.'
    }

    $CurrentStage = 'AccountAuth'

    $AccountToken = Get-WatchGuardAccessToken `
        -AuthenticationUrl $AuthenticationUrl `
        -AccessId $ReadOnlyAccessId `
        -Password $ReadOnlyPassword `
        -Audience $Audience

    $Headers = @{
        Accept = 'application/json'
        'Content-Type' = 'application/json'
        Authorization = "Bearer $AccountToken"
        'WatchGuard-API-Key' = $ApiKey
    }

    # --------------------------------------------------------
    # DEVICE DETAILS: DIRECT ID <-> NAME ASSOCIATION
    # --------------------------------------------------------

    $CurrentStage = 'DeviceDetails'

    $DeviceDetailsUri =
        "$BaseApiUrl/firebox/management/v1/info/$TargetAccountId/devices?device_type=FB"

    $DeviceDetailsResponse = Invoke-RestMethod `
        -Method Get `
        -Uri $DeviceDetailsUri `
        -Headers $Headers `
        -TimeoutSec 120

    $DeviceDetails = @(
        Get-ResponseItems -Response $DeviceDetailsResponse
    )

    if ($DeviceDetails.Count -eq 0) {
        throw 'Device Details API returned no Fireboxes or FireClusters for the target account.'
    }

    $DeviceRecords = @()

    foreach ($Device in $DeviceDetails) {
        $DetailsId = [string]$Device.id
        $FriendlyName = [string]$Device.name

        try {
            $ConfigurationDeviceId = Get-ConfigurationDeviceId `
                -DeviceDetailsId $DetailsId

            $DeviceRecords += [pscustomobject]@{
                DetailsId = $DetailsId
                ConfigurationDeviceId = $ConfigurationDeviceId
                Name = $FriendlyName
                Serial = [string]$Device.serial_number
                Model = [string]$Device.short_model_name
                Version = [string]$Device.version
                State = [string]$Device.state
                CloudManaged = [string]$Device.cloud_managed
                DeviceObject = $Device
            }
        }
        catch {
            $DiagnosticErrors.Add(
                'DeviceDetailsId={0} Error={1}' -f
                (ConvertTo-SafeOutput -Value $DetailsId),
                (ConvertTo-SafeOutput -Value $_.Exception.Message)
            )
        }
    }

    if ($DeviceRecords.Count -eq 0) {
        throw 'No supported Firebox device IDs were returned by Device Details API.'
    }

    # --------------------------------------------------------
    # REPORT / PER-DEVICE COLLISION DISCOVERY
    # --------------------------------------------------------

    $ReportBuilder = [System.Text.StringBuilder]::new()

    Add-ReportLine 'WATCHGUARD FIREWALL POLICY COLLISION CHECK'
    Add-ReportLine ('Generated: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Add-ReportLine ("Account ID: $TargetAccountId")
    Add-ReportLine ("Devices returned by Device Details API: $($DeviceRecords.Count)")
    Add-ReportLine ''
    Add-ReportLine 'DEVICE ASSOCIATION SOURCE'
    Add-ReportLine 'Device IDs and friendly names below come directly from the WatchGuard Firebox Management Device Details API.'
    Add-ReportLine 'Standalone FB-<id> values are normalized to numeric <id> only for configuration/deployment calls per current WatchGuard API documentation.'
    Add-ReportLine ''

    Add-ReportLine 'DEVICE MAP'
    foreach ($Record in $DeviceRecords | Sort-Object Name, ConfigurationDeviceId) {
        Add-ReportLine (
            'Name={0} | DetailsId={1} | ConfigurationDeviceId={2} | Serial={3} | Model={4} | Version={5} | State={6} | CloudManaged={7}' -f
            (ConvertTo-SafeOutput -Value $Record.Name),
            (ConvertTo-SafeOutput -Value $Record.DetailsId),
            (ConvertTo-SafeOutput -Value $Record.ConfigurationDeviceId),
            (ConvertTo-SafeOutput -Value $Record.Serial),
            (ConvertTo-SafeOutput -Value $Record.Model),
            (ConvertTo-SafeOutput -Value $Record.Version),
            (ConvertTo-SafeOutput -Value $Record.State),
            (ConvertTo-SafeOutput -Value $Record.CloudManaged)
        )
    }

    $AllCollisionRecords = @()
    $AllDevicePolicyExports = @()
    $TemplateCache = @{}

    foreach ($Record in $DeviceRecords | Sort-Object Name, ConfigurationDeviceId) {
        $DeviceId = [string]$Record.ConfigurationDeviceId
        $DeviceName = [string]$Record.Name

        Add-ReportLine ''
        Add-ReportLine '============================================================================'
        Add-ReportLine ("DEVICE NAME: $DeviceName")
        Add-ReportLine ("DEVICE DETAILS ID: $($Record.DetailsId)")
        Add-ReportLine ("CONFIGURATION DEVICE ID: $DeviceId")
        Add-ReportLine ("STATE: $($Record.State)")
        Add-ReportLine ("CLOUD MANAGED: $($Record.CloudManaged)")

        Write-Log (
            'DEVICE_START | Account={0} Device={1} Name={2}' -f
            $TargetAccountId,
            $DeviceId,
            (ConvertTo-SafeOutput -Value $DeviceName)
        )

        if ([string]$Record.CloudManaged -cne 'yes') {
            Add-ReportLine 'STATUS: SKIPPED - device is not reported as cloud-managed.'
            Write-Log (
                'DEVICE_SKIP | Account={0} Device={1} Name={2} Reason=NotCloudManaged' -f
                $TargetAccountId,
                $DeviceId,
                (ConvertTo-SafeOutput -Value $DeviceName)
            )
            continue
        }

        $DevicePolicies = @()
        $SubscribedTemplates = @()
        $DeviceTemplateRecords = @()

        try {
            $CurrentStage = "Policies:$DeviceId"

            $PolicyUri =
                "$BaseApiUrl/firebox/management/v1/configuration/$TargetAccountId/firewall/policies?device=$([uri]::EscapeDataString($DeviceId))&full=1"

            $PolicyResponse = Invoke-RestMethod `
                -Method Get `
                -Uri $PolicyUri `
                -Headers $Headers `
                -TimeoutSec 120

            $DevicePolicies = @(
                Get-ResponseItems -Response $PolicyResponse
            )

            $AllDevicePolicyExports += [pscustomobject]@{
                DeviceId = $DeviceId
                DeviceName = $DeviceName
                Policies = $DevicePolicies
            }
        }
        catch {
            $DiagHttp = Get-HttpStatusCode -Exception $_.Exception
            if ($null -eq $DiagHttp) {
                $DiagHttp = 'N/A'
            }

            $Message = (
                'Device={0} Name={1} Stage=Policies HTTP={2} Error={3}' -f
                $DeviceId,
                (ConvertTo-SafeOutput -Value $DeviceName),
                $DiagHttp,
                (ConvertTo-SafeOutput -Value $_.Exception.Message)
            )

            $DiagnosticErrors.Add($Message)
            Add-ReportLine ("ERROR: $Message")
            Write-Log "DIAG_ERROR | $Message"
            continue
        }

        try {
            $CurrentStage = "TemplateSubscriptions:$DeviceId"

            $SubscriptionUri =
                "$BaseApiUrl/firebox/management/v1/configuration/$TargetAccountId/templates/subscribe?device=$([uri]::EscapeDataString($DeviceId))"

            $SubscriptionResponse = Invoke-RestMethod `
                -Method Get `
                -Uri $SubscriptionUri `
                -Headers $Headers `
                -TimeoutSec 120

            if (
                $null -ne $SubscriptionResponse -and
                $SubscriptionResponse.PSObject.Properties.Name -contains 'templates'
            ) {
                $SubscribedTemplates = @($SubscriptionResponse.templates)
            }
        }
        catch {
            $DiagHttp = Get-HttpStatusCode -Exception $_.Exception
            if ($null -eq $DiagHttp) {
                $DiagHttp = 'N/A'
            }

            $Message = (
                'Device={0} Name={1} Stage=TemplateSubscriptions HTTP={2} Error={3}' -f
                $DeviceId,
                (ConvertTo-SafeOutput -Value $DeviceName),
                $DiagHttp,
                (ConvertTo-SafeOutput -Value $_.Exception.Message)
            )

            $DiagnosticErrors.Add($Message)
            Add-ReportLine ("ERROR: $Message")
            Write-Log "DIAG_ERROR | $Message"
            continue
        }

        foreach ($Template in $SubscribedTemplates) {
            $TemplateId = [string]$Template.id
            $TemplateName = [string]$Template.name

            if ([string]::IsNullOrWhiteSpace($TemplateId)) {
                continue
            }

            if (-not $TemplateCache.ContainsKey($TemplateId)) {
                try {
                    $CurrentStage = "TemplatePolicyGroups:$TemplateId"

                    $TemplatePolicyGroupsUri =
                        "$BaseApiUrl/firebox/management/v1/configuration/$TargetAccountId/firewall/policy_groups?templateid=$([uri]::EscapeDataString($TemplateId))"

                    $TemplatePolicyGroupsResponse = Invoke-RestMethod `
                        -Method Get `
                        -Uri $TemplatePolicyGroupsUri `
                        -Headers $Headers `
                        -TimeoutSec 120

                    $TemplateCache[$TemplateId] = [pscustomobject]@{
                        Id = $TemplateId
                        Name = $TemplateName
                        Policies = @(
                            Get-FirewallPoliciesFromGroups `
                                -InputObject $TemplatePolicyGroupsResponse
                        )
                        Error = $null
                    }
                }
                catch {
                    $DiagHttp = Get-HttpStatusCode -Exception $_.Exception
                    if ($null -eq $DiagHttp) {
                        $DiagHttp = 'N/A'
                    }

                    $Message = (
                        'TemplateId={0} Name={1} Stage=TemplatePolicyGroups HTTP={2} Error={3}' -f
                        $TemplateId,
                        (ConvertTo-SafeOutput -Value $TemplateName),
                        $DiagHttp,
                        (ConvertTo-SafeOutput -Value $_.Exception.Message)
                    )

                    $DiagnosticErrors.Add($Message)

                    $TemplateCache[$TemplateId] = [pscustomobject]@{
                        Id = $TemplateId
                        Name = $TemplateName
                        Policies = @()
                        Error = $Message
                    }

                    Write-Log "DIAG_ERROR | $Message"
                }
            }

            $DeviceTemplateRecords += $TemplateCache[$TemplateId]
        }

        $DeviceCollisions = @()

        foreach ($LocalPolicy in $DevicePolicies) {
            $LocalPolicyName = [string]$LocalPolicy.name

            if ([string]::IsNullOrWhiteSpace($LocalPolicyName)) {
                continue
            }

            foreach ($TemplateRecord in $DeviceTemplateRecords) {
                foreach ($TemplatePolicy in @($TemplateRecord.Policies)) {
                    if ([string]$TemplatePolicy.name -cne $LocalPolicyName) {
                        continue
                    }

                    $Collision = [pscustomobject]@{
                        DeviceName = $DeviceName
                        DeviceDetailsId = [string]$Record.DetailsId
                        DeviceId = $DeviceId
                        LocalPolicyName = $LocalPolicyName
                        LocalPolicyId = [string]$LocalPolicy.id
                        LocalGroup = [string]$LocalPolicy.group
                        LocalEnabled = $LocalPolicy.enabled
                        LocalPermanent = $LocalPolicy.permanent
                        TemplateName = [string]$TemplateRecord.Name
                        TemplateId = [string]$TemplateRecord.Id
                        TemplatePolicyId = [string]$TemplatePolicy.id
                        TemplatePolicyEnabled = $TemplatePolicy.enabled
                    }

                    $DeviceCollisions += $Collision
                    $AllCollisionRecords += $Collision
                }
            }
        }

        Add-ReportLine ("LOCAL POLICY COUNT: $($DevicePolicies.Count)")
        Add-ReportLine ("SUBSCRIBED TEMPLATE COUNT: $($SubscribedTemplates.Count)")
        Add-ReportLine ("SAME-NAME COLLISION COUNT: $($DeviceCollisions.Count)")

        if ($SubscribedTemplates.Count -gt 0) {
            Add-ReportLine 'SUBSCRIBED TEMPLATES:'
            foreach ($Template in $SubscribedTemplates) {
                $CacheEntry = $TemplateCache[[string]$Template.id]

                if ($null -ne $CacheEntry) {
                    Add-ReportLine (
                        '  Name={0} | TemplateId={1} | DirectPolicies={2} | Error={3}' -f
                        (ConvertTo-SafeOutput -Value $CacheEntry.Name),
                        (ConvertTo-SafeOutput -Value $CacheEntry.Id),
                        @($CacheEntry.Policies).Count,
                        (ConvertTo-SafeOutput -Value $CacheEntry.Error)
                    )
                }
            }
        }

        if ($DeviceCollisions.Count -eq 0) {
            Add-ReportLine 'COLLISIONS: None'
        }
        else {
            Add-ReportLine 'COLLISIONS:'

            foreach ($Collision in $DeviceCollisions) {
                Add-ReportLine ''
                Add-ReportLine (
                    '  Device={0} | DeviceId={1} | LocalName={2} | LocalId={3} | LocalGroup={4} | LocalEnabled={5} | LocalPermanent={6} | Template={7} | TemplateId={8} | TemplatePolicyId={9} | TemplateEnabled={10}' -f
                    (ConvertTo-SafeOutput -Value $Collision.DeviceName),
                    (ConvertTo-SafeOutput -Value $Collision.DeviceId),
                    (ConvertTo-SafeOutput -Value $Collision.LocalPolicyName),
                    (ConvertTo-SafeOutput -Value $Collision.LocalPolicyId),
                    (ConvertTo-SafeOutput -Value $Collision.LocalGroup),
                    (ConvertTo-SafeOutput -Value $Collision.LocalEnabled),
                    (ConvertTo-SafeOutput -Value $Collision.LocalPermanent),
                    (ConvertTo-SafeOutput -Value $Collision.TemplateName),
                    (ConvertTo-SafeOutput -Value $Collision.TemplateId),
                    (ConvertTo-SafeOutput -Value $Collision.TemplatePolicyId),
                    (ConvertTo-SafeOutput -Value $Collision.TemplatePolicyEnabled)
                )
            }
        }

        Write-Log (
            'DEVICE_DONE | Account={0} Device={1} Name={2} Policies={3} Templates={4} Collisions={5}' -f
            $TargetAccountId,
            $DeviceId,
            (ConvertTo-SafeOutput -Value $DeviceName),
            $DevicePolicies.Count,
            $SubscribedTemplates.Count,
            $DeviceCollisions.Count
        )
    }

    # --------------------------------------------------------
    # GLOBAL SUMMARY
    # --------------------------------------------------------

    Add-ReportLine ''
    Add-ReportLine '============================================================================'
    Add-ReportLine 'ACCOUNT COLLISION SUMMARY'
    Add-ReportLine ("Account: $TargetAccountId")
    Add-ReportLine ("Devices evaluated: $($DeviceRecords.Count)")
    Add-ReportLine ("Collisions found: $($AllCollisionRecords.Count)")
    Add-ReportLine ("Diagnostic errors: $($DiagnosticErrors.Count)")

    if ($AllCollisionRecords.Count -gt 0) {
        Add-ReportLine ''
        Add-ReportLine 'REMEDIATION CANDIDATES'
        Add-ReportLine 'Use the exact DeviceId and LocalId values below only after reviewing the corresponding device in WatchGuard Cloud.'

        foreach ($Collision in $AllCollisionRecords | Sort-Object DeviceName, LocalPolicyName, LocalPolicyId, TemplateName) {
            Add-ReportLine (
                'Device={0} | DeviceId={1} | LocalName={2} | LocalId={3} | LocalGroup={4} | LocalEnabled={5} | LocalPermanent={6} | Template={7} | TemplatePolicyId={8} | TemplateEnabled={9}' -f
                (ConvertTo-SafeOutput -Value $Collision.DeviceName),
                (ConvertTo-SafeOutput -Value $Collision.DeviceId),
                (ConvertTo-SafeOutput -Value $Collision.LocalPolicyName),
                (ConvertTo-SafeOutput -Value $Collision.LocalPolicyId),
                (ConvertTo-SafeOutput -Value $Collision.LocalGroup),
                (ConvertTo-SafeOutput -Value $Collision.LocalEnabled),
                (ConvertTo-SafeOutput -Value $Collision.LocalPermanent),
                (ConvertTo-SafeOutput -Value $Collision.TemplateName),
                (ConvertTo-SafeOutput -Value $Collision.TemplatePolicyId),
                (ConvertTo-SafeOutput -Value $Collision.TemplatePolicyEnabled)
            )
        }
    }

    if ($DiagnosticErrors.Count -gt 0) {
        Add-ReportLine ''
        Add-ReportLine 'DIAGNOSTIC ERRORS'

        foreach ($DiagnosticError in $DiagnosticErrors) {
            Add-ReportLine ("  $DiagnosticError")
        }
    }

    # --------------------------------------------------------
    # FULL LOCAL POLICY EXPORT BY DEVICE
    # --------------------------------------------------------

    Add-ReportLine ''
    Add-ReportLine '============================================================================'
    Add-ReportLine 'FULL DEVICE-LOCAL FIREWALL POLICY EXPORT'

    foreach ($DeviceExport in $AllDevicePolicyExports | Sort-Object DeviceName, DeviceId) {
        Add-ReportLine ''
        Add-ReportLine '----------------------------------------------------------------------------'
        Add-ReportLine ("DEVICE NAME: $($DeviceExport.DeviceName)")
        Add-ReportLine ("DEVICE ID: $($DeviceExport.DeviceId)")
        Add-ReportLine ("POLICY COUNT: $(@($DeviceExport.Policies).Count)")

        $Index = 0

        foreach ($Policy in @($DeviceExport.Policies) | Sort-Object name, id) {
            $Index++

            Add-ReportLine ''
            Add-ReportLine (
                'POLICY {0}/{1}: {2}' -f
                $Index,
                @($DeviceExport.Policies).Count,
                (ConvertTo-SafeOutput -Value $Policy.name)
            )

            Add-ReportLine (
                $Policy |
                ConvertTo-Json -Depth 40
            )
        }
    }

    $ReportBuilder.ToString() |
        Set-Content `
            -LiteralPath $ReportPath `
            -Encoding UTF8

    if ($DiagnosticErrors.Count -gt 0) {
        $FinalOutput = (
            'ERROR | Stage=DeviceDiagnostics HTTP=N/A Error=One or more devices/templates could not be fully evaluated. Errors={0} File={1}' -f
            $DiagnosticErrors.Count,
            $ReportPath
        )
    }
    elseif ($AllCollisionRecords.Count -gt 0) {
        $FinalOutput = (
            'TRIGGER | Local/template policy collisions found | Account={0} Devices={1} Collisions={2} File={3}' -f
            $TargetAccountId,
            $DeviceRecords.Count,
            $AllCollisionRecords.Count,
            $ReportPath
        )
    }
    else {
        $FinalOutput = (
            'NO_ACTION | No local/template policy collisions | Account={0} Devices={1} File={2}' -f
            $TargetAccountId,
            $DeviceRecords.Count,
            $ReportPath
        )
    }

    Write-Log $FinalOutput
}
catch {
    $HttpStatus = Get-HttpStatusCode -Exception $_.Exception

    if ($null -eq $HttpStatus) {
        $HttpStatus = 'N/A'
    }

    $ErrorText = ConvertTo-SafeOutput -Value $_.Exception.Message

    $FinalOutput = (
        'ERROR | Stage={0} HTTP={1} Error={2}' -f
        (ConvertTo-SafeOutput -Value $CurrentStage),
        $HttpStatus,
        $ErrorText
    )

    Write-Log $FinalOutput
}
finally {
    try {
        $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    }
    catch {
    }

    $ServiceAccountToken = $null
    $WatchGuardItem = $null
    $ApiKey = $null
    $ReadOnlyAccessId = $null
    $ReadOnlyPassword = $null
    $AuthenticationUrl = $null
    $BaseApiUrl = $null
    $ProviderToken = $null
    $AccountToken = $null
    $Audience = $null
    $Headers = $null
    $AudienceHeaders = $null
}

if ([string]::IsNullOrWhiteSpace([string]$FinalOutput)) {
    $FinalOutput = 'ERROR | Stage=Finalize HTTP=N/A Error=No final output was generated.'
}

Write-Output $FinalOutput
exit 0