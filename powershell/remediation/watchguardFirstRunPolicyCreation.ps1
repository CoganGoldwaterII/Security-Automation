# ============================================================================
# NAME: WatchGuard First Run Firewall Policy Create
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Configuration Write POC
# SCOPE: Windows / Authorized Credential Broker / One Target Firebox
#
# VARIABLES:
#   Required configuration (script arguments or Ninja environment variables):
#     OnePasswordVault       / onePasswordVault
#     BootstrapTokenField    / bootstrapTokenField (secure Ninja field name)
#   Optional configuration:
#     WatchGuardItemName     (default: WatchGuard)
#     LogRoot                (default: ProgramData\AutomationPlaybook\Logs)
#   Required Ninja script environment variables:
#     watchguardCloudAccountId  - Target WatchGuard Cloud account ID
#     deviceId                  - Firebox ID or FireCluster ID
#     policyName                - New policy name
#     trafficType               - Existing device traffic-type ID/name or port
#     source                    - Source address, FQDN, or system alias
#     destination               - Destination address, FQDN, or system alias
#
# OUTPUT TOKENS:
#   RESULT    | PolicyCreated | Account=<id> Device=<id> Policy=<name>
#               PolicyId=<id> Deployment=NotRequested
#   NO_ACTION | PolicyAlreadyExists | Account=<id> Device=<id> Policy=<name>
#   ERROR     | Stage=<stage> HTTP=<status> Error=<message>
#   Exit Code: Always 0 after script execution
#
# CUSTOM FIELDS:
#   Reads: Secure Ninja field specified by BootstrapTokenField
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   <LogRoot>\WatchGuard_First_Run_Firewall_Policy_Create.log
#
# DESCRIPTION:
#   Troubleshooting utility for Fireboxes experiencing technical issues.
#   Creates one enabled ALLOW policy in the existing "First Run Policies"
#   group as a temporary first-run rule to help restore required device
#   functionality while the underlying issue is investigated.
#
#   Resolves the target device ID, policy group, device-local traffic type,
#   and source/destination address values. Checks for an existing policy
#   by name before writing. Template lookup is diagnostic only: inherited
#   traffic types are never used for the policy creation request.
#
#   For standalone Fireboxes, FB-<number> input is normalized to its numeric
#   API device ID; FireCluster FBCL-<number> IDs remain unchanged.
#   Address formats: IP host, CIDR, IP range, FQDN, Any, Any-Internal,
#   Any-External, and Firebox. Traffic type can be an existing ID, exact
#   name, TCP/port, UDP/port, or an unambiguous single port.
#
#   Saves the rule in WatchGuard Cloud and verifies the saved policy ID
#   and device. Does NOT request deployment, but a later deployment of
#   pending changes may activate the rule on the Firebox.
#
#   SECURITY:
#   An ALLOW first-run rule can weaken firewall restrictions. This is a
#   targeted troubleshooting POC, not a baseline or permanent policy.
#   Review scope and remove temporary allowances after troubleshooting.
#   Customer/device identifiers are runtime inputs, not hardcoded.
# ============================================================================

[CmdletBinding()]
param(
    [string]$OnePasswordVault = [string]$env:onePasswordVault,
    [string]$BootstrapTokenField = [string]$env:bootstrapTokenField,
    [string]$WatchGuardItemName = 'WatchGuard',
    [string]$LogRoot = (Join-Path $env:ProgramData 'AutomationPlaybook\Logs')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ============================================================
# CONSTANTS
# ============================================================

$BuildId =
    'WATCHGUARD-FIRST-RUN-POLICY-CREATE-POC-v6-20260902'

$LogPath =
    Join-Path `
        $LogRoot `
        'WatchGuard_First_Run_Firewall_Policy_Create.log'

$FirstRunGroupName =
    'First Run Policies'

$CurrentStage =
    'Initialize'

$FinalOutput =
    $null

# ============================================================
# SECRET-BEARING STATE
# ============================================================

$ServiceAccountToken = $null
$WatchGuardItem = $null
$ApiKey = $null
$ReadWriteAccessId = $null
$ReadWritePassword = $null
$AuthenticationUrl = $null
$BaseApiUrl = $null
$ProviderToken = $null
$AccountToken = $null
$Audience = $null

# ============================================================
# HELPERS
# ============================================================

function Initialize-Logging {

    if (-not (Test-Path -LiteralPath $LogRoot)) {

        New-Item `
            -ItemType Directory `
            -Path $LogRoot `
            -Force |
            Out-Null
    }

    Set-Content `
        -LiteralPath $LogPath `
        -Value (
            'WatchGuard First Run Firewall Policy Create - {0}' -f
            (Get-Date -Format s)
        ) `
        -Encoding UTF8
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

function Get-HttpResponseBody {

    param(
        [AllowNull()]
        [object]$Exception
    )

    if ($null -eq $Exception) {
        return ''
    }

    try {

        if ($null -eq $Exception.Response) {
            return ''
        }

        $ResponseStream =
            $Exception.Response.GetResponseStream()

        if ($null -eq $ResponseStream) {
            return ''
        }

        $Reader =
            New-Object `
                System.IO.StreamReader(
                    $ResponseStream
                )

        try {

            return (
                ConvertTo-SafeOutput `
                    -Value $Reader.ReadToEnd()
            )
        }
        finally {

            try {
                $Reader.Dispose()
            }
            catch {
            }

            try {
                $ResponseStream.Dispose()
            }
            catch {
            }
        }
    }
    catch {

        return ''
    }
}

function Get-OnePasswordField {

    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$Label
    )

    $Field =
        @(
            $Item.fields |
            Where-Object {
                $_.label -eq $Label
            }
        ) |
        Select-Object -First 1

    if ($null -eq $Field) {
        throw "Required 1Password field not found: $Label"
    }

    $Value =
        [string]$Field.value

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

    $CredentialBytes =
        [System.Text.Encoding]::ASCII.GetBytes(
            ('{0}:{1}' -f $AccessId, $Password)
        )

    $Headers = @{
        Accept        = 'application/json'
        Authorization = 'Basic {0}' -f (
            [Convert]::ToBase64String(
                $CredentialBytes
            )
        )
    }

    $Body = @{
        grant_type = 'client_credentials'
        scope      = 'api-access'
    }

    if (-not [string]::IsNullOrWhiteSpace($Audience)) {
        $Body['audience'] = $Audience
    }

    $Response =
        Invoke-RestMethod `
            -Method Post `
            -Uri $AuthenticationUrl `
            -Headers $Headers `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body $Body `
            -TimeoutSec 60

    if (
        $null -eq $Response -or
        [string]::IsNullOrWhiteSpace(
            [string]$Response.access_token
        )
    ) {

        throw (
            'WatchGuard authentication response did not contain an access token.'
        )
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

        if (
            $Response.PSObject.Properties.Name -contains
            $PropertyName
        ) {

            return @(
                $Response.$PropertyName
            )
        }
    }

    return @($Response)
}

function Resolve-DeviceId {

    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $Requested =
        $Value.Trim()

    if ([string]::IsNullOrWhiteSpace($Requested)) {
        throw 'deviceId cannot be empty.'
    }

    # WatchGuard Cloud standalone Firebox URL format:
    # /fb/device/FB-123456/configure
    #
    # Firebox Management API uses the numeric standalone device ID.
    if ($Requested -match '^(?i)FB-(\d+)$') {
        return $Matches[1]
    }

    # Already-normalized standalone Firebox device ID.
    if ($Requested -match '^\d+$') {
        return $Requested
    }

    # FireClusters use the FBCL- form.
    if ($Requested -match '^(?i)FBCL-\d+$') {
        return $Requested.ToUpperInvariant()
    }

    throw (
        "Unsupported deviceId '$Requested'. " +
        'Use FB-<number>, <number>, or FBCL-<number>.'
    )
}

function Get-IpAddressFamily {

    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $ParsedAddress =
        $null

    if (
        -not [System.Net.IPAddress]::TryParse(
            $Value,
            [ref]$ParsedAddress
        )
    ) {

        return $null
    }

    if (
        $ParsedAddress.AddressFamily -eq
        [System.Net.Sockets.AddressFamily]::InterNetwork
    ) {

        return 'ipv4'
    }

    if (
        $ParsedAddress.AddressFamily -eq
        [System.Net.Sockets.AddressFamily]::InterNetworkV6
    ) {

        return 'ipv6'
    }

    return $null
}

function ConvertTo-WatchGuardAddress {

    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $Trimmed =
        $Value.Trim()

    if ([string]::IsNullOrWhiteSpace($Trimmed)) {
        throw 'Source/destination value cannot be empty.'
    }

    $SystemAliases =
        @(
            'Any'
            'Any-Internal'
            'Any-External'
            'Firebox'
        )

    foreach ($Alias in $SystemAliases) {

        if ($Trimmed -ieq $Alias) {

            return [PSCustomObject]@{
                type  = 'system_alias'
                value = $Alias
            }
        }
    }

    if ($Trimmed -match '^(.+?)/(\d{1,3})$') {

        $AddressPart =
            $Matches[1].Trim()

        $Prefix =
            [int]$Matches[2]

        $Family =
            Get-IpAddressFamily `
                -Value $AddressPart

        if ($Family -eq 'ipv4') {

            if ($Prefix -lt 0 -or $Prefix -gt 32) {
                throw "Invalid IPv4 CIDR prefix: $Trimmed"
            }

            return [PSCustomObject]@{
                type  = 'ipv4_network'
                value = $Trimmed
            }
        }

        if ($Family -eq 'ipv6') {

            if ($Prefix -lt 0 -or $Prefix -gt 128) {
                throw "Invalid IPv6 CIDR prefix: $Trimmed"
            }

            return [PSCustomObject]@{
                type  = 'ipv6_network'
                value = $Trimmed
            }
        }

        throw "Invalid CIDR address: $Trimmed"
    }

    if ($Trimmed -match '^(.+?)-(.+)$') {

        $StartAddress =
            $Matches[1].Trim()

        $EndAddress =
            $Matches[2].Trim()

        $StartFamily =
            Get-IpAddressFamily `
                -Value $StartAddress

        $EndFamily =
            Get-IpAddressFamily `
                -Value $EndAddress

        if (
            $StartFamily -eq 'ipv4' -and
            $EndFamily -eq 'ipv4'
        ) {

            return [PSCustomObject]@{
                type  = 'ipv4_range'
                value = $Trimmed
            }
        }

        if (
            $StartFamily -eq 'ipv6' -and
            $EndFamily -eq 'ipv6'
        ) {

            return [PSCustomObject]@{
                type  = 'ipv6_range'
                value = $Trimmed
            }
        }
    }

    $Family =
        Get-IpAddressFamily `
            -Value $Trimmed

    if ($Family -eq 'ipv4') {

        return [PSCustomObject]@{
            type  = 'ipv4_host'
            value = $Trimmed
        }
    }

    if ($Family -eq 'ipv6') {

        return [PSCustomObject]@{
            type  = 'ipv6_host'
            value = $Trimmed
        }
    }

    if (
        $Trimmed -match
        '^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+(?:[A-Za-z]{2,63})$'
    ) {

        return [PSCustomObject]@{
            type  = 'fqdn'
            value = $Trimmed
        }
    }

    throw (
        "Unsupported source/destination value '$Trimmed'. " +
        'Use an IP host, CIDR network, IP range, FQDN, or supported system alias.'
    )
}

function Resolve-TrafficType {

    param(
        [Parameter(Mandatory)]
        [object[]]$TrafficTypes,

        [Parameter(Mandatory)]
        [string]$RequestedValue
    )

    $Requested =
        $RequestedValue.Trim()

    if ([string]::IsNullOrWhiteSpace($Requested)) {
        throw 'trafficType cannot be empty.'
    }

    $MatchesById =
        @(
            $TrafficTypes |
            Where-Object {
                [string]$_.id -ieq $Requested
            }
        )

    if ($MatchesById.Count -eq 1) {
        return $MatchesById[0]
    }

    $MatchesByName =
        @(
            $TrafficTypes |
            Where-Object {
                [string]$_.name -ieq $Requested
            }
        )

    if ($MatchesByName.Count -eq 1) {
        return $MatchesByName[0]
    }

    if (
        $Requested -match
        '^(?i)(TCP|UDP)[\s/:_-]*(\d{1,5})$'
    ) {

        $ProtocolName =
            $Matches[1].ToUpperInvariant()

        $Port =
            [int]$Matches[2]

        if ($Port -lt 0 -or $Port -gt 65535) {
            throw "trafficType port is outside 0-65535: $Port"
        }

        $ProtocolNumber =
            if ($ProtocolName -eq 'TCP') {
                6
            }
            else {
                17
            }

        $MatchesByProtocolPort =
            @(
                $TrafficTypes |
                Where-Object {

                    $Protocols =
                        @($_.protocols)

                    if ($Protocols.Count -ne 1) {
                        return $false
                    }

                    $Protocol =
                        $Protocols[0]

                    return (
                        [string]$Protocol.type -ieq 'single_port' -and
                        [int]$Protocol.protocol -eq $ProtocolNumber -and
                        [int]$Protocol.value -eq $Port
                    )
                }
            )

        if ($MatchesByProtocolPort.Count -eq 1) {
            return $MatchesByProtocolPort[0]
        }

        if ($MatchesByProtocolPort.Count -gt 1) {

            $Names =
                (
                    $MatchesByProtocolPort |
                    ForEach-Object {
                        [string]$_.name
                    }
                ) -join ', '

            throw (
                "trafficType '$Requested' matched multiple existing traffic types: $Names"
            )
        }

        throw (
            "No existing traffic type matched $ProtocolName port $Port on this Firebox."
        )
    }

    if ($Requested -match '^\d{1,5}$') {

        $Port =
            [int]$Requested

        if ($Port -lt 0 -or $Port -gt 65535) {
            throw "trafficType port is outside 0-65535: $Port"
        }

        $MatchesByPort =
            @(
                $TrafficTypes |
                Where-Object {

                    $Protocols =
                        @($_.protocols)

                    if ($Protocols.Count -ne 1) {
                        return $false
                    }

                    $Protocol =
                        $Protocols[0]

                    return (
                        [string]$Protocol.type -ieq 'single_port' -and
                        [int]$Protocol.value -eq $Port
                    )
                }
            )

        if ($MatchesByPort.Count -eq 1) {
            return $MatchesByPort[0]
        }

        if ($MatchesByPort.Count -gt 1) {

            $Descriptions =
                @(
                    $MatchesByPort |
                    ForEach-Object {

                        $Protocol =
                            @($_.protocols)[0]

                        $ProtocolLabel =
                            switch ([int]$Protocol.protocol) {
                                6  { 'TCP' }
                                17 { 'UDP' }
                                default { [string]$Protocol.protocol }
                            }

                        '{0}({1}/{2})' -f
                            [string]$_.name,
                            $ProtocolLabel,
                            $Port
                    }
                ) -join ', '

            throw (
                "Bare port '$Port' is ambiguous. Matches: $Descriptions. " +
                'Pass TCP/<port>, UDP/<port>, the exact traffic type name, or its ftyp_ ID.'
            )
        }

        throw "No existing single-port traffic type matched port $Port."
    }

    throw (
        "trafficType '$Requested' did not match an existing traffic type ID or name."
    )
}

function Find-DiagnosticTrafficTypeMatch {

    param(
        [Parameter(Mandatory)]
        [object[]]$TrafficTypes,

        [Parameter(Mandatory)]
        [string]$RequestedValue
    )

    $Requested =
        $RequestedValue.Trim()

    if ([string]::IsNullOrWhiteSpace($Requested)) {
        return $null
    }

    # Exact object ID.
    $ById =
        @(
            $TrafficTypes |
            Where-Object {
                [string]$_.id -ieq $Requested
            }
        )

    if ($ById.Count -gt 0) {
        return $ById[0]
    }

    # Exact traffic type name.
    $ByName =
        @(
            $TrafficTypes |
            Where-Object {
                [string]$_.name -ieq $Requested
            }
        )

    if ($ByName.Count -gt 0) {
        return $ByName[0]
    }

    # TCP/443, TCP:443, TCP 443, UDP equivalents.
    if (
        $Requested -match
        '^(?i)(TCP|UDP)[\s/:_-]*(\d{1,5})$'
    ) {

        $ProtocolName =
            $Matches[1].ToUpperInvariant()

        $Port =
            [int]$Matches[2]

        $ProtocolNumber =
            if ($ProtocolName -eq 'TCP') {
                6
            }
            else {
                17
            }

        $ByProtocolPort =
            @(
                $TrafficTypes |
                Where-Object {

                    $Protocols =
                        @($_.protocols)

                    if ($Protocols.Count -ne 1) {
                        return $false
                    }

                    $Protocol =
                        $Protocols[0]

                    return (
                        [string]$Protocol.type -ieq 'single_port' -and
                        [int]$Protocol.protocol -eq $ProtocolNumber -and
                        [int]$Protocol.value -eq $Port
                    )
                }
            )

        if ($ByProtocolPort.Count -gt 0) {
            return $ByProtocolPort[0]
        }
    }

    # Bare port diagnostic match.
    if ($Requested -match '^\d{1,5}$') {

        $Port =
            [int]$Requested

        $ByPort =
            @(
                $TrafficTypes |
                Where-Object {

                    $Protocols =
                        @($_.protocols)

                    if ($Protocols.Count -ne 1) {
                        return $false
                    }

                    $Protocol =
                        $Protocols[0]

                    return (
                        [string]$Protocol.type -ieq 'single_port' -and
                        [int]$Protocol.value -eq $Port
                    )
                }
            )

        if ($ByPort.Count -gt 0) {
            return $ByPort[0]
        }
    }

    return $null
}

# ============================================================
# MAIN
# ============================================================

try {

    $CurrentStage = 'Configuration'
    foreach ($ConfigurationInput in @(
        @{ Name = 'OnePasswordVault'; Value = $OnePasswordVault }
        @{ Name = 'BootstrapTokenField'; Value = $BootstrapTokenField }
        @{ Name = 'WatchGuardItemName'; Value = $WatchGuardItemName }
        @{ Name = 'LogRoot'; Value = $LogRoot }
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$ConfigurationInput.Value)) {
            throw "Required configuration '$($ConfigurationInput.Name)' was empty."
        }
    }

    # ========================================================
    # NINJA SCRIPT VARIABLES
    #
    # NinjaOne injects Automation Script Variables as
    # environment variables for the lifetime of the script.
    # All values arrive as strings.
    # ========================================================

    $CurrentStage =
        'ScriptVariables'

    $watchguardCloudAccountId =
        [string]$env:watchguardCloudAccountId

    $deviceId =
        [string]$env:deviceId

    $policyName =
        [string]$env:policyName

    $trafficType =
        [string]$env:trafficType

    $source =
        [string]$env:source

    $destination =
        [string]$env:destination

    $CurrentStage =
        'InputValidation'

    foreach ($InputPair in @(
        @{ Name = 'watchguardCloudAccountId'; Value = $watchguardCloudAccountId }
        @{ Name = 'deviceId'; Value = $deviceId }
        @{ Name = 'policyName'; Value = $policyName }
        @{ Name = 'trafficType'; Value = $trafficType }
        @{ Name = 'source'; Value = $source }
        @{ Name = 'destination'; Value = $destination }
    )) {

        if (
            [string]::IsNullOrWhiteSpace(
                [string]$InputPair.Value
            )
        ) {

            throw (
                "Required script variable '$($InputPair.Name)' was empty."
            )
        }
    }

    $watchguardCloudAccountId =
        $watchguardCloudAccountId.Trim()

    $RequestedDeviceId =
        $deviceId.Trim()

    $ResolvedDeviceId =
        Resolve-DeviceId `
            -Value $RequestedDeviceId

    $policyName =
        $policyName.Trim()

    $trafficType =
        [string]$trafficType

    $source =
        $source.Trim()

    $destination =
        $destination.Trim()

    $SourceObject =
        ConvertTo-WatchGuardAddress `
            -Value $source

    $DestinationObject =
        ConvertTo-WatchGuardAddress `
            -Value $destination

    $CurrentStage =
        'Logging'

    Initialize-Logging

    Write-Log (
        'START | Build={0} Account={1} RequestedDevice={2} ApiDevice={3} Policy={4} TrafficType={5} Source={6} Destination={7}' -f
        $BuildId,
        (ConvertTo-SafeOutput $watchguardCloudAccountId),
        (ConvertTo-SafeOutput $RequestedDeviceId),
        (ConvertTo-SafeOutput $ResolvedDeviceId),
        (ConvertTo-SafeOutput $policyName),
        (ConvertTo-SafeOutput $trafficType),
        (ConvertTo-SafeOutput $source),
        (ConvertTo-SafeOutput $destination)
    )

    # ========================================================
    # NINJA -> 1PASSWORD BOOTSTRAP
    # ========================================================

    $CurrentStage =
        'NinjaField'

    $ServiceAccountToken =
        (
            Ninja-Property-Get `
                -Name $BootstrapTokenField
        ).Trim()

    if ([string]::IsNullOrWhiteSpace($ServiceAccountToken)) {

        throw (
            "Ninja secure custom field $BootstrapTokenField returned no value."
        )
    }

    Write-Log (
        "PASS | $BootstrapTokenField retrieved"
    )

    # ========================================================
    # 1PASSWORD CLI
    # ========================================================

    $CurrentStage =
        'OnePasswordCLI'

    $OpCommand =
        Get-Command `
            'op.exe' `
            -ErrorAction SilentlyContinue

    if ($null -ne $OpCommand) {

        $OpExe =
            $OpCommand.Source
    }
    else {

        $OpExe =
            @(
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

    # ========================================================
    # 1PASSWORD AUTH
    # ========================================================

    $CurrentStage =
        'OnePasswordAuth'

    $env:OP_SERVICE_ACCOUNT_TOKEN =
        $ServiceAccountToken

    $WhoAmI =
        & $OpExe `
            user get `
            --me `
            --format json `
            2>&1

    if ($LASTEXITCODE -ne 0) {

        throw (
            '1Password service account authentication failed: {0}' -f
            (ConvertTo-SafeOutput -Value ($WhoAmI -join ' '))
        )
    }

    Write-Log (
        'PASS | 1Password service account authenticated'
    )

    # ========================================================
    # WATCHGUARD CREDENTIAL ITEM
    # ========================================================

    $CurrentStage =
        'WatchGuardItem'

    $WatchGuardItemJson =
        & $OpExe `
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

        $WatchGuardItem =
            $WatchGuardItemJson |
            ConvertFrom-Json
    }
    catch {

        throw (
            "1Password item '$WatchGuardItemName' returned invalid JSON."
        )
    }

    # ========================================================
    # WATCHGUARD READ-WRITE CONFIGURATION
    # ========================================================

    $CurrentStage =
        'WatchGuardConfig'

    $ApiKey =
        Get-OnePasswordField `
            -Item $WatchGuardItem `
            -Label 'credential'

    $ReadWriteAccessId =
        Get-OnePasswordField `
            -Item $WatchGuardItem `
            -Label 'readWriteAccessId'

    $ReadWritePassword =
        Get-OnePasswordField `
            -Item $WatchGuardItem `
            -Label 'readWritePassword'

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

    $env:OP_SERVICE_ACCOUNT_TOKEN =
        $null

    $ServiceAccountToken =
        $null

    $WatchGuardItem =
        $null

    Write-Log (
        'PASS | WatchGuard READ-WRITE API configuration retrieved'
    )

    # ========================================================
    # PROVIDER AUTH
    # ========================================================

    $CurrentStage =
        'ProviderAuth'

    $ProviderToken =
        Get-WatchGuardAccessToken `
            -AuthenticationUrl $AuthenticationUrl `
            -AccessId $ReadWriteAccessId `
            -Password $ReadWritePassword

    Write-Log (
        'PASS | WatchGuard provider READ-WRITE token retrieved'
    )

    # ========================================================
    # TARGET ACCOUNT AUDIENCE
    # ========================================================

    $CurrentStage =
        'Audience'

    $AudienceUri =
        "$BaseApiUrl/platform/authorization/v1/audiences"

    $AudienceHeaders = @{
        Accept               = 'application/json'
        'Content-Type'       = 'application/json'
        Authorization        = "Bearer $ProviderToken"
        'WatchGuard-API-Key' = $ApiKey
    }

    $AudienceBody =
        @{
            accountId = $watchguardCloudAccountId
        } |
        ConvertTo-Json `
            -Compress

    $AudienceResponse =
        Invoke-RestMethod `
            -Method Post `
            -Uri $AudienceUri `
            -Headers $AudienceHeaders `
            -Body $AudienceBody `
            -TimeoutSec 60

    $Audience =
        [string]$AudienceResponse.audience

    if ([string]::IsNullOrWhiteSpace($Audience)) {
        throw 'WatchGuard returned no audience for the target account.'
    }

    # ========================================================
    # TARGET ACCOUNT AUTH
    # ========================================================

    $CurrentStage =
        'AccountAuth'

    $AccountToken =
        Get-WatchGuardAccessToken `
            -AuthenticationUrl $AuthenticationUrl `
            -AccessId $ReadWriteAccessId `
            -Password $ReadWritePassword `
            -Audience $Audience

    $Headers = @{
        Accept               = 'application/json'
        'Content-Type'       = 'application/json'
        Authorization        = "Bearer $AccountToken"
        'WatchGuard-API-Key' = $ApiKey
    }

    Write-Log (
        'PASS | Target account READ-WRITE token retrieved'
    )

    # ========================================================
    # FIRST RUN POLICY GROUP + DEVICE VALIDATION
    # ========================================================

    $CurrentStage =
        'PolicyGroup'

    $PolicyGroupsUri =
        "$BaseApiUrl/firebox/management/v1/configuration/$watchguardCloudAccountId/firewall/policy_groups?device=$([uri]::EscapeDataString($ResolvedDeviceId))"

    $PolicyGroupsResponse =
        Invoke-RestMethod `
            -Method Get `
            -Uri $PolicyGroupsUri `
            -Headers $Headers `
            -TimeoutSec 60

    $PolicyGroups =
        @(
            Get-ResponseItems `
                -Response $PolicyGroupsResponse
        )

    if ($PolicyGroups.Count -eq 0) {

        throw (
            "No policy groups were returned for Device=$ResolvedDeviceId. " +
            'Verify deviceId belongs to the specified WatchGuard Cloud account and is cloud-managed.'
        )
    }

    $FirstRunGroups =
        @(
            $PolicyGroups |
            Where-Object {
                [string]$_.name -ieq $FirstRunGroupName
            }
        )

    if ($FirstRunGroups.Count -ne 1) {

        throw (
            "Expected exactly one '$FirstRunGroupName' policy group for device $ResolvedDeviceId. " +
            "Found $($FirstRunGroups.Count)."
        )
    }

    $FirstRunGroup =
        $FirstRunGroups[0]

    if (
        [string]::IsNullOrWhiteSpace(
            [string]$FirstRunGroup.id
        )
    ) {

        throw (
            "The '$FirstRunGroupName' group did not contain an object ID."
        )
    }

    Write-Log (
        'PASS | Device validated and First Run group resolved Device={0} Group={1} GroupId={2}' -f
        (ConvertTo-SafeOutput $ResolvedDeviceId),
        (ConvertTo-SafeOutput $FirstRunGroup.name),
        (ConvertTo-SafeOutput $FirstRunGroup.id)
    )

    # ========================================================
    # EXISTING POLICY DUPLICATE CHECK
    # ========================================================

    $CurrentStage =
        'ExistingPolicyCheck'

    $DevicePoliciesUri =
        "$BaseApiUrl/firebox/management/v1/configuration/$watchguardCloudAccountId/firewall/policies?device=$([uri]::EscapeDataString($ResolvedDeviceId))&full=1"

    $DevicePoliciesResponse =
        Invoke-RestMethod `
            -Method Get `
            -Uri $DevicePoliciesUri `
            -Headers $Headers `
            -TimeoutSec 120

    $DevicePolicies =
        @(
            Get-ResponseItems `
                -Response $DevicePoliciesResponse
        )

    $ExistingPolicy =
        @(
            $DevicePolicies |
            Where-Object {
                [string]$_.name -ieq $policyName
            }
        ) |
        Select-Object -First 1

    if ($null -ne $ExistingPolicy) {

        Write-Log (
            'NO_ACTION | PolicyAlreadyExists Account={0} Device={1} Policy={2} PolicyId={3}' -f
            (ConvertTo-SafeOutput $watchguardCloudAccountId),
            (ConvertTo-SafeOutput $ResolvedDeviceId),
            (ConvertTo-SafeOutput $policyName),
            (ConvertTo-SafeOutput $ExistingPolicy.id)
        )

        $FinalOutput =
            (
                'NO_ACTION | PolicyAlreadyExists | Account={0} Device={1} Policy={2}' -f
                $watchguardCloudAccountId,
                $ResolvedDeviceId,
                $policyName
            )

        return
    }

    # ========================================================
    # TRAFFIC TYPE
    # ========================================================

    $CurrentStage =
        'TrafficType'

    $TrafficTypesUri =
        "$BaseApiUrl/firebox/management/v1/configuration/$watchguardCloudAccountId/firewall/traffic_types?device=$([uri]::EscapeDataString($ResolvedDeviceId))"

    $TrafficTypesResponse =
        Invoke-RestMethod `
            -Method Get `
            -Uri $TrafficTypesUri `
            -Headers $Headers `
            -TimeoutSec 60

    $TrafficTypes =
        @(
            Get-ResponseItems `
                -Response $TrafficTypesResponse
        )

    if ($TrafficTypes.Count -eq 0) {
        throw 'WatchGuard returned no traffic types for the target Firebox.'
    }

    try {

        $ResolvedTrafficType =
            Resolve-TrafficType `
                -TrafficTypes $TrafficTypes `
                -RequestedValue $trafficType
    }
    catch {

        $LocalResolutionError =
            ConvertTo-SafeOutput `
                -Value $_.Exception.Message

        Write-Log (
            'INFO | Device-local traffic type resolution failed Requested={0} Reason={1}' -f
            (ConvertTo-SafeOutput $trafficType),
            $LocalResolutionError
        )

        # ====================================================
        # READ-ONLY DIAGNOSTIC: SUBSCRIBED TEMPLATE LOOKUP
        #
        # IMPORTANT:
        # Template-owned traffic types are NOT used in the POST.
        # This diagnostic exists only to turn a vague lookup error
        # into an explicit, useful limitation message.
        # ====================================================

        $CurrentStage =
            'TrafficTypeDiagnostic'

        $TemplateSubscriptionsUri =
            "$BaseApiUrl/firebox/management/v1/configuration/$watchguardCloudAccountId/templates/subscribe?device=$([uri]::EscapeDataString($ResolvedDeviceId))"

        $TemplateSubscriptionsResponse =
            Invoke-RestMethod `
                -Method Get `
                -Uri $TemplateSubscriptionsUri `
                -Headers $Headers `
                -TimeoutSec 60

        $SubscribedTemplates =
            @(
                $TemplateSubscriptionsResponse.templates
            )

        $InheritedMatch =
            $null

        $InheritedTemplateName =
            $null

        $InheritedTemplateId =
            $null

        foreach ($Template in $SubscribedTemplates) {

            $TemplateId =
                [string]$Template.id

            $TemplateName =
                [string]$Template.name

            if ([string]::IsNullOrWhiteSpace($TemplateId)) {
                continue
            }

            $TemplateTrafficTypesUri =
                "$BaseApiUrl/firebox/management/v1/configuration/$watchguardCloudAccountId/firewall/traffic_types?templateid=$([uri]::EscapeDataString($TemplateId))"

            $TemplateTrafficTypesResponse =
                Invoke-RestMethod `
                    -Method Get `
                    -Uri $TemplateTrafficTypesUri `
                    -Headers $Headers `
                    -TimeoutSec 60

            $CurrentTemplateTrafficTypes =
                @(
                    Get-ResponseItems `
                        -Response $TemplateTrafficTypesResponse
                )

            $Candidate =
                Find-DiagnosticTrafficTypeMatch `
                    -TrafficTypes $CurrentTemplateTrafficTypes `
                    -RequestedValue $trafficType

            if ($null -ne $Candidate) {

                $InheritedMatch =
                    $Candidate

                $InheritedTemplateName =
                    $TemplateName

                $InheritedTemplateId =
                    $TemplateId

                break
            }
        }

        if ($null -ne $InheritedMatch) {

            $InheritedObjectId =
                [string]$InheritedMatch.id

            $InheritedOwner =
                [string]$InheritedMatch.account

            throw (
                "Traffic type '$trafficType' exists only in a subscribed/inherited template " +
                "'$InheritedTemplateName' (TemplateId=$InheritedTemplateId, Owner=$InheritedOwner, ObjectId=$InheritedObjectId). " +
                'The documented firewall-policy create path used by this automation cannot create a device policy with that inherited traffic-type reference. ' +
                'Create or expose an equivalent traffic type directly for the target Firebox/account, then rerun.'
            )
        }

        throw (
            "Traffic type '$trafficType' was not found in the target Firebox's available device/account traffic types. " +
            'If this is a custom port or custom traffic type, create it in WatchGuard first, then rerun the automation.'
        )
    }

    if (
        [string]::IsNullOrWhiteSpace(
            [string]$ResolvedTrafficType.id
        )
    ) {

        throw 'Resolved traffic type did not contain an object ID.'
    }

    Write-Log (
        'PASS | Traffic type resolved Requested={0} Name={1} Id={2}' -f
        (ConvertTo-SafeOutput $trafficType),
        (ConvertTo-SafeOutput $ResolvedTrafficType.name),
        (ConvertTo-SafeOutput $ResolvedTrafficType.id)
    )

    # ========================================================
    # CREATE FIRST RUN POLICY
    # ========================================================

    $CurrentStage =
        'PolicyCreate'

    $PolicyCreateUri =
        "$BaseApiUrl/firebox/management/v1/configuration/$watchguardCloudAccountId/firewall/policies"

    $PolicyBody =
        @{
            device        = $ResolvedDeviceId
            name          = $policyName
            description   = 'Created by Automation Playbook FIRST RUN policy POC'
            enabled       = $true
            group         = [string]$FirstRunGroup.id
            action        = 'allow'
            type          = 'first'
            traffic_types = @(
                [string]$ResolvedTrafficType.id
            )
            sources       = @(
                @{
                    type  = [string]$SourceObject.type
                    value = [string]$SourceObject.value
                }
            )
            destinations  = @(
                @{
                    type  = [string]$DestinationObject.type
                    value = [string]$DestinationObject.value
                }
            )
        } |
        ConvertTo-Json `
            -Depth 20 `
            -Compress

    Write-Log (
        'WRITE_START | Create FIRST RUN allow policy Account={0} RequestedDevice={1} ApiDevice={2} Policy={3} TrafficType={4}/{5} Source={6}:{7} Destination={8}:{9} Deployment=NotRequested' -f
        (ConvertTo-SafeOutput $watchguardCloudAccountId),
        (ConvertTo-SafeOutput $RequestedDeviceId),
        (ConvertTo-SafeOutput $ResolvedDeviceId),
        (ConvertTo-SafeOutput $policyName),
        (ConvertTo-SafeOutput $ResolvedTrafficType.name),
        (ConvertTo-SafeOutput $ResolvedTrafficType.id),
        (ConvertTo-SafeOutput $SourceObject.type),
        (ConvertTo-SafeOutput $SourceObject.value),
        (ConvertTo-SafeOutput $DestinationObject.type),
        (ConvertTo-SafeOutput $DestinationObject.value)
    )

    $CreatedPolicy =
        Invoke-RestMethod `
            -Method Post `
            -Uri $PolicyCreateUri `
            -Headers $Headers `
            -Body $PolicyBody `
            -TimeoutSec 120

    if (
        $null -eq $CreatedPolicy -or
        [string]::IsNullOrWhiteSpace(
            [string]$CreatedPolicy.id
        )
    ) {

        throw (
            'WatchGuard policy create returned no policy object ID.'
        )
    }

    # ========================================================
    # VERIFY SAVED POLICY
    # ========================================================

    $CurrentStage =
        'PolicyVerify'

    $CreatedPolicyId =
        [string]$CreatedPolicy.id

    $VerifyUri =
        "$BaseApiUrl/firebox/management/v1/configuration/$watchguardCloudAccountId/firewall/policies/$([uri]::EscapeDataString($CreatedPolicyId))"

    $VerifiedPolicy =
        Invoke-RestMethod `
            -Method Get `
            -Uri $VerifyUri `
            -Headers $Headers `
            -TimeoutSec 60

    if (
        [string]$VerifiedPolicy.id -ne
        $CreatedPolicyId
    ) {

        throw (
            'Policy verification returned an unexpected policy object.'
        )
    }

    if (
        [string]$VerifiedPolicy.device -ne
        [string]$ResolvedDeviceId
    ) {

        throw (
            "Policy verification returned unexpected Device=$($VerifiedPolicy.device)."
        )
    }

    Write-Log (
        'RESULT | PolicyCreated Account={0} RequestedDevice={1} ApiDevice={2} Policy={3} PolicyId={4} Group={5} TrafficType={6} Deployment=NotRequested' -f
        (ConvertTo-SafeOutput $watchguardCloudAccountId),
        (ConvertTo-SafeOutput $RequestedDeviceId),
        (ConvertTo-SafeOutput $ResolvedDeviceId),
        (ConvertTo-SafeOutput $policyName),
        (ConvertTo-SafeOutput $CreatedPolicyId),
        (ConvertTo-SafeOutput $VerifiedPolicy.group),
        (ConvertTo-SafeOutput $ResolvedTrafficType.name)
    )

    $FinalOutput =
        (
            'RESULT | PolicyCreated | Account={0} Device={1} Policy={2} PolicyId={3} Deployment=NotRequested' -f
            $watchguardCloudAccountId,
            $ResolvedDeviceId,
            $policyName,
            $CreatedPolicyId
        )
}
catch {

    $HttpStatus =
        Get-HttpStatusCode `
            -Exception $_.Exception

    if ($null -eq $HttpStatus) {
        $HttpStatus = 'N/A'
    }

    $SafeError =
        ConvertTo-SafeOutput `
            -Value $_.Exception.Message

    $ResponseBody =
        Get-HttpResponseBody `
            -Exception $_.Exception

    if (-not [string]::IsNullOrWhiteSpace($ResponseBody)) {

        Write-Log (
            'ERROR | Stage={0} HTTP={1} Error={2} Response={3}' -f
            $CurrentStage,
            $HttpStatus,
            $SafeError,
            $ResponseBody
        )
    }
    else {

        Write-Log (
            'ERROR | Stage={0} HTTP={1} Error={2}' -f
            $CurrentStage,
            $HttpStatus,
            $SafeError
        )
    }

    $FinalOutput =
        (
            'ERROR | Stage={0} HTTP={1} Error={2}' -f
            $CurrentStage,
            $HttpStatus,
            $SafeError
        )
}
finally {

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null

    $ServiceAccountToken = $null
    $WatchGuardItem = $null
    $ApiKey = $null
    $ReadWriteAccessId = $null
    $ReadWritePassword = $null
    $AuthenticationUrl = $null
    $BaseApiUrl = $null
    $ProviderToken = $null
    $AccountToken = $null
    $Audience = $null
}

if ([string]::IsNullOrWhiteSpace([string]$FinalOutput)) {

    $FinalOutput =
        'ERROR | Stage=Finalize HTTP=N/A Error=Script completed without a final output token.'
}

Write-Output $FinalOutput
exit 0