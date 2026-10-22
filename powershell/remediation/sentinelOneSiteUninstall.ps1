
# ============================================================================
# NAME: SentinelOne Site Uninstall
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Site-Wide Security Agent Removal
# SCOPE: Windows / Authorized Credential Broker / NinjaOne Execution
#
# VARIABLES:
#   Required NinjaOne String/Text variables:
#     siteName             - Exact target SentinelOne site name
#     onePasswordVault     - Vault containing the SentinelOne API item
#     bootstrapTokenField  - Name of secure NinjaOne field with 1Password token
#   Optional: None
#
# OUTPUT TOKENS:
#   RESULT    | UNINSTALL_SENT=<count>; includes console-connectivity audit
#   NO_ACTION | Site not found or matched site has no current endpoints
#   ERROR     | Stage=<stage> | <sanitized error>
#   Exit Code: Always 0 after script execution
#
# CUSTOM FIELDS:
#   Reads: NinjaOne secure field specified by bootstrapTokenField
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   %ProgramData%\AutomationPlaybook\Logs\S1_Site_Uninstall.log
#
# DESCRIPTION:
#   Resolves siteName to one SentinelOne Site ID, inventories current agents,
#   audits Console Connectivity using agent.isActive, then sends the uninstall
#   action to the ENTIRE resolved site, including online and offline agents.
#   Console connectivity is audit-only and NEVER filters uninstall scope.
#   Offline endpoint names are retained for manual follow-up. UNINSTALL_SENT
#   means the SentinelOne API accepted the request, NOT that all endpoints
#   have completed uninstall.
#
#   WARNING: Destructive security-agent removal. Confirm the exact site
#   before execution. Resulting logs can contain customer site and device
#   identifiers; do not publish them without separate sanitization.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# =============================================================================
# NINJAONE SCRIPT VARIABLE
# =============================================================================

$TargetSiteName = [string]$env:siteName

# =============================================================================
# CONFIGURATION
# =============================================================================

$LogFolder = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogFile   = Join-Path $LogFolder 'S1_Site_Uninstall.log'

$OpField    = [string]$env:bootstrapTokenField
$Vault      = [string]$env:onePasswordVault
$ItemName   = 'SentinelOne'
$TokenField = 'credential'
$UrlField   = 'consoleUrl'

# =============================================================================
# HELPERS
# =============================================================================

function Safe-Text {
    param([AllowNull()][object]$Value)

    $s = [string]$Value

    foreach ($secret in @($script:OpToken, $script:ApiToken)) {
        if (-not [string]::IsNullOrEmpty($secret)) {
            $s = $s.Replace($secret, '[REDACTED]')
        }
    }

    $s = $s -replace '[\r\n|]+', ' ' -replace '\s{2,}', ' '

    if ($s.Length -gt 900) {
        $s = $s.Substring(0, 900)
    }

    return $s.Trim()
}

function Write-Log {
    param([string]$Message)

    try {
        $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -LiteralPath $LogFile -Value "$stamp | $Message" -Encoding UTF8
    }
    catch {
        # Logging failure must not change the remediation result.
    }
}

function Get-1PField {
    param(
        [Parameter(Mandatory = $true)]$Item,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $matches = @(
        $Item.fields | Where-Object {
            ([string]$_.label).Trim() -eq $Label
        }
    )

    if ($matches.Count -ne 1) {
        throw "Expected exactly one 1Password field named '$Label'; found $($matches.Count)"
    }

    $value = [string]$matches[0].value

    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "1Password field '$Label' was empty"
    }

    return $value.Trim()
}

function Get-HttpErrorDetail {
    param($Exception)

    try {
        $response = $Exception.Response

        if ($null -eq $response) {
            return (Safe-Text $Exception.Message)
        }

        $status = [int]$response.StatusCode
        $stream = $response.GetResponseStream()

        if ($null -ne $stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            $body = $reader.ReadToEnd()
            $reader.Dispose()

            if (-not [string]::IsNullOrWhiteSpace($body)) {
                return (Safe-Text "HTTP=$status Response=$body")
            }
        }

        return (Safe-Text "HTTP=$status Message=$($Exception.Message)")
    }
    catch {
        return (Safe-Text $Exception.Message)
    }
}

function Invoke-S1Get {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][hashtable]$Headers
    )

    try {
        return Invoke-RestMethod `
            -Method Get `
            -Uri $Uri `
            -Headers $Headers `
            -ContentType 'application/json' `
            -UseBasicParsing
    }
    catch {
        throw (Get-HttpErrorDetail -Exception $_.Exception)
    }
}


function Invoke-S1Post {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][hashtable]$Headers,
        [Parameter(Mandatory = $true)][object]$Body
    )

    try {
        $json = $Body | ConvertTo-Json -Depth 8 -Compress

        return Invoke-RestMethod `
            -Method Post `
            -Uri $Uri `
            -Headers $Headers `
            -ContentType 'application/json' `
            -Body $json `
            -UseBasicParsing
    }
    catch {
        throw (Get-HttpErrorDetail -Exception $_.Exception)
    }
}


# =============================================================================
# MAIN
# =============================================================================

$Stage       = 'Initialize'
$ApiToken    = $null
$OpToken     = $null
$Item        = $null
$ItemText    = $null
$FinalOutput = $null

try {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
    Write-Log 'START | SentinelOne Site Uninstall'

    $Stage = 'ValidateConfiguration'

    if ([string]::IsNullOrWhiteSpace($OpField) -or
        [string]::IsNullOrWhiteSpace($Vault)) {
        throw 'Required NinjaOne configuration onePasswordVault or bootstrapTokenField was empty'
    }

    $Stage = 'ValidateInput'

    if ([string]::IsNullOrWhiteSpace($TargetSiteName)) {
        throw 'Ninja automation variable siteName was empty'
    }

    $TargetSiteName = $TargetSiteName.Trim()
    Write-Log "INPUT | TargetSiteName=$TargetSiteName"

    $Stage = 'BrokerBootstrap'

    $OpToken = [string](Ninja-Property-Get -Name $OpField)
    $OpToken = $OpToken.Trim()

    if (-not $OpToken) {
        throw "Ninja secure custom field '$OpField' was empty"
    }

    $Stage = 'OnePasswordCLI'

    $cmd = Get-Command 'op.exe' -ErrorAction SilentlyContinue

    $op = if ($cmd) {
        $cmd.Source
    }
    else {
        @(
            'C:\Program Files\1Password CLI\op.exe',
            'C:\Program Files\1Password\op.exe',
            'C:\Windows\System32\op.exe'
        ) |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
    }

    if (-not $op) {
        throw 'op.exe was not found on the Credential Broker'
    }

    $env:OP_SERVICE_ACCOUNT_TOKEN = $OpToken

    $who = & $op user get --me --format json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw '1Password service-account authentication failed'
    }

    $ItemText = & $op item get $ItemName --vault $Vault --format json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw '1Password SentinelOne item lookup failed'
    }

    $Item = $ItemText | ConvertFrom-Json

    $ApiToken = Get-1PField -Item $Item -Label $TokenField
    $BaseUrl  = Get-1PField -Item $Item -Label $UrlField
    $BaseUrl  = $BaseUrl.TrimEnd('/')

    $baseUri = [Uri]$BaseUrl

    if ($baseUri.Scheme -ne 'https') {
        throw 'SentinelOne consoleUrl was not HTTPS'
    }

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $OpToken  = $null
    $Item     = $null
    $ItemText = $null
    $who      = $null

    $Headers = @{
        Authorization = "ApiToken $ApiToken"
        Accept        = 'application/json'
    }

    Write-Log "AUTH_OK | Host=$($baseUri.Host)"

    $Stage  = 'EnumerateSites'
    $Sites  = @()
    $Cursor = $null

    do {
        $SiteUri = "$BaseUrl/web/api/v2.1/sites?limit=1000"

        if ($Cursor) {
            $SiteUri += '&cursor=' + [Uri]::EscapeDataString([string]$Cursor)
        }

        $SiteResponse = Invoke-S1Get -Uri $SiteUri -Headers $Headers

        if ($null -eq $SiteResponse.data -or $null -eq $SiteResponse.data.sites) {
            throw 'SentinelOne Sites response did not contain data.sites'
        }

        $Sites += @($SiteResponse.data.sites)

        $Cursor = $null

        if (
            $null -ne $SiteResponse.pagination -and
            -not [string]::IsNullOrWhiteSpace([string]$SiteResponse.pagination.nextCursor)
        ) {
            $Cursor = [string]$SiteResponse.pagination.nextCursor
        }
    }
    while ($Cursor)

    $Matches = @(
        $Sites | Where-Object {
            ([string]$_.name) -eq $TargetSiteName
        }
    )

    if ($Matches.Count -eq 0) {
        $FinalOutput = "NO_ACTION | Site not found | Name=`"$TargetSiteName`""
        Write-Log $FinalOutput
    }
    elseif ($Matches.Count -gt 1) {
        throw "Exact site name matched $($Matches.Count) SentinelOne sites"
    }
    else {
        $SiteId = [string]$Matches[0].id

        if ([string]::IsNullOrWhiteSpace($SiteId)) {
            throw 'Matched SentinelOne Site did not contain an ID'
        }

        Write-Log "SITE_FOUND | Name=$TargetSiteName SiteId=$SiteId"

        $Stage  = 'EnumerateEndpoints'
        $Agents = @()
        $Cursor = $null

        do {
            $AgentUri = "$BaseUrl/web/api/v2.1/agents?siteIds=$([Uri]::EscapeDataString($SiteId))&isUninstalled=false&isDecommissioned=false&limit=1000"

            if ($Cursor) {
                $AgentUri += '&cursor=' + [Uri]::EscapeDataString([string]$Cursor)
            }

            $AgentResponse = Invoke-S1Get -Uri $AgentUri -Headers $Headers

            if ($null -eq $AgentResponse.data) {
                throw 'SentinelOne Agents response did not contain data'
            }

            $PageAgents = @($AgentResponse.data)

            foreach ($Agent in $PageAgents) {
                if ($null -eq $Agent) {
                    continue
                }

                if ([string]::IsNullOrWhiteSpace([string]$Agent.computerName)) {
                    throw 'SentinelOne Agent record was missing computerName'
                }

                if ($Agent.PSObject.Properties.Name -notcontains 'isActive') {
                    throw "SentinelOne Agent '$([string]$Agent.computerName)' was missing isActive"
                }

                $Agents += $Agent
            }

            $Cursor = $null

            if (
                $null -ne $AgentResponse.pagination -and
                -not [string]::IsNullOrWhiteSpace([string]$AgentResponse.pagination.nextCursor)
            ) {
                $Cursor = [string]$AgentResponse.pagination.nextCursor
            }
        }
        while ($Cursor)

        $TotalCount = @($Agents).Count

        if ($TotalCount -eq 0) {
            $FinalOutput = "NO_ACTION | Site found but no current endpoints | Name=`"$TargetSiteName`" SiteId=`"$SiteId`""
            Write-Log $FinalOutput
        }
        else {
            $Stage = 'ConnectivityStatus'

            $OnlineAgents = @(
                $Agents | Where-Object {
                    $_.isActive -eq $true
                }
            )

            $OfflineAgents = @(
                $Agents | Where-Object {
                    $_.isActive -eq $false
                }
            )

            $OnlineCount  = @($OnlineAgents).Count
            $OfflineCount = @($OfflineAgents).Count

            if (($OnlineCount + $OfflineCount) -ne $TotalCount) {
                throw "Console Connectivity classification did not account for all $TotalCount agents"
            }

            foreach ($Agent in ($Agents | Sort-Object computerName)) {
                $Name          = Safe-Text $Agent.computerName
                $IsActive      = [bool]$Agent.isActive
                $NetworkStatus = Safe-Text $Agent.networkStatus
                $LastActive    = Safe-Text $Agent.lastActiveDate

                $ConsoleConnectivity = if ($IsActive) { 'ONLINE' } else { 'OFFLINE' }

                Write-Log "ENDPOINT | ComputerName=$Name ConsoleConnectivity=$ConsoleConnectivity IsActive=$IsActive NetworkStatus=$NetworkStatus LastActive=$LastActive"
            }

            $OfflineNames = @(
                $OfflineAgents |
                Sort-Object computerName |
                ForEach-Object { Safe-Text $_.computerName }
            )

            $AuditOutput = "AUDIT | Site=`"$TargetSiteName`" Total=$TotalCount Online=$OnlineCount Offline=$OfflineCount"

            if ($OfflineNames.Count -gt 0) {
                $AuditOutput += " OfflineDevices=`"$($OfflineNames -join ',')`""
            }

            Write-Log "$AuditOutput | SiteId=$SiteId"

            # -----------------------------------------------------------------
            # Send uninstall to the entire exact resolved Site ID.
            #
            # IMPORTANT:
            # Console Connectivity is audit-only. There is deliberately NO
            # isActive / online / offline filter in this request. SentinelOne
            # receives the uninstall action for the whole exact site scope.
            # -----------------------------------------------------------------

            $Stage = 'SendUninstall'

            $UninstallUri = "$BaseUrl/web/api/v2.1/agents/actions/uninstall"

            $UninstallBody = @{
                filter = @{
                    siteIds = @($SiteId)
                }
            }

            $UninstallResponse = Invoke-S1Post `
                -Uri $UninstallUri `
                -Headers $Headers `
                -Body $UninstallBody

            if ($null -eq $UninstallResponse.data -or $null -eq $UninstallResponse.data.affected) {
                throw 'SentinelOne uninstall response did not contain data.affected'
            }

            $AcceptedCount = [int]$UninstallResponse.data.affected

            if ($AcceptedCount -ne $TotalCount) {
                throw "SentinelOne accepted uninstall for $AcceptedCount Agents but current site inventory contained $TotalCount"
            }

            $Stage = 'Complete'

            $FinalOutput = "RESULT | UNINSTALL_SENT=$AcceptedCount | Site=`"$TargetSiteName`" Total=$TotalCount Online=$OnlineCount Offline=$OfflineCount"

            if ($OfflineNames.Count -gt 0) {
                $FinalOutput += " OfflineDevices=`"$($OfflineNames -join ',')`""
            }

            Write-Log "$FinalOutput | SiteId=$SiteId"
        }
    }
}
catch {
    $detail = Safe-Text $_.Exception.Message
    $FinalOutput = "ERROR | Stage=$Stage | $detail"
    Write-Log $FinalOutput
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $OpToken  = $null
    $ApiToken = $null
    $Item     = $null
    $ItemText = $null
}

if ([string]::IsNullOrWhiteSpace($FinalOutput)) {
    $FinalOutput = 'ERROR | Stage=Finalize | Script completed without a final result'
    Write-Log $FinalOutput
}

Write-Output $FinalOutput
exit 0
