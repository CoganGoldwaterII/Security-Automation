# ============================================================================
# NAME: SentinelOne Site Policy Inheritance Reversion
# TYPE: Remediation / Single SentinelOne Site
# SCOPE: Windows / NinjaOne / Authorized 1Password Credential Broker
#
# NINJAONE VARIABLES (String/Text):
#   siteId              - Exact SentinelOne Site ID (required)
#
# CREDENTIAL BROKER CONFIGURATION (fixed; not Ninja script variables):
#   Broker              - Approved Credential Broker (Device 9800)
#   Ninja secure field  - opServiceAccountToken
#   1Password vault     - MME Automation
#   1Password item      - SentinelOne
#   Item fields         - credential (API token), consoleUrl (API origin)
#
# SOURCE ACCOUNT: MME-NinjaOne Clients (under Global)
# EXCLUSIONS: Group names containing Xray/X-ray or TerminalServer/TermServ
#             (including separators, singular/plural, and TermSrv variants)
#
# ACTION: Revert the selected SITE to its ACCOUNT policy. Revert only
#         nonexcluded GROUP policies to the selected SITE policy.
#         Group membership, site/account structure, and Account policy unchanged.
#
# OUTPUT: RESULT | NO_ACTION | ERROR. Exit code always 0.
# LOG:    C:\MME\AutoLogs\S1_Site_Policy_Inheritance_Revert.log
#
# CAUTION: Revert replaces custom policy settings at each affected scope.
#          No automatic rollback is available. Test on one selected site.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$TargetSiteId   = ([string]$env:siteId).Trim()
$AccountName   = 'MME-NinjaOne Clients'
$Vault         = 'MME Automation'
$OpField       = 'opServiceAccountToken'
$ItemName      = 'SentinelOne'
$LogFolder     = 'C:\MME\AutoLogs'
$LogFile       = Join-Path $LogFolder 'S1_Site_Policy_Inheritance_Revert.log'

$Stage         = 'Initialize'
$OpToken       = $null
$ApiToken      = $null
$Item          = $null
$ItemText      = $null
$FinalOutput   = $null
$SiteChanged   = 0
$GroupsChanged = 0
$GroupsSkipped = 0
$GroupsAlready = 0

function Safe-Text {
    param([AllowNull()][object]$Value)
    $s = [string]$Value
    foreach ($secret in @($script:OpToken, $script:ApiToken)) {
        if (-not [string]::IsNullOrEmpty($secret)) {
            $s = $s.Replace($secret, '[REDACTED]')
        }
    }
    $s = $s -replace '[\r\n|]+', ' ' -replace '\s{2,}', ' '
    if ($s.Length -gt 900) { $s = $s.Substring(0, 900) }
    return $s.Trim()
}

function Write-Log {
    param([string]$Message)
    try {
        Add-Content -LiteralPath $LogFile -Encoding UTF8 -Value (
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $(Safe-Text $Message)"
        )
    }
    catch { }
}

function Get-1PField {
    param([object]$Item, [string]$Label)
    $matches = @($Item.fields | Where-Object { ([string]$_.label).Trim() -ceq $Label })
    if ($matches.Count -ne 1) { throw "Expected one 1Password field '$Label'; found $($matches.Count)" }
    $value = ([string]$matches[0].value).Trim()
    if (-not $value) { throw "1Password field '$Label' was empty" }
    return $value
}

function Get-HttpErrorDetail {
    param($Exception)
    try {
        $response = $Exception.Response
        if ($null -eq $response) { return (Safe-Text $Exception.Message) }
        $status = [int]$response.StatusCode
        $body = ''
        if ($response.GetResponseStream()) {
            $reader = New-Object IO.StreamReader($response.GetResponseStream())
            try { $body = $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        return (Safe-Text "HTTP=$status $body $($Exception.Message)")
    }
    catch { return (Safe-Text $Exception.Message) }
}

function Invoke-S1 {
    param(
        [ValidateSet('GET','PUT')][string]$Method,
        [string]$Path,
        [AllowNull()][object]$Body = $null
    )
    try {
        $args = @{
            Uri = "$script:BaseUrl$Path"
            Method = $Method
            Headers = $script:Headers
            ContentType = 'application/json'
            ErrorAction = 'Stop'
            UseBasicParsing = $true
        }
        if ($Method -eq 'PUT') { $args.Body = $Body | ConvertTo-Json -Depth 8 -Compress }
        return Invoke-RestMethod @args
    }
    catch { throw (Get-HttpErrorDetail -Exception $_.Exception) }
}

function Get-S1Paged {
    param([string]$Path, [ValidateSet('accounts','sites','groups')][string]$Kind)
    $items = @()
    $cursor = $null
    do {
        $uri = $Path
        if ($cursor) { $uri += '&cursor=' + [uri]::EscapeDataString([string]$cursor) }
        $resp = Invoke-S1 -Method GET -Path $uri
        if ($null -eq $resp -or $null -eq $resp.data) {
            throw "SentinelOne $Kind response did not contain data"
        }
        switch ($Kind) {
            'accounts' { $page = @($resp.data) }
            'sites' {
                if ($null -eq $resp.data.sites) { throw 'Sites response missing data.sites' }
                $page = @($resp.data.sites)
            }
            'groups' { $page = @($resp.data) }
        }
        $items += @($page | Where-Object { $null -ne $_ })
        $cursor = $null
        if ($resp.pagination -and $resp.pagination.nextCursor) {
            $cursor = [string]$resp.pagination.nextCursor
        }
    } while ($cursor)
    return $items
}

function Get-Inherits {
    param([object]$Record)
    if ($null -eq $Record) { return $null }
    if ($Record.PSObject.Properties.Name -contains 'inherits' -and
        $null -ne $Record.inherits) {
        if ($Record.inherits -is [bool]) { return [bool]$Record.inherits }
        if ([string]$Record.inherits -eq 'true') { return $true }
        if ([string]$Record.inherits -eq 'false') { return $false }
    }
    return $null
}

function Test-ProtectedGroupName {
    param([string]$Name)
    # Normalizing punctuation handles X-ray, X_Ray, Term-Serv, Terminal Servers.
    $normalized = ($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    return ($normalized -match 'xray|terminalserv|terminalservers|termserv|termsrv|terminalsrv|terminalsvr|termsvr')
}

function Confirm-AfterRevert {
    param([string]$Kind, [string]$Id)
    $resource = if ($Kind -eq 'Site') { 'sites' } else { 'groups' }
    $result = Invoke-S1 -Method GET -Path "/web/api/v2.1/$resource/$Id"
    if ($null -eq $result -or $null -eq $result.data) {
        throw "$Kind verification response missing data"
    }
    $state = Get-Inherits -Record $result.data
    if ($null -ne $state -and -not $state) {
        throw "$Kind revert request returned success but inherits=false afterward"
    }
    # Some console versions do not expose 'inherits' in this response.
    # In that case the successful PUT is recorded as API accepted, not verified.
    if ($null -eq $state) { Write-Log "API_ACCEPTED | $Kind Id=$Id; inheritance property not present in verification response" }
    else { Write-Log "VERIFIED | $Kind Id=$Id inherits=true" }
}

try {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
    Write-Log 'START | S1 Site Policy Inheritance Reversion'

    $Stage = 'ValidateInput'
    if (-not $TargetSiteId) { throw 'Ninja variable siteId was empty' }
    Write-Log "TARGET | Account=$AccountName SiteId=$TargetSiteId"

    $Stage = 'BrokerBootstrap'
    $OpToken = ([string](Ninja-Property-Get -Name $OpField)).Trim()
    if (-not $OpToken) { throw "Ninja secure field '$OpField' was empty" }

    $Stage = 'OnePasswordCLI'
    $cmd = Get-Command 'op.exe' -ErrorAction SilentlyContinue
    $op = if ($cmd) { $cmd.Source } else {
        @('C:\Program Files\1Password CLI\op.exe',
          'C:\Program Files\1Password\op.exe',
          'C:\Windows\System32\op.exe') |
          Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if (-not $op) { throw 'op.exe was not found on Credential Broker' }
    $env:OP_SERVICE_ACCOUNT_TOKEN = $OpToken
    $who = & $op user get --me --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw '1Password service-account authentication failed' }
    $ItemText = & $op item get $ItemName --vault $Vault --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw '1Password SentinelOne item lookup failed' }
    $Item = $ItemText | ConvertFrom-Json
    $ApiToken = Get-1PField -Item $Item -Label 'credential'
    $BaseUrl = (Get-1PField -Item $Item -Label 'consoleUrl').TrimEnd('/')
    $baseUri = [uri]$BaseUrl
    if ($baseUri.Scheme -ne 'https' -or $baseUri.AbsolutePath -ne '/') {
        throw 'SentinelOne consoleUrl must be an HTTPS console origin'
    }
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $OpToken = $null
    $Item = $null; $ItemText = $null; $who = $null
    $Headers = @{ Authorization = "ApiToken $ApiToken"; Accept = 'application/json' }
    Write-Log "AUTH_OK | Host=$($baseUri.Host)"

    $Stage = 'FindAccount'
    $accounts = @(Get-S1Paged -Path '/web/api/v2.1/accounts?limit=1000' -Kind accounts)
    $accountMatches = @($accounts | Where-Object { ([string]$_.name) -eq $AccountName })
    if ($accountMatches.Count -ne 1) {
        throw "Required Account '$AccountName' matched $($accountMatches.Count) accounts; expected exactly 1"
    }
    $AccountId = [string]$accountMatches[0].id
    if (-not $AccountId) { throw 'Matched Account was missing id' }
    Write-Log "ACCOUNT_FOUND | Name=$AccountName AccountId=$AccountId"

    $Stage = 'FindSite'
    $sites = @(Get-S1Paged -Path "/web/api/v2.1/sites?accountIds=$([uri]::EscapeDataString($AccountId))&limit=1000" -Kind sites)
    $siteMatches = @($sites | Where-Object {
        ([string]$_.id) -eq $TargetSiteId -and ([string]$_.accountId) -eq $AccountId
    })
    if ($siteMatches.Count -eq 0) {
        $FinalOutput = "NO_ACTION | Site ID not found in Account=$AccountName | SiteId=$TargetSiteId"
        Write-Log $FinalOutput
    }
    elseif ($siteMatches.Count -gt 1) {
        throw "Site ID '$TargetSiteId' matched multiple Sites in Account '$AccountName'"
    }
    else {
        $site = $siteMatches[0]
        $SiteId = [string]$site.id
        $TargetSiteName = [string]$site.name
        if (-not $SiteId) { throw 'Matched Site was missing id' }
        Write-Log "SITE_FOUND | Name=$TargetSiteName SiteId=$SiteId"

        $Stage = 'EnumerateGroups'
        $groups = @(Get-S1Paged -Path "/web/api/v2.1/groups?siteIds=$([uri]::EscapeDataString($SiteId))&limit=200" -Kind groups)
        $ids = @{}
        foreach ($group in $groups) {
            $name = [string]$group.name
            $id = [string]$group.id
            if (-not $name -or -not $id) { throw 'Group inventory included a record missing name or id' }
            if ([string]$group.siteId -ne $SiteId) {
                throw "Group '$name' did not belong to exact target SiteId=$SiteId"
            }
            if ($ids.ContainsKey($id)) { throw "Duplicate group id '$id' in API inventory" }
            $ids[$id] = $true
        }
        $excluded = @($groups | Where-Object { Test-ProtectedGroupName -Name ([string]$_.name) })
        $targets  = @($groups | Where-Object { -not (Test-ProtectedGroupName -Name ([string]$_.name)) })
        $GroupsSkipped = $excluded.Count
        foreach ($g in $excluded) { Write-Log "EXCLUDED | Group=$($g.name) GroupId=$($g.id)" }
        Write-Log "PLAN | Account=$AccountName Site=$TargetSiteName GroupsTotal=$($groups.Count) GroupsEligible=$($targets.Count) GroupsExcluded=$GroupsSkipped"

        # Step 1: the SITE must inherit ACCOUNT before GROUPS can inherit it.
        $Stage = 'RevertSite'
        if ((Get-Inherits -Record $site) -eq $true) {
            Write-Log "NO_ACTION | Site already inherits Account; SiteId=$SiteId"
        }
        else {
            $body = @{ data = @{ id = $SiteId } }
            $null = Invoke-S1 -Method PUT -Path "/web/api/v2.1/sites/$SiteId/revert-policy" -Body $body
            $SiteChanged = 1
            Write-Log "SITE_REVERT_ACCEPTED | SiteId=$SiteId ParentAccountId=$AccountId"
            $Stage = 'VerifySite'
            Confirm-AfterRevert -Kind Site -Id $SiteId
        }

        # Step 2: all eligible GROUPS inherit SITE. Protected groups are untouched.
        foreach ($group in ($targets | Sort-Object name)) {
            $groupId = [string]$group.id
            $groupName = [string]$group.name
            $Stage = "RevertGroup:$groupId"
            if ((Get-Inherits -Record $group) -eq $true) {
                $GroupsAlready++
                Write-Log "NO_ACTION | Group already inherits Site; Name=$groupName GroupId=$groupId"
                continue
            }
            $body = @{ data = @{ id = $groupId } }
            $null = Invoke-S1 -Method PUT -Path "/web/api/v2.1/groups/$groupId/revert-policy" -Body $body
            $GroupsChanged++
            Write-Log "GROUP_REVERT_ACCEPTED | Group=$groupName GroupId=$groupId ParentSiteId=$SiteId"
            $Stage = "VerifyGroup:$groupId"
            Confirm-AfterRevert -Kind Group -Id $groupId
        }

        $Stage = 'Complete'
        if ($SiteChanged -eq 0 -and $GroupsChanged -eq 0) {
            $FinalOutput = "NO_ACTION | Site=$TargetSiteName Account=$AccountName AlreadyInherited=$GroupsAlready Excluded=$GroupsSkipped"
        }
        else {
            $FinalOutput = "RESULT | Site=$TargetSiteName Account=$AccountName SiteReverted=$SiteChanged GroupsReverted=$GroupsChanged AlreadyInherited=$GroupsAlready Excluded=$GroupsSkipped"
        }
        Write-Log $FinalOutput
    }
}
catch {
    $FinalOutput = "ERROR | Stage=$Stage | $(Safe-Text $_.Exception.Message) | SiteReverted=$SiteChanged GroupsReverted=$GroupsChanged"
    Write-Log $FinalOutput
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $OpToken = $null; $ApiToken = $null; $Item = $null; $ItemText = $null
    $Headers = $null
}

if (-not $FinalOutput) {
    $FinalOutput = 'ERROR | Stage=Finalize | Missing final result'
    Write-Log $FinalOutput
}
Write-Output $FinalOutput
exit 0
