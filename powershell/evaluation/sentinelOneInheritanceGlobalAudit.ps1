# ============================================================================
# NAME: SentinelOne Account-Wide Inheritance Manifest
# TYPE: Evaluation / Read-Only / Manifest Generation
# SCOPE: Windows / NinjaOne / Approved Credential Broker (Device 9800)
#
# NINJA SCRIPT VARIABLES: None
# CREDENTIALS: Ninja secure field opServiceAccountToken; 1Password vault
#              MME Automation; item SentinelOne (credential, consoleUrl).
# ACCOUNT: MME-NinjaOne Clients
# SITE EXCLUSIONS: DC and MOS as separate tokens; Dolphin Cloud; Hosted
# GROUP EXCLUSIONS: X-ray/Xray and TerminalServer/TermServ variants
#
# MANIFEST: C:\MME\CS\S1_Inheritance_Restoration_Manifest.json
# LOG:      C:\MME\AutoLogs\S1_Inheritance_Manifest.log
# OUTPUT:   TRIGGER | NO_ACTION | ERROR (exit code always 0)
#
# Identifies eligible Sites requiring a reversion attempt, and records
# GroupTargets whose inherited state is not already TRUE. For sites where
# the Sites list omits inheritance, GET the individual site to check again.
# If neither response exposes inherits, retain UNKNOWN as before.
# Sites with Site inheritance TRUE and all eligible Groups already inheriting
# are omitted from the target set. Protected groups/sites never targeted.
# Does not call any policy-changing endpoint.
# ============================================================================

[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$AccountName    = 'MME-NinjaOne Clients'
$Vault          = 'MME Automation'
$OpField        = 'opServiceAccountToken'
$ItemName       = 'SentinelOne'
$LogFolder      = 'C:\MME\AutoLogs'
$ManifestFile   = 'C:\MME\CS\S1_Inheritance_Restoration_Manifest.json'
$ManifestSchema = 'MME.S1.PolicyInheritance.Manifest.v1'
$GroupRule      = 'xray|terminalserv|terminalservers|termserv|termsrv|terminalsrv|terminalsvr|termsvr'
$SiteRules      = @('DC (separate token)', 'Dolphin Cloud', 'Hosted', 'MOS (separate token)')

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
    param([string]$Path)
    try {
        return Invoke-RestMethod -Method Get -Uri "$script:BaseUrl$Path" `
            -Headers $script:Headers -ContentType 'application/json' `
            -ErrorAction Stop -UseBasicParsing
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
        $resp = Invoke-S1 -Path $uri
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


function Get-ProtectedSiteRule {
    param([string]$Name)
    # DC and MOS are separate tokens, avoiding accidental matches inside customer names.
    if ($Name -match '(?i)(^|[^a-z0-9])DC($|[^a-z0-9])') { return 'DC' }
    if ($Name -match '(?i)(^|[^a-z0-9])MOS($|[^a-z0-9])') { return 'MOS' }
    $compact = ($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    if ($compact -match 'dolphincloud') { return 'Dolphin Cloud' }
    if ($compact -match 'hosted') { return 'Hosted' }
    return $null
}

function Get-InheritanceLabel {
    param([object]$Record)
    $v = Get-Inherits -Record $Record
    if ($null -eq $v) { return 'UNKNOWN' }
    if ($v) { return 'TRUE' }
    return 'FALSE'
}

$Stage = 'Initialize'
$OpToken = $null
$ApiToken = $null
$Item = $null
$ItemText = $null
$FinalOutput = $null
$BaseUrl = $null
$LogFile = Join-Path $LogFolder 'S1_Inheritance_Manifest.log'

try {
    New-Item -ItemType Directory -Force -Path $LogFolder | Out-Null
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ManifestFile) | Out-Null
    Write-Log 'START | S1 Account-Wide Inheritance Manifest (read-only)'
    # Never leave a stale previous manifest actionable after a failed audit.
    $Stage = 'InvalidatePreviousManifest'
    if (Test-Path -LiteralPath $ManifestFile) { Remove-Item -LiteralPath $ManifestFile -Force }
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

    $Stage = 'EnumerateSites'
    $sites = @(Get-S1Paged -Path "/web/api/v2.1/sites?accountIds=$([uri]::EscapeDataString($AccountId))&limit=1000" -Kind sites)
    $seenSites = @{}
    $selected = @()
    $excludedSites = @()
    $already = 0
    $allGroupTargets = 0
    $protectedCount = 0
    $siteKnownBroken = 0
    $siteUnknown = 0
    $sitesWithGroupTargets = 0
    $eligibleInheritedCount = 0

    foreach ($site in ($sites | Sort-Object name)) {
        $siteId = [string]$site.id
        $siteName = [string]$site.name
        if (-not $siteId -or -not $siteName) { throw 'Site inventory contained a record missing id or name' }
        if ([string]$site.accountId -ne $AccountId) {
            throw "Out-of-account Site returned by API: SiteId=$siteId"
        }
        if ($seenSites.ContainsKey($siteId)) { throw "Duplicate SiteId=$siteId in API inventory" }
        $seenSites[$siteId] = $true

        $reason = Get-ProtectedSiteRule -Name $siteName
        if ($reason) {
            $excludedSites += [ordered]@{ SiteId = $siteId; SiteName = $siteName; Rule = $reason }
            Write-Log "SITE_EXCLUDED | Site=$siteName SiteId=$siteId Rule=$reason"
            continue
        }

        $Stage = "EnumerateGroups:$siteId"
        $groups = @(Get-S1Paged -Path "/web/api/v2.1/groups?siteIds=$([uri]::EscapeDataString($siteId))&limit=200" -Kind groups)
        $groupIds = @{}
        $targets = @()
        $protected = @()
        $inherited = 0
        foreach ($group in ($groups | Sort-Object name)) {
            $groupName = [string]$group.name
            $groupId = [string]$group.id
            if (-not $groupName -or -not $groupId) {
                throw "Group missing id/name in Site=$siteName"
            }
            if ([string]$group.siteId -ne $siteId) {
                throw "Group=$groupName returned outside SiteId=$siteId"
            }
            if ($groupIds.ContainsKey($groupId)) { throw "Duplicate GroupId=$groupId" }
            $groupIds[$groupId] = $true

            if (Test-ProtectedGroupName -Name $groupName) {
                $protected += [ordered]@{ GroupId = $groupId; GroupName = $groupName }
                $protectedCount++
                Write-Log "GROUP_EXCLUDED | Site=$siteName Group=$groupName GroupId=$groupId"
                continue
            }
            $status = Get-InheritanceLabel -Record $group
            if ($status -eq 'TRUE') { $inherited++; $eligibleInheritedCount++; continue }
            $targets += [ordered]@{
                GroupId = $groupId
                GroupName = $groupName
                InheritanceAtAudit = $status
            }
            $allGroupTargets++
        }

        $siteStatus = Get-InheritanceLabel -Record $site
        if ($siteStatus -eq 'UNKNOWN') {
            # The Sites list may omit inherits. Check the individual Site record.
            $Stage = "GetSiteInheritance:$siteId"
            $detailResponse = Invoke-S1 -Path "/web/api/v2.1/sites/$([uri]::EscapeDataString($siteId))"
            if ($null -eq $detailResponse -or $null -eq $detailResponse.data) {
                throw "Site detail response missing data for SiteId=$siteId"
            }
            $detailSite = $detailResponse.data
            if ([string]$detailSite.id -ne $siteId -or [string]$detailSite.accountId -ne $AccountId) {
                throw "Site detail identity/account mismatch for SiteId=$siteId"
            }
            $siteStatus = Get-InheritanceLabel -Record $detailSite
            Write-Log "SITE_INHERITANCE_DETAIL | Site=$siteName SiteId=$siteId Inheritance=$siteStatus"
        }
        if ($siteStatus -eq 'FALSE') { $siteKnownBroken++ }
        if ($siteStatus -eq 'UNKNOWN') { $siteUnknown++ }
        if ($siteStatus -eq 'TRUE' -and $targets.Count -eq 0) {
            $already++
            Write-Log "NO_ACTION | Site=$siteName already inherits, eligible groups already inherit"
            continue
        }
        # Match the validated single-Site remediation: an UNKNOWN Site inheritance
        # state is not treated as already inherited. It remains eligible for
        # a Site-level reversion attempt, even with zero GroupTargets.
        if ($targets.Count -gt 0) { $sitesWithGroupTargets++ }

        $selected += [ordered]@{
            SiteId = $siteId
            SiteName = $siteName
            AccountId = $AccountId
            SiteInheritanceAtAudit = $siteStatus
            GroupTargets = @($targets)
            ProtectedGroups = @($protected)
            GroupsAlreadyInheritedAtAudit = $inherited
            GroupsTotalAtAudit = $groups.Count
        }
        Write-Log "TARGET | Site=$siteName SiteId=$siteId SiteInheritance=$siteStatus GroupsToRevert=$($targets.Count) Protected=$($protected.Count)"
    }

    $manifest = [ordered]@{
        Schema = $ManifestSchema
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        ConsoleHost = $baseUri.Host
        AccountName = $AccountName
        AccountId = $AccountId
        Rules = [ordered]@{
            GroupExclusionNormalizedRegex = $GroupRule
            SiteExclusions = @($SiteRules)
        }
        Sites = @($selected)
        ExcludedSites = @($excludedSites)
        Summary = [ordered]@{
            SitesScanned = $sites.Count
            SitesToRevert = $selected.Count
            EligibleGroupsToRevert = $allGroupTargets
            ProtectedGroupsSeen = $protectedCount
            SitesKnownBroken = $siteKnownBroken
            SitesInheritanceUnknown = $siteUnknown
            SitesWithGroupTargets = $sitesWithGroupTargets
            EligibleGroupsAlreadyInherited = $eligibleInheritedCount
            SitesExcluded = $excludedSites.Count
            SitesAlreadyInherited = $already
        }
    }

    $Stage = 'WriteManifest'
    $json = $manifest | ConvertTo-Json -Depth 15
    $temp = "$ManifestFile.tmp"
    try {
        [IO.File]::WriteAllText($temp, $json, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temp -Destination $ManifestFile -Force
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
    $Stage = 'Complete'
    if ($selected.Count -eq 0) {
        $FinalOutput = "NO_ACTION | SitesScanned=$($sites.Count) SitesTargeted=0 GroupsToRevert=0 ExcludedSites=$($excludedSites.Count) File=$ManifestFile"
    }
    else {
        $FinalOutput = "TRIGGER | SitesScanned=$($sites.Count) SitesTargeted=$($selected.Count) GroupsToRevert=$allGroupTargets ExcludedSites=$($excludedSites.Count) File=$ManifestFile"
    }
    Write-Log $FinalOutput
}
catch {
    $FinalOutput = "ERROR | Stage=$Stage | $(Safe-Text $_.Exception.Message)"
    Write-Log $FinalOutput
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $OpToken = $null; $ApiToken = $null; $Item = $null; $ItemText = $null
    $Headers = $null
}
if (-not $FinalOutput) { $FinalOutput = 'ERROR | Stage=Finalize | Missing final result'; Write-Log $FinalOutput }
Write-Output $FinalOutput
exit 0
