# ============================================================================
# NAME: SentinelOne Inheritance Restoration - Account-Wide Manifest Apply
# TYPE: Remediation / All eligible sites listed in the read-only manifest
# SCOPE: Windows / NinjaOne / Approved Credential Broker (Device 9800)
#
# NINJA SCRIPT VARIABLES: None
# CREDENTIALS: Ninja secure field opServiceAccountToken; 1Password vault
#              MME Automation; item SentinelOne (credential, consoleUrl).
# ACCOUNT: MME-NinjaOne Clients
# SITE EXCLUSIONS: DC and MOS as separate tokens; Dolphin Cloud; Hosted
# GROUP EXCLUSIONS: X-ray/Xray and TerminalServer/TermServ variants
#
# INPUT:  C:\MME\CS\S1_Inheritance_Restoration_Manifest.json
# LOG:    C:\MME\AutoLogs\S1_Inheritance_Apply_Global.log
# OUTPUT: RESULT | NO_ACTION | ERROR (exit code always 0)
#
# Processes EVERY site listed by Script A in the supplied manifest, including
# sites with no GroupTargets (site policy only). Only listed GroupTargets can
# be reverted. No site discovery is used to expand the manifest's target set.
# Revalidates account/site/group IDs and names before any policy changes;
# all listed sites/groups pass preflight before the first policy write.
# Checks site detail inheritance when the site list omits it; skips site PUT if TRUE.
# Reverts each site only when not TRUE, then its listed group policies.
# This discards policy overrides; no rollback. Review manifest before running.
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

function Get-ProtectedSiteRule {
    param([string]$Name)
    # DC and MOS are separate tokens to avoid matching names like Mosafari.
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
$LogFile = Join-Path $LogFolder 'S1_Inheritance_Apply_Global.log'
$SitesChanged = 0
$GroupsChanged = 0
$SitesAlready = 0
$GroupsAlready = 0

try {
    New-Item -ItemType Directory -Force -Path $LogFolder | Out-Null
    Write-Log 'START | S1 Inheritance Remediation Global | Source=Manifest'

    $Stage = 'ValidateManifest'
    if (-not (Test-Path -LiteralPath $ManifestFile -PathType Leaf)) {
        throw "Manifest file not found: $ManifestFile"
    }
    $manifest = Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $manifest -or $manifest.Schema -cne $ManifestSchema) {
        throw 'Invalid or unsupported manifest schema'
    }
    if ([string]$manifest.AccountName -cne $AccountName) {
        throw 'Manifest account name did not match approved account'
    }
    if ([string]$manifest.Rules.GroupExclusionNormalizedRegex -cne $GroupRule) {
        throw 'Manifest group exclusion rules differ from current script'
    }
    if ((@($manifest.Rules.SiteExclusions) -join '|') -cne ($SiteRules -join '|')) {
        throw 'Manifest site exclusion rules differ from current script'
    }
    if ([string]::IsNullOrWhiteSpace([string]$manifest.AccountId) -or
        [string]::IsNullOrWhiteSpace([string]$manifest.ConsoleHost)) {
        throw 'Manifest account or console identity was missing'
    }
    $entries = @($manifest.Sites | Where-Object { $null -ne $_ })
    if ($entries.Count -eq 0) {
        $FinalOutput = 'NO_ACTION | Manifest has no targeted sites'
        Write-Log $FinalOutput
    }
    else {
        $seen = @{}
        foreach ($entry in $entries) {
            $id = [string]$entry.SiteId
            if (-not $id -or -not ([string]$entry.SiteName)) { throw 'Manifest site entry missing id/name' }
            if ($seen.ContainsKey($id)) { throw "Duplicate SiteId=$id in manifest" }
            $seen[$id] = $true
            if ([string]$entry.AccountId -ne [string]$manifest.AccountId) {
                throw "Manifest SiteId=$id lists an unexpected parent account"
            }
            if (Get-ProtectedSiteRule -Name ([string]$entry.SiteName)) {
                throw "Manifest targets protected SiteId=$id"
            }
            $seenGroups = @{}
            foreach ($tg in @($entry.GroupTargets)) {
                if ($null -eq $tg -or -not ([string]$tg.GroupId) -or -not ([string]$tg.GroupName)) {
                    throw "Manifest Group target was missing id/name in SiteId=$id"
                }
                $gid = [string]$tg.GroupId
                if ($seenGroups.ContainsKey($gid)) { throw "Duplicate GroupId=$gid in manifest SiteId=$id" }
                $seenGroups[$gid] = $true
                if (Test-ProtectedGroupName -Name ([string]$tg.GroupName)) {
                    throw "Manifest targets a protected group GroupId=$gid"
                }
            }
        }

        # Script A's manifest is authoritative for global targets. A site with
        # zero GroupTargets remains listed for site-level reversion only.
        # This is the ONLY site list used by preflight and remediation below.
        $Stage = 'SelectManifestTargets'
        $globalEntries = @($entries)
        $groupTargetsInManifest = 0
        foreach ($selectedSite in $globalEntries) {
            $groupTargetsInManifest += @($selectedSite.GroupTargets).Count
        }
        Write-Log "GLOBAL_PLAN | ManifestSites=$($entries.Count) TargetSites=$($globalEntries.Count) GroupsToEvaluate=$groupTargetsInManifest"
        foreach ($selectedSite in $globalEntries) {
            Write-Log "GLOBAL_TARGET | Site=$($selectedSite.SiteName) SiteId=$($selectedSite.SiteId) GroupsToEvaluate=$(@($selectedSite.GroupTargets).Count)"
        }

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

        if ($AccountId -ne [string]$manifest.AccountId) {
            throw 'Manifest account ID does not match the live approved Account'
        }
        if ($baseUri.Host -cne [string]$manifest.ConsoleHost) {
            throw 'Manifest console host does not match the live SentinelOne console'
        }

        $Stage = 'PreflightSites'
        $siteList = @(Get-S1Paged -Path "/web/api/v2.1/sites?accountIds=$([uri]::EscapeDataString($AccountId))&limit=1000" -Kind sites)
        $liveSites = @{}
        foreach ($site in $siteList) {
            $id = [string]$site.id
            if (-not $id -or [string]$site.accountId -ne $AccountId) {
                throw "Invalid/out-of-account site encountered in site inventory"
            }
            if ($liveSites.ContainsKey($id)) { throw "Duplicate live site ID: $id" }
            $liveSites[$id] = $site
        }

        $plans = @()
        foreach ($entry in $globalEntries) {
            $siteId = [string]$entry.SiteId
            $siteName = [string]$entry.SiteName
            if (-not $liveSites.ContainsKey($siteId)) { throw "Manifest SiteId=$siteId no longer exists in approved account" }
            $live = $liveSites[$siteId]
            if ([string]$live.name -cne $siteName) { throw "Site renamed since manifest: SiteId=$siteId" }
            if (Get-ProtectedSiteRule -Name ([string]$live.name)) { throw "Site now protected: SiteId=$siteId" }

            $Stage = "PreflightGroups:$siteId"
            $liveGroups = @(Get-S1Paged -Path "/web/api/v2.1/groups?siteIds=$([uri]::EscapeDataString($siteId))&limit=200" -Kind groups)
            $byId = @{}
            foreach ($group in $liveGroups) {
                $gid = [string]$group.id
                if (-not $gid -or -not ([string]$group.name)) { throw "Live group missing id/name, SiteId=$siteId" }
                if ([string]$group.siteId -ne $siteId) { throw "Out-of-site GroupId=$gid" }
                if ($byId.ContainsKey($gid)) { throw "Duplicate GroupId=$gid in live SiteId=$siteId" }
                $byId[$gid] = $group
                if (Test-ProtectedGroupName -Name ([string]$group.name)) {
                    Write-Log "EXCLUDED | Site=$siteName Group=$($group.name) GroupId=$gid"
                }
            }
            $planGroups = @()
            foreach ($tg in @($entry.GroupTargets)) {
                $gid = [string]$tg.GroupId
                $name = [string]$tg.GroupName
                if (-not $byId.ContainsKey($gid)) { throw "Manifest GroupId=$gid no longer exists under SiteId=$siteId" }
                $liveGroup = $byId[$gid]
                if ([string]$liveGroup.name -cne $name) { throw "Group renamed since manifest: GroupId=$gid" }
                if (Test-ProtectedGroupName -Name ([string]$liveGroup.name)) { throw "Protected GroupId=$gid unexpectedly included" }
                $planGroups += $liveGroup
            }
            $plans += [pscustomobject]@{ Site = $live; Groups = @($planGroups) }
            Write-Log "PREFLIGHT_OK | Site=$siteName SiteId=$siteId GroupsToEvaluate=$($planGroups.Count)"
        }

        # All manifest-targeted sites/groups are preflighted before any write.
        if ($plans.Count -ne $globalEntries.Count) { throw 'Global preflight scope did not match manifest target count' }
        foreach ($plan in $plans) {
            $site = $plan.Site
            $siteId = [string]$site.id
            $siteName = [string]$site.name
            $Stage = "RevertSite:$siteId"
            $siteInherits = Get-Inherits -Record $site
            if ($null -eq $siteInherits) {
                # The site-list response can omit inherits; query the site detail before a PUT.
                $Stage = "GetSiteInheritance:$siteId"
                $detailResponse = Invoke-S1 -Method GET -Path "/web/api/v2.1/sites/$([uri]::EscapeDataString($siteId))"
                if ($null -eq $detailResponse -or $null -eq $detailResponse.data) {
                    throw "Site detail response missing data for SiteId=$siteId"
                }
                $detailSite = $detailResponse.data
                if ([string]$detailSite.id -ne $siteId -or [string]$detailSite.accountId -ne $AccountId) {
                    throw "Site detail identity/account mismatch for SiteId=$siteId"
                }
                $siteInherits = Get-Inherits -Record $detailSite
                $detailStatus = if ($null -eq $siteInherits) { 'UNKNOWN' } elseif ($siteInherits) { 'TRUE' } else { 'FALSE' }
                Write-Log "SITE_INHERITANCE_DETAIL | Site=$siteName SiteId=$siteId Inheritance=$detailStatus"
            }
            if ($siteInherits -eq $true) {
                $SitesAlready++
                Write-Log "NO_ACTION | Site already inherits Account; Site=$siteName SiteId=$siteId"
            }
            else {
                $Stage = "RevertSite:$siteId"
                $body = @{ data = @{ id = $siteId } }
                $null = Invoke-S1 -Method PUT -Path "/web/api/v2.1/sites/$siteId/revert-policy" -Body $body
                $SitesChanged++
                Write-Log "SITE_REVERT_ACCEPTED | Site=$siteName SiteId=$siteId ParentAccountId=$AccountId"
                $Stage = "VerifySite:$siteId"
                Confirm-AfterRevert -Kind Site -Id $siteId
            }

            # Use the proven paginated group-list endpoint for live state.
            $Stage = "RefreshGroups:$siteId"
            $currentGroups = @(Get-S1Paged -Path "/web/api/v2.1/groups?siteIds=$([uri]::EscapeDataString($siteId))&limit=200" -Kind groups)
            $refreshedById = @{}
            foreach ($row in $currentGroups) {
                $rowId = [string]$row.id
                if (-not $rowId -or [string]$row.siteId -ne $siteId) { throw "Unexpected group in refresh for SiteId=$siteId" }
                if ($refreshedById.ContainsKey($rowId)) { throw "Duplicate group in refresh: GroupId=$rowId" }
                $refreshedById[$rowId] = $row
            }
            foreach ($group in ($plan.Groups | Sort-Object name)) {
                $gid = [string]$group.id
                $name = [string]$group.name
                $Stage = "RevertGroup:$gid"
                if (-not $refreshedById.ContainsKey($gid)) { throw "Group vanished after preflight: GroupId=$gid" }
                $freshGroup = $refreshedById[$gid]
                if ([string]$freshGroup.name -cne $name -or [string]$freshGroup.siteId -ne $siteId) {
                    throw "Group identity changed after preflight: GroupId=$gid"
                }
                if (Test-ProtectedGroupName -Name ([string]$freshGroup.name)) {
                    throw "Group protected after preflight: GroupId=$gid"
                }
                if ((Get-Inherits -Record $freshGroup) -eq $true) {
                    $GroupsAlready++
                    Write-Log "NO_ACTION | Group already inherits Site; Group=$name GroupId=$gid"
                    continue
                }
                $body = @{ data = @{ id = $gid } }
                $null = Invoke-S1 -Method PUT -Path "/web/api/v2.1/groups/$gid/revert-policy" -Body $body
                $GroupsChanged++
                Write-Log "GROUP_REVERT_ACCEPTED | Group=$name GroupId=$gid ParentSiteId=$siteId"
                $Stage = "VerifyGroup:$gid"
                Confirm-AfterRevert -Kind Group -Id $gid
            }
        }
        $Stage = 'Complete'
        if ($SitesChanged -eq 0 -and $GroupsChanged -eq 0) {
            $FinalOutput = "NO_ACTION | ManifestSites=$($entries.Count) SitesPlanned=$($plans.Count) SitesAlready=$SitesAlready GroupsAlready=$GroupsAlready"
        }
        else {
            $FinalOutput = "RESULT | ManifestSites=$($entries.Count) SitesPlanned=$($plans.Count) SitesReverted=$SitesChanged GroupsReverted=$GroupsChanged SitesAlready=$SitesAlready GroupsAlready=$GroupsAlready"
        }
        Write-Log $FinalOutput
    }
}
catch {
    $FinalOutput = "ERROR | Stage=$Stage | $(Safe-Text $_.Exception.Message) | SitesReverted=$SitesChanged GroupsReverted=$GroupsChanged"
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
