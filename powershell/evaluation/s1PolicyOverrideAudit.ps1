# ============================================================================
# NAME: SentinelOne Protected Group Policy + Config Override Global Audit
# TYPE: Evaluation / Read-Only / Independent Global Account Audit
# SCOPE: Windows / NinjaOne / Approved Credential Broker (Device 9800)
#
# NINJA SCRIPT VARIABLES: None
# CREDENTIALS: Ninja secure field opServiceAccountToken; 1Password vault
#              MME Automation; item SentinelOne (credential, consoleUrl).
# ACCOUNT: MME-NinjaOne Clients (all eligible sites in this account)
# INPUT:   Live SentinelOne APIs only. No inheritance manifest dependency.
# OUTPUT:  C:\MME\CS\S1_Protected_Group_Policy_Override_Audit_Global.json
# LOG:     C:\MME\AutoLogs\S1_Protected_Group_Policy_Override_Audit_Global.log
# NINJA:   TRIGGER | NO_ACTION | ERROR (always exit 0)
#
# READ-ONLY: Every SentinelOne request uses GET.
# Enumerates the entire account, excludes the SAME site patterns as the
# inheritance audit BEFORE retrieving groups, and records sites without any
# matching groups. Audits group policy and configuration override responses
# for EVERY eligible XRay and Terminal Server group (no sampling).
# Returns ERROR if any group read fails; preserves other results for review.
# Does not create, update, revert or otherwise modify policy or overrides.
#
# CAUTION: JSON contains complete policy and configuration data. Review and
# sanitize before publishing to Git or any shared system.
# ============================================================================

[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$AccountName = 'MME-NinjaOne Clients'
$GroupRule  = 'xray|terminalserv|terminalservers|termserv|termsrv|terminalsrv|terminalsvr|termsvr'
$SiteRules  = @('DC (separate token)', 'Dolphin Cloud', 'Hosted', 'MOS (separate token)')
$Vault       = 'MME Automation'
$OpField     = 'opServiceAccountToken'
$ItemName    = 'SentinelOne'
$LogFolder   = 'C:\MME\AutoLogs'
$OutputFile  = 'C:\MME\CS\S1_Protected_Group_Policy_Override_Audit_Global.json'
$LogFile     = 'C:\MME\AutoLogs\S1_Protected_Group_Policy_Override_Audit_Global.log'

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
    $seenCursors = @{}
    do {
        $uri = $Path
        if ($cursor) { $uri += '&cursor=' + [uri]::EscapeDataString($cursor) }
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
            if ($seenCursors.ContainsKey($cursor)) {
                throw "SentinelOne $Kind pagination repeated a cursor"
            }
            $seenCursors[$cursor] = $true
        }
    } while ($cursor)
    return $items
}

function Get-GroupKind {
    param([string]$Name)
    # Reuse the same name matching rules from the earlier inheritance project.
    $normalized = ($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    if ($normalized -match 'xray') { return 'XRay' }
    if ($normalized -match 'terminalserv|termserv|termsrv|terminalsrv|terminalsvr|termsvr') {
        return 'TerminalServer'
    }
    return $null
}

function Get-ProtectedSiteRule {
    param([string]$Name)
    # Exact site exclusion logic from S1_Inheritance_Manifest_Eval.ps1.
    # DC and MOS are separate tokens to avoid matching customer names.
    if ($Name -match '(?i)(^|[^a-z0-9])DC($|[^a-z0-9])') { return 'DC' }
    if ($Name -match '(?i)(^|[^a-z0-9])MOS($|[^a-z0-9])') { return 'MOS' }
    $compact = ($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    if ($compact -match 'dolphincloud') { return 'Dolphin Cloud' }
    if ($compact -match 'hosted') { return 'Hosted' }
    return $null
}

function Confirm-LiveGroup {
    param([object]$Selection, [string]$AccountId)
    $siteResponse = Invoke-S1 -Path "/web/api/v2.1/sites/$($Selection.SiteId)"
    if ($null -eq $siteResponse -or $null -eq $siteResponse.data) {
        throw "Site detail missing data: SiteId=$($Selection.SiteId)"
    }
    $site = $siteResponse.data
    if ([string]$site.id -ne $Selection.SiteId -or
        [string]$site.accountId -ne $AccountId -or
        [string]$site.name -cne $Selection.SiteName) {
        throw "Live Site identity mismatch: SiteId=$($Selection.SiteId)"
    }
    $groupResponse = Invoke-S1 -Path "/web/api/v2.1/groups/$($Selection.GroupId)"
    if ($null -eq $groupResponse -or $null -eq $groupResponse.data) {
        throw "Group detail missing data: GroupId=$($Selection.GroupId)"
    }
    $group = $groupResponse.data
    if ([string]$group.id -ne $Selection.GroupId -or
        [string]$group.siteId -ne $Selection.SiteId -or
        [string]$group.name -cne $Selection.GroupName) {
        throw "Live Group identity mismatch: GroupId=$($Selection.GroupId)"
    }
}

function Get-ConfigOverrideResponses {
    param([string]$GroupId)
    $pages = @()
    $cursor = $null
    $seenCursors = @{}
    do {
        $path = "/web/api/v2.1/config-override?groupIds=$([uri]::EscapeDataString($GroupId))&limit=1000"
        if ($cursor) { $path += '&cursor=' + [uri]::EscapeDataString($cursor) }
        $response = Invoke-S1 -Path $path
        if ($null -eq $response -or $null -eq $response.data) {
            throw "Config override response missing data for GroupId=$GroupId"
        }
        # Preserve the API response unchanged: the groupIds filter can include
        # configuration objects with broader/inherited scope.
        $pages += $response
        $cursor = $null
        if ($response.pagination -and $response.pagination.nextCursor) {
            $cursor = [string]$response.pagination.nextCursor
            if ($seenCursors.ContainsKey($cursor)) {
                throw "Config override pagination repeated a cursor for GroupId=$GroupId"
            }
            $seenCursors[$cursor] = $true
        }
    } while ($cursor)
    return $pages
}

function Write-JsonAtomic {
    param([object]$Object, [string]$Path)
    $temp = "$Path.tmp"
    try {
        $json = $Object | ConvertTo-Json -Depth 80
        [IO.File]::WriteAllText($temp, $json, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temp -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temp) {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        }
    }
}

$Stage = 'Initialize'
$OpToken = $null
$ApiToken = $null
$Item = $null
$ItemText = $null
$FinalOutput = $null
$BaseUrl = $null
$Headers = $null

try {
    New-Item -ItemType Directory -Force -Path $LogFolder | Out-Null
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputFile) | Out-Null
    Write-Log 'START | SentinelOne Protected Group Policy Override Global Audit | READ_ONLY | Scope=AllEligibleGroups | Inventory=AllAccountSites'
    if (Test-Path -LiteralPath $OutputFile) { Remove-Item -LiteralPath $OutputFile -Force }

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
    $matched = @($accounts | Where-Object { ([string]$_.name) -eq $AccountName })
    if ($matched.Count -ne 1) {
        throw "Required account '$AccountName' matched $($matched.Count) accounts; expected 1"
    }
    $AccountId = [string]$matched[0].id
    if ($AccountId -notmatch '^\d+$') { throw 'Matched Account was missing a valid ID' }
    Write-Log "ACCOUNT_FOUND | Name=$AccountName AccountId=$AccountId"

    $Stage = 'EnumerateSites'
    $sites = @(Get-S1Paged -Path "/web/api/v2.1/sites?accountIds=$([uri]::EscapeDataString($AccountId))&limit=1000" -Kind sites)
    if ($sites.Count -eq 0) { throw "No sites returned for AccountId=$AccountId" }
    $allSites = @()
    $excludedSites = @()
    $allMatches = @()
    $seenSiteIds = @{}
    $seenGroupIds = @{}
    $siteNone = 0
    $siteXRayOnly = 0
    $siteTerminalOnly = 0
    $siteBoth = 0
    $totalXRay = 0
    $totalTerminal = 0

    foreach ($site in ($sites | Sort-Object name, id)) {
        $siteId = [string]$site.id
        $siteName = [string]$site.name
        if ($siteId -notmatch '^\d+$' -or [string]::IsNullOrWhiteSpace($siteName)) {
            throw 'Site inventory contained invalid id or name'
        }
        if ([string]$site.accountId -ne $AccountId) {
            throw "Out-of-account Site returned by API: SiteId=$siteId"
        }
        if ($seenSiteIds.ContainsKey($siteId)) { throw "Duplicate SiteId=$siteId in API inventory" }
        $seenSiteIds[$siteId] = $true

        $siteExclusion = Get-ProtectedSiteRule -Name $siteName
        if ($siteExclusion) {
            $excludedSites += [ordered]@{
                SiteId = $siteId
                SiteName = $siteName
                Rule = $siteExclusion
            }
            Write-Log "SITE_EXCLUDED | Site=$siteName SiteId=$siteId Rule=$siteExclusion"
            continue
        }

        $Stage = "EnumerateGroups:$siteId"
        $groups = @(Get-S1Paged -Path "/web/api/v2.1/groups?siteIds=$([uri]::EscapeDataString($siteId))&limit=200" -Kind groups)
        $matchingGroups = @()
        $siteXRay = 0
        $siteTerminal = 0
        foreach ($group in ($groups | Sort-Object name, id)) {
            $groupId = [string]$group.id
            $groupName = [string]$group.name
            if ($groupId -notmatch '^\d+$' -or [string]::IsNullOrWhiteSpace($groupName)) {
                throw "Group contained invalid id or name in SiteId=$siteId"
            }
            if ([string]$group.siteId -ne $siteId) {
                throw "Group=$groupName returned outside SiteId=$siteId"
            }
            if ($seenGroupIds.ContainsKey($groupId)) { throw "Duplicate GroupId=$groupId in account inventory" }
            $seenGroupIds[$groupId] = $true

            $kind = Get-GroupKind -Name $groupName
            if (-not $kind) { continue }
            $match = [ordered]@{
                Kind = $kind
                SiteId = $siteId
                SiteName = $siteName
                GroupId = $groupId
                GroupName = $groupName
            }
            $matchingGroups += $match
            $allMatches += $match
            if ($kind -eq 'XRay') { $siteXRay++; $totalXRay++ }
            if ($kind -eq 'TerminalServer') { $siteTerminal++; $totalTerminal++ }
            Write-Log "GROUP_MATCH | Kind=$kind Site=$siteName SiteId=$siteId Group=$groupName GroupId=$groupId"
        }

        $status = if ($siteXRay -gt 0 -and $siteTerminal -gt 0) { 'Both' }
                  elseif ($siteXRay -gt 0) { 'XRayOnly' }
                  elseif ($siteTerminal -gt 0) { 'TerminalServerOnly' }
                  else { 'None' }
        switch ($status) {
            'Both' { $siteBoth++ }
            'XRayOnly' { $siteXRayOnly++ }
            'TerminalServerOnly' { $siteTerminalOnly++ }
            'None' { $siteNone++ }
        }

        $allSites += [ordered]@{
            SiteId = $siteId
            SiteName = $siteName
            GroupStatus = $status
            GroupsScanned = $groups.Count
            XRayGroups = $siteXRay
            TerminalServerGroups = $siteTerminal
            MatchingGroups = @($matchingGroups)
        }
        if ($status -eq 'None') {
            Write-Log "SITE_NO_MATCH | Site=$siteName SiteId=$siteId GroupsScanned=$($groups.Count) Status=None"
        }
        else {
            Write-Log "SITE_MATCH | Site=$siteName SiteId=$siteId Status=$status XRay=$siteXRay TerminalServer=$siteTerminal"
        }
    }
    Write-Log "INVENTORY_COMPLETE | SitesScanned=$($sites.Count) SitesEligible=$($allSites.Count) SitesExcluded=$($excludedSites.Count) SitesWithoutGroups=$siteNone SitesXRayOnly=$siteXRayOnly SitesTerminalServerOnly=$siteTerminalOnly SitesBoth=$siteBoth XRayGroups=$totalXRay TerminalServerGroups=$totalTerminal"

    $Stage = 'AuditAllProtectedGroups'
    $records = @()
    $groupsWithErrors = 0
    $policiesRead = 0
    $overridesRead = 0
    $groupsWithDirectOverride = 0
    $groupsWithoutDirectOverride = 0
    $groupsWithOtherScopeOnly = 0
    $xrayWithoutDirectOverride = 0
    $terminalWithoutDirectOverride = 0

    foreach ($selection in $allMatches) {
        $groupId = [string]$selection.GroupId
        $policyData = $null
        $policyStatus = 'NOT_CHECKED'
        $overrideStatus = 'NOT_CHECKED'
        $overrideReadStatus = 'NOT_CHECKED'
        $pages = @()
        $returnedCount = $null
        $directCount = $null
        $otherCount = $null
        $errors = @()
        $verified = $false

        # Keep the live site/group identity checks from the successful pilot.
        # An identity failure prevents reads against an uncertain target.
        try {
            $Stage = "VerifyGroup:$groupId"
            Confirm-LiveGroup -Selection $selection -AccountId $AccountId
            $verified = $true
            Write-Log "GROUP_VERIFIED | Kind=$($selection.Kind) Site=$($selection.SiteName) Group=$($selection.GroupName) GroupId=$groupId"
        }
        catch {
            $message = Safe-Text $_.Exception.Message
            $errors += "VerifyGroup: $message"
            Write-Log "GROUP_AUDIT_ERROR | Stage=VerifyGroup Kind=$($selection.Kind) Site=$($selection.SiteName) Group=$($selection.GroupName) GroupId=$groupId Detail=$message"
        }

        if ($verified) {
            try {
                $Stage = "GroupPolicy:$groupId"
                $policyResponse = Invoke-S1 -Path "/web/api/v2.1/groups/$groupId/policy"
                if ($null -eq $policyResponse -or $null -eq $policyResponse.data) {
                    throw "Group policy response missing data for GroupId=$groupId"
                }
                $policyData = $policyResponse.data
                $policyStatus = 'READ'
                $policiesRead++
                Write-Log "POLICY_READ | Kind=$($selection.Kind) GroupId=$groupId"
            }
            catch {
                $policyStatus = 'ERROR'
                $message = Safe-Text $_.Exception.Message
                $errors += "GroupPolicy: $message"
                Write-Log "GROUP_AUDIT_ERROR | Stage=GroupPolicy Kind=$($selection.Kind) GroupId=$groupId Detail=$message"
            }

            try {
                $Stage = "ConfigOverride:$groupId"
                $pages = @(Get-ConfigOverrideResponses -GroupId $groupId)
                $returned = @()
                foreach ($page in $pages) {
                    foreach ($entry in @($page.data)) {
                        if ($null -ne $entry) { $returned += $entry }
                    }
                }
                $direct = @($returned | Where-Object {
                    ([string]$_.scope -eq 'group') -and
                    ($null -ne $_.group) -and
                    ([string]$_.group.id -eq $groupId)
                })
                $returnedCount = $returned.Count
                $directCount = $direct.Count
                $otherCount = $returnedCount - $directCount
                $overrideReadStatus = 'READ'
                $overridesRead++

                if ($directCount -gt 0) {
                    $overrideStatus = 'GROUP_OVERRIDE_PRESENT'
                    $groupsWithDirectOverride++
                }
                elseif ($returnedCount -gt 0) {
                    # An inherited/other-scope response is not a direct group override.
                    $overrideStatus = 'OTHER_SCOPE_ONLY'
                    $groupsWithoutDirectOverride++
                    $groupsWithOtherScopeOnly++
                }
                else {
                    $overrideStatus = 'NO_GROUP_OVERRIDE'
                    $groupsWithoutDirectOverride++
                }
                if ($directCount -eq 0) {
                    if ($selection.Kind -eq 'XRay') { $xrayWithoutDirectOverride++ }
                    elseif ($selection.Kind -eq 'TerminalServer') { $terminalWithoutDirectOverride++ }
                }
                Write-Log "CONFIG_OVERRIDE_READ | Kind=$($selection.Kind) GroupId=$groupId Pages=$($pages.Count) Returned=$returnedCount GroupScoped=$directCount OtherScope=$otherCount Status=$overrideStatus"
            }
            catch {
                $overrideReadStatus = 'ERROR'
                $overrideStatus = 'ERROR'
                $pages = @()
                $returnedCount = $null
                $directCount = $null
                $otherCount = $null
                $message = Safe-Text $_.Exception.Message
                $errors += "ConfigOverride: $message"
                Write-Log "GROUP_AUDIT_ERROR | Stage=ConfigOverride Kind=$($selection.Kind) GroupId=$groupId Detail=$message"
            }
        }

        if ($errors.Count -gt 0) { $groupsWithErrors++ }
        $records += [ordered]@{
            Kind = $selection.Kind
            SiteId = $selection.SiteId
            SiteName = $selection.SiteName
            GroupId = $groupId
            GroupName = $selection.GroupName
            LiveIdentityVerified = $verified
            PolicyReadStatus = $policyStatus
            PolicyData = $policyData
            OverrideReadStatus = $overrideReadStatus
            OverrideStatus = $overrideStatus
            GroupScopedOverrides = $directCount
            OtherScopeOverrides = $otherCount
            TotalOverridesReturned = $returnedCount
            ReturnedForGroupFilter = $true
            ConfigOverrideResponses = @($pages)
            Errors = @($errors)
        }
    }

    $artifact = [ordered]@{
        Schema = 'MME.S1.ProtectedGroupPolicyOverrideAudit.Global.v1'
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        ReadOnly = $true
        Source = 'LiveSentinelOneAPI'
        AccountName = $AccountName
        AccountId = $AccountId
        ConsoleHost = $baseUri.Host
        Rules = [ordered]@{
            GroupNameNormalizedRegex = $GroupRule
            SiteExclusionRules = @($SiteRules)
            Scope = 'AllEligibleGroupsInAccount'
        }
        Summary = [ordered]@{
            SitesScanned = $sites.Count
            SitesEligible = $allSites.Count
            SitesExcluded = $excludedSites.Count
            SitesWithoutGroups = $siteNone
            SitesXRayOnly = $siteXRayOnly
            SitesTerminalServerOnly = $siteTerminalOnly
            SitesBoth = $siteBoth
            XRayGroupsFound = $totalXRay
            TerminalServerGroupsFound = $totalTerminal
            GroupsAudited = $records.Count
            PoliciesRead = $policiesRead
            ConfigOverridesRead = $overridesRead
            GroupOverridesPresent = $groupsWithDirectOverride
            GroupsWithoutDirectOverride = $groupsWithoutDirectOverride
            GroupsWithOtherScopeOnly = $groupsWithOtherScopeOnly
            XRayWithoutDirectOverride = $xrayWithoutDirectOverride
            TerminalServerWithoutDirectOverride = $terminalWithoutDirectOverride
            GroupsWithErrors = $groupsWithErrors
        }
        Sites = @($allSites)
        ExcludedSites = @($excludedSites)
        GroupAudits = @($records)
    }
    $Stage = 'WriteOutput'
    Write-JsonAtomic -Object $artifact -Path $OutputFile
    if ($groupsWithErrors -gt 0) {
        $FinalOutput = "ERROR | AuditComplete SitesScanned=$($sites.Count) SitesExcluded=$($excludedSites.Count) SitesWithoutGroups=$siteNone XRayGroups=$totalXRay TerminalServerGroups=$totalTerminal GroupsAudited=$($records.Count) GroupsWithErrors=$groupsWithErrors Mode=READ_ONLY File=$OutputFile"
    }
    else {
        $FinalOutput = "NO_ACTION | AuditComplete SitesScanned=$($sites.Count) SitesExcluded=$($excludedSites.Count) SitesWithoutGroups=$siteNone XRayGroups=$totalXRay TerminalServerGroups=$totalTerminal GroupsAudited=$($records.Count) WithGroupOverride=$groupsWithDirectOverride WithoutGroupOverride=$groupsWithoutDirectOverride TerminalServerWithoutOverride=$terminalWithoutDirectOverride Mode=READ_ONLY File=$OutputFile"
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
if (-not $FinalOutput) {
    $FinalOutput = 'ERROR | Stage=Finalize | Missing final result'
    Write-Log $FinalOutput
}
Write-Output $FinalOutput
exit 0
