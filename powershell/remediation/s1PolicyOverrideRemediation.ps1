# ============================================================================
# NAME: SentinelOne Protected Group Config Override - Global Remediation
# TYPE: Remediation / Manifest-driven / Approved protected-group families
# SCOPE: Windows / NinjaOne SYSTEM / Approved Credential Broker (Device 9800)
#
# NINJA SCRIPT VARIABLES: None
# CREDENTIALS: Ninja secure field opServiceAccountToken; 1Password vault
#              MME Automation; item SentinelOne (credential, consoleUrl).
# ACCOUNT: MME-NinjaOne Clients
# TARGET: Eligible XRay and TerminalServer groups from approved global audit.
#         Excludes DC, Dolphin Cloud, Hosted, MOS per approved audit rules.
# INPUT:  C:\MME\CS\S1_Protected_Group_Policy_Override_Audit_Global.json
# LOG:    C:\MME\AutoLogs\S1_Protected_Group_Override_Apply_Global.log
# NINJA: RESULT | NO_ACTION | ERROR (always exit 0)
#
# Source TerminalServer: About Faces and Braces / TerminalServers
#                        override MME-Termserver-Standards
# Source XRay:          XYZTestCompany / Test-XRay
#                        override MME-XRay-Standards
#
# PRECONDITION: Generate a current, successful global read-only audit at
# INPUT above. The manifest must contain the approved source overrides.
# TARGET SELECTION: Eligible group identities and counts come exclusively
# from the audit manifest; approved source group names are defined above.
# SAFETY: Validate manifest integrity, account/site/group identities, and
# both approved source configurations. Preflight every target before writes.
# Create missing group-scoped overrides only; verify each creation by GET.
# Existing matching overrides are preserved. Conflicting overrides fail
# closed. No policy-inheritance changes, account/site policy changes, or
# writes to excluded sites. Uses POST(create) only, no PUT/PATCH/DELETE.
# Failed runs can leave verified overrides in place; subsequent runs check
# existing configurations before attempting additional creation.
# ============================================================================

[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$AccountName    = 'MME-NinjaOne Clients'
$Vault          = 'MME Automation'
$OpField        = 'opServiceAccountToken'
$ItemName       = 'SentinelOne'
$ManifestFile   = 'C:\MME\CS\S1_Protected_Group_Policy_Override_Audit_Global.json'
$ManifestSchema = 'MME.S1.ProtectedGroupPolicyOverrideAudit.Global.v1'
$LogFile        = 'C:\MME\AutoLogs\S1_Protected_Group_Override_Apply_Global.log'
$GroupRule      = 'xray|terminalserv|terminalservers|termserv|termsrv|terminalsrv|terminalsvr|termsvr'
$SiteRules      = @('DC (separate token)', 'Dolphin Cloud', 'Hosted', 'MOS (separate token)')

$SourceDefinitions = @(
    [pscustomobject]@{
        Kind = 'TerminalServer'
        SiteName = 'About Faces and Braces (LehmanGrimes, Shawn)'
        GroupName = 'TerminalServers'
        OverrideName = 'MME-Termserver-Standards'
    },
    [pscustomobject]@{
        Kind = 'XRay'
        SiteName = 'XYZTestCompany'
        GroupName = 'Test-XRay'
        OverrideName = 'MME-XRay-Standards'
    }
)

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
        [ValidateSet('GET','POST')][string]$Method,
        [string]$Path,
        [AllowNull()][object]$Body = $null
    )
    try {
        $args = @{
            Method       = $Method
            Uri          = "$script:BaseUrl$Path"
            Headers      = $script:Headers
            ContentType  = 'application/json'
            ErrorAction  = 'Stop'
            UseBasicParsing = $true
        }
        if ($Method -eq 'POST') {
            if ($null -eq $Body) { throw 'POST request requires body' }
            $args.Body = $Body | ConvertTo-Json -Depth 80 -Compress
        }
        return Invoke-RestMethod @args
    }
    catch { throw (Get-HttpErrorDetail -Exception $_.Exception) }
}

function Get-S1Paged {
    param([string]$Path, [ValidateSet('accounts')][string]$Kind)
    $items = @()
    $cursor = $null
    $seenCursors = @{}
    do {
        $uri = $Path
        if ($cursor) { $uri += '&cursor=' + [uri]::EscapeDataString($cursor) }
        $resp = Invoke-S1 -Method GET -Path $uri
        if ($null -eq $resp -or $null -eq $resp.data) {
            throw "SentinelOne $Kind response did not contain data"
        }
        $items += @($resp.data | Where-Object { $null -ne $_ })
        $cursor = $null
        if ($resp.pagination -and $resp.pagination.nextCursor) {
            $cursor = [string]$resp.pagination.nextCursor
            if ($seenCursors.ContainsKey($cursor)) { throw 'Account pagination repeated a cursor' }
            $seenCursors[$cursor] = $true
        }
    } while ($cursor)
    return $items
}

function Get-GroupKind {
    param([string]$Name)
    $normalized = ($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    if ($normalized -match 'xray') { return 'XRay' }
    if ($normalized -match 'terminalserv|termserv|termsrv|terminalsrv|terminalsvr|termsvr') {
        return 'TerminalServer'
    }
    return $null
}

function Get-ProtectedSiteRule {
    param([string]$Name)
    if ($Name -match '(?i)(^|[^a-z0-9])DC($|[^a-z0-9])') { return 'DC' }
    if ($Name -match '(?i)(^|[^a-z0-9])MOS($|[^a-z0-9])') { return 'MOS' }
    $compact = ($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    if ($compact -match 'dolphincloud') { return 'Dolphin Cloud' }
    if ($compact -match 'hosted') { return 'Hosted' }
    return $null
}

function Confirm-LiveGroup {
    param([object]$Selection, [string]$AccountId)
    $siteResponse = Invoke-S1 -Method GET -Path "/web/api/v2.1/sites/$($Selection.SiteId)"
    if ($null -eq $siteResponse -or $null -eq $siteResponse.data) {
        throw "Site detail missing data: SiteId=$($Selection.SiteId)"
    }
    $site = $siteResponse.data
    if ([string]$site.id -cne [string]$Selection.SiteId -or
        [string]$site.accountId -cne $AccountId -or
        [string]$site.name -cne [string]$Selection.SiteName) {
        throw "Live site identity mismatch: SiteId=$($Selection.SiteId)"
    }
    $groupResponse = Invoke-S1 -Method GET -Path "/web/api/v2.1/groups/$($Selection.GroupId)"
    if ($null -eq $groupResponse -or $null -eq $groupResponse.data) {
        throw "Group detail missing data: GroupId=$($Selection.GroupId)"
    }
    $group = $groupResponse.data
    if ([string]$group.id -cne [string]$Selection.GroupId -or
        [string]$group.siteId -cne [string]$Selection.SiteId -or
        [string]$group.name -cne [string]$Selection.GroupName) {
        throw "Live group identity mismatch: GroupId=$($Selection.GroupId)"
    }
}

function Get-GroupOverrides {
    param([string]$GroupId)
    $items = @()
    $cursor = $null
    $seenCursors = @{}
    do {
        $path = "/web/api/v2.1/config-override?groupIds=$([uri]::EscapeDataString($GroupId))&limit=1000"
        if ($cursor) { $path += '&cursor=' + [uri]::EscapeDataString($cursor) }
        $response = Invoke-S1 -Method GET -Path $path
        if ($null -eq $response -or $null -eq $response.data) {
            throw "Override response missing data for GroupId=$GroupId"
        }
        $items += @($response.data | Where-Object { $null -ne $_ })
        $cursor = $null
        if ($response.pagination -and $response.pagination.nextCursor) {
            $cursor = [string]$response.pagination.nextCursor
            if ($seenCursors.ContainsKey($cursor)) {
                throw "Override pagination repeated cursor for GroupId=$GroupId"
            }
            $seenCursors[$cursor] = $true
        }
    } while ($cursor)
    return $items
}

function Get-DirectOverrides {
    param([object[]]$Items, [string]$GroupId)
    return @($Items | Where-Object {
        ([string]$_.scope -eq 'group') -and
        ($null -ne $_.group) -and
        ([string]$_.group.id -eq $GroupId)
    })
}

function Get-ConfigJson {
    param([object]$Config)
    if ($null -eq $Config) { throw 'Config value was null' }
    return ($Config | ConvertTo-Json -Depth 80 -Compress)
}


$Stage = 'Initialize'
$OpToken = $null
$ApiToken = $null
$Item = $null
$ItemText = $null
$Headers = $null
$BaseUrl = $null
$FinalOutput = $null
$AccountId = $null
$TargetCount = 0
$TerminalPlanned = 0
$XRayPlanned = 0
$TerminalCreated = 0
$XRayCreated = 0
$TerminalAlready = 0
$XRayAlready = 0
$CurrentGroup = ''

try {
    New-Item -ItemType Directory -Path 'C:\MME\AutoLogs' -Force | Out-Null
    Write-Log 'START | SentinelOne Protected Group Config Override Global Remediation | Scope=AllEligibleGroups'

    $Stage = 'ReadManifest'
    if (-not (Test-Path -LiteralPath $ManifestFile -PathType Leaf)) {
        throw "Required global audit manifest was not found: $ManifestFile"
    }
    $manifest = Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $manifest -or [string]$manifest.Schema -cne $ManifestSchema -or
        $manifest.ReadOnly -cne $true -or [string]$manifest.Source -cne 'LiveSentinelOneAPI' -or
        [string]$manifest.AccountName -cne $AccountName -or
        [string]$manifest.Rules.Scope -cne 'AllEligibleGroupsInAccount') {
        throw 'Manifest schema/source/account/scope does not match approved global audit'
    }
    if ([string]$manifest.Rules.GroupNameNormalizedRegex -cne $GroupRule -or
        (@($manifest.Rules.SiteExclusionRules) -join '|') -cne ($SiteRules -join '|')) {
        throw 'Manifest group/site matching rules differ from approved audit'
    }
    if ([int]$manifest.Summary.GroupsWithErrors -ne 0 -or
        [int]$manifest.Summary.PoliciesRead -ne [int]$manifest.Summary.GroupsAudited -or
        [int]$manifest.Summary.ConfigOverridesRead -ne [int]$manifest.Summary.GroupsAudited -or
        [string]$manifest.AccountId -notmatch '^\d+$' -or
        [string]::IsNullOrWhiteSpace([string]$manifest.ConsoleHost)) {
        throw 'Manifest has errors/incomplete reads or invalid account identity'
    }

    $targets = @($manifest.GroupAudits | Where-Object { $null -ne $_ })
    $TargetCount = $targets.Count
    if ($TargetCount -eq 0 -or $TargetCount -ne [int]$manifest.Summary.GroupsAudited) {
        throw 'Manifest target total does not match audit summary'
    }
    $TerminalPlanned = @($targets | Where-Object { [string]$_.Kind -ceq 'TerminalServer' }).Count
    $XRayPlanned = @($targets | Where-Object { [string]$_.Kind -ceq 'XRay' }).Count
    if ($TerminalPlanned -ne [int]$manifest.Summary.TerminalServerGroupsFound -or
        $XRayPlanned -ne [int]$manifest.Summary.XRayGroupsFound -or
        ($TerminalPlanned + $XRayPlanned) -ne $TargetCount) {
        throw 'Manifest protected-group family counts do not match summary'
    }

    # Validate every group against inventory, exclusion rules, audited status,
    # and matching regex BEFORE opening any session or making any write.
    $siteIndex = @{}
    foreach ($site in @($manifest.Sites)) {
        $sid = [string]$site.SiteId
        if (-not $sid -or $siteIndex.ContainsKey($sid)) {
            throw "Manifest has missing/duplicate site ID: $sid"
        }
        $siteIndex[$sid] = $site
    }
    $seenGroups = @{}
    foreach ($target in $targets) {
        $gid = [string]$target.GroupId
        $sid = [string]$target.SiteId
        $kind = [string]$target.Kind
        if ($gid -notmatch '^\d+$' -or $sid -notmatch '^\d+$' -or
            $seenGroups.ContainsKey($gid) -or -not $siteIndex.ContainsKey($sid)) {
            throw "Invalid or duplicate manifest group/site identity: GroupId=$gid"
        }
        $seenGroups[$gid] = $true
        $site = $siteIndex[$sid]
        if ([string]$site.SiteName -cne [string]$target.SiteName -or
            (Get-ProtectedSiteRule -Name ([string]$target.SiteName)) -or
            (Get-GroupKind -Name ([string]$target.GroupName)) -cne $kind) {
            throw "Out-of-scope group/site or naming-rule mismatch: GroupId=$gid"
        }
        if ($target.LiveIdentityVerified -cne $true -or
            [string]$target.PolicyReadStatus -cne 'READ' -or
            [string]$target.OverrideReadStatus -cne 'READ' -or
            @($target.Errors).Count -ne 0) {
            throw "Group was not fully verified by the audit: GroupId=$gid"
        }
        $status = [string]$target.OverrideStatus
        if ($status -ceq 'NO_GROUP_OVERRIDE') {
            if ([int]$target.GroupScopedOverrides -ne 0 -or
                [int]$target.TotalOverridesReturned -ne 0) {
                throw "Inconsistent missing-override record: GroupId=$gid"
            }
        }
        elseif ($status -ceq 'GROUP_OVERRIDE_PRESENT') {
            if ([int]$target.GroupScopedOverrides -ne 1 -or
                [int]$target.TotalOverridesReturned -ne 1) {
                throw "Unexpected existing-override count in manifest: GroupId=$gid"
            }
        }
        else { throw "Unsupported override status in manifest: GroupId=$gid Status=$status" }
    }

    # The sources are individual, known-good group overrides; NEVER infer an
    # XRay configuration from TerminalServer (or vice versa).
    $sourceRecords = @{}
    $templates = @{}
    $templateJsons = @{}
    foreach ($def in $SourceDefinitions) {
        $kind = [string]$def.Kind
        $sources = @($targets | Where-Object {
            [string]$_.Kind -ceq $kind -and
            [string]$_.SiteName -ceq [string]$def.SiteName -and
            [string]$_.GroupName -ceq [string]$def.GroupName
        })
        if ($sources.Count -ne 1) {
            throw "Expected exactly one manifest source for $kind at $($def.SiteName)/$($def.GroupName). Rerun global audit after creating the standard."
        }
        $source = $sources[0]
        if ([string]$source.OverrideStatus -cne 'GROUP_OVERRIDE_PRESENT' -or
            [int]$source.GroupScopedOverrides -ne 1) {
            throw "Source $kind lacks a direct group override in manifest. Rerun the approved global audit after the standard is saved."
        }
        $items = @()
        foreach ($page in @($source.ConfigOverrideResponses)) {
            $items += @($page.data | Where-Object { $null -ne $_ })
        }
        $direct = @(Get-DirectOverrides -Items $items -GroupId ([string]$source.GroupId))
        if ($items.Count -ne 1 -or $direct.Count -ne 1) {
            throw "Source $kind manifest has an ambiguous or missing direct override"
        }
        $template = $direct[0]
        if ([string]$template.name -cne [string]$def.OverrideName -or
            [string]$template.scope -cne 'group' -or
            [string]$template.group.id -cne [string]$source.GroupId -or
            [string]$template.site.id -cne [string]$source.SiteId -or
            [string]$template.account.id -cne [string]$manifest.AccountId -or
            [string]::IsNullOrWhiteSpace([string]$template.osType) -or
            [string]::IsNullOrWhiteSpace([string]$template.versionOption)) {
            throw "Source $kind override does not match its approved name/scope/identity"
        }
        if ($kind -ceq 'TerminalServer' -and
            ([string]$template.osType -cne 'windows' -or
             [string]$template.versionOption -cne 'ALL')) {
            throw 'TerminalServer source must be Windows/ALL'
        }
        $sourceRecords[$kind] = $source
        $templates[$kind] = $template
        $templateJsons[$kind] = Get-ConfigJson -Config $template.config
        Write-Log "SOURCE_MANIFEST_OK | Kind=$kind Site=$($source.SiteName) Group=$($source.GroupName) GroupId=$($source.GroupId) OverrideId=$($template.id) Name=$($template.name) Os=$($template.osType) Version=$($template.versionOption)"
    }
    Write-Log "MANIFEST_OK | SitesScanned=$($manifest.Summary.SitesScanned) SitesExcluded=$($manifest.Summary.SitesExcluded) Groups=$TargetCount TerminalServer=$TerminalPlanned XRay=$XRayPlanned"

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
    if ($baseUri.Scheme -ne 'https' -or $baseUri.AbsolutePath -ne '/' -or
        $baseUri.Host -cne [string]$manifest.ConsoleHost) {
        throw 'SentinelOne consoleUrl does not match manifest console origin'
    }
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $OpToken = $null
    $Item = $null; $ItemText = $null; $who = $null
    $Headers = @{ Authorization = "ApiToken $ApiToken"; Accept = 'application/json' }
    Write-Log "AUTH_OK | Host=$($baseUri.Host)"

    $Stage = 'FindAccount'
    $accounts = @(Get-S1Paged -Path '/web/api/v2.1/accounts?limit=1000' -Kind accounts)
    $matched = @($accounts | Where-Object { ([string]$_.name) -ceq $AccountName })
    if ($matched.Count -ne 1 -or [string]$matched[0].id -cne [string]$manifest.AccountId) {
        throw 'Live account does not match manifest account ID and name'
    }
    $AccountId = [string]$matched[0].id
    Write-Log "ACCOUNT_OK | AccountId=$AccountId"

    $Stage = 'PreflightSources'
    foreach ($def in $SourceDefinitions) {
        $kind = [string]$def.Kind
        $source = $sourceRecords[$kind]
        $template = $templates[$kind]
        Confirm-LiveGroup -Selection $source -AccountId $AccountId
        $liveItems = @(Get-GroupOverrides -GroupId ([string]$source.GroupId))
        $liveDirect = @(Get-DirectOverrides -Items $liveItems -GroupId ([string]$source.GroupId))
        if ($liveItems.Count -ne 1 -or $liveDirect.Count -ne 1) {
            throw "Live $kind source no longer has exactly one direct override"
        }
        $liveSource = $liveDirect[0]
        if ([string]$liveSource.id -cne [string]$template.id -or
            [string]$liveSource.name -cne [string]$def.OverrideName -or
            [string]$liveSource.osType -cne [string]$template.osType -or
            [string]$liveSource.versionOption -cne [string]$template.versionOption -or
            [string]$liveSource.group.id -cne [string]$source.GroupId -or
            [string]$liveSource.site.id -cne [string]$source.SiteId -or
            [string]$liveSource.account.id -cne $AccountId -or
            (Get-ConfigJson -Config $liveSource.config) -cne [string]$templateJsons[$kind]) {
            throw "Live $kind source differs from audited source manifest. Rerun audit first."
        }
        Write-Log "SOURCE_LIVE_OK | Kind=$kind GroupId=$($source.GroupId) OverrideId=$($liveSource.id) Name=$($liveSource.name)"
    }

    $Stage = 'PreflightAllTargets'
    $plans = @()
    foreach ($target in $targets) {
        $CurrentGroup = [string]$target.GroupId
        $kind = [string]$target.Kind
        $template = $templates[$kind]
        $expectedConfigJson = [string]$templateJsons[$kind]
        Confirm-LiveGroup -Selection $target -AccountId $AccountId
        $existing = @(Get-GroupOverrides -GroupId $CurrentGroup)
        if ($existing.Count -eq 0) {
            if ([string]$target.OverrideStatus -cne 'NO_GROUP_OVERRIDE') {
                throw "An existing override disappeared since audit: GroupId=$CurrentGroup"
            }
            $plans += $target
            Write-Log "TARGET_PREFLIGHT_CREATE | Kind=$kind Site=$($target.SiteName) Group=$($target.GroupName) GroupId=$CurrentGroup"
        }
        else {
            $direct = @(Get-DirectOverrides -Items $existing -GroupId $CurrentGroup)
            if ($existing.Count -ne 1 -or $direct.Count -ne 1) {
                throw "Ambiguous existing live override: GroupId=$CurrentGroup Returned=$($existing.Count) Direct=$($direct.Count)"
            }
            $current = $direct[0]
            if ([string]$current.osType -cne [string]$template.osType -or
                [string]$current.versionOption -cne [string]$template.versionOption -or
                [string]$current.group.id -cne $CurrentGroup -or
                [string]$current.site.id -cne [string]$target.SiteId -or
                [string]$current.account.id -cne $AccountId -or
                (Get-ConfigJson -Config $current.config) -cne $expectedConfigJson) {
                throw "Existing $kind override differs from approved template, refusing overwrite: GroupId=$CurrentGroup"
            }
            if ($kind -ceq 'TerminalServer') { $TerminalAlready++ }
            else { $XRayAlready++ }
            Write-Log "TARGET_ALREADY | Kind=$kind Site=$($target.SiteName) Group=$($target.GroupName) GroupId=$CurrentGroup OverrideId=$($current.id) Name=$($current.name)"
        }
    }
    if (($plans.Count + $TerminalAlready + $XRayAlready) -ne $TargetCount) {
        throw 'Live target preflight totals do not equal audit target total'
    }
    $toCreateTerminal = @($plans | Where-Object { [string]$_.Kind -ceq 'TerminalServer' }).Count
    $toCreateXRay = @($plans | Where-Object { [string]$_.Kind -ceq 'XRay' }).Count
    $CurrentGroup = ''
    Write-Log "GLOBAL_PLAN | TerminalServerTotal=$TerminalPlanned TerminalServerToCreate=$toCreateTerminal TerminalServerAlready=$TerminalAlready XRayTotal=$XRayPlanned XRayToCreate=$toCreateXRay XRayAlready=$XRayAlready ExcludedSites=$($manifest.Summary.SitesExcluded)"

    $Stage = 'ApplyOverrides'
    foreach ($target in $plans) {
        $CurrentGroup = [string]$target.GroupId
        $kind = [string]$target.Kind
        $template = $templates[$kind]
        $name = if ($kind -ceq 'TerminalServer') { 'MME-Termserver-Standards' } else { 'MME-XRay-Standards' }
        $body = [ordered]@{
            data = [ordered]@{
                config        = $template.config
                description   = [string]$template.description
                osType        = [string]$template.osType
                name          = $name
                versionOption = [string]$template.versionOption
                group         = [ordered]@{ id = $CurrentGroup }
                scope         = 'group'
            }
        }
        $Stage = "POSTOverride:$CurrentGroup"
        Write-Log "OVERRIDE_CREATE_BEGIN | Kind=$kind Site=$($target.SiteName) Group=$($target.GroupName) GroupId=$CurrentGroup Name=$name"
        $null = Invoke-S1 -Method POST -Path '/web/api/v2.1/config-override' -Body $body

        $Stage = "VerifyCreatedOverride:$CurrentGroup"
        $after = @(Get-GroupOverrides -GroupId $CurrentGroup)
        $directAfter = @(Get-DirectOverrides -Items $after -GroupId $CurrentGroup)
        if ($directAfter.Count -ne 1 -or $after.Count -ne 1) {
            throw "POST completed but expected one direct group override: GroupId=$CurrentGroup Returned=$($after.Count) Direct=$($directAfter.Count)"
        }
        $created = $directAfter[0]
        if ([string]$created.name -cne $name -or
            [string]$created.osType -cne [string]$template.osType -or
            [string]$created.versionOption -cne [string]$template.versionOption -or
            [string]$created.group.id -cne $CurrentGroup -or
            [string]$created.site.id -cne [string]$target.SiteId -or
            [string]$created.account.id -cne $AccountId -or
            (Get-ConfigJson -Config $created.config) -cne [string]$templateJsons[$kind]) {
            throw "Created override does not match audited source: GroupId=$CurrentGroup"
        }
        if ($kind -ceq 'TerminalServer') { $TerminalCreated++ }
        else { $XRayCreated++ }
        Write-Log "OVERRIDE_CREATED_VERIFIED | Kind=$kind Site=$($target.SiteName) Group=$($target.GroupName) GroupId=$CurrentGroup OverrideId=$($created.id) Name=$name"
    }
    $CurrentGroup = ''
    if (($TerminalCreated + $XRayCreated) -eq 0) {
        $FinalOutput = "NO_ACTION | Scope=Global TerminalServerTotal=$TerminalPlanned TerminalServerCreated=0 TerminalServerAlready=$TerminalAlready XRayTotal=$XRayPlanned XRayCreated=0 XRayAlready=$XRayAlready ExcludedSites=$($manifest.Summary.SitesExcluded)"
    }
    else {
        $FinalOutput = "RESULT | Scope=Global TerminalServerTotal=$TerminalPlanned TerminalServerCreated=$TerminalCreated TerminalServerAlready=$TerminalAlready XRayTotal=$XRayPlanned XRayCreated=$XRayCreated XRayAlready=$XRayAlready ExcludedSites=$($manifest.Summary.SitesExcluded)"
    }
    Write-Log $FinalOutput
}
catch {
    $FinalOutput = "ERROR | Stage=$Stage Scope=Global GroupId=$CurrentGroup TerminalServerCreated=$TerminalCreated XRayCreated=$XRayCreated Detail=$(Safe-Text $_.Exception.Message)"
    Write-Log $FinalOutput
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $OpToken = $null; $ApiToken = $null; $Item = $null; $ItemText = $null
    $Headers = $null
}
if (-not $FinalOutput) {
    $FinalOutput = 'ERROR | Stage=Finalize Scope=Global | Missing final result'
    Write-Log $FinalOutput
}
Write-Output $FinalOutput
exit 0
