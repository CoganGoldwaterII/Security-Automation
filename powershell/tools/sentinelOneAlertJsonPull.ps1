
# ============================================================================
# NAME: SentinelOne Alert + Deep Visibility IR Acquisition
# AUTHORED BY: Cogan Goldwater
# TYPE: Tool / Read-Only Incident Response Acquisition
# SCOPE: Windows / Authorized Credential Broker / NinjaOne
#
# VARIABLES:
#   Required NinjaOne String/Text variables:
#     AlertURL               - Full Unified Alert URL from the configured tenant
#     sentinelOneBaseUrl     - Tenant base URL, HTTPS, e.g. https://tenant.sentinelone.net
#     onePasswordVault      - Vault containing the SentinelOne API credential item
#     bootstrapTokenField   - Name of secure NinjaOne field holding 1Password token
#   Optional investigation settings (script constants):
#     FromUtcOverride, ToUtcOverride, WindowSecondsEachSide, DvMaxEvents
#
# OUTPUT TOKENS:
#   RESULT    | Evidence acquired, including PARTIAL/WARN or LIMIT_REACHED
#   NO_ACTION | No data acquired
#   ERROR     | Acquisition or packaging failed, with stage and details
#   Exit Code: Always 0 after script execution
#
# CUSTOM FIELDS:
#   Reads: Secure NinjaOne field specified by bootstrapTokenField
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   %ProgramData%\AutomationPlaybook\Logs\S1_IR_Acquisition.log
#
# DESCRIPTION:
#   Parses and verifies a Unified Alert UUID from AlertURL, retrieves the
#   exact alert and alert history, validates its site and agent, extracts
#   analyst notes, and downloads available mitigation reports. Executes ONE
#   alert-centered Deep Visibility query with up to 1,000 collected events.
#   Records retrieved event time bounds and hashes preserved evidence files.
#   Packages output under %ProgramData%\AutomationPlaybook\Evidence.
#   Collection-limit exhaustion is informational, not an acquisition error.
#   Performs no SentinelOne, NinjaOne, or endpoint remediation actions.
#
# SECURITY:
#   Outputs can contain customer-identifying and sensitive forensic records.
#   Never publicly upload resulting evidence without approved IR sanitization.
#   Tenant, credential source, and output locations are not hardcoded to an
#   identifiable organization in this publication copy.
# ============================================================================

[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ====================== NINJAONE SCRIPT VARIABLE ==========================
# Create FOUR required String/Text variables in NinjaOne (listed in header):
#    Name: AlertURL        Calculated name: AlertURL
#    Value: https://tenant.sentinelone.net/incidents/unified-alerts?alertId=<UUID>
# Paste the normal full URL. If NinjaOne strips &, the parser removes the viewType suffix.
$AlertURL = [string]$env:AlertURL
# ===========================================================================

# Optional investigation-time adjustments IN SCRIPT. Normally leave blank/default.
$FromUtcOverride = ''  # Optional ISO UTC, e.g. 2026-09-22T23:55:00Z.
$ToUtcOverride   = ''  # Optional ISO UTC, e.g. 2026-09-23T00:05:00Z.
# Automatic DV scope is one symmetric window around the alert's detectedAt timestamp.
# One DV query is created. The collector follows only that query's event pagination
# until it has collected at most DvMaxEvents. It NEVER creates additional sliced DV
# searches to work around the event cap.
$WindowSecondsEachSide = 60
$DvMaxEvents            = 1000

$BaseUrl     = ([string]$env:sentinelOneBaseUrl).TrimEnd('/')
$Vault       = [string]$env:onePasswordVault
$ItemName    = 'SentinelOne'
$TokenField  = 'credential'
$OpField     = [string]$env:bootstrapTokenField
$OutDir      = Join-Path $env:ProgramData 'AutomationPlaybook\Evidence'
$LogDir      = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogFile     = Join-Path $LogDir 'S1_IR_Acquisition.log'
$RunStamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$RunTag      = $RunStamp  # Alert URL is validated below; manifest records the alert UUID.
$Folder      = Join-Path $OutDir "S1_IR_$RunTag"
$ZipPath     = "$Folder.zip"
$Stage       = 'Initialize'
$AlertId     = ''
$SiteId      = ''
$SiteName    = ''
$AgentUuid   = ''
$OpToken     = $null
$ApiToken    = $null
$FinalOutput = ''
$Files       = New-Object System.Collections.ArrayList
$Warnings    = New-Object System.Collections.ArrayList
$QueryId     = ''
$EventCount  = 0
$PageCount   = 0
$Agent       = $null
$Site        = $null
$Alert       = $null
$FromUtc     = ''
$ToUtc       = ''
$HistoryPages= 0
$ReportCount = 0
$DVStorylineHits = 0
$AlertCenterUtc = ''
$DvRetrievedFromUtc = ''
$DvRetrievedToUtc = ''
$DvLimitReached = $false
$HistoryNotes = New-Object System.Collections.ArrayList

function Safe-Text {
    param([AllowNull()][object]$Value, [int]$Limit = 700)
    $s = [string]$Value
    foreach ($secret in @($script:OpToken, $script:ApiToken)) {
        if (-not [string]::IsNullOrEmpty($secret)) { $s = $s.Replace($secret, '[REDACTED]') }
    }
    $s = $s -replace '[\r\n|]+',' ' -replace '\s{2,}',' '
    if ($s.Length -gt $Limit) { $s = $s.Substring(0,$Limit) }
    return $s.Trim()
}
function Log {
    param([string]$Message)
    try {
        ('{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (Safe-Text $Message)) |
            Add-Content -LiteralPath $LogFile -Encoding UTF8
    } catch { }
}
function Warn {
    param([string]$Message)
    [void]$script:Warnings.Add($Message)
    Log "WARN | $Message"
}
function Get-1PField {
    param([object]$Item,[string]$Label)
    $matches = @($Item.fields | Where-Object { $_.label -eq $Label })
    if ($matches.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$matches[0].value)) {
        throw "Missing or ambiguous 1Password field: $Label"
    }
    return [string]$matches[0].value
}
function Save-Raw {
    param([string]$Path,[string]$Raw,[string]$Kind)
    [IO.File]::WriteAllText($Path,$Raw,[Text.UTF8Encoding]::new($false))
    $file = Get-Item -LiteralPath $Path
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    [void]$script:Files.Add([ordered]@{
        kind=$Kind;name=$file.Name;relativePath=$Path.Substring($script:Folder.Length).TrimStart('\');
        bytes=$file.Length;sha256=$hash
    })
    Log "FILE | Kind=$Kind Name=$($file.Name) Bytes=$($file.Length) SHA256=$hash"
}
function Get-HttpFailure {
    param([object]$Err)
    $status = 'N/A'; $body = ''
    try {
        if ($Err.Exception.Response) {
            $status = [string][int]$Err.Exception.Response.StatusCode
            $stream = $Err.Exception.Response.GetResponseStream()
            if ($stream) {
                $reader = New-Object IO.StreamReader($stream)
                try { $body = $reader.ReadToEnd() } finally { $reader.Dispose() }
            }
        }
    } catch { }
    if (-not $body) { try { $body = [string]$Err.ErrorDetails.Message } catch { } }
    if (-not $body) { $body = [string]$Err.Exception.Message }
    return ('HTTP={0} Detail={1}' -f $status,(Safe-Text $body))
}
function Invoke-S1 {
    param([string]$Method,[string]$Path,[hashtable]$Params=$null,[object]$Body=$null,[string]$Auth='ApiToken')
    $uri = "$script:BaseUrl$Path"
    if ($Params -and $Params.Count -gt 0) {
        $parts = @(foreach ($key in ($Params.Keys | Sort-Object)) {
            if ($null -ne $Params[$key] -and [string]$Params[$key] -ne '') {
                '{0}={1}' -f [Uri]::EscapeDataString([string]$key), [Uri]::EscapeDataString([string]$Params[$key])
            }
        })
        if ($parts.Count) { $uri += '?' + ($parts -join '&') }
    }
    $headers = @{ Authorization = "$Auth $script:ApiToken"; Accept = 'application/json' }
    try {
        if ($Method -eq 'POST') {
            $bodyJson = ConvertTo-Json -InputObject $Body -Depth 16 -Compress
            $reply = Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -ContentType 'application/json' `
                -Body $bodyJson -UseBasicParsing -TimeoutSec 120
        } else {
            $reply = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers -UseBasicParsing -TimeoutSec 120
        }
        $raw = [string]$reply.Content
        if ([string]::IsNullOrWhiteSpace($raw)) { throw "Empty response from $Method $Path" }
        $parsed = $raw | ConvertFrom-Json
        Log "HTTP_OK | $Method $Path Status=$($reply.StatusCode) Bytes=$($raw.Length)"
        return [pscustomobject]@{Raw=$raw;Parsed=$parsed}
    } catch {
        $err = Get-HttpFailure $_
        Log "HTTP_FAIL | $Method $Path $err"
        throw "$Method $Path | $err"
    }
}
function Invoke-GQL {
    param([string]$Query,[hashtable]$Variables)
    $r = Invoke-S1 -Method POST -Path '/web/api/v2.1/unifiedalerts/graphql' `
        -Body @{query=$Query;variables=$Variables} -Auth 'Bearer'
    if (@($r.Parsed.errors | Where-Object { $null -ne $_ }).Count -gt 0) {
        throw ('GraphQL returned errors: ' + (Safe-Text ($r.Parsed.errors | ConvertTo-Json -Depth 6 -Compress)))
    }
    return $r
}
function Get-PagedRest {
    param([string]$Path,[hashtable]$Params,[string]$ResponseMember,[string]$Prefix)
    $results = New-Object System.Collections.ArrayList
    $cursor = ''; $pageNum = 0
    do {
        $pageNum++
        if ($pageNum -gt 100) { throw "$Prefix exceeded 100 pages" }
        $p = @{}; foreach ($k in $Params.Keys) { $p[$k]=$Params[$k] }
        if ($cursor) { $p.cursor=$cursor }
        $r = Invoke-S1 -Method GET -Path $Path -Params $p
        Save-Raw (Join-Path $script:Folder ("{0}_page_{1:D3}_RAW.json" -f $Prefix,$pageNum)) $r.Raw $Prefix
        $arr = if ($ResponseMember) { @($r.Parsed.data.$ResponseMember) } else { @($r.Parsed.data) }
        foreach ($item in $arr) { if ($null -ne $item) { [void]$results.Add($item) } }
        $cursor = [string]$r.Parsed.pagination.nextCursor
    } while ($cursor)
    return $results.ToArray()
}
function Fetch-Mitigation {
    param([string]$Relative,[string]$Label)
    # Use report paths returned by S1 alert history only. Never accept arbitrary URLs.
    if ($Relative -notmatch '^/web/api/v2\.1/unifiedalerts/alerts/mitigation-report/[a-zA-Z0-9-]+$') {
        Warn "Skipped invalid mitigation report path for $Label"
        return
    }
    $reportId = ($Relative -split '/')[-1]
    try {
        $headers = @{ Authorization = "ApiToken $script:ApiToken"; Accept = '*/*' }
        $response = Invoke-WebRequest -Uri "$script:BaseUrl$Relative" -Method GET -Headers $headers `
            -UseBasicParsing -TimeoutSec 120
        if (-not $response.RawContentStream) { throw 'Response had no raw stream' }
        $bytes = $response.RawContentStream.ToArray()
        if (-not $bytes.Length) { throw 'Response was empty' }
        $type = [string]$response.Headers['Content-Type']; $ext='.bin'
        if ($type -match 'json') { $ext='.json' }
        elseif ($type -match 'pdf') { $ext='.pdf' }
        elseif ($type -match 'text') { $ext='.txt' }
        elseif ($type -match 'csv') { $ext='.csv' }
        $safeLabel = $Label -replace '[^A-Za-z0-9_-]','_'
        $path = Join-Path $script:Folder "MITIGATION_${safeLabel}_${reportId}${ext}"
        [IO.File]::WriteAllBytes($path,$bytes)
        $file=Get-Item -LiteralPath $path
        [void]$script:Files.Add([ordered]@{
            kind='mitigation_report';name=$file.Name;relativePath=$file.Name;bytes=$file.Length;
            sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        })
        $script:ReportCount++
        Log "REPORT | $reportId Bytes=$($file.Length)"
    } catch { Warn "Mitigation report $reportId unavailable: $(Get-HttpFailure $_)" }
}
function Parse-UTC {
    param([string]$Value,[string]$Name)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "Missing $Name" }
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
}

try {
    $Stage = 'Configuration'
    foreach ($RequiredSetting in @(
        @{ Name='sentinelOneBaseUrl'; Value=$BaseUrl },
        @{ Name='onePasswordVault'; Value=$Vault },
        @{ Name='bootstrapTokenField'; Value=$OpField }
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$RequiredSetting.Value)) {
            throw "Required configuration '$($RequiredSetting.Name)' is missing."
        }
    }
    $TenantUri = $null
    if (-not [Uri]::TryCreate($BaseUrl, [UriKind]::Absolute, [ref]$TenantUri) -or
        $TenantUri.Scheme -ne 'https' -or
        $TenantUri.Host -notmatch '^[A-Za-z0-9-]+\.sentinelone\.net$' -or
        $TenantUri.AbsolutePath -ne '/') {
        throw 'sentinelOneBaseUrl must be an HTTPS SentinelOne tenant base URL.'
    }
    $ExpectedTenantHost = $TenantUri.Host

    New-Item -ItemType Directory -Path $OutDir,$LogDir,$Folder -Force | Out-Null
    Set-Content -LiteralPath $LogFile -Value "S1 IR acquisition started $(Get-Date -Format o)" -Encoding UTF8
    # Parse the EXACT copied alert URL. Never accept a different host/path or
    # interpret the numeric legacy threat/external ID as an alert UUID.
    #
    # Current SentinelOne Unified Alert URLs embed the UUID in the path:
    #   /incidents/unified-alerts/<UUID>?viewType=...
    #
    # Older copied URLs may instead use:
    #   /incidents/unified-alerts?alertId=<UUID>
    #
    # Accept either known form, extract exactly one Unified Alert UUID, and
    # discard UI-only query context before any API work.
    $Stage = 'ValidateAlertURL'
    if ([string]::IsNullOrWhiteSpace($AlertURL)) { throw 'NinjaOne AlertURL String/Text variable is mandatory' }

    $parsedUrl = $null
    if (-not [Uri]::TryCreate($AlertURL.Trim(), [UriKind]::Absolute, [ref]$parsedUrl)) {
        throw 'AlertURL must be a complete HTTPS SentinelOne Unified Alerts URL'
    }

    if ($parsedUrl.Scheme -ne 'https' -or
        $parsedUrl.Host -ine $ExpectedTenantHost) {
        throw 'AlertURL host does not match this SentinelOne tenant'
    }

    $uuidPattern = '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    $pathMatch = [regex]::Match(
        $parsedUrl.AbsolutePath.TrimEnd('/'),
        "(?i)^/incidents/unified-alerts/($uuidPattern)$"
    )

    if ($pathMatch.Success) {
        $AlertId = $pathMatch.Groups[1].Value
    }
    elseif ($parsedUrl.AbsolutePath.TrimEnd('/') -ceq '/incidents/unified-alerts') {
        # Legacy URL compatibility. NinjaOne previously stripped an ampersand
        # from submitted query strings, concatenating viewType onto alertId.
        # Capture exactly 36 UUID characters and permit only the known suffix.
        $idsFound = [regex]::Matches(
            $parsedUrl.Query,
            "(?i)(?:[?&])alertId=($uuidPattern)(?=$|&|viewType=)"
        )
        if ($idsFound.Count -ne 1) {
            throw 'Expected exactly one Unified Alert UUID in the Unified Alerts URL'
        }
        $AlertId = $idsFound[0].Groups[1].Value
    }
    else {
        throw 'AlertURL path does not match a supported SentinelOne Unified Alerts URL'
    }

    $NormalizedAlertURL = "$BaseUrl/incidents/unified-alerts/$AlertId"
    Log "ALERT_URL_OK | AlertUUID=$AlertId NormalizedURL=$NormalizedAlertURL"

    if (($FromUtcOverride -and -not $ToUtcOverride) -or ($ToUtcOverride -and -not $FromUtcOverride)) {
        throw 'Provide BOTH UTC time overrides, or leave BOTH blank'
    }
    if ($WindowSecondsEachSide -lt 1 -or $WindowSecondsEachSide -gt 300) {
        throw 'WindowSecondsEachSide must be between 1 and 300 seconds'
    }
    if ($DvMaxEvents -lt 1 -or $DvMaxEvents -gt 1000) {
        throw 'DvMaxEvents must be between 1 and 1000'
    }
    if (([Uri]$BaseUrl).Host -ine $ExpectedTenantHost) {
        throw 'Unexpected SentinelOne tenant host'
    }
    Log "START | AlertUUID=$AlertId"

    # Credential broker service-account chain.
    # Keep the credential source unchanged. The checks below are deliberately
    # null-safe so a missing Ninja field/CLI value produces a precise error
    # instead of a generic "method on a null-valued expression" failure.
    $Stage = 'BrokerAuth.NinjaField'
    $rawOpToken = Ninja-Property-Get -Name $OpField
    if ($null -eq $rawOpToken) {
        throw "Ninja custom field $OpField returned null on this device"
    }
    $OpToken = ([string]$rawOpToken).Trim()
    $rawOpToken = $null
    if ([string]::IsNullOrWhiteSpace($OpToken)) {
        throw "Ninja custom field $OpField was empty on this device"
    }
    Log "BROKER_FIELD_OK | Field=$OpField"

    $Stage = 'BrokerAuth.Find1PasswordCLI'
    $cmd = Get-Command 'op.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    $op = ''
    if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Source)) {
        $op = [string]$cmd.Source
    } else {
        $op = [string](@('C:\Program Files\1Password CLI\op.exe','C:\Program Files\1Password\op.exe','C:\Windows\System32\op.exe') |
            Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
    }
    $cmd = $null
    if ([string]::IsNullOrWhiteSpace($op)) { throw '1Password CLI not installed on broker' }
    Log 'BROKER_CLI_OK'

    $Stage = 'BrokerAuth.1PasswordAuth'
    $env:OP_SERVICE_ACCOUNT_TOKEN = $OpToken
    $who = & $op user get --me --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('1Password auth failed: ' + (Safe-Text ($who -join ' '))) }
    if ($null -eq $who -or @($who).Count -eq 0) { throw '1Password auth returned no output' }
    Log 'BROKER_1P_AUTH_OK'

    $Stage = 'BrokerAuth.1PasswordItem'
    $itemText = & $op item get $ItemName --vault $Vault --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('1Password item lookup failed: ' + (Safe-Text ($itemText -join ' '))) }
    if ($null -eq $itemText -or @($itemText).Count -eq 0) { throw '1Password item lookup returned no output' }
    $item = $itemText | ConvertFrom-Json
    if ($null -eq $item) { throw '1Password item JSON parsed to null' }

    $Stage = 'BrokerAuth.SentinelOneToken'
    $ApiToken = Get-1PField -Item $item -Label $TokenField
    if ([string]::IsNullOrWhiteSpace([string]$ApiToken)) { throw "1Password field $TokenField was empty" }
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null; $OpToken=$null; $who=$null; $itemText=$null; $item=$null
    Log 'AUTH_OK'

    # Get the one selected alert (NOT the numeric legacy threat/external ID).
    # The alert itself, NOT a possibly duplicated hostname, determines scope.
    $Stage='ExactAlert'
    $qAlert=@'
query GetAlert($id: ID!) {
  alert(id: $id) {
    id externalId name description severity status detectedAt firstSeenAt lastSeenAt
    analystVerdict classification confidenceLevel result storylineId
    detectionSource { product vendor }
    asset { id name type agentUuid }
    realTime { scope { site { id name } } }
  }
}
'@
    $detail=Invoke-GQL $qAlert @{id=$AlertId}
    Save-Raw (Join-Path $Folder 'alert_RAW.json') $detail.Raw 'alert'
    $Alert=$detail.Parsed.data.alert
    if (-not $Alert -or [string]$Alert.id -cne $AlertId) {
        throw 'GraphQL did not return the exact requested alert ID; refusing DV attribution'
    }
    $TargetHost=[string]$Alert.asset.name
    $AlertAgentUuid=[string]$Alert.asset.agentUuid
    $SiteId=[string]$Alert.realTime.scope.site.id
    $SiteName=[string]$Alert.realTime.scope.site.name
    if ([string]::IsNullOrWhiteSpace($TargetHost)) { throw 'Alert has no endpoint asset name; saved raw alert, but cannot target DV' }
    if ($SiteId -notmatch '^\d+$') {
        throw 'Alert GraphQL did not return a numeric realTime.scope.site.id. Saved raw alert; refusing to guess site from hostname.'
    }
    if ($AlertAgentUuid -notmatch '^[a-fA-F0-9]{32}$') {
        throw 'Alert GraphQL did not return a valid asset.agentUuid. Saved raw alert; refusing to guess among same-named devices.'
    }
    Log "ALERT_OK | UUID=$AlertId Host=$TargetHost SiteId=$SiteId AgentUUID=$AlertAgentUuid Storyline=$($Alert.storylineId)"

    # Confirm the alert's site ID and agent UUID against REST inventory.
    # This tenant has many duplicate workstation names: NEVER select by name alone.
    $Stage='ExactAgent'
    $agents=@(Get-PagedRest '/web/api/v2.1/agents' @{limit=1000;siteIds=$SiteId;computerName=$TargetHost} '' 'agents')
    $candidates=@($agents | Where-Object {
        [string]$_.computerName -ieq $TargetHost -and
        [string]$_.siteId -eq $SiteId -and
        [string]$_.uuid -ieq $AlertAgentUuid
    })
    if ($candidates.Count -ne 1) {
        throw "Alert site=$SiteId agentUUID=$AlertAgentUuid host=$TargetHost matched $($candidates.Count) exact REST agents. Raw files preserved; refusing DV attribution."
    }
    $Agent=$candidates[0]
    $AgentUuid=[string]$Agent.uuid
    Log "AGENT_OK | Name=$TargetHost SiteId=$SiteId UUID=$AgentUuid AgentId=$($Agent.id)"

    # Build ONE symmetric DV window around the selected alert's detectedAt
    # timestamp. This keeps the alert centered in the requested evidence scope.
    # The hard event cap is enforced during export; reaching it is informational,
    # not an acquisition error.
    $Stage='TimeWindow'
    if ($FromUtcOverride) {
        $from=Parse-UTC $FromUtcOverride 'FromUtcOverride'
        $to=Parse-UTC $ToUtcOverride 'ToUtcOverride'
        if ($to -le $from) { throw 'DV ToUtc must be after FromUtc' }
        # Overrides are deliberate analyst input. Use their midpoint only for
        # manifest/log context; event selection remains the supplied interval.
        $center=$from.AddTicks([int64](($to-$from).Ticks / 2))
        $windowSource='ExplicitOverride'
    } else {
        $center=Parse-UTC ([string]$Alert.detectedAt) 'alert detectedAt'
        $from=$center.AddSeconds(-$WindowSecondsEachSide)
        $to=$center.AddSeconds($WindowSecondsEachSide)
        $windowSource='AlertDetectedAt'
    }
    $AlertCenterUtc=$center.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $FromUtc=$from.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $ToUtc=$to.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    Log "WINDOW | Source=$windowSource Center=$AlertCenterUtc From=$FromUtc To=$ToUtc SecondsEachSide=$WindowSecondsEachSide MaxEvents=$DvMaxEvents"

    # Alert history includes analyst decisions, response actions, NOTES events,
    # and mitigation report URLs. Raw history is preserved. Notes are also
    # extracted into a convenience JSON from those already validated history
    # records; no separate unverified AlertNotes GraphQL schema is queried.
    $Stage='AlertHistory'
    $reportPaths=@{}
    try {
        $qHistory=@'
query GetHistory($id: ID!, $first: Int!, $after: String) {
  alertHistory(alertId:$id, first:$first, after:$after) {
    edges { node { createdAt eventText eventType reportUrl historyItemCreator {
      __typename ... on UserHistoryItemCreator { userId userType }
    } } cursor }
    pageInfo { hasNextPage endCursor }
    totalCount
  }
}
'@
        $after=$null
        do {
            $HistoryPages++
            if ($HistoryPages -gt 50) { throw 'History exceeded 50 pages' }
            $h=Invoke-GQL $qHistory @{id=$AlertId;first=100;after=$after}
            Save-Raw (Join-Path $Folder ("history_page_{0:D3}_RAW.json" -f $HistoryPages)) $h.Raw 'alert_history'
            $hist=$h.Parsed.data.alertHistory
            foreach ($edge in @($hist.edges)) {
                if (-not $edge -or -not $edge.node) { continue }
                if ([string]$edge.node.eventType -ieq 'NOTES') {
                    [void]$HistoryNotes.Add([ordered]@{
                        createdAt=[string]$edge.node.createdAt
                        eventType=[string]$edge.node.eventType
                        eventText=[string]$edge.node.eventText
                        historyItemCreator=$edge.node.historyItemCreator
                        cursor=[string]$edge.cursor
                    })
                }
                if ($edge.node.reportUrl) {
                    $url=[string]$edge.node.reportUrl
                    $eventType=[string]$edge.node.eventType
                    if ($eventType -ieq 'MITIGATION_ACTION' -and
                        $url -match '^/web/api/v2\.1/unifiedalerts/alerts/mitigation-report/[a-zA-Z0-9-]+$') {
                        $reportPaths[$url]=$eventType
                    } else {
                        # Preserve non-mitigation links in raw history. They are not
                        # acquisition failures and must not create false warnings.
                        Log "HISTORY_LINK | Kind=$eventType Path=$url"
                    }
                }
            }
            $more=[bool]$hist.pageInfo.hasNextPage
            $after=[string]$hist.pageInfo.endCursor
            if ($more -and -not $after) { throw 'History cursor missing' }
        } while ($more)
    } catch { Warn ('Alert history incomplete: ' + (Safe-Text $_.Exception.Message)) }
    $Stage='AlertNotesFromHistory'
    if ($HistoryNotes.Count -gt 0) {
        $notesDerived=[ordered]@{
            source='Derived from raw alertHistory eventType=NOTES records'
            alertId=$AlertId
            count=$HistoryNotes.Count
            notes=@($HistoryNotes.ToArray())
        } | ConvertTo-Json -Depth 12
        Save-Raw (Join-Path $Folder 'notes_FROM_HISTORY.json') $notesDerived 'alert_notes_from_history'
        Log "NOTES | Source=AlertHistory Count=$($HistoryNotes.Count)"
    } else {
        Log 'NOTES | Source=AlertHistory Count=0'
    }
    $Stage='MitigationReports'
    foreach ($path in @($reportPaths.Keys)) { Fetch-Mitigation $path $reportPaths[$path] }

    # Use the previously validated single-query DV payload/paths for
    # exports. ONE init-query only. No slicing, recursion, storyline inference,
    # adaptive searches, or automatic reruns. The event export follows pagination
    # only for this one query and stops permanently at DvMaxEvents.
    $Stage='InitDeepVisibility'
    $DvQuery='AgentUUID = "' + $AgentUuid + '"'
    $request=[ordered]@{query=$DvQuery;queryType=@('events');fromDate=$FromUtc;toDate=$ToUtc;tenant=$true}
    $init=Invoke-S1 -Method POST -Path '/web/api/v2.1/dv/init-query' -Body $request
    Save-Raw (Join-Path $Folder 'dv_init_RAW.json') $init.Raw 'dv_init'
    $QueryId=[string]$init.Parsed.data.queryId
    if (-not $QueryId) { throw 'DV init returned no queryId' }
    Log "DV_QUERY | QueryId=$QueryId Center=$AlertCenterUtc From=$FromUtc To=$ToUtc Query=$DvQuery MaxEvents=$DvMaxEvents"

    $Stage='PollDeepVisibility'
    $done=$false
    $check=$null
    for ($attempt=1; $attempt -le 24; $attempt++) {
        Start-Sleep -Seconds 5
        $check=Invoke-S1 -Method GET -Path '/web/api/v2.1/dv/query-status' -Params @{queryId=$QueryId}
        $state=[string]$check.Parsed.data.responseState
        if (-not $state) { $state=[string]$check.Parsed.data.status }
        Log "DV_STATUS | QueryId=$QueryId State=$state Attempt=$attempt"
        if ($state -eq 'FINISHED') { $done=$true;break }
        if ($state -in @('FAILED','TIMED_OUT','CANCELLED','ERROR')) { throw "DV query ended: $state QueryId=$QueryId" }
    }
    if ($check) { Save-Raw (Join-Path $Folder 'dv_status_RAW.json') $check.Raw 'dv_status' }
    if (-not $done) { throw "DV query did not finish after 24 checks. QueryId=$QueryId" }

    $Stage='ExportRawDV'
    $cursor=$null
    $allTimes=New-Object System.Collections.ArrayList
    do {
        $remaining=$DvMaxEvents-$EventCount
        if ($remaining -le 0) { break }

        $PageCount++
        if ($PageCount -gt 250) { throw 'DV cursor exceeded 250 pages; saved pages retained' }

        $p=@{queryId=$QueryId;limit=$remaining;sortBy='createdAt';sortOrder='asc'}
        if ($cursor) { $p.cursor=$cursor }
        $page=Invoke-S1 -Method GET -Path '/web/api/v2.1/dv/events' -Params $p
        Save-Raw (Join-Path $Folder ("dv_events_page_{0:D3}_RAW.json" -f $PageCount)) $page.Raw 'dv_events'

        $events=@($page.Parsed.data | Where-Object { $null -ne $_ })
        if ($events.Count -gt $remaining) {
            # Defensive only: the request limit should prevent this. Never silently
            # exceed the analyst-defined acquisition cap.
            $events=@($events | Select-Object -First $remaining)
        }
        $EventCount += $events.Count

        $mismatch=@($events | Where-Object {
            ([string]$_.agentUuid -ine $AgentUuid) -or
            ([string]$_.siteId -ne $SiteId) -or
            ([string]$_.agentName -ine $TargetHost)
        })
        if ($mismatch.Count) {
            Warn "DV returned $($mismatch.Count) agent/site/hostname mismatch(es) on page $PageCount. Raw page retained."
        }

        if ($Alert.storylineId) {
            $hits=@($events | Where-Object { [string]$_.storyline -ieq [string]$Alert.storylineId })
            $DVStorylineHits += $hits.Count
        }

        foreach ($event in $events) {
            $eventTimestamp=[string]$event.eventTime
            if ([string]::IsNullOrWhiteSpace($eventTimestamp)) { $eventTimestamp=[string]$event.createdAt }
            if (-not [string]::IsNullOrWhiteSpace($eventTimestamp)) {
                try { [void]$allTimes.Add((Parse-UTC $eventTimestamp 'DV event timestamp')) } catch { }
            }
        }

        $cursor=[string]$page.Parsed.pagination.nextCursor
        Log "DV_PAGE | Page=$PageCount Events=$($events.Count) Total=$EventCount Remaining=$($DvMaxEvents-$EventCount) More=$([bool]$cursor) QueryId=$QueryId"

        if ($events.Count -eq 0) { break }
    } while ($cursor -and $EventCount -lt $DvMaxEvents)

    if ($allTimes.Count -gt 0) {
        $sortedReturned=@($allTimes | Sort-Object)
        $DvRetrievedFromUtc=$sortedReturned[0].ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $DvRetrievedToUtc=$sortedReturned[-1].ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        Log "DV_RETRIEVED_WINDOW | Events=$EventCount From=$DvRetrievedFromUtc To=$DvRetrievedToUtc RequestedCenter=$AlertCenterUtc RequestedFrom=$FromUtc RequestedTo=$ToUtc"
    } else {
        Log "DV_RETRIEVED_WINDOW | Events=0 From=<none> To=<none> RequestedCenter=$AlertCenterUtc RequestedFrom=$FromUtc RequestedTo=$ToUtc"
    }

    if ($EventCount -ge $DvMaxEvents) {
        $DvLimitReached=$true
        Log "DV_LIMIT_REACHED | Limit=$DvMaxEvents Events=$EventCount RetrievedFrom=$DvRetrievedFromUtc RetrievedTo=$DvRetrievedToUtc RequestedCenter=$AlertCenterUtc"
    }

    if ($EventCount -eq 0) { Warn 'DV returned zero events in the selected UTC window.' }
    if ($Alert.storylineId -and $DVStorylineHits -eq 0) {
        Warn 'No matching alert storyline found in returned DV events. Alert-to-agent attribution remains confirmed by alert.asset.agentUuid plus exact REST inventory; review the returned DV timeframe for this alert type.'
    }

}
catch {
    $errorMessage=Safe-Text $_.Exception.Message
    Log "ERROR | Stage=$Stage QueryId=$QueryId Detail=$errorMessage"
    $FinalOutput="ERROR | Stage=$Stage Detail=$errorMessage QueryId=$QueryId Folder=$Folder Log=$LogFile"
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN=$null
    $OpToken=$null; $rawOpToken=$null; $ApiToken=$null; $item=$null; $itemText=$null
    # Preserve every file obtained before any error; never discard good data.
    try {
        if (Test-Path -LiteralPath $Folder) {
            $manifest=[ordered]@{
                build='S1-IR-v11-URL-BROKERFIX-07OCT2026';createdUtc=[DateTimeOffset]::UtcNow.ToString('o')
                siteName=$SiteName;siteId=$SiteId
                alertUuid=$AlertId;inputType='Unified Alert URL';asset=$(if($Alert){[string]$Alert.asset.name}else{$null})
                agentUuid=$(if($Agent){[string]$Agent.uuid}else{$null})
                alertStoryline=$(if($Alert){[string]$Alert.storylineId}else{$null})
                alertCenterUtc=$AlertCenterUtc;fromUtc=$FromUtc;toUtc=$ToUtc;dvQueryId=$QueryId
                dvPages=$PageCount;dvEvents=$EventCount;dvMaxEvents=$DvMaxEvents;dvLimitReached=$DvLimitReached
                dvRetrievedFromUtc=$DvRetrievedFromUtc;dvRetrievedToUtc=$DvRetrievedToUtc;matchingStorylineEvents=$DVStorylineHits
                historyPages=$HistoryPages;historyNotes=$HistoryNotes.Count;mitigationReports=$ReportCount
                warnings=@($Warnings.ToArray());files=@($Files.ToArray())
                result=$(if($FinalOutput){'PARTIAL_OR_ERROR'}elseif($Warnings.Count){'PARTIAL_WARNING'}elseif($DvLimitReached){'SUCCESS_LIMIT_REACHED'}else{'SUCCESS'})
                caveat='Read-only export. Alert site+UUID must be confirmed before Deep Visibility. One alert-centered DV query is created and up to 1000 events are preserved. Reaching the 1000-event limit is not an error; the actual earliest/latest timestamps represented by the returned events are recorded. May contain sensitive personal data. Never upload externally without IR sanitization.'
            }
            $manifestPath=Join-Path $Folder 'manifest.json'
            $manifest | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
            # Compress only the new per-run folder. Original API JSON files remain.
            Compress-Archive -Path (Join-Path $Folder '*') -DestinationPath $ZipPath -Force
            $zipHash=(Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash
            Log "ZIP | File=$ZipPath SHA256=$zipHash"
            if (-not $FinalOutput) {
                if ($DvRetrievedFromUtc) { $retrievedFromOut=$DvRetrievedFromUtc } else { $retrievedFromOut='N/A' }
                if ($DvRetrievedToUtc) { $retrievedToOut=$DvRetrievedToUtc } else { $retrievedToOut='N/A' }
                $retrievedWindow="RetrievedFrom=$retrievedFromOut RetrievedTo=$retrievedToOut"
                if ($Warnings.Count) {
                    if ($DvLimitReached) { $limitText=" LimitReached=$DvMaxEvents" } else { $limitText='' }
                    $FinalOutput="RESULT | PARTIAL/WARN | Alert=$AlertId Events=$EventCount$limitText $retrievedWindow Pages=$PageCount Reports=$ReportCount Warnings=$($Warnings.Count) ZIP=$ZipPath"
                } elseif ($DvLimitReached) {
                    $FinalOutput="RESULT | LIMIT_REACHED | Alert=$AlertId Events=$EventCount Limit=$DvMaxEvents $retrievedWindow Pages=$PageCount Reports=$ReportCount ZIP=$ZipPath"
                } else {
                    $FinalOutput="RESULT | Alert=$AlertId Events=$EventCount $retrievedWindow Pages=$PageCount Reports=$ReportCount ZIP=$ZipPath"
                }
            } else {
                $FinalOutput += " | ZIP=$ZipPath"
            }
        }
    } catch {
        Log "ERROR | Packaging $(Safe-Text $_.Exception.Message)"
        if (-not $FinalOutput) { $FinalOutput='ERROR | Packaging failed; inspect preserved folder: '+$Folder }
    }
    if (-not $FinalOutput) { $FinalOutput='NO_ACTION | No data acquired; inspect log' }
    Write-Output $FinalOutput
    exit 0
}
