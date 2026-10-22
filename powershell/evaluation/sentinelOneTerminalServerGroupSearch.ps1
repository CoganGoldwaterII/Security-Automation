
# ============================================================================
# NAME: SentinelOne Terminal Server Group Override Evaluation
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Authorized Credential Broker / NinjaOne / SentinelOne tenant (read-only API)
# VARIABLES:
#   Required NinjaOne environment/script variables:
#     sentinelOneExpectedHost   - Exact approved SentinelOne console hostname
#     terminalServerOverrideName - Expected group-scoped Config Override name
#     onePasswordVault         - 1Password vault containing SentinelOne API item
#     bootstrapTokenField      - NinjaOne secure field containing 1Password token
# OUTPUT TOKENS:
#   TRIGGER   | At least one group requires a group-scoped Config Override
#   NO_ACTION | No matching groups or all matching groups compliant
#   ERROR     | At least one evaluation error or a fatal failure
#   Exit Code: Always 0; Ninja condition: output contains TRIGGER, code 0
# CUSTOM FIELDS:
#   Reads: Secure NinjaOne field specified by bootstrapTokenField
#   Writes: None
# FILE TRANSFERS: None
# LOGGING PATH:
#   %ProgramData%\AutomationPlaybook\Logs\S1_TermServer_Group_Override_Eval.log
# REPORT PATH:
#   %ProgramData%\AutomationPlaybook\Reports\S1_TermServer_Group_Override_Manifest_<timestamp>.csv
#   %ProgramData%\AutomationPlaybook\Reports\S1_TermServer_Group_Override_Eval_<timestamp>\
# DESCRIPTION:
#   Enumerates groups accessible to the SentinelOne API token, identifies
#   Terminal Server groups using a conservative name regex, and compares their
#   Config Override records with the embedded desired policy JSON.
#   An explicitly GROUP-scoped override with the configured name, Windows / ALL
#   settings, and the required JSON properties is necessary for compliance.
#   Inherited Global/Account/Site overrides do not satisfy this requirement.
#   No SentinelOne API writes are performed. Locally writes a CSV manifest and
#   diagnostic Config Override snapshots that may contain environment details.
# SECURITY NOTES:
#   Requires an appropriately scoped 1Password service token and SentinelOne
#   API token. Intended broker-only operation, but the original code does not
#   implement a machine identity check. Restrict execution through NinjaOne.
#   The embedded policy defines broad exclusion paths and disabled protection
#   capabilities. Review these carefully before applying any remediation.
#   Do not publish generated client metadata/diagnostic snapshots to GitHub.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ============================== CONFIGURATION ==============================
$ExpectedConsoleHost   = ([string]$env:sentinelOneExpectedHost).Trim()
$ExpectedOverrideName  = ([string]$env:terminalServerOverrideName).Trim()
$ExpectedOsType        = 'windows'
$ExpectedVersionOption = 'ALL'

$Vault      = ([string]$env:onePasswordVault).Trim()
$ItemName   = 'SentinelOne'
$TokenField = 'credential'
$UrlField   = 'consoleUrl'
$OpField    = ([string]$env:bootstrapTokenField).Trim()

$OutDir   = Join-Path $env:ProgramData 'AutomationPlaybook\Reports'
$LogDir   = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogFile  = Join-Path $LogDir 'S1_TermServer_Group_Override_Eval.log'
$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$ManifestPath = Join-Path $OutDir "S1_TermServer_Group_Override_Manifest_$RunStamp.csv"
$SnapshotDir  = Join-Path $OutDir "S1_TermServer_Group_Override_Eval_$RunStamp"

# Intentionally conservative.
# Matches TermServer / TerminalServer / Term Server / Terminal Server variants,
# including names with prefixes or suffixes.
# Does NOT match generic TS / RDS / Citrix names.
$GroupNameRegex = '(?i)(?<![A-Za-z0-9])term(?:inal)?[\s._-]*servers?(?![A-Za-z0-9])'

# Approved raw JSON that belongs inside the Config Override "config" value.
$DesiredConfigJson = @'
{
    "policy": {
        "description": "Deep Hooking (third-party only) + RDS performance & stability tuning",
        "exclusions": [
            "C:\\Users\\*\\AppData\\Local\\Temp\\*",
            "C:\\ProgramData\\Temp\\*",
            "C:\\ProgramData\\Microsoft\\Search\\Data\\*",
            "C:\\Windows\\System32\\spool\\PRINTERS\\*",
            "C:\\Windows\\Installer\\*",
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\*",
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\FSLogix\\*",
            "C:\\Users\\TEMP*\\*",
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Caches\\*",
            "C:\\Windows\\System32\\LServer\\*",
            "C:\\Program Files\\NinjaRMMAgent\\*"
        ],
        "groupType": "server",
        "name": "Terminal Server Optimized (RDS/Citrix/AVD)",
        "overrides": {
            "behavioralAi": {
                "credential_theft_protection_enabled": true,
                "deep_hooking_enabled": true,
                "deep_hooking_mode": "third_party_only",
                "memory_protection_enabled": true,
                "ransomware_detection_enabled": true,
                "script_control_enabled": true
            },
            "deviceControl": {
                "enabled": false
            },
            "firewall": {
                "enabled": false
            },
            "mitigation": {
                "auto_remediate_malicious_enabled": true,
                "auto_remediate_suspicious_enabled": false,
                "kill_process_tree_suspicious_enabled": false,
                "network_quarantine_enabled": false,
                "reboot_on_remediation_enabled": false,
                "rollback_enabled": true
            },
            "star": {
                "auto_action": "tag_only",
                "enabled": true
            },
            "staticAi": {
                "enabled": true,
                "scan_archives_enabled": false
            },
            "telemetry": {
                "agent_health_telemetry_enabled": true,
                "deep_visibility_enabled": false,
                "logging_level": "normal"
            },
            "updates": {
                "auto_update_enabled": false,
                "defer_reboots_enabled": true
            }
        }
    }
}
'@
# ===========================================================================

$Stage       = 'Initialize'
$OpToken     = $null
$ApiToken    = $null
$BaseUrl     = $null
$FinalOutput = ''

$Rows = New-Object System.Collections.ArrayList

$MatchedCount          = 0
$CompliantCount        = 0
$NeedsRemediationCount = 0
$EvaluationErrorCount  = 0

function Safe-Text {
    param(
        [AllowNull()][object]$Value,
        [int]$Limit = 900
    )

    $s = [string]$Value

    foreach ($secret in @($script:OpToken, $script:ApiToken)) {
        if (-not [string]::IsNullOrEmpty([string]$secret)) {
            $s = $s.Replace([string]$secret, '[REDACTED]')
        }
    }

    $s = $s -replace '[\r\n|]+', ' ' -replace '\s{2,}', ' '

    if ($s.Length -gt $Limit) {
        $s = $s.Substring(0, $Limit)
    }

    return $s.Trim()
}

function Log {
    param([string]$Message)

    try {
        ('{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (Safe-Text $Message)) |
            Add-Content -LiteralPath $LogFile -Encoding UTF8
    }
    catch {
        # Logging must never change evaluation behavior.
    }
}

function Get-1PField {
    param(
        [object]$Item,
        [string]$Label
    )

    $matches = @($Item.fields | Where-Object { $_.label -eq $Label })

    if ($matches.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$matches[0].value)) {
        throw "Missing or ambiguous 1Password field: $Label"
    }

    return [string]$matches[0].value
}

function Get-HttpFailure {
    param([object]$Err)

    $status = 'N/A'
    $body = ''

    try {
        if ($Err.Exception.Response) {
            $status = [string][int]$Err.Exception.Response.StatusCode
            $stream = $Err.Exception.Response.GetResponseStream()

            if ($stream) {
                $reader = New-Object IO.StreamReader($stream)

                try {
                    $body = $reader.ReadToEnd()
                }
                finally {
                    $reader.Dispose()
                }
            }
        }
    }
    catch {
    }

    if (-not $body) {
        try {
            $body = [string]$Err.ErrorDetails.Message
        }
        catch {
        }
    }

    if (-not $body) {
        $body = [string]$Err.Exception.Message
    }

    return ('HTTP={0} Detail={1}' -f $status, (Safe-Text $body))
}

function Invoke-S1Get {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [hashtable]$Params = $null
    )

    # Hard guard: this evaluation script implements GET only.
    $uri = "$script:BaseUrl$Path"

    if ($Params -and $Params.Count -gt 0) {
        $parts = @(
            foreach ($key in ($Params.Keys | Sort-Object)) {
                if ($null -ne $Params[$key] -and [string]$Params[$key] -ne '') {
                    '{0}={1}' -f `
                        [Uri]::EscapeDataString([string]$key), `
                        [Uri]::EscapeDataString([string]$Params[$key])
                }
            }
        )

        if ($parts.Count -gt 0) {
            $uri += '?' + ($parts -join '&')
        }
    }

    $headers = @{
        Authorization = "ApiToken $script:ApiToken"
        Accept        = 'application/json'
    }

    try {
        $reply = Invoke-WebRequest `
            -Uri $uri `
            -Method Get `
            -Headers $headers `
            -UseBasicParsing `
            -TimeoutSec 120

        $raw = [string]$reply.Content

        if ([string]::IsNullOrWhiteSpace($raw)) {
            throw "Empty response from GET $Path"
        }

        $parsed = $raw | ConvertFrom-Json

        Log "HTTP_OK | GET $Path Status=$($reply.StatusCode) Bytes=$($raw.Length)"

        return [pscustomobject]@{
            Raw    = $raw
            Parsed = $parsed
        }
    }
    catch {
        $err = Get-HttpFailure $_
        Log "HTTP_FAIL | GET $Path $err"
        throw "GET $Path | $err"
    }
}

function Get-AllGroups {
    $results = New-Object System.Collections.ArrayList
    $cursor = ''
    $page = 0

    do {
        $page++

        if ($page -gt 250) {
            throw 'Group enumeration exceeded 250 cursor pages'
        }

        # SentinelOne documents a maximum group-list page size of 200.
        $params = @{
            limit     = 200
            sortBy    = 'name'
            sortOrder = 'asc'
            skipCount = 'true'
        }

        if ($cursor) {
            $params.cursor = $cursor
        }

        $response = Invoke-S1Get -Path '/web/api/v2.1/groups' -Params $params
        $items = @($response.Parsed.data | Where-Object { $null -ne $_ })

        foreach ($item in $items) {
            [void]$results.Add($item)
        }

        $cursor = [string]$response.Parsed.pagination.nextCursor

        Log "GROUP_PAGE | Page=$page Items=$($items.Count) TotalCollected=$($results.Count) More=$([bool]$cursor)"

        # Do not persist raw group-list responses because those records can contain
        # registrationToken values.
        $response = $null
        $items = $null
    }
    while ($cursor)

    return $results.ToArray()
}

function Get-SiteMetadata {
    param([Parameter(Mandatory = $true)][string]$SiteId)

    $response = Invoke-S1Get -Path "/web/api/v2.1/sites/$SiteId"
    $site = $response.Parsed.data

    if ($site -is [System.Array]) {
        if (@($site).Count -ne 1) {
            throw "Site lookup for $SiteId returned $(@($site).Count) objects"
        }

        $site = @($site)[0]
    }

    if (-not $site) {
        throw "Site lookup for $SiteId returned no data"
    }

    return [pscustomobject]@{
        SiteName    = [string]$site.name
        AccountId   = [string]$site.accountId
        AccountName = [string]$site.accountName
    }
}

function Get-ConfigOverridesForGroup {
    param(
        [Parameter(Mandatory = $true)][string]$GroupId,
        [Parameter(Mandatory = $true)][string]$SnapshotPath
    )

    $results = New-Object System.Collections.ArrayList
    $rawPages = New-Object System.Collections.ArrayList
    $cursor = ''
    $page = 0

    do {
        $page++

        if ($page -gt 50) {
            throw "Config Override query for group $GroupId exceeded 50 cursor pages"
        }

        $params = @{
            groupIds  = $GroupId
            limit     = 1000
            sortBy    = 'id'
            sortOrder = 'asc'
            skipCount = 'true'
        }

        if ($cursor) {
            $params.cursor = $cursor
        }

        $response = Invoke-S1Get -Path '/web/api/v2.1/config-override' -Params $params
        [void]$rawPages.Add($response.Parsed)

        $items = @($response.Parsed.data | Where-Object { $null -ne $_ })

        foreach ($item in $items) {
            [void]$results.Add($item)
        }

        $cursor = [string]$response.Parsed.pagination.nextCursor

        Log "OVERRIDE_PAGE | GroupId=$GroupId Page=$page Items=$($items.Count) TotalCollected=$($results.Count) More=$([bool]$cursor)"
    }
    while ($cursor)

    # Keep the filtered response as a diagnostic artifact for this evaluation.
    # These are Config Override records only, not raw group inventory.
    $rawPages |
        ConvertTo-Json -Depth 40 |
        Set-Content -LiteralPath $SnapshotPath -Encoding UTF8

    return $results.ToArray()
}

function Get-ObjectProperty {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) {
        return [pscustomobject]@{
            Exists = $false
            Value  = $null
        }
    }

    $prop = @($Object.PSObject.Properties | Where-Object { $_.Name -eq $Name } | Select-Object -First 1)

    if ($prop.Count -eq 0) {
        return [pscustomobject]@{
            Exists = $false
            Value  = $null
        }
    }

    return [pscustomobject]@{
        Exists = $true
        Value  = $prop[0].Value
    }
}

function Test-ScalarEqual {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Desired
    )

    if ($Desired -is [bool]) {
        if ($Actual -is [bool]) {
            return ([bool]$Actual -eq [bool]$Desired)
        }

        $parsedBool = $false

        if ([bool]::TryParse([string]$Actual, [ref]$parsedBool)) {
            return ($parsedBool -eq [bool]$Desired)
        }

        return $false
    }

    if ($null -eq $Desired) {
        return ($null -eq $Actual)
    }

    return ([string]$Actual -ceq [string]$Desired)
}

function Compare-ConfigNode {
    param(
        [AllowNull()][object]$ActualNode,
        [Parameter(Mandatory = $true)][object]$DesiredNode,
        [string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Differences
    )

    foreach ($desiredProp in $DesiredNode.PSObject.Properties) {
        $name = [string]$desiredProp.Name
        $desiredValue = $desiredProp.Value
        $currentPath = if ($Path) { "$Path.$name" } else { $name }

        $actualLookup = Get-ObjectProperty -Object $ActualNode -Name $name

        if (-not $actualLookup.Exists) {
            [void]$Differences.Add("$currentPath=<missing>")
            continue
        }

        $actualValue = $actualLookup.Value

        if ($desiredValue -is [System.Management.Automation.PSCustomObject]) {
            if ($null -eq $actualValue) {
                [void]$Differences.Add("$currentPath=<null>")
                continue
            }

            Compare-ConfigNode `
                -ActualNode $actualValue `
                -DesiredNode $desiredValue `
                -Path $currentPath `
                -Differences $Differences

            continue
        }

        if ($desiredValue -is [System.Array]) {
            # Required-array behavior: all approved exclusions must exist.
            # Additional existing exclusions do not make the override noncompliant.
            $actualStrings = @(
                @($actualValue) |
                    ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
                    Where-Object { $_ -ne '' } |
                    Sort-Object -Unique
            )

            foreach ($requiredValue in @($desiredValue)) {
                $requiredString = ([string]$requiredValue).Trim().ToLowerInvariant()

                if ($actualStrings -notcontains $requiredString) {
                    [void]$Differences.Add("$currentPath missing [$requiredValue]")
                }
            }

            continue
        }

        if (-not (Test-ScalarEqual -Actual $actualValue -Desired $desiredValue)) {
            $actualSafe = Safe-Text $actualValue 220
            $desiredSafe = Safe-Text $desiredValue 220
            [void]$Differences.Add("$currentPath current=[$actualSafe] required=[$desiredSafe]")
        }
    }
}

function Convert-ConfigValueToObject {
    param([AllowNull()][object]$ConfigValue)

    if ($null -eq $ConfigValue) {
        throw 'Config Override record has no config value'
    }

    if ($ConfigValue -is [string]) {
        if ([string]::IsNullOrWhiteSpace($ConfigValue)) {
            throw 'Config Override config value is empty'
        }

        try {
            return ($ConfigValue | ConvertFrom-Json)
        }
        catch {
            throw ('Config Override config string was not valid JSON: ' + (Safe-Text $_.Exception.Message))
        }
    }

    if ($ConfigValue -is [System.Management.Automation.PSCustomObject] -or
        $ConfigValue -is [System.Collections.IDictionary]) {
        return $ConfigValue
    }

    throw "Unsupported Config Override config type: $($ConfigValue.GetType().FullName)"
}

function Get-ScopeAssessment {
    param(
        [Parameter(Mandatory = $true)][object]$Override,
        [Parameter(Mandatory = $true)][string]$TargetGroupId
    )

    # We must positively prove the override itself is group-scoped.
    # The GET filter can select overrides relevant to a group, including inherited
    # parent-scope overrides, so query membership alone is not compliance proof.

    $groupIdProp = Get-ObjectProperty -Object $Override -Name 'groupId'
    if ($groupIdProp.Exists -and [string]$groupIdProp.Value -eq $TargetGroupId) {
        return [pscustomobject]@{
            State = 'MATCH'
            Proof = "groupId=$TargetGroupId"
        }
    }

    $groupIdsProp = Get-ObjectProperty -Object $Override -Name 'groupIds'
    if ($groupIdsProp.Exists) {
        $ids = @($groupIdsProp.Value | ForEach-Object { [string]$_ })
        if ($ids -contains $TargetGroupId) {
            return [pscustomobject]@{
                State = 'MATCH'
                Proof = "groupIds contains $TargetGroupId"
            }
        }

        if ($ids.Count -gt 0) {
            return [pscustomobject]@{
                State = 'NOT_MATCH'
                Proof = 'groupIds targets a different group'
            }
        }
    }

    $scopeProp = Get-ObjectProperty -Object $Override -Name 'scope'
    $groupProp = Get-ObjectProperty -Object $Override -Name 'group'

    # Observed SentinelOne Config Override schema:
    #   "scope": "group"
    #   "group": { "id": "<GROUP_ID>", "name": "<GROUP_NAME>" }
    #
    # This is authoritative proof that the override is materialized directly at
    # the target group rather than inherited from Global / Account / Site.
    if ($scopeProp.Exists -and
        [string]$scopeProp.Value -ieq 'group' -and
        $groupProp.Exists -and
        $null -ne $groupProp.Value) {

        $nestedGroupId = Get-ObjectProperty -Object $groupProp.Value -Name 'id'

        if ($nestedGroupId.Exists) {
            if ([string]$nestedGroupId.Value -eq $TargetGroupId) {
                return [pscustomobject]@{
                    State = 'MATCH'
                    Proof = "scope=group; group.id=$TargetGroupId"
                }
            }

            if (-not [string]::IsNullOrWhiteSpace([string]$nestedGroupId.Value)) {
                return [pscustomobject]@{
                    State = 'NOT_MATCH'
                    Proof = "scope=group; group.id=$($nestedGroupId.Value)"
                }
            }
        }
    }

    if (-not $scopeProp.Exists -or $null -eq $scopeProp.Value) {
        return [pscustomobject]@{
            State = 'UNKNOWN'
            Proof = 'No scope/groupId/groupIds field available'
        }
    }

    $scope = $scopeProp.Value

    if ($scope -is [string]) {
        $scopeText = ([string]$scope).Trim()
        $lower = $scopeText.ToLowerInvariant()

        if ($lower -match 'group' -and $scopeText -match [regex]::Escape($TargetGroupId)) {
            return [pscustomobject]@{
                State = 'MATCH'
                Proof = "scope=$scopeText"
            }
        }

        if ($lower -match '^(global|tenant|account|site|agent)$') {
            return [pscustomobject]@{
                State = 'NOT_MATCH'
                Proof = "scope=$scopeText"
            }
        }

        if ($lower -match 'group') {
            return [pscustomobject]@{
                State = 'UNKNOWN'
                Proof = "Group scope found but target group ID could not be proven: $scopeText"
            }
        }

        return [pscustomobject]@{
            State = 'UNKNOWN'
            Proof = "Unrecognized scope string: $scopeText"
        }
    }

    # Object-form scope. Check explicit group identifiers first.
    foreach ($fieldName in @('groupId', 'groupIds')) {
        $p = Get-ObjectProperty -Object $scope -Name $fieldName

        if ($p.Exists) {
            $ids = @($p.Value | ForEach-Object { [string]$_ })

            if ($ids -contains $TargetGroupId) {
                return [pscustomobject]@{
                    State = 'MATCH'
                    Proof = "scope.$fieldName contains $TargetGroupId"
                }
            }

            if ($ids.Count -gt 0) {
                return [pscustomobject]@{
                    State = 'NOT_MATCH'
                    Proof = "scope.$fieldName targets a different group"
                }
            }
        }
    }

    # Common object shape: scope.type=group plus scope.id=<group id>.
    $scopeTypeProp = Get-ObjectProperty -Object $scope -Name 'type'
    $scopeIdProp = Get-ObjectProperty -Object $scope -Name 'id'

    if ($scopeTypeProp.Exists) {
        $scopeType = ([string]$scopeTypeProp.Value).Trim().ToLowerInvariant()

        if ($scopeType -eq 'group') {
            if ($scopeIdProp.Exists -and [string]$scopeIdProp.Value -eq $TargetGroupId) {
                return [pscustomobject]@{
                    State = 'MATCH'
                    Proof = "scope.type=group; scope.id=$TargetGroupId"
                }
            }

            return [pscustomobject]@{
                State = 'UNKNOWN'
                Proof = 'scope.type=group but target group ID could not be proven'
            }
        }

        if ($scopeType -in @('global', 'tenant', 'account', 'site', 'agent')) {
            return [pscustomobject]@{
                State = 'NOT_MATCH'
                Proof = "scope.type=$scopeType"
            }
        }
    }

    # Last safe inspection: serialize ONLY the scope object. We still require both
    # an explicit group marker and the exact group ID. Otherwise refuse to guess.
    $scopeJson = $scope | ConvertTo-Json -Depth 12 -Compress
    $scopeLower = $scopeJson.ToLowerInvariant()

    if ($scopeLower -match 'group' -and $scopeJson -match [regex]::Escape($TargetGroupId)) {
        return [pscustomobject]@{
            State = 'MATCH'
            Proof = 'scope JSON contains explicit group marker and exact target group ID'
        }
    }

    if ($scopeLower -match '"(global|tenant|account|site|agent)"') {
        return [pscustomobject]@{
            State = 'NOT_MATCH'
            Proof = 'scope JSON identifies a non-group scope'
        }
    }

    return [pscustomobject]@{
        State = 'UNKNOWN'
        Proof = 'Scope schema not recognized; refusing to infer group scope'
    }
}

function Write-Manifest {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$ManifestRows,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $columns = @(
        'AccountName',
        'AccountId',
        'SiteName',
        'SiteId',
        'GroupName',
        'GroupId',
        'GroupType',
        'AgentCount',
        'MatchedPattern',
        'OverrideQueryStatus',
        'ReturnedOverrideCount',
        'ExplicitGroupOverrideCount',
        'UnknownScopeOverrideCount',
        'ExpectedOverridePresent',
        'OverrideName',
        'OverrideId',
        'OverrideScopeProof',
        'OsType',
        'VersionOption',
        'OverrideMatchesDesired',
        'Compliance',
        'Differences',
        'OverrideSnapshot',
        'DiscoveredAtUtc'
    )

    if ($ManifestRows.Count -gt 0) {
        $ManifestRows |
            Select-Object $columns |
            Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    }
    else {
        Set-Content -LiteralPath $Path -Value ($columns -join ',') -Encoding UTF8
    }
}

try {
    $Stage = 'ConfigurationValidation'
    foreach ($setting in @(
        @{ Name = 'sentinelOneExpectedHost'; Value = $ExpectedConsoleHost }
        @{ Name = 'terminalServerOverrideName'; Value = $ExpectedOverrideName }
        @{ Name = 'onePasswordVault'; Value = $Vault }
        @{ Name = 'bootstrapTokenField'; Value = $OpField }
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$setting.Value)) {
            throw "Required configuration '$($setting.Name)' is missing."
        }
    }

    New-Item -ItemType Directory -Path $OutDir, $LogDir, $SnapshotDir -Force | Out-Null

    Log "START | Manifest=$ManifestPath Regex=$GroupNameRegex ExpectedOverride=$ExpectedOverrideName"

    $Stage = 'ParseDesiredConfig'

    $DesiredConfig = $DesiredConfigJson | ConvertFrom-Json

    if (-not $DesiredConfig -or -not $DesiredConfig.policy) {
        throw 'Embedded desired Config Override JSON did not contain policy'
    }

    $Stage = 'BrokerAuth'

    $OpToken = [string](Ninja-Property-Get -Name $OpField)
    $OpToken = $OpToken.Trim()

    if (-not $OpToken) {
        throw "Ninja custom field $OpField was empty"
    }

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
        throw '1Password CLI not installed on broker'
    }

    $env:OP_SERVICE_ACCOUNT_TOKEN = $OpToken

    $who = & $op user get --me --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw ('1Password auth failed: ' + (Safe-Text ($who -join ' ')))
    }

    $itemText = & $op item get $ItemName --vault $Vault --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw ('1Password item lookup failed: ' + (Safe-Text ($itemText -join ' ')))
    }

    $item = $itemText | ConvertFrom-Json

    $ApiToken = Get-1PField -Item $item -Label $TokenField
    $BaseUrl = (Get-1PField -Item $item -Label $UrlField).Trim().TrimEnd('/')

    $consoleUri = $null

    if (-not [Uri]::TryCreate($BaseUrl, [UriKind]::Absolute, [ref]$consoleUri)) {
        throw 'SentinelOne consoleUrl is not a valid absolute URL'
    }

    if ($consoleUri.Scheme -ne 'https' -or $consoleUri.Host -ne $ExpectedConsoleHost) {
        throw "Unexpected SentinelOne consoleUrl host: $($consoleUri.Host)"
    }

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $OpToken = $null
    $who = $null
    $itemText = $null
    $item = $null

    Log "AUTH_OK | Host=$($consoleUri.Host)"

    $Stage = 'EnumerateGroups'

    $allGroups = @(Get-AllGroups)

    Log "GROUP_ENUM_COMPLETE | Groups=$($allGroups.Count)"

    $matchedGroups = @(
        $allGroups |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_.name) -and
                [regex]::IsMatch([string]$_.name, $GroupNameRegex)
            }
    )

    $MatchedCount = $matchedGroups.Count

    Log "MATCH_COMPLETE | MatchedGroups=$MatchedCount"

    # The full group inventory is no longer needed after matching.
    $allGroups = $null

    $siteCache = @{}

    foreach ($group in $matchedGroups) {
        $Stage = 'EvaluateMatchedGroup'

        $GroupName  = [string]$group.name
        $GroupId    = [string]$group.id
        $SiteId     = [string]$group.siteId
        $GroupType  = [string]$group.type
        $AgentCount = [string]$group.totalAgents

        $SiteName = ''
        $AccountId = ''
        $AccountName = ''

        $OverrideQueryStatus = 'OK'
        $ReturnedOverrideCount = 0
        $ExplicitGroupOverrideCount = 0
        $UnknownScopeOverrideCount = 0
        $ExpectedOverridePresent = $false
        $OverrideName = ''
        $OverrideId = ''
        $OverrideScopeProof = ''
        $OsType = ''
        $VersionOption = ''
        $OverrideMatchesDesired = $false
        $Compliance = 'UNKNOWN'

        $Differences = New-Object System.Collections.ArrayList

        if ([string]::IsNullOrWhiteSpace($GroupId)) {
            [void]$Differences.Add('Matched group returned no id')
            $OverrideQueryStatus = 'ERROR'
        }

        if ([string]::IsNullOrWhiteSpace($SiteId)) {
            [void]$Differences.Add('Matched group returned no siteId')
            $OverrideQueryStatus = 'ERROR'
        }

        if ($SiteId) {
            try {
                if (-not $siteCache.ContainsKey($SiteId)) {
                    $siteCache[$SiteId] = Get-SiteMetadata -SiteId $SiteId
                }

                $SiteName = [string]$siteCache[$SiteId].SiteName
                $AccountId = [string]$siteCache[$SiteId].AccountId
                $AccountName = [string]$siteCache[$SiteId].AccountName
            }
            catch {
                # Site/account names are manifest enrichment only. The direct SiteId
                # and GroupId remain authoritative for evaluation.
                Log "SITE_METADATA_WARN | SiteId=$SiteId GroupId=$GroupId Detail=$(Safe-Text $_.Exception.Message)"
            }
        }

        $safeGroupName = ($GroupName -replace '[^A-Za-z0-9._-]', '_').Trim('_')

        if (-not $safeGroupName) {
            $safeGroupName = 'Group'
        }

        $SnapshotPath = Join-Path $SnapshotDir "${safeGroupName}_${GroupId}_config_overrides_RAW.json"

        if ($OverrideQueryStatus -eq 'OK') {
            try {
                $Stage = 'ReadConfigOverrides'

                $allOverrides = @(
                    Get-ConfigOverridesForGroup `
                        -GroupId $GroupId `
                        -SnapshotPath $SnapshotPath
                )

                $ReturnedOverrideCount = $allOverrides.Count

                $explicitGroupOverrides = New-Object System.Collections.ArrayList
                $unknownScopeOverrides = New-Object System.Collections.ArrayList

                foreach ($override in $allOverrides) {
                    $assessment = Get-ScopeAssessment -Override $override -TargetGroupId $GroupId

                    if ($assessment.State -eq 'MATCH') {
                        [void]$explicitGroupOverrides.Add([pscustomobject]@{
                            Override = $override
                            Proof    = $assessment.Proof
                        })
                    }
                    elseif ($assessment.State -eq 'UNKNOWN') {
                        [void]$unknownScopeOverrides.Add([pscustomobject]@{
                            Override = $override
                            Proof    = $assessment.Proof
                        })
                    }
                }

                $ExplicitGroupOverrideCount = $explicitGroupOverrides.Count
                $UnknownScopeOverrideCount = $unknownScopeOverrides.Count

                if ($UnknownScopeOverrideCount -gt 0) {
                    $proofs = @($unknownScopeOverrides | ForEach-Object { [string]$_.Proof } | Sort-Object -Unique)
                    [void]$Differences.Add('Could not positively determine scope for one or more returned Config Overrides: ' + ($proofs -join ' / '))
                    $OverrideQueryStatus = 'ERROR'
                }
                else {
                    $nameMatches = @(
                        $explicitGroupOverrides |
                            Where-Object {
                                [string]$_.Override.name -ieq $ExpectedOverrideName
                            }
                    )

                    if ($nameMatches.Count -eq 0) {
                        [void]$Differences.Add("Explicit group-scoped override [$ExpectedOverrideName] not present")
                    }
                    elseif ($nameMatches.Count -gt 1) {
                        [void]$Differences.Add("Multiple explicit group-scoped overrides named [$ExpectedOverrideName] found: $($nameMatches.Count)")
                        $OverrideQueryStatus = 'ERROR'
                    }
                    else {
                        $ExpectedOverridePresent = $true
                        $target = $nameMatches[0].Override
                        $OverrideScopeProof = [string]$nameMatches[0].Proof

                        $OverrideName = [string]$target.name
                        $OverrideId = [string]$target.id
                        $OsType = [string]$target.osType
                        $VersionOption = [string]$target.versionOption

                        if ([string]::IsNullOrWhiteSpace($OverrideId)) {
                            [void]$Differences.Add('Expected Config Override returned no id')
                            $OverrideQueryStatus = 'ERROR'
                        }

                        if ($OsType -ine $ExpectedOsType) {
                            [void]$Differences.Add("osType current=[$OsType] required=[$ExpectedOsType]")
                        }

                        if ($VersionOption -ine $ExpectedVersionOption) {
                            [void]$Differences.Add("versionOption current=[$VersionOption] required=[$ExpectedVersionOption]")
                        }

                        try {
                            $ActualConfig = Convert-ConfigValueToObject -ConfigValue $target.config

                            Compare-ConfigNode `
                                -ActualNode $ActualConfig `
                                -DesiredNode $DesiredConfig `
                                -Path '' `
                                -Differences $Differences
                        }
                        catch {
                            [void]$Differences.Add('ConfigParseError=' + (Safe-Text $_.Exception.Message 500))
                            $OverrideQueryStatus = 'ERROR'
                        }

                        if ($OverrideQueryStatus -eq 'OK' -and $Differences.Count -eq 0) {
                            $OverrideMatchesDesired = $true
                        }
                    }
                }
            }
            catch {
                $OverrideQueryStatus = 'ERROR'
                [void]$Differences.Add('OverrideReadError=' + (Safe-Text $_.Exception.Message 500))
                Log "OVERRIDE_READ_FAIL | Group=$GroupName GroupId=$GroupId SiteId=$SiteId Detail=$(Safe-Text $_.Exception.Message)"
            }
        }

        if ($OverrideQueryStatus -eq 'ERROR') {
            $Compliance = 'UNKNOWN'
            $EvaluationErrorCount++
        }
        elseif ($ExpectedOverridePresent -and $OverrideMatchesDesired) {
            $Compliance = 'COMPLIANT'
            $CompliantCount++
        }
        else {
            $Compliance = 'NEEDS_REMEDIATION'
            $NeedsRemediationCount++
        }

        [void]$Rows.Add([pscustomobject][ordered]@{
            AccountName               = $AccountName
            AccountId                 = $AccountId
            SiteName                  = $SiteName
            SiteId                    = $SiteId
            GroupName                 = $GroupName
            GroupId                   = $GroupId
            GroupType                 = $GroupType
            AgentCount                = $AgentCount
            MatchedPattern            = $GroupNameRegex
            OverrideQueryStatus       = $OverrideQueryStatus
            ReturnedOverrideCount     = $ReturnedOverrideCount
            ExplicitGroupOverrideCount= $ExplicitGroupOverrideCount
            UnknownScopeOverrideCount = $UnknownScopeOverrideCount
            ExpectedOverridePresent   = $ExpectedOverridePresent
            OverrideName              = $OverrideName
            OverrideId                = $OverrideId
            OverrideScopeProof        = $OverrideScopeProof
            OsType                    = $OsType
            VersionOption             = $VersionOption
            OverrideMatchesDesired    = $OverrideMatchesDesired
            Compliance                = $Compliance
            Differences               = ($Differences -join '; ')
            OverrideSnapshot          = $SnapshotPath
            DiscoveredAtUtc           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        })

        Log "GROUP_RESULT | Site=$SiteName SiteId=$SiteId Group=$GroupName GroupId=$GroupId ReturnedOverrides=$ReturnedOverrideCount GroupOverrides=$ExplicitGroupOverrideCount UnknownScope=$UnknownScopeOverrideCount ExpectedPresent=$ExpectedOverridePresent Match=$OverrideMatchesDesired Status=$OverrideQueryStatus Compliance=$Compliance"
    }

    $Stage = 'WriteManifest'

    Write-Manifest -ManifestRows $Rows -Path $ManifestPath

    Log "MANIFEST | Path=$ManifestPath Rows=$($Rows.Count)"

    if ($EvaluationErrorCount -gt 0) {
        $FinalOutput = "ERROR | Stage=ConfigOverrideEval | MatchedGroups=$MatchedCount EvaluationErrors=$EvaluationErrorCount NeedsRemediation=$NeedsRemediationCount Compliant=$CompliantCount Manifest=$ManifestPath"
    }
    elseif ($MatchedCount -eq 0) {
        $FinalOutput = "NO_ACTION | No Terminal Server groups discovered | Manifest=$ManifestPath"
    }
    elseif ($NeedsRemediationCount -gt 0) {
        $FinalOutput = "TRIGGER | Terminal Server group override remediation required | Groups=$MatchedCount NeedsRemediation=$NeedsRemediationCount Compliant=$CompliantCount Manifest=$ManifestPath"
    }
    else {
        $FinalOutput = "NO_ACTION | All discovered Terminal Server groups have compliant group-scoped overrides | Groups=$MatchedCount Manifest=$ManifestPath"
    }

    Log "FINAL | $FinalOutput"
}
catch {
    $detail = Safe-Text $_.Exception.Message
    $FinalOutput = "ERROR | Stage=$Stage | $detail"

    Log "FINAL | $FinalOutput"

    try {
        if ($Rows.Count -gt 0) {
            Write-Manifest -ManifestRows $Rows -Path $ManifestPath
            Log "PARTIAL_MANIFEST | Path=$ManifestPath Rows=$($Rows.Count)"
        }
    }
    catch {
        Log "PARTIAL_MANIFEST_FAIL | $(Safe-Text $_.Exception.Message)"
    }
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $OpToken = $null
    $ApiToken = $null
}

Write-Output $FinalOutput
exit 0
