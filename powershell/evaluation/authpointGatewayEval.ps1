# ============================================================================
# NAME: AuthPoint Gateway - Official Stable Version Check (Dual WatchGuard)
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows
# VARIABLES:
#   GatewayAppName     = WatchGuard AuthPoint Gateway
#   Source1            = WatchGuard AuthPoint Agent Releases
#   Source2            = WatchGuard AuthPoint Release Notes
#   RequestTimeoutSec  = 15
#   RequestAttempts    = 2 per source
# OUTPUT TOKENS:
#   TRIGGER | ...
#   NO_ACTION | ...
#   ERROR | ...
# ROUTING MARKERS:
#   GATEWAY_TICKET
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# LOGGING PATH:
#   C:\MME\AutoLogs\AuthPointGateway_Eval.log
# DESCRIPTION:
#   Compares the installed AuthPoint Gateway against the latest stable release
#   published on BOTH official WatchGuard pages. The sources must agree.
#   Never uses the locally staged MSI as the version authority. Does not
#   check or change Corretto. Windows numeric installer/build suffixes such as
#   7.6.0-8, 7.6.0.8, or 7.5.1.834 are ignored when comparing the published
#   major.minor.patch release. Beta/preview versions are never considered
#   approved stable releases. Missing Gateway is NO_ACTION (existing policy).
#   Ambiguous, unavailable, or conflicting sources return actionable ERROR,
#   never TRIGGER. Writes exactly one Ninja result line and always exits 0.
# ============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$LogRoot         = 'C:\MME\AutoLogs'
$LogFile         = Join-Path $LogRoot 'AuthPointGateway_Eval.log'
$GatewayAppName  = 'WatchGuard AuthPoint Gateway'
$AgentReleasesUrl = 'https://www.watchguard.com/support/release-notes/Cloud/Content/en-US/AuthPoint/agent_releases.html'
$AuthPointNotesUrl = 'https://www.watchguard.com/support/release-notes/Cloud/Content/en-US/AuthPoint/EN_release-notes_authpoint.html'
$RequestTimeoutSec = 15
$RequestAttempts   = 2

$Stage  = 'Initialize'
$Source = 'Local'
$InstalledRaw = 'Unknown'
$ResultMessage = $null

function Write-Log {
    param([string]$Message)
    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"
    Add-Content -LiteralPath $LogFile -Value $Line -ErrorAction Stop
}

function Stop-Evaluation {
    param(
        [string]$Reason,
        [string]$Action
    )
    # Only structured, operator-readable messages are allowed in Ninja output.
    throw "EVAL_DIAGNOSTIC::Reason=$Reason | Action=$Action"
}

function Get-InstalledGateway {
    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    # Uninstall inventory is authoritative for this evaluation, as before.
    @(Get-ItemProperty -Path $RegistryPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $GatewayAppName })
}

function ConvertTo-InstalledReleaseVersion {
    param([string]$RawVersion)

    # Accept major.minor.patch, optionally followed by one NUMERIC build part.
    # Reject beta, RC, other labels and unexpected formats, rather than guess.
    $Match = [regex]::Match(
        $RawVersion,
        '^\s*(?<release>\d+\.\d+\.\d+)(?:[.-]\d+)?\s*$'
    )
    if (-not $Match.Success) {
        Stop-Evaluation `
            -Reason "Installed Gateway DisplayVersion format is not recognized ('$RawVersion')" `
            -Action 'Inspect the Gateway version in Programs and Features and review the version parser'
    }

    return [version]$Match.Groups['release'].Value
}

function Get-NetworkDiagnosis {
    param([System.Exception]$Exception)

    $WebError = $Exception
    while ($WebError -and -not ($WebError -is [System.Net.WebException])) {
        $WebError = $WebError.InnerException
    }

    if ($WebError) {
        if ($WebError.Response -is [System.Net.HttpWebResponse]) {
            $HttpStatus = [int]$WebError.Response.StatusCode
            switch ($HttpStatus) {
                401 { return @{ Reason='WatchGuard page returned HTTP 401 (authentication required)'; Action='Check endpoint proxy authentication and page accessibility' } }
                403 { return @{ Reason='WatchGuard page returned HTTP 403 (access denied)'; Action='Check outbound proxy or web-filter policy for www.watchguard.com' } }
                404 { return @{ Reason='WatchGuard release page returned HTTP 404 (page not found)'; Action='Verify the official WatchGuard release page URL has not changed' } }
                429 { return @{ Reason='WatchGuard page returned HTTP 429 (request rate limited)'; Action='Reduce concurrent audits and retry later' } }
                default {
                    if ($HttpStatus -ge 500) {
                        return @{ Reason="WatchGuard page returned HTTP $HttpStatus (server error)"; Action='Retry later and check the official WatchGuard release page' }
                    }
                    return @{ Reason="WatchGuard page returned HTTP $HttpStatus"; Action='Check the official page in a browser and review the web-filter policy' }
                }
            }
        }

        switch ([string]$WebError.Status) {
            'NameResolutionFailure' { return @{ Reason='DNS could not resolve www.watchguard.com'; Action='Check endpoint DNS and outbound name resolution' } }
            'Timeout'               { return @{ Reason='WatchGuard release page request timed out'; Action='Check outbound HTTPS access and any proxy timeout' } }
            'TrustFailure'          { return @{ Reason='TLS certificate validation failed'; Action='Check endpoint certificate trust and HTTPS inspection settings' } }
            'SecureChannelFailure' { return @{ Reason='TLS handshake failed'; Action='Check TLS support and HTTPS inspection settings' } }
            'ConnectFailure'       { return @{ Reason='Could not establish an HTTPS connection to WatchGuard'; Action='Check TCP 443, firewall, and proxy connectivity' } }
            'ProxyNameResolutionFailure' { return @{ Reason='Configured proxy name could not be resolved'; Action='Check the endpoint proxy configuration and DNS' } }
            default { }
        }
    }

    return @{
        Reason = 'Could not retrieve the WatchGuard release page'
        Action = 'Check HTTPS access and the technical details in the evaluation log'
    }
}

function Get-WatchGuardText {
    param(
        [string]$Url,
        [string]$SourceName
    )

    $LastDiagnosis = $null
    for ($Attempt = 1; $Attempt -le $RequestAttempts; $Attempt++) {
        try {
            # Standard TLS validation stays ON. No stored version fallback.
            $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing `
                -TimeoutSec $RequestTimeoutSec -ErrorAction Stop

            $Html = [string]$Response.Content
            if ([int]$Response.StatusCode -ne 200 -or [string]::IsNullOrWhiteSpace($Html)) {
                $LastDiagnosis = @{
                    Reason = 'WatchGuard returned a blank page or unexpected response'
                    Action = 'Open the official source URL and check web filtering or proxy interception'
                }
                Write-Log "SOURCE=$SourceName ATTEMPT=$Attempt RESULT=EMPTY_OR_INVALID_RESPONSE"
            }
            else {
                # Convert stable headings and list items to line-oriented text.
                $Text = [regex]::Replace($Html, '(?is)<!--.*?-->', ' ')
                $Text = [regex]::Replace($Text, '(?is)<(script|style|noscript)\b[^>]*>.*?</\1>', ' ')
                $Text = [regex]::Replace($Text, '(?i)<br\s*/?>', "`n")
                $Text = [regex]::Replace($Text, '(?i)</(?:h[1-6]|p|li|div|section|article|ul|ol|tr|table)>', "`n")
                $Text = [regex]::Replace($Text, '(?s)<[^>]+>', ' ')
                $Text = [System.Net.WebUtility]::HtmlDecode($Text)
                $Text = $Text.Replace([char]0x00A0, ' ')
                $Text = [regex]::Replace($Text, '[^\S\r\n]+', ' ')
                $Text = [regex]::Replace($Text, '\s*\r?\n\s*', "`n")
                Write-Log "SOURCE=$SourceName ATTEMPT=$Attempt RESULT=FETCHED CONTENT_CHARS=$($Text.Length)"
                return $Text
            }
        }
        catch {
            $LastDiagnosis = Get-NetworkDiagnosis -Exception $_.Exception
            $Technical = ($_.Exception.Message -replace '[\r\n\|]+', ' ')
            if ($Technical.Length -gt 350) { $Technical = $Technical.Substring(0, 350) }
            Write-Log "SOURCE=$SourceName ATTEMPT=$Attempt RESULT=FAILED REASON=$($LastDiagnosis.Reason) TECHNICAL=$Technical"
        }

        if ($Attempt -lt $RequestAttempts) {
            Start-Sleep -Seconds 2
        }
    }

    Stop-Evaluation `
        -Reason "$SourceName unavailable after $RequestAttempts attempts: $($LastDiagnosis.Reason)" `
        -Action $LastDiagnosis.Action
}

function Get-OfficialGatewayVersion {
    param(
        [string]$PageText,
        [ValidateSet('AgentReleases','AuthPointNotes')]
        [string]$SourceName
    )

    if ($SourceName -eq 'AgentReleases') {
        # Must be the Gateway's Latest Release, not another agent or the
        # Gateway's Previous Releases section.
        $Pattern = '(?im)^[ \t]*AuthPoint Gateway[ \t]*\n[ \t]*Latest Release[ \t]*\n[ \t]*AuthPoint Gateway[ \t]+v(?<version>\d+\.\d+\.\d+)(?<tail>[^\r\n]*)'
        $Matches = [regex]::Matches($PageText, $Pattern)
    }
    else {
        # Only the current Gateway row of AuthPoint Component Versions.
        # The historical release notes contain many older Gateway versions.
        $SectionPattern = '(?ms)^[ \t]*AuthPoint Component Versions[ \t]*\n(?<body>.*?)(?=^[ \t]*Latest Release[ \t]*$)'
        $Section = [regex]::Match($PageText, $SectionPattern)
        if (-not $Section.Success) {
            Stop-Evaluation `
                -Reason 'AuthPoint Release Notes no longer exposes a recognizable current Component Versions section' `
                -Action 'Inspect the Component Versions section on the official page and update the parser'
        }

        $Pattern = '(?im)^[ \t]*AuthPoint Gateway[ \t]*:[ \t]*(?<version>\d+\.\d+\.\d+)(?<tail>[^\r\n]*)'
        $Matches = [regex]::Matches($Section.Groups['body'].Value, $Pattern)
    }

    if ($Matches.Count -ne 1) {
        Stop-Evaluation `
            -Reason "$SourceName returned $($Matches.Count) recognizable current Gateway version entries; expected exactly one" `
            -Action 'Inspect the Gateway latest-release/component-version section; WatchGuard may have changed its page layout'
    }

    $VersionText = $Matches[0].Groups['version'].Value
    $Tail = $Matches[0].Groups['tail'].Value

    # Public release-label text only, safely abbreviated; log the exact suffix
    # for future page-layout investigations without dumping an entire HTML page.
    $TailDiagnostic = [regex]::Replace($Tail, '[\x00-\x1F\|]+', ' ').Trim()
    if ($TailDiagnostic.Length -gt 160) {
        $TailDiagnostic = $TailDiagnostic.Substring(0, 160) + '...'
    }
    if ([string]::IsNullOrWhiteSpace($TailDiagnostic)) { $TailDiagnostic = '<empty>' }
    Write-Log "SOURCE=$SourceName PARSE_VERSION=$VersionText RELEASE_TAIL=$TailDiagnostic"

    # Reject all recognizable pre-release labels; a current "Latest Release"
    # line is not sufficient when WatchGuard explicitly marks it as a beta.
    if ($Tail -match '(?i)\b(beta|alpha|preview|pre[ -]?release|release[ -]?candidate|candidate|rc\d*|nightly|snapshot|canary|experimental|test(?:ing|build)?|dev(?:elopment)?)\b') {
        Stop-Evaluation `
            -Reason "$SourceName labels the Gateway release $VersionText as beta or pre-release" `
            -Action 'Verify the latest GA release in both WatchGuard pages; do not deploy a beta'
    }

    if ($SourceName -eq 'AgentReleases') {
        # WatchGuard publishes a date on the Gateway Latest Release line.
        # Verify the semantic date, not a single exact em-dash/whitespace HTML
        # rendering. This was the over-strict v2 check that failed in testing.
        $HasReleaseDate = ($Tail -match '(?i)\bRelease\s*Date\s*:\s*(?:\d{1,2}\s+[A-Za-z]+,?\s+\d{4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})\b')
        if (-not $HasReleaseDate) {
            Stop-Evaluation `
                -Reason "$SourceName Gateway latest-release entry has no recognizable release date after version $VersionText" `
                -Action 'Review RELEASE_TAIL in the local evaluation log and compare against the official release page'
        }
    }
    else {
        # The Component Versions line is just "AuthPoint Gateway: x.y.z".
        # Anything besides whitespace or a simple terminal period is ambiguous.
        if ($Tail -notmatch '^\s*\.?\s*$') {
            Stop-Evaluation `
                -Reason "$SourceName Gateway component-version entry contains unexpected text after $VersionText" `
                -Action 'Review RELEASE_TAIL in the local evaluation log and compare against the official release page'
        }
    }

    return [version]$VersionText
}

try {
    if (-not (Test-Path -LiteralPath $LogRoot)) {
        New-Item -Path $LogRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    Write-Log '===== AuthPoint Gateway Official Dual-Source Evaluation START ====='
    $Stage = 'InstalledGatewayDiscovery'
    $GatewayEntries = @(Get-InstalledGateway)

    if ($GatewayEntries.Count -eq 0) {
        Write-Log 'GATEWAY=NOT_FOUND; existing NO_ACTION policy; official pages not queried'
        $ResultMessage = 'NO_ACTION | Gateway=NotFound'
    }
    else {
        $Stage = 'InstalledVersionParse'
        $Versions = @(
            foreach ($Entry in $GatewayEntries) {
                ConvertTo-InstalledReleaseVersion -RawVersion ([string]$Entry.DisplayVersion)
            }
        )
        $Distinct = @($Versions | Select-Object -Unique)
        if ($Distinct.Count -gt 1) {
            Stop-Evaluation `
                -Reason 'Multiple Gateway uninstall entries report different release versions' `
                -Action 'Review duplicate installed Gateway entries before determining compliance'
        }

        $InstalledRaw = ([string]$GatewayEntries[0].DisplayVersion).Trim()
        $InstalledRelease = $Distinct[0]
        Write-Log "INSTALLED_RAW=$InstalledRaw INSTALLED_RELEASE=$InstalledRelease ENTRY_COUNT=$($GatewayEntries.Count)"

        $Source = 'AgentReleases'
        $Stage  = 'OfficialVersionFetch'
        $AgentText = Get-WatchGuardText -Url $AgentReleasesUrl -SourceName $Source
        $Stage  = 'OfficialVersionParse'
        $AgentVersion = Get-OfficialGatewayVersion -PageText $AgentText -SourceName $Source
        Write-Log "SOURCE=AgentReleases VERIFIED_RELEASE=$AgentVersion"

        $Source = 'AuthPointNotes'
        $Stage  = 'OfficialVersionFetch'
        $NotesText = Get-WatchGuardText -Url $AuthPointNotesUrl -SourceName $Source
        $Stage  = 'OfficialVersionParse'
        $NotesVersion = Get-OfficialGatewayVersion -PageText $NotesText -SourceName $Source
        Write-Log "SOURCE=AuthPointNotes VERIFIED_RELEASE=$NotesVersion"

        $Source = 'BothWatchGuardPages'
        $Stage  = 'SourceAgreement'
        if ($AgentVersion -ne $NotesVersion) {
            Stop-Evaluation `
                -Reason "Official Gateway versions disagree (AgentReleases=$AgentVersion, AuthPointNotes=$NotesVersion)" `
                -Action 'Review both WatchGuard pages and rerun after their current stable versions agree'
        }

        $LatestStable = $AgentVersion
        Write-Log "LATEST_VERIFIED_STABLE=$LatestStable"

        $Stage = 'VersionComparison'
        if ($InstalledRelease -lt $LatestStable) {
            $ResultMessage = "TRIGGER | GATEWAY_TICKET | Gateway=$InstalledRaw LatestStable=$LatestStable"
        }
        else {
            $ResultMessage = "NO_ACTION | Gateway=$InstalledRaw LatestStable=$LatestStable"
        }
    }
}
catch {
    $Technical = ($_.Exception.Message -replace '[\r\n]+', ' ')
    try { Write-Log "FAILURE_STAGE=$Stage SOURCE=$Source TECHNICAL=$Technical" } catch { }

    $Marker = 'EVAL_DIAGNOSTIC::'
    if ($Technical.StartsWith($Marker)) {
        $Diagnostic = $Technical.Substring($Marker.Length)
        $ResultMessage = "ERROR | Stage=$Stage | Source=$Source | $Diagnostic"
    }
    else {
        $ResultMessage = "ERROR | Stage=$Stage | Source=$Source | Reason=Unexpected evaluation failure | Action=Review $LogFile for technical details"
    }
}

# Logging is best-effort, never hide or duplicate the one Ninja output line.
try { Write-Log $ResultMessage } catch { }
Write-Output $ResultMessage
exit 0
