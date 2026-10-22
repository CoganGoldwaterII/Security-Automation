# ============================================================================
# NAME: TeamViewer Version Check - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LogDir  = C:\MME\AutoLogs
#   LogFile = C:\MME\AutoLogs\TeamViewer_Eval.log
# OUTPUT TOKENS:
#   TRIGGER   | TeamViewer outdated or installed version unreadable
#   NO_ACTION | TeamViewer absent or all detected versions current
#   ERROR     | Latest version unavailable or evaluation failure
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\TeamViewer_Eval.log
# DESCRIPTION:
#   Detects installed TeamViewer variants through Windows uninstall
#   registry entries and compares versions against the latest stable
#   release obtained from public TeamViewer download pages.
#   Triggers remediation if any detected version is outdated or unreadable.
#   Reports NO_ACTION when TeamViewer is absent or all versions are current.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "TeamViewer_Eval.log"

# -------- HELPERS --------
function Ensure-Dir($p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}

function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    Add-Content -Path $LogFile -Value $line
}

function Extract-VersionString($raw) {
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $m = [regex]::Match($raw, '(\d+(\.\d+){1,3})')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-TeamViewerApps() {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $apps = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and ($_.DisplayName -match '(?i)teamviewer') } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation
    }

    $apps | Sort-Object DisplayName, DisplayVersion -Unique
}

function Get-LatestTeamViewerVersion {
    # Keep it simple and compatible with locked-down endpoints
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $urls = @(
        # Often easiest to parse, includes: "Current version: X.Y.Z"
        "https://www.teamviewer.com/en-us/download/previous-versions/previous-version-15x/",
        "https://www.teamviewer.com/en/download/previous-versions/previous-version-15x/",

        # Main portal also includes "Current version: X.Y.Z"
        "https://www.teamviewer.com/en-us/download/portal/windows/",
        "https://www.teamviewer.com/en/download/portal/windows/"
    )

    $headers = @{
        "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        "Accept"          = "text/html,*/*"
        "Accept-Language" = "en-US,en;q=0.9"
    }

    foreach ($u in $urls) {
        try {
            Log "Fetching latest stable version from: $($u)"
            $resp = Invoke-WebRequest -Uri $u -Headers $headers -MaximumRedirection 5 -TimeoutSec 25 -UseBasicParsing
            $html = $resp.Content

            # Tolerant parse: find first version number near "Current version"
            $m = [regex]::Match($html, 'Current\s*version[^0-9]{0,80}([0-9]+(\.[0-9]+){1,3})', 'IgnoreCase')
            if ($m.Success) {
                $v = $m.Groups[1].Value
                Log "Parsed latest stable (Current version): $v"
                return $v
            }

            # Debug snippet if markup changes again
            $snippet = $html
            if ($snippet.Length -gt 250) { $snippet = $snippet.Substring(0,250) }
            Log "Parse miss for $($u). First 250 chars: $snippet"
        } catch {
            Log "Fetch error for $($u): $($_.Exception.Message)"
        }
    }

    return $null
}

# -------- START --------
Ensure-Dir $LogDir
Log "==== TeamViewer EVAL start ===="

try {
    $apps = Get-TeamViewerApps

    if (!$apps -or $apps.Count -eq 0) {
        Log "NO_ACTION: No TeamViewer apps found."
        Write-Output "NO_ACTION | No TeamViewer detected"
        exit 0
    }

    foreach ($a in $apps) {
        Log "FOUND APP: $($a.DisplayName) | DisplayVersion: '$($a.DisplayVersion)' | Publisher: '$($a.Publisher)'"
    }

    $latestStr = Get-LatestTeamViewerVersion
    if ([string]::IsNullOrWhiteSpace($latestStr)) {
        Log "ERROR: Could not determine latest stable TeamViewer version from source."
        Write-Output "ERROR | Could not determine latest TeamViewer stable version"
        exit 0
    }

    $latestVerStr = Extract-VersionString $latestStr
    if ([string]::IsNullOrWhiteSpace($latestVerStr)) {
        Log "ERROR: Latest version parse failed. Raw latestStr='$latestStr'"
        Write-Output "ERROR | Could not parse latest TeamViewer stable version"
        exit 0
    }

    $latestV = [version]$latestVerStr
    Log "Latest stable TeamViewer version (parsed): $latestVerStr"

    $needsRemediation = $false
    $reasons = @()
    $foundSummaries = @()

    foreach ($a in $apps) {
        $name = $a.DisplayName
        $installedStr = Extract-VersionString $a.DisplayVersion

        if ([string]::IsNullOrWhiteSpace($installedStr)) {
            $needsRemediation = $true
            $foundSummaries += "$name (version unknown)"
            $reasons += "$name version missing/unparseable"
            Log "APP VERSION UNKNOWN: $name | Raw: '$($a.DisplayVersion)' (TRIGGER)"
            continue
        }

        $installedV = [version]$installedStr
        $foundSummaries += "$name $installedStr"
        Log "APP VERSION: $name | Installed: $installedStr"

        if ($installedV -lt $latestV) {
            $needsRemediation = $true
            $reasons += "$name ($installedStr < $latestVerStr)"
        }
    }

    if ($needsRemediation) {
        $foundText  = ($foundSummaries -join "; ")
        $reasonText = ($reasons -join "; ")
        Log "TRIGGER: Remediation required. Found=[$foundText] Reasons=[$reasonText]"
        Write-Output "TRIGGER | TeamViewer remediation required | Latest=$latestVerStr | Found=[$foundText] | Reasons=[$reasonText]"
        exit 0
    }

    $foundOk = ($foundSummaries -join "; ")
    Log "NO_ACTION: TeamViewer present and current. Latest=$latestVerStr Found=[$foundOk]"
    Write-Output "NO_ACTION | TeamViewer current | Latest=$latestVerStr | Found=[$foundOk]"
}
catch {
    Log "ERROR: $($_.Exception.Message)"
    Write-Output "ERROR | TeamViewer eval failed: $($_.Exception.Message)"
}

exit 0