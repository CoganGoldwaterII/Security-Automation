# ============================================================================
# NAME: Google Chrome - Version Evaluation
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LogPath  = C:\MME\AutoLogs\Chrome_Detect.log
#   Platform = win
#   Channel  = stable
# OUTPUT TOKENS:
#   TRIGGER   | Chrome outdated, API failure, or version parsing failure
#   NO_ACTION | Chrome not installed or installed version is current
#   ERROR     | Not emitted; detection failures produce TRIGGER
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\Chrome_Detect.log
# DESCRIPTION:
#   Evaluates the installed Google Chrome version against the latest
#   fully rolled-out Windows Stable release using Google's public
#   Chrome VersionHistory API.
#
#   Uses the VersionHistory releases endpoint with fraction=1 ONLY
#   to identify releases that have reached 100% rollout.
#
#   Detects Chrome through standard 64-bit and 32-bit installation paths
#   and compares the installed version against the authoritative release.
#
#   Reports TRIGGER when Chrome is outdated, the API cannot provide a
#   usable version, or version parsing fails.
#
#   Reports NO_ACTION when Chrome is not installed or the installed
#   version meets or exceeds the latest fully rolled-out Stable release.
#
#   Uses TLS 1.2 for API communication.
#   Always exits with code 0 for NinjaOne automation compatibility.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LogPath  = "C:\MME\AutoLogs\Chrome_Detect.log"
$Platform = "win"
$Channel  = "stable"

function Ensure-LogDir {
    $dir = Split-Path -Parent $LogPath
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}

function Log([string]$msg) {
    Ensure-LogDir
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $LogPath -Value "$ts [ChromeDetect] $msg"
}

function Emit([string]$line) {
    Write-Output $line
    exit 0
}

function Get-InstalledChromeVersion {
    $paths = @(
        "C:\Program Files\Google\Chrome\Application\chrome.exe",
        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Log "Found chrome.exe at: $p"
            $v = (Get-Item $p).VersionInfo.ProductVersion
            $v = ($v -as [string]).Trim()
            if ($v) { return $v }
        }
    }
    return $null
}

function Get-LatestStableFromVersionHistory {
    # SINGLE source of truth: 100% rollout Stable for Windows
    $url = "https://versionhistory.googleapis.com/v1/chrome/platforms/$Platform/channels/$Channel/versions/all/releases" +
           "?filter=fraction=1&order_by=version%20desc&pageSize=1"

    try {
        Log "Querying VersionHistory releases (fraction=1 ONLY): $url"
        $r = Invoke-RestMethod -Method Get -Uri $url -TimeoutSec 60

        if ($r -and $r.releases -and $r.releases.Count -ge 1 -and $r.releases[0].name) {
            $m = [regex]::Match($r.releases[0].name, "/versions/([0-9\.]+)/")
            if ($m.Success) { return $m.Groups[1].Value }
        }

        Log "No usable version returned from releases endpoint."
        return $null
    } catch {
        Log "ERROR: VersionHistory releases call failed: $($_.Exception.Message)"
        return $null
    }
}

Ensure-LogDir
Log "============================================================"
Log "Starting Chrome evaluation (VersionHistory API source, fraction=1 ONLY)..."

$installed = Get-InstalledChromeVersion
if (-not $installed) {
    Log "Chrome not installed."
    Emit "NO_ACTION | Chrome not installed"
}

Log "Installed Chrome version: $installed"

$latest = Get-LatestStableFromVersionHistory
if (-not $latest) {
    Log "UNKNOWN: could not determine latest stable (fraction=1) from VersionHistory API."
    Emit "TRIGGER | Unknown latest stable (API failure) - investigate"
}

Log "Latest stable (API, fraction=1): $latest"

try {
    $installedV = [version]$installed
    $latestV    = [version]$latest
} catch {
    Log "UNKNOWN: version parse failed. Installed='$installed' Latest='$latest'"
    Emit "TRIGGER | Unknown version parse (Installed='$installed' Latest='$latest') - investigate"
}

if ($installedV -lt $latestV) {
    Log "VULNERABLE: Installed ($installedV) < LatestStable ($latestV)"
    Emit "TRIGGER | Outdated Chrome ($installedV < $latestV)"
}

Log "NO_ACTION: Installed ($installedV) >= LatestStable ($latestV)"
Emit "NO_ACTION | Up-to-date ($installedV >= $latestV)"