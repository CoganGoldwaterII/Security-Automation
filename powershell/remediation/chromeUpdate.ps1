# ============================================================================
# NAME: Google Chrome - Update Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogPath  = C:\Temp\Chrome_Update.log
#   TempDir  = C:\Temp
#   MsiUrl   = https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi
#   MsiPath  = C:\Temp\googlechromestandaloneenterprise64.msi
#   Platform = win
#   Channel  = stable
# OUTPUT TOKENS:
#   RESULT: UPDATED       | Chrome successfully updated
#   RESULT: NO_ACTION     | Chrome already meets/exceeds target version
#   RESULT: NOT_INSTALLED | Chrome not installed; installation skipped
#   RESULT: ERROR         | Download, installation, or verification failure
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
#   Installer downloaded directly from Google's public download endpoint.
# LOGGING PATH:
#   C:\Temp\Chrome_Update.log
# DESCRIPTION:
#   Updates an existing Google Chrome installation using the official
#   Google Chrome Enterprise MSI installer.
#
#   Queries Google's Chrome VersionHistory API to determine the latest
#   fully rolled-out Windows Stable release (fraction=1 ONLY).
#
#   Compares the installed Chrome version against the authoritative
#   release and skips remediation when already current.
#
#   Stops running Chrome processes before downloading and installing
#   the Enterprise MSI silently without initiating a reboot.
#
#   Verifies the installed version after remediation and reports
#   UPDATED only when the installed version meets or exceeds the
#   authoritative Stable release.
#
#   Does not install Chrome when it is absent.
#   Uses TLS 1.2 for HTTPS communication.
#   Always exits with code 0 for NinjaOne automation compatibility.
# ============================================================================

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LogPath  = "C:\Temp\Chrome_Update.log"
$TempDir  = "C:\Temp"
$MsiUrl   = "https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi"
$MsiPath  = Join-Path $TempDir "googlechromestandaloneenterprise64.msi"

$Platform = "win"
$Channel  = "stable"

function Ensure-Temp {
    if (-not (Test-Path $TempDir)) { New-Item -Path $TempDir -ItemType Directory -Force | Out-Null }
}

function Log([string]$msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Ensure-Temp
    Add-Content -Path $LogPath -Value "$ts [ChromeFix] $msg"
}

function Finish([string]$result, [string]$reason) {
    if ($reason) { Log "REASON: $reason" }
    Log "RESULT: $result"
    Write-Output "RESULT: $result"
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

function Kill-Chrome {
    Log "Stopping chrome.exe (if any)..."
    Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

function Download-Msi {
    Log "Downloading Enterprise MSI..."
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop

    $bytes = (Get-Item $MsiPath -ErrorAction Stop).Length
    Log "MSI bytes: $bytes"
    if ($bytes -lt 5MB) { throw "MSI download too small ($bytes bytes)" }
}

function Install-Msi {
    Log "Installing MSI silently..."
    $args = "/i `"$MsiPath`" /qn /norestart"
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru -ErrorAction Stop
    Log "msiexec exit code: $($p.ExitCode)"
    return $p.ExitCode
}

try {
    Ensure-Temp
    Log "============================================================"
    Log "Starting Chrome remediation (MSI + VersionHistory comparator, fraction=1 ONLY)..."

    $installed = Get-InstalledChromeVersion
    if (-not $installed) {
        Finish "NOT_INSTALLED" "chrome.exe not found; will not install Chrome."
    }

    Log "Installed Chrome version (pre): $installed"

    $latest = Get-LatestStableFromVersionHistory
    if (-not $latest) {
        Finish "ERROR" "Could not determine latest stable (fraction=1) from VersionHistory API."
    }

    Log "Latest stable (API, fraction=1): $latest"

    try {
        $installedV = [version]$installed
        $latestV    = [version]$latest
    } catch {
        Finish "ERROR" "Version parse failed. Installed='$installed' Latest='$latest'"
    }

    if ($installedV -ge $latestV) {
        Finish "NO_ACTION" "Already meets/exceeds latest stable ($installedV >= $latestV)."
    }

    Kill-Chrome
    Download-Msi

    $exitCode = Install-Msi
    if ($exitCode -ne 0) {
        Finish "ERROR" "msiexec failed with exit code $exitCode"
    }

    Start-Sleep -Seconds 5
    $after = Get-InstalledChromeVersion
    if (-not $after) {
        Finish "ERROR" "Chrome missing after install (unexpected)."
    }

    Log "Installed Chrome version (post): $after"

    try {
        $afterV  = [version]$after
        $latestV = [version]$latest
    } catch {
        Finish "ERROR" "Post version parse failed. Post='$after' Latest='$latest'"
    }

    if ($afterV -ge $latestV) {
        Finish "UPDATED" "Updated to $afterV (>= latest stable $latestV)."
    }

    # If this happens, it's not Early Stable anymore (we filtered it out).
    # This means the installer didn't move the needle (locked down endpoint, broken updater, etc.).
    Finish "ERROR" "Install completed but still below latest stable ($afterV < $latestV)."
}
catch {
    Finish "ERROR" "Unhandled exception: $($_.Exception.Message)"
}