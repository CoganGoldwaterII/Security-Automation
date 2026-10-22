# ============================================================================
# NAME: Zoom Version Evaluation - Windows
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LogDir           = C:\MME\AutoLogs
#   LogFile          = C:\MME\AutoLogs\Zoom_Eval.log
#   ZoomLatestMsiUrl = https://zoom.us/client/latest/ZoomInstallerFull.msi
# OUTPUT TOKENS:
#   TRIGGER   | Outdated Zoom detected
#   NO_ACTION | Zoom current or not installed
#   ERROR     | Latest version unavailable or evaluation failure
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\Zoom_Eval.log
# DESCRIPTION:
#   Detects installed Zoom versions through HKLM/HKU uninstall entries
#   and user profile executable paths.
#   Resolves the public Zoom MSI URL to determine the latest version.
#   Compares the highest detected installed version against the latest.
#   Reports TRIGGER when outdated and NO_ACTION when current or absent.
#   Runs under SYSTEM and always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "Zoom_Eval.log"
$ZoomLatestMsiUrl = "https://zoom.us/client/latest/ZoomInstallerFull.msi"

# -------- HELPERS --------
function Ensure-Dir($p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts | $Message"
}
function Parse-VersionFromString {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $m = [regex]::Match($s, '(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+)')
    if ($m.Success) {
        try { return [version]$m.Groups[1].Value } catch { return $null }
    }
    return $null
}
function Get-LatestZoomVersion {
    try {
        $req = [System.Net.HttpWebRequest]::Create($ZoomLatestMsiUrl)
        $req.Method = "GET"
        $req.AllowAutoRedirect = $true
        $req.MaximumAutomaticRedirections = 10
        $req.Timeout = 25000
        $req.UserAgent = "Mozilla/5.0"
        $req.KeepAlive = $false

        $resp = $req.GetResponse()
        $finalUrl = $resp.ResponseUri.AbsoluteUri
        $resp.Close()

        Write-Log "Latest MSI resolved to: $finalUrl"
        return (Parse-VersionFromString $finalUrl)
    }
    catch {
        Write-Log "Failed to resolve latest MSI URL: $($_.Exception.Message)"
        return $null
    }
}

# -------- START --------
Ensure-Dir $LogDir
Write-Log "=== Zoom version evaluation start (SYSTEM-safe) ==="

try {
    $installedVersions = New-Object System.Collections.Generic.List[version]

    # HKLM uninstall keys
    $hklmPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $hklmPaths) {
        $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            if ($null -ne $app.DisplayName -and $app.DisplayName -match '^Zoom(\b|$)|Zoom Workplace|Zoom Meetings') {
                $v = Parse-VersionFromString $app.DisplayVersion
                if ($v) {
                    Write-Log "Installed via HKLM: $($app.DisplayName) $($app.DisplayVersion) -> $v"
                    $installedVersions.Add($v) | Out-Null
                }
            }
        }
    }

    # HKU uninstall keys
    $userSids = Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
        Select-Object -ExpandProperty PSChildName

    foreach ($sid in $userSids) {
        $userUninstall = "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $apps = Get-ItemProperty $userUninstall -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            if ($null -ne $app.DisplayName -and $app.DisplayName -match '^Zoom(\b|$)|Zoom Workplace|Zoom Meetings') {
                $v = Parse-VersionFromString $app.DisplayVersion
                if ($v) {
                    Write-Log "Installed via HKU($sid): $($app.DisplayName) $($app.DisplayVersion) -> $v"
                    $installedVersions.Add($v) | Out-Null
                }
            }
        }
    }

    # File fallback
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }

    foreach ($p in $profiles) {
        $candidates = @(
            (Join-Path $p.FullName "AppData\Roaming\Zoom\bin\Zoom.exe"),
            (Join-Path $p.FullName "AppData\Local\Zoom\bin\Zoom.exe")
        )

        foreach ($exe in $candidates) {
            if (Test-Path $exe) {
                try {
                    $pv = (Get-Item $exe).VersionInfo.ProductVersion
                    $v = Parse-VersionFromString $pv
                    if ($v) {
                        Write-Log "Installed via file: $exe $pv -> $v"
                        $installedVersions.Add($v) | Out-Null
                    }
                } catch {}
            }
        }
    }

    if ($installedVersions.Count -eq 0) {
        Write-Log "Evaluation result: NO_ACTION (Zoom not installed)"
        Write-Output "NO_ACTION | Zoom not installed"
        Write-Log "=== Zoom version evaluation end ==="
        exit 0
    }

    $installed = ($installedVersions | Sort-Object -Descending | Select-Object -First 1)
    Write-Log "Installed version chosen: $installed"

    $latest = Get-LatestZoomVersion
    if (-not $latest) {
        Write-Log "Evaluation result: ERROR (unable to determine latest)"
        Write-Output "ERROR | Unable to determine latest Zoom version"
        Write-Log "=== Zoom version evaluation end ==="
        exit 0
    }

    Write-Log "Latest version (public): $latest"

    if ($installed -lt $latest) {
        Write-Log "Evaluation result: TRIGGER ($installed < $latest)"
        Write-Output "TRIGGER | Outdated Zoom ($installed < $latest)"
    } else {
        Write-Log "Evaluation result: NO_ACTION ($installed >= $latest)"
        Write-Output "NO_ACTION | Zoom is current ($installed >= $latest)"
    }
}
catch {
    $msg = $_.Exception.Message
    Write-Log "ERROR (exception): $msg"
    Write-Log ("ERROR (full): " + ($_ | Out-String))
    Write-Output "ERROR | Evaluation failure: $msg"
}

Write-Log "=== Zoom version evaluation end ==="
exit 0