# ============================================================================
# NAME: TeamViewer Update - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir      = C:\MME\AutoLogs
#   LedgerLimit = 4000
#   MaxLines    = 50
#   DlUrlX64    = https://download.teamviewer.com/download/TeamViewer_Setup_x64.exe
#   DlUrlX86    = https://download.teamviewer.com/download/TeamViewer_Setup.exe
# OUTPUT TOKENS:
#   RESULT    | TeamViewer updated successfully
#   NO_ACTION | TeamViewer absent or already current
#   ERROR     | Version lookup, installation, or verification failure
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\TeamViewer_Remediation.log
# DESCRIPTION:
#   Detects installed TeamViewer variants and compares versions against
#   the latest stable release obtained from public TeamViewer pages.
#   Downloads and silently installs the appropriate Windows installer.
#   Attempts removal and reinstallation of older versions when needed.
#   Verifies installation results and updates the NinjaOne remediation
#   ledger with capped entries. Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir      = "C:\MME\AutoLogs"
$LogFile     = Join-Path $LogDir "TeamViewer_Remediation.log"

# Caps
$LedgerLimit = 4000   # hard cap on field length (chars)
$MaxLines    = 50     # keep last N entries (lines)

$DlUrlX64 = "https://download.teamviewer.com/download/TeamViewer_Setup_x64.exe"
$DlUrlX86 = "https://download.teamviewer.com/download/TeamViewer_Setup.exe"

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

function Get-TeamViewerAppsRaw {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $apps = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and ($_.DisplayName -match '(?i)teamviewer') } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString, QuietUninstallString, PSPath
    }

    $apps | Sort-Object DisplayName, DisplayVersion -Unique
}

function Get-LatestTeamViewerVersion {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $urls = @(
        "https://www.teamviewer.com/en-us/download/previous-versions/previous-version-15x/",
        "https://www.teamviewer.com/en/download/previous-versions/previous-version-15x/",
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
            Log "Fetching latest stable version from: ${u}"
            $resp = Invoke-WebRequest -Uri $u -Headers $headers -MaximumRedirection 5 -TimeoutSec 25 -UseBasicParsing
            $html = $resp.Content

            $m = [regex]::Match($html, 'Current\s*version[^0-9]{0,80}([0-9]+(\.[0-9]+){1,3})', 'IgnoreCase')
            if ($m.Success) {
                $v = $m.Groups[1].Value
                Log "Parsed latest stable (page): $v"
                return $v
            }

            Log "Parse miss for ${u}"
        } catch {
            Log "Fetch error for ${u}: $($_.Exception.Message)"
        }
    }

    return $null
}

function Stop-TeamViewer {
    try {
        Log "Stopping TeamViewer processes..."
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "(?i)teamviewer" } |
            Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}

    try {
        Log "Stopping TeamViewer services..."
        Get-Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "(?i)teamviewer" -or $_.DisplayName -match "(?i)teamviewer" } |
            ForEach-Object {
                try { Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue } catch {}
            }
    } catch {}
}

function Run-TeamViewerInstaller([string]$installerPath) {
    Log "Running installer silently: $installerPath /S"
    $p = Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait -PassThru
    Log "Installer exit code: $($p.ExitCode)"
    return $p.ExitCode
}

function Try-UninstallTeamViewer($apps) {
    # Remove older TeamViewer entries (esp. v13/14) if in-place upgrade doesn't work.
    $didAnything = $false

    foreach ($a in $apps) {
        $name = $a.DisplayName
        $ver  = Extract-VersionString $a.DisplayVersion
        if (-not $ver) { $ver = "unknown" }

        $major = $null
        try { $major = ([version]$ver).Major } catch {}

        # Keep 15+ entries, target older majors only.
        if ($major -and $major -ge 15) { continue }

        $cmd = $a.QuietUninstallString
        if ([string]::IsNullOrWhiteSpace($cmd)) { $cmd = $a.UninstallString }
        if ([string]::IsNullOrWhiteSpace($cmd)) {
            Log "No uninstall command found for: $name ($ver)"
            continue
        }

        Log "Attempting uninstall for: $name ($ver) | Cmd: $cmd"

        # MSI uninstall
        if ($cmd -match '(?i)msiexec') {
            $guid = $null
            $m = [regex]::Match($cmd, '(\{[0-9A-Fa-f\-]{36}\})')
            if ($m.Success) { $guid = $m.Groups[1].Value }

            if ($guid) {
                $args = "/x $guid /qn /norestart"
                Log "Running: msiexec $args"
                $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
                Log "MSI uninstall exit code: $($p.ExitCode)"
                $didAnything = $true
                continue
            }
        }

        # EXE uninstall
        $exe  = $null
        $args = $null

        if ($cmd.StartsWith('"')) {
            $exe = $cmd.Split('"')[1]
            $args = $cmd.Substring($exe.Length + 2).Trim()
        } else {
            $parts = $cmd.Split(" ",2)
            $exe = $parts[0]
            $args = if ($parts.Count -gt 1) { $parts[1] } else { "" }
        }

        if ($args -notmatch '(?i)/S|/silent|/verysilent|/qn') {
            $args = ($args + " /S").Trim()
        }

        Log "Running: $exe $args"
        $p2 = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru
        Log "EXE uninstall exit code: $($p2.ExitCode)"
        $didAnything = $true
    }

    return $didAnything
}

function Set-NinjaField($name, $value) {
    try {
        if (Get-Command ninja-property-set -ErrorAction SilentlyContinue) {
            ninja-property-set $name "$value"
        } else {
            Log "Ninja CLI not found, skipping field set: $name"
        }
    } catch {
        Log "Failed setting Ninja field: $name"
    }
}

function Get-NinjaField($name) {
    try {
        if (Get-Command ninja-property-get -ErrorAction SilentlyContinue) {
            return (ninja-property-get $name 2>$null)
        }
    } catch {}
    return $null
}

function Append-RemediationSummary([string]$entry) {
    $existing = Get-NinjaField "remediationSummary"
    if ([string]::IsNullOrWhiteSpace($existing)) { $existing = "" }

    # Normalize newlines and split into non-empty lines
    $lines = @()
    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        $lines = $existing -split "(\r\n|\n|\r)" | Where-Object { $_ -and $_.Trim() -ne "" }
    }

    $newLine = $entry.Trim()

    # Optional de-dupe: don't append if identical to last line
    if ($lines.Count -gt 0 -and $lines[-1].Trim() -eq $newLine) {
        Log "RemediationSummary: last entry identical; skipping duplicate append."
        return
    }

    # Append new entry
    $lines += $newLine

    # Keep only the last N lines
    if ($lines.Count -gt $MaxLines) {
        $lines = $lines[-$MaxLines..-1]
    }

    # Rebuild with clean CRLF
    $combined = ($lines -join "`r`n").Trim()

    # Hard cap too (belt + suspenders)
    if ($combined.Length -gt $LedgerLimit) {
        $combined = $combined.Substring($combined.Length - $LedgerLimit)
        # Try to start at a newline boundary if we clipped mid-line
        $idx = $combined.IndexOf("`n")
        if ($idx -gt 0 -and $idx -lt 200) { $combined = $combined.Substring($idx + 1) }
        $combined = $combined.Trim()
    }

    Set-NinjaField "remediationSummary" $combined
}

function Get-HighestTeamViewerVersion([object[]]$apps) {
    $best = $null
    foreach ($a in $apps) {
        $vStr = Extract-VersionString $a.DisplayVersion
        if (-not $vStr) { continue }
        try {
            $v = [version]$vStr
            if (-not $best -or $v -gt $best) { $best = $v }
        } catch {}
    }
    return $best
}

function Get-AppSummary([object[]]$apps) {
    if (-not $apps -or $apps.Count -eq 0) { return "not detected" }
    return (($apps | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" }) -join "; ")
}

# -------- START --------
Ensure-Dir $LogDir
Log "==== TeamViewer remediation start ===="

try {
    # FORCE ARRAY to avoid single-object .Count bugs
    $appsBefore = @(Get-TeamViewerAppsRaw)
    Log "DEBUG appsBefore count=$($appsBefore.Count)"

    if ($appsBefore.Count -eq 0) {
        Log "NO_ACTION: No TeamViewer apps found."
        Write-Output "NO_ACTION | TeamViewer not installed"
        exit 0
    }

    foreach ($a in $appsBefore) {
        Log "FOUND (pre): $($a.DisplayName) | DisplayVersion: '$($a.DisplayVersion)'"
    }

    $latestStr = Get-LatestTeamViewerVersion
    if ([string]::IsNullOrWhiteSpace($latestStr)) {
        Log "ERROR: Could not determine latest stable TeamViewer version."
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

    # Lightweight need check
    $highestBefore = Get-HighestTeamViewerVersion -apps $appsBefore
    if ($highestBefore -and $highestBefore -ge $latestV) {
        Log "NO_ACTION: Already current. HighestInstalled=$highestBefore >= LatestParsed=$latestV"
        Write-Output "NO_ACTION | TeamViewer already current (>= $latestVerStr)"
        exit 0
    }

    Stop-TeamViewer

    # Download installer
    $is64 = [Environment]::Is64BitOperatingSystem
    $dl = if ($is64) { $DlUrlX64 } else { $DlUrlX86 }
    $tmp = Join-Path $env:TEMP ("TeamViewer_Setup_" + [guid]::NewGuid().ToString() + ".exe")

    Log "Downloading installer: $dl -> $tmp"
    Invoke-WebRequest -Uri $dl -UseBasicParsing -TimeoutSec 180 -OutFile $tmp

    # Attempt in-place update
    $ec = Run-TeamViewerInstaller -installerPath $tmp
    Start-Sleep -Seconds 10

    # Mid snapshot
    $appsMid = @(Get-TeamViewerAppsRaw)
    Log "DEBUG appsMid count=$($appsMid.Count)"

    $highestMid = Get-HighestTeamViewerVersion -apps $appsMid

    $stillBelowParsed = $true
    if ($highestMid -and $highestMid -ge $latestV) { $stillBelowParsed = $false }

    $olderMajorsExist = $false
    foreach ($a in $appsMid) {
        $vStr = Extract-VersionString $a.DisplayVersion
        if (-not $vStr) { continue }
        try {
            if (([version]$vStr).Major -lt 15) { $olderMajorsExist = $true; break }
        } catch {}
    }

    if ($stillBelowParsed -or $olderMajorsExist) {
        Log "In-place update insufficient (stillBelowParsed=$stillBelowParsed, olderMajorsExist=$olderMajorsExist). Attempting uninstall of old versions then reinstall..."
        Stop-TeamViewer
        $didUninstall = Try-UninstallTeamViewer -apps $appsMid
        Log "Uninstall attempted: $didUninstall"
        Start-Sleep -Seconds 8
        Stop-TeamViewer
        $ec2 = Run-TeamViewerInstaller -installerPath $tmp
        Log "Reinstall attempt exit code: $ec2"
        Start-Sleep -Seconds 10
    }

    # Cleanup installer
    Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue

    # Final verification
    $appsAfter = @(Get-TeamViewerAppsRaw)
    Log "DEBUG appsAfter count=$($appsAfter.Count)"

    $afterSummary = Get-AppSummary -apps $appsAfter
    Log "FOUND (post): $afterSummary"

    $highestAfter = Get-HighestTeamViewerVersion -apps $appsAfter

    # Success criteria:
    # 1) TeamViewer exists post-remediation
    # 2) highest installed version >= parsed latest (allow newer)
    # 3) no older (<15) majors remain (prevents "15 installed but left v13 behind")
    $success = $true

    if ($appsAfter.Count -eq 0) { $success = $false }

    if (-not $highestAfter) { $success = $false }
    elseif ($highestAfter -lt $latestV) { $success = $false }

    foreach ($a in $appsAfter) {
        $vStr = Extract-VersionString $a.DisplayVersion
        if (-not $vStr) { continue }
        try {
            if (([version]$vStr).Major -lt 15) { $success = $false; break }
        } catch {}
    }

    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Set-NinjaField "lastRemediationDate" $now

    if (-not $success) {
        $entry = "$now - TeamViewer update FAILED. LatestParsed=$latestVerStr | HighestInstalled=$highestAfter | Post=[$afterSummary]"
        Append-RemediationSummary $entry
        Log "ERROR: Post-check indicates not compliant."
        Write-Output "ERROR | TeamViewer update failed (Latest=$latestVerStr) | Post=[$afterSummary]"
        exit 0
    }

    $entryOk = "$now - TeamViewer updated successfully. LatestParsed=$latestVerStr | HighestInstalled=$highestAfter | Post=[$afterSummary]"
    Append-RemediationSummary $entryOk

    Log "RESULT: TeamViewer updated successfully."
    Write-Output "RESULT | TeamViewer updated successfully (Latest=$latestVerStr) | Post=[$afterSummary]"

} catch {
    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Set-NinjaField "lastRemediationDate" $now
    Append-RemediationSummary "$now - TeamViewer remediation ERROR: $($_.Exception.Message)"

    Log "ERROR: $($_.Exception.Message)"
    Write-Output "ERROR | TeamViewer remediation failed: $($_.Exception.Message)"
}

exit 0