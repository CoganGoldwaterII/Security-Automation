# ============================================================================
# NAME: SentinelOne + LogMeIn Antivirus - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   TRIGGER   | SentinelOne and LogMeIn Antivirus both detected
#   TRIGGER   | Evaluation error (fail-safe)
#   NO_ACTION | One or both products not detected
#   ERROR     | Not emitted; evaluation errors produce TRIGGER
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\Eval-S1-And-LAV.log
# DESCRIPTION:
#   Evaluates Windows endpoints for simultaneous installation of
#   SentinelOne and LogMeIn Antivirus.
#
#   Detects SentinelOne through Windows uninstall registry entries,
#   validates the publisher, and checks for Sentinel Agent files.
#
#   Uses strict product-name matching for LogMeIn Antivirus to avoid
#   false positives from other LogMeIn applications.
#
#   Reports TRIGGER only when both security products are detected
#   or when an unhandled evaluation error occurs.
#
#   Reports NO_ACTION when either product is absent.
#   Logs detection results and LogMeIn Antivirus version information.
#
#   Always exits with code 0 for NinjaOne automation compatibility.
# ============================================================================

# -------- GLOBAL LOG LOCATION --------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "Eval-S1-And-LAV.log"

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts | $Message"
    try {
        if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
        Add-Content -Path $LogFile -Value $line
    } catch { Write-Output $line }
}

function Emit {
    param(
        [ValidateSet("TRIGGER","NO_ACTION")]
        [string]$Token,
        [string]$Detail
    )
    $out = "$Token | $Detail"
    Write-Output $out
    Write-Log $out
    exit 0
}

function Get-UninstallEntriesLike {
    param([string]$LikePattern)

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $hits = @()
    foreach ($path in $regPaths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $dn = ($_.DisplayName | ForEach-Object { "$_" }).Trim()
                if ($dn -and ($dn -like $LikePattern)) {
                    $hits += [pscustomobject]@{
                        DisplayName    = $dn
                        DisplayVersion = $_.DisplayVersion
                        Publisher      = ($_.Publisher | ForEach-Object { "$_" }).Trim()
                    }
                }
            }
        } catch { }
    }
    $hits
}

function Test-SentinelOneInstalled {
    # Look for Sentinel Agent or SentinelOne entries
    $hits = @()
    $hits += Get-UninstallEntriesLike -LikePattern "*Sentinel Agent*"
    $hits += Get-UninstallEntriesLike -LikePattern "*SentinelOne*"

    # Require Publisher to actually be SentinelOne
    if ($hits | Where-Object { $_.Publisher -match '^(?i)SentinelOne' }) {
        return $true
    }

    # Strong file-based detection
    if (Test-Path "C:\Program Files\SentinelOne\Sentinel Agent*\sentinelctl.exe") {
        return $true
    }

    return $false
}

function Get-LAVStrict {
    # Strict match prevents LogMeIn client collisions
    $strictRegex = '^(?i)LogMeIn Antivirus(\b|$)'

    $hits = Get-UninstallEntriesLike -LikePattern "*LogMeIn*"
    foreach ($h in $hits) {
        if ($h.DisplayName -match $strictRegex) {
            return $h
        }
    }
    return $null
}

try {
    Write-Log "=== Starting eval: TRIGGER only when SentinelOne + LogMeIn Antivirus ==="

    $hasS1  = Test-SentinelOneInstalled
    $lav    = Get-LAVStrict
    $hasLAV = ($null -ne $lav)

    Write-Log "SentinelOneDetected=$hasS1"
    Write-Log "LAVDetected_Strict=$hasLAV"
    if ($hasLAV) { Write-Log "LAVVersion=$($lav.DisplayVersion)" }

    if ($hasS1 -and $hasLAV) {
        Emit -Token "TRIGGER" -Detail ("S1=YES | LAV=YES | LAV_VER={0}" -f $lav.DisplayVersion)
    }

    Emit -Token "NO_ACTION" -Detail ("S1={0} | LAV={1}" -f ($(if($hasS1){"YES"}else{"NO"}), $(if($hasLAV){"YES"}else{"NO"})))
}
catch {
    Emit -Token "TRIGGER" -Detail ("Eval error: {0}" -f $_.Exception.Message)
}