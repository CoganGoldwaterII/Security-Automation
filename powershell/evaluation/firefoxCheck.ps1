# ============================================================================
# NAME: Firefox Version Check - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LogDir  = C:\MME\AutoLogs
#   LogFile = C:\MME\AutoLogs\Firefox_Eval.log
# OUTPUT TOKENS:
#   TRIGGER   | Firefox outdated
#   NO_ACTION | Firefox current or not installed
#   NO_ACTION | Evaluation error
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\Firefox_Eval.log
# DESCRIPTION:
#   Detects the installed Firefox version using Mozilla registry entries.
#   Queries Mozilla's public product-details API for the latest Firefox
#   release and compares the installed version against it.
#   Triggers remediation when Firefox is outdated.
#   Reports NO_ACTION when Firefox is absent, current, or evaluation fails.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "Firefox_Eval.log"

# -------- HELPERS --------
function Ensure-Dir($p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Write-Log {
    param([string]$Message)
    Ensure-Dir $LogDir
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [FirefoxEval] $Message"
}

function Normalize-VersionString {
    param([string]$s)

    if ([string]::IsNullOrWhiteSpace($s)) { return $null }

    # Extract first "digits.digits[.digits[.digits]]" token (e.g., 146.0.1)
    $m = [regex]::Match($s, '\d+(\.\d+){1,3}')
    if ($m.Success) { return $m.Value }

    return $null
}

function Get-FirefoxVersionRaw {
    $paths = @(
        "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox",
        "HKLM:\SOFTWARE\WOW6432Node\Mozilla\Mozilla Firefox"
    )

    foreach ($p in $paths) {
        if (Test-Path $p) {
            try { return (Get-ItemProperty $p)."CurrentVersion" } catch {}
        }
    }
    return $null
}

# -------- MAIN --------
Write-Log "Starting Firefox evaluation..."

try {
    $rawInstalled = Get-FirefoxVersionRaw

    if (-not $rawInstalled) {
        Write-Log "Firefox not installed."
        Write-Output "NO_ACTION | Firefox not installed"
        exit 0
    }

    $installedStr = Normalize-VersionString $rawInstalled
    Write-Log "Installed Firefox version (raw): $rawInstalled"
    Write-Log "Installed Firefox version (parsed): $installedStr"

    if (-not $installedStr) {
        Write-Log "Could not parse installed Firefox version."
        Write-Output "NO_ACTION | Evaluation error (cannot parse installed version)"
        exit 0
    }

    $apiUrl = "https://product-details.mozilla.org/1.0/firefox_versions.json"
    Write-Log "Querying Mozilla version endpoint..."

    $latestRaw = (Invoke-RestMethod -Uri $apiUrl -UseBasicParsing).LATEST_FIREFOX_VERSION
    $latestStr = Normalize-VersionString $latestRaw

    Write-Log "Latest Firefox version (raw): $latestRaw"
    Write-Log "Latest Firefox version (parsed): $latestStr"

    if (-not $latestStr) {
        Write-Log "Could not parse latest Firefox version."
        Write-Output "NO_ACTION | Evaluation error (cannot parse latest version)"
        exit 0
    }

    if ([version]$installedStr -lt [version]$latestStr) {
        Write-Log "Firefox outdated."
        Write-Output "TRIGGER | Firefox outdated ($installedStr < $latestStr)"
        exit 0
    }

    Write-Log "Firefox current."
    Write-Output "NO_ACTION | Firefox current ($installedStr)"
    exit 0
}
catch {
    Write-Log "Evaluation error: $_"
    Write-Output "NO_ACTION | Evaluation error"
    exit 0
}