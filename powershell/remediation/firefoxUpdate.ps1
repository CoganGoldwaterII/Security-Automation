# ============================================================================
# NAME: Firefox Update - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir    = C:\MME\AutoLogs
#   LogFile   = C:\MME\AutoLogs\Firefox_Remediation.log
#   Installer = %TEMP%\Firefox_Setup.exe
# OUTPUT TOKENS:
#   RESULT | UPDATED
#   RESULT | ERROR
#   NO_ACTION | Not emitted
# CUSTOM FIELDS:
#   Reads: remediationSummary (Multi-line, via append operation)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\Firefox_Remediation.log
# DESCRIPTION:
#   Downloads the latest stable Firefox installer directly from Mozilla.
#   Stops running Firefox processes and performs a silent installation.
#   Relies on a separate evaluation script to determine remediation need.
#   Attempts to update NinjaOne remediation tracking fields.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "Firefox_Remediation.log"
$Installer = "$env:TEMP\Firefox_Setup.exe"

# -------- HELPERS --------
function Ensure-Dir($p) {
    if (!(Test-Path $p)) {
        New-Item -ItemType Directory -Path $p -Force | Out-Null
    }
}

function Write-Log {
    param([string]$Message)
    Ensure-Dir $LogDir
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [FirefoxFix] $Message"
}

function Update-Ledger {
    try {
        $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # lastRemediationDate overwrite
        Ninja-Property-Set lastRemediationDate $now

        # remediationSummary append
        $entry = "$now - Firefox updated"
        Ninja-Property-Append remediationSummary $entry
    } catch {
        Write-Log "Ledger update failed: $_"
    }
}

# -------- MAIN --------
Write-Log "Starting Firefox remediation..."

try {
    Write-Log "Stopping Firefox processes..."
    Get-Process firefox -ErrorAction SilentlyContinue | Stop-Process -Force

    Write-Log "Downloading latest Firefox installer..."
    Invoke-WebRequest `
        -Uri "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US" `
        -OutFile $Installer

    Write-Log "Running silent installer..."
    Start-Process -FilePath $Installer -ArgumentList "-ms" -Wait

    Write-Log "Firefox installation completed."

    Update-Ledger

    Write-Output "RESULT | UPDATED"
    exit 0
}
catch {
    Write-Log "Remediation failed: $_"
    Write-Output "RESULT | ERROR"
    exit 0
}