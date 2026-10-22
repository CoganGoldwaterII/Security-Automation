# ============================================================================
# NAME: Microsoft 365 Apps for Business Evaluation
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   TRIGGER   | Microsoft 365 Apps for business not detected
#   NO_ACTION | Microsoft 365 Apps for business detected
#   ERROR     | Unexpected script error occurred
#
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   C:\MME\AutoLogs\M365Business_Eval.log
#
# DESCRIPTION:
#   Evaluates Windows endpoints for Microsoft 365 Apps for business.
#
#   Detection methods:
#     - 64-bit installed application registry entries
#     - 32-bit installed application registry entries
#     - Microsoft Office Click-to-Run product configuration
#
#   Target application display name:
#     Microsoft 365 Apps for business - en-us
#
#   Target Click-to-Run product ID:
#     O365BusinessRetail
#
#   Returns NO_ACTION when either the exact application display
#   name or the target Click-to-Run product ID is detected.
#
#   Returns TRIGGER when neither detection method identifies
#   Microsoft 365 Apps for business.
#
#   Returns ERROR when an unexpected terminating exception occurs.
#
#   Read-only evaluation. No remediation is performed.
#
#   EXIT CODES:
#     TRIGGER:   0
#     NO_ACTION: 0
#     ERROR:     1
#
#   NOTE:
#   Existing error exit behavior is preserved.
#   This does not fully comply with the NinjaOne requirement
#   to always exit 0.
# ============================================================================

$ErrorActionPreference = "Stop"

$LogRoot = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogRoot "M365Business_Eval.log"

$TargetName = "Microsoft 365 Apps for business - en-us"
$TargetProductId = "O365BusinessRetail"

New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null

function Write-Log {
    param([string]$Message)

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

try {
    Write-Log "Starting Microsoft 365 Apps for business evaluation."

    $DisplayNameHit = $false
    $ProductIdHit = $false
    $Evidence = @()

    # Primary check: Programs & Features uninstall registry
    $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($Path in $UninstallPaths) {
        $Matches = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $TargetName }

        foreach ($Match in $Matches) {
            $DisplayNameHit = $true
            $Evidence += "DisplayName=$($Match.DisplayName); Version=$($Match.DisplayVersion)"
        }
    }

    # Secondary check: Office Click-to-Run product configuration
    $CtrPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"

    if (Test-Path $CtrPath) {
        $Ctr = Get-ItemProperty -Path $CtrPath -ErrorAction SilentlyContinue
        $ProductReleaseIds = $Ctr.ProductReleaseIds

        if ($ProductReleaseIds -match $TargetProductId) {
            $ProductIdHit = $true
            $Evidence += "ProductReleaseIds=$ProductReleaseIds"
        }
        else {
            Write-Log "Click-to-Run config found, but target product ID not detected. ProductReleaseIds=$ProductReleaseIds"
        }
    }
    else {
        Write-Log "Click-to-Run configuration key not found."
    }

    if ($DisplayNameHit -or $ProductIdHit) {
        $EvidenceText = if ($Evidence.Count -gt 0) { $Evidence -join " | " } else { "Evidence unavailable" }

        Write-Log "NO_ACTION | Microsoft 365 Apps for business detected. $EvidenceText"
        Write-Host "NO_ACTION | Microsoft 365 Apps for business detected"
        exit 0
    }
    else {
        Write-Log "TRIGGER | Microsoft 365 Apps for business not detected"
        Write-Host "TRIGGER | Microsoft 365 Apps for business not detected"
        exit 0
    }
}
catch {
    Write-Log "ERROR | $($_.Exception.Message)"
    Write-Host "ERROR | $($_.Exception.Message)"
    exit 1
}