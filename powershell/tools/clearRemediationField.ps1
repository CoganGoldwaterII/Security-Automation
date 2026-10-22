# ============================================================================
# NAME: NinjaOne Remediation Ledger - Clear
# AUTHORED BY: Cogan Goldwater
# TYPE: Maintenance
# SCOPE: Windows endpoints / NinjaOne maintenance automation
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   RESULT | CLEARED
#   RESULT | ERROR
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#   Writes:
#     remediationSummary (Multi-line)
#   Unchanged:
#     lastRemediationDate (Text)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\Clear_RemediationSummary.log
# DESCRIPTION:
#   Manually clears the NinjaOne remediationSummary device custom field.
#   Intended for monthly maintenance of the running remediation ledger.
#   Logs the previous field length without exposing its contents.
#   Performs a best-effort readback verification after clearing.
#   Leaves lastRemediationDate unchanged.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"

$LogDir  = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogDir "Clear_RemediationSummary.log"

function Ensure-Dir($path) {
    $dir = Split-Path $path -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Write-Log($msg) {
    Ensure-Dir $LogPath
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogPath -Value "$ts | $msg"
}

Write-Log "==== START Clear remediationSummary ===="

try {
    # Read current value (best-effort) just for logging
    $current = $null
    try { $current = Ninja-Property-Get remediationSummary } catch { $current = $null }

    if ([string]::IsNullOrWhiteSpace($current)) {
        Write-Log "remediationSummary already empty."
    } else {
        # Log size only (avoid dumping potentially huge content)
        Write-Log ("remediationSummary current length: {0} chars" -f $current.Length)
    }

    # Clear the multi-line field
    Ninja-Property-Set remediationSummary ""

    # Verify (best-effort)
    $after = $null
    try { $after = Ninja-Property-Get remediationSummary } catch { $after = $null }
    if (-not [string]::IsNullOrWhiteSpace($after)) {
        Write-Log "WARNING: remediationSummary did not read back as empty (may be replication delay)."
    } else {
        Write-Log "remediationSummary cleared."
    }

    Write-Output "RESULT | CLEARED"
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Output "RESULT | ERROR"
    exit 0
}