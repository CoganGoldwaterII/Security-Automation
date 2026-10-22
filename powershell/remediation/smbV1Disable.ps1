# ============================================================================
# NAME: SMBv1 Disable + Midnight Reboot - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir   = C:\MME\AutoLogs
#   LogFile  = C:\MME\AutoLogs\SMBv1_Remediation.log
#   TaskName = MME-Reboot-SMBv1
# OUTPUT TOKENS:
#   RESULT | SMBv1 disable applied
#   ERROR  | SMBv1 remediation failed
#   NO_ACTION | Not emitted
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\SMBv1_Remediation.log
# DESCRIPTION:
#   Disables enabled SMBv1 Windows optional features and attempts to
#   disable SMBv1 server protocol support.
#   Schedules a one-time forced reboot at the next local midnight
#   using a SYSTEM scheduled task.
#   Relies on a separate evaluation script to determine remediation need.
#   Does not perform additional usage or compliance checks.
#   Always exits 0.
# WARNING:
#   The scheduled reboot forcibly closes running applications and may
#   interrupt active sessions. Confirm the maintenance window before use.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir   = "C:\MME\AutoLogs"
$LogFile  = Join-Path $LogDir "SMBv1_Remediation.log"
$TaskName = "MME-Reboot-SMBv1"

# -------- HELPERS --------
function Ensure-Dir($p) {
    if (!(Test-Path $p)) {
        New-Item -Path $p -ItemType Directory -Force | Out-Null
    }
}

function Write-Log($m) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts | $m"
}

Ensure-Dir $LogDir
Write-Log "=== START SMBv1 remediation ==="

try {
    # Disable SMBv1 optional features
    $features = Get-WindowsOptionalFeature -Online |
        Where-Object { $_.FeatureName -like "SMB1Protocol*" -and $_.State -eq "Enabled" }

    foreach ($f in $features) {
        Write-Log "Disabling feature: $($f.FeatureName)"
        Disable-WindowsOptionalFeature -Online -FeatureName $f.FeatureName -NoRestart | Out-Null
    }

    # Disable SMBv1 server protocol (best effort)
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
        Write-Log "Server config SMBv1 disabled"
    } catch {
        Write-Log "Server config change not supported on this OS"
    }

    # Schedule reboot at next midnight
    $nextMidnight = (Get-Date).Date.AddDays(1)
    $sd = $nextMidnight.ToString("MM/dd/yyyy")

    schtasks /Create `
        /TN $TaskName `
        /SC ONCE `
        /SD $sd `
        /ST 00:00 `
        /RU SYSTEM `
        /RL HIGHEST `
        /F `
        /TR 'shutdown.exe /r /t 0 /f' | Out-Null

    Write-Log "Reboot scheduled for $($nextMidnight.ToString('yyyy-MM-dd')) 00:00"

    Write-Output "RESULT | SMBv1 disable applied"
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Output "ERROR | SMBv1 remediation failed"
    exit 0
}