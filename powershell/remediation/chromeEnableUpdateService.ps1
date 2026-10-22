# ============================================================================
# NAME: Google Chrome - Re-enable Update Services
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Testing Utility
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir  = C:\MME\AutoLogs
#   LogFile = C:\MME\AutoLogs\ReEnable-Chrome-Updates.log
# OUTPUT TOKENS:
#   None; script writes diagnostic information to the log.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\ReEnable-Chrome-Updates.log
# DESCRIPTION:
#   Re-enables Google Update scheduled tasks and restores Google Update
#   services after controlled Chrome update testing.
#
#   Attempts to enable GoogleUpdateTaskMachineCore and
#   GoogleUpdateTaskMachineUA scheduled tasks.
#
#   Sets gupdate and gupdatem services to Automatic startup and starts
#   them when they are not already running.
#
#   Logs attempted operations and encountered errors.
#   Does not remove previously configured Google Update policies.
#
#   Intended to restore update functionality following testing.
#   Contains an explicit exit 0 on normal completion.
# ============================================================================

# ==========================================
# Re-enable Google Chrome Update Services
# Logs to C:\Temp
# Always exit 0
# ==========================================

$LogDir  = "C:\MME\AutoLogs"
$LogFile = "$LogDir\ReEnable-Chrome-Updates.log"

if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts | $Message"
}

Write-Log "=== START re-enable Chrome updates ==="

# --- Enable Google Update scheduled tasks ---
$taskNames = @(
    "\GoogleUpdateTaskMachineCore",
    "\GoogleUpdateTaskMachineUA"
)

foreach ($task in $taskNames) {
    try {
        Write-Log "Enabling scheduled task (if present): $task"
        $null = & schtasks.exe /Change /TN $task /Enable 2>&1
        Write-Log "Attempted enable for task: $task"
    }
    catch {
        Write-Log ("ERROR enabling task $task: " + $_.Exception.Message)
    }
}

# --- Set Google Update services back to Automatic and start them ---
$serviceNames = @(
    "gupdate",
    "gupdatem"
)

foreach ($svcName in $serviceNames) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc) {
            Write-Log "Setting service startup to Automatic: $svcName"
            Set-Service -Name $svcName -StartupType Automatic -ErrorAction Stop

            if ($svc.Status -ne "Running") {
                Write-Log "Starting service: $svcName"
                Start-Service -Name $svcName -ErrorAction Stop
                Write-Log "Started service: $svcName"
            } else {
                Write-Log "Service already running: $svcName"
            }
        } else {
            Write-Log "Service not found (ok): $svcName"
        }
    }
    catch {
        Write-Log ("ERROR handling service $svcName: " + $_.Exception.Message)
    }
}

Write-Log "=== END re-enable Chrome updates ==="
exit 0