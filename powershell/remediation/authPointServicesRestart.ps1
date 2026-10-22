# ============================================================================
# NAME: AuthPoint LDAP Service Recovery
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Service Recovery
# SCOPE: Windows endpoints / NinjaOne automation
# VARIABLES:
#   LogPath = C:\MME\AutoLogs
#   LogFile = C:\MME\AutoLogs\AuthPoint_LDAP_Restart.log
# OUTPUT TOKENS:
#   NO_ACTION | LDAP service not found
#   NO_ACTION | LDAP service checked/restarted
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\AuthPoint_LDAP_Restart.log
# DESCRIPTION:
#   Identifies AuthPoint LDAP services using service and display names.
#   Starts matching services when they are not running.
#   Refreshes service status after attempting recovery and logs results.
#   Does not restart services that are already running.
#   Explicit completion paths exit 0.
# ============================================================================

$LogPath = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogPath "AuthPoint_LDAP_Restart.log"

if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

function Write-Log {
    param($Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [LDAPRestart] $Message"
}

Write-Log "============================================================"
Write-Log "Checking AuthPoint LDAP service..."

# Try common service display names
$services = Get-Service | Where-Object {
    $_.DisplayName -like "*AuthPoint*LDAP*" -or
    $_.Name -like "*AuthPoint*LDAP*"
}

if (-not $services) {
    Write-Log "LDAP service not found."
    Write-Output "NO_ACTION | LDAP service not found"
    exit 0
}

foreach ($svc in $services) {
    Write-Log "Found service: $($svc.Name) Status=$($svc.Status)"

    if ($svc.Status -ne "Running") {
        Write-Log "Starting service $($svc.Name)..."
        Start-Service $svc.Name
        Start-Sleep -Seconds 2
        $svc.Refresh()
    }

    Write-Log "Post-check status: $($svc.Status)"
}

Write-Output "NO_ACTION | LDAP service checked/restarted"
exit 0