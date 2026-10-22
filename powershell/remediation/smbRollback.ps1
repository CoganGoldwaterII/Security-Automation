# ============================================================================
# NAME: SMB Signing Requirement - Emergency Rollback
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Rollback
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   RESULT    | SMB signing requirement rolled back
#   NO_ACTION | Not emitted
#   ERROR     | Not emitted
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\SMBSigning_Rollback.log
# DESCRIPTION:
#   Emergency rollback of SMB signing enforcement for client and server.
#   Sets RequireSecuritySignature to 0 for both services, logs before/after
#   values, and attempts to restart SMB services.
#   Intended for emergency compatibility recovery only.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"

$LogPath = "C:\MME\AutoLogs\SMBSigning_Rollback.log"

function Ensure-Dir($path) {
    $dir = Split-Path $path -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}
function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content $LogPath "$ts | $msg"
}

Ensure-Dir $LogPath
"==== START SMB Signing Rollback ====" | Out-File $LogPath

$wkstPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$srvrPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

# Snapshot current
$wkstBefore = (Get-ItemProperty $wkstPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
$srvrBefore = (Get-ItemProperty $srvrPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
Write-Log "Before: Workstation RequireSecuritySignature=$wkstBefore"
Write-Log "Before: Server      RequireSecuritySignature=$srvrBefore"

# Rollback (not required)
Set-ItemProperty -Path $wkstPath -Name RequireSecuritySignature -Value 0 -Type DWord -Force | Out-Null
Set-ItemProperty -Path $srvrPath -Name RequireSecuritySignature -Value 0 -Type DWord -Force | Out-Null

# Verify after
$wkstAfter = (Get-ItemProperty $wkstPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
$srvrAfter = (Get-ItemProperty $srvrPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
Write-Log "After:  Workstation RequireSecuritySignature=$wkstAfter"
Write-Log "After:  Server      RequireSecuritySignature=$srvrAfter"

# Optional: restart services to apply quicker (safe attempt)
Write-Log "Attempting service restart (best-effort): lanmanworkstation, lanmanserver"
Restart-Service -Name lanmanworkstation -Force -ErrorAction SilentlyContinue
Restart-Service -Name lanmanserver -Force -ErrorAction SilentlyContinue

Write-Log "Rollback complete."

Write-Output "RESULT | SMB signing requirement rolled back (Workstation=$wkstAfter, Server=$srvrAfter)"
exit 0