# ============================================================================
# NAME: SMB Signing Requirement - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LogPath = C:\MME\AutoLogs\SMBSigning_Check.log
# OUTPUT TOKENS:
#   TRIGGER   | SMB signing not required
#   NO_ACTION | SMB signing required
#   ERROR     | Unable to read SMB signing configuration
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\SMBSigning_Check.log
# DESCRIPTION:
#   Evaluates SMB signing requirements for both the Windows SMB client
#   (LanmanWorkstation) and SMB server (LanmanServer).
#
#   Reads the RequireSecuritySignature registry value for both services.
#   Reports TRIGGER when either value is not set to 1.
#
#   Reports NO_ACTION when SMB signing is required for both services.
#   Reports ERROR when required registry settings cannot be read.
#
#   Read-only evaluation. Does not modify SMB configuration.
#   Always exits with code 0 for NinjaOne automation compatibility.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"
$LogPath = "C:\MME\AutoLogs\SMBSigning_Check.log"

function Ensure-Dir($filePath) {
    $dir = Split-Path -Parent $filePath
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Log($msg) {
    Ensure-Dir $LogPath
    Add-Content -Path $LogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
}

function Emit($line) { Write-Output $line; exit 0 }

$wkstPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$srvrPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

try {
    $wkst = (Get-ItemProperty $wkstPath -Name RequireSecuritySignature -ErrorAction Stop).RequireSecuritySignature
    $srvr = (Get-ItemProperty $srvrPath -Name RequireSecuritySignature -ErrorAction Stop).RequireSecuritySignature
    Log "Workstation RequireSecuritySignature=$wkst ; Server RequireSecuritySignature=$srvr"
} catch {
    Log "ERROR reading SMB signing values: $($_.Exception.Message)"
    Emit "ERROR | Unable to read SMB signing configuration"
}

if (($wkst -ne 1) -or ($srvr -ne 1)) {
    Log "TRIGGER: SMB signing not required"
    Emit "TRIGGER | SMB signing not required"
}

Log "NO_ACTION: SMB signing required"
Emit "NO_ACTION | SMB signing required"