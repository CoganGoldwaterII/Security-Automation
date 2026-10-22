# ============================================================================
# NAME: NTLM / SMB Configuration Posture - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LogPath = C:\MME\AutoLogs\NTLMv1_Config_Posture.log
# OUTPUT TOKENS:
#   TRIGGER   | Weak NTLM or SMB signing configuration detected
#   TRIGGER   | Required NTLM configuration unknown (fail-safe)
#   NO_ACTION | Configuration appears hardened
#   ERROR     | Not emitted by this script
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\NTLMv1_Config_Posture.log
# DESCRIPTION:
#   Evaluates Windows NTLM and SMB signing configuration using local
#   registry settings without modifying endpoint configuration.
#
#   Checks LmCompatibilityLevel to determine whether NTLMv2-only
#   authentication is required (value 5).
#
#   Checks SMB signing requirements for both the Workstation and
#   Server services using RequireSecuritySignature (value 1).
#
#   Reports TRIGGER when NTLM authentication settings are weaker than
#   the required level, SMB signing is not required, or the NTLM
#   compatibility setting cannot be determined.
#
#   Reports NO_ACTION when the evaluated settings meet requirements.
#   Logs configuration values for troubleshooting and auditing.
#
#   Always exits with code 0 for NinjaOne automation compatibility.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"

# ---------- CONFIG ----------
$LogPath = "C:\MME\AutoLogs\NTLMv1_Config_Posture.log"

# ---------- HELPERS ----------
function Ensure-Dir($path) {
    $dir = Split-Path -Path $path -Parent
    if (!(Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}
function Write-Log($msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $LogPath -Value "$ts | $msg" -Encoding UTF8
}
function Get-RegDword($path, $name) {
    try {
        return [int]((Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name)
    } catch {
        return $null
    }
}
function IsRequireOn($v) { return ($v -eq 1) }

# ---------- MAIN ----------
Ensure-Dir $LogPath
"==== START NTLM/SMB Config Posture ====" | Out-File -FilePath $LogPath -Encoding UTF8

$unknown = $false
$details = New-Object System.Collections.Generic.List[string]

# NTLM level
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lmLevel = Get-RegDword $lsaPath "LmCompatibilityLevel"

if ($null -eq $lmLevel) {
    Write-Log "LmCompatibilityLevel not set."
    $unknown = $true
    $details.Add("LmCompatibilityLevel=NOT_SET")
} else {
    Write-Log "LmCompatibilityLevel=$lmLevel"
    if ($lmLevel -lt 5) { $details.Add("LmCompatibilityLevel<5 (=$lmLevel)") }
}

# SMB signing
$wkstPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$srvrPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

$wkstReq = Get-RegDword $wkstPath "RequireSecuritySignature"
$srvrReq = Get-RegDword $srvrPath "RequireSecuritySignature"

Write-Log "Workstation RequireSecuritySignature=$wkstReq"
Write-Log "Server      RequireSecuritySignature=$srvrReq"

if (-not (IsRequireOn $wkstReq)) { $details.Add("Workstation SMB signing NOT required (Require=$wkstReq)") }
if (-not (IsRequireOn $srvrReq)) { $details.Add("Server SMB signing NOT required (Require=$srvrReq)") }

if ($unknown) {
    Write-Output "TRIGGER | UNKNOWN: Could not fully determine config posture (details=$($details -join '; '))"
    exit 0
}

if ($details.Count -gt 0) {
    Write-Output "TRIGGER | Weak config (details=$($details -join '; '))"
    exit 0
}

Write-Output "NO_ACTION | Config appears hardened"
exit 0