# ============================================================================
# NAME: SMBv1 Enabled + Usage - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LookbackHours = 168
#   LogFile       = C:\MME\AutoLogs\SMBv1_Eval.log
# OUTPUT TOKENS:
#   TRIGGER   | SMBv1 enabled with no recent usage detected
#   NO_ACTION | SMBv1 disabled or usage detected
#   ERROR     | Unable to determine SMBv1 state
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\SMBv1_Eval.log
# DESCRIPTION:
#   Evaluates SMBv1 configuration using Windows optional features and
#   SMB server settings. Checks active SMBv1 connections and SMB server
#   audit events over a configurable lookback period.
#   Triggers remediation when SMBv1 is enabled without detected usage.
#   Suppresses remediation when SMBv1 is disabled or usage is detected.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"

$LookbackHours = 168
$LogFile = "C:\MME\AutoLogs\SMBv1_Eval.log"

function Ensure-Dir($filePath) {
    $dir = Split-Path -Parent $filePath
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Log($msg) {
    Ensure-Dir $LogFile
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
}

function Emit($line) { Write-Output $line; exit 0 }

Log "=== SMBv1 eval start ==="

# ---- SMBv1 enabled state (best effort) ----
$smb1Enabled = $false
$stateKnown  = $false

try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    $stateKnown = $true
    if ($feature.State -eq "Enabled") { $smb1Enabled = $true }
} catch {
    Log "Optional feature check failed: $($_.Exception.Message)"
}

try {
    $cfg = Get-SmbServerConfiguration
    $stateKnown = $true
    if ($cfg.EnableSMB1Protocol) { $smb1Enabled = $true }
} catch {
    Log "Server config check failed: $($_.Exception.Message)"
}

if (-not $stateKnown) {
    Log "ERROR | Unable to determine SMBv1 state"
    Emit "ERROR | Unable to determine SMBv1 state"
}

Log "SMBv1 enabled: $smb1Enabled"

if (-not $smb1Enabled) {
    Log "NO_ACTION | SMBv1 already disabled"
    Emit "NO_ACTION | SMBv1 already disabled"
}

# ---- Usage checks ----
$activeCount = 0
try {
    $activeCount = @(Get-SmbConnection | Where-Object { $_.Dialect -eq "NT LM 0.12" }).Count
} catch {
    Log "Connection query failed: $($_.Exception.Message)"
}

Log "Active SMBv1 connections: $activeCount"

$auditCount = 0
try {
    $startTime  = (Get-Date).AddHours(-$LookbackHours)
    $auditCount = @(Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-SMBServer/Audit"; StartTime=$startTime }).Count
} catch {
    Log "Audit log unavailable"
}

Log "Audit events (last $LookbackHours hours): $auditCount"

if (($activeCount -gt 0) -or ($auditCount -gt 0)) {
    Log "NO_ACTION | SMBv1 usage detected"
    Emit "NO_ACTION | SMBv1 usage detected"
}

Log "TRIGGER | SMBv1 enabled with no recent usage"
Emit "TRIGGER | SMBv1 enabled with no recent usage"