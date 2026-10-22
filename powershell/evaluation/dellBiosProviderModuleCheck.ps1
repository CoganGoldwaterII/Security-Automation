# ============================================================================
# NAME: Dell Command | PowerShell Provider Module - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LogDir  = C:\MME\AutoLogs
#   LogFile = C:\MME\AutoLogs\DellBIOSProvider_Eval.log
# OUTPUT TOKENS:
#   TRIGGER   | DellBIOSProvider module missing
#   NO_ACTION | Not Dell hardware
#   NO_ACTION | DellBIOSProvider module present
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\DellBIOSProvider_Eval.log
# DESCRIPTION:
#   Identifies Dell hardware using the Windows CIM manufacturer property.
#   Checks for the DellBIOSProvider and DellBIOSProviderX86 modules.
#   Reports the highest available module version when installed.
#   Triggers remediation when a Dell system is missing both modules.
#   Reports NO_ACTION for non-Dell hardware or installed modules.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"

$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "DellBIOSProvider_Eval.log"

function Ensure-Dir([string]$p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Write-Log([string]$msg) {
    Ensure-Dir $LogDir
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [DellBIOSProviderEval] $msg"
}

function Finish([string]$out) {
    Write-Log "FINAL: $out"
    Write-Output $out
    exit 0
}

Write-Log "============================================"
Write-Log "Starting Dell BIOS Provider evaluation..."

# --- Detect manufacturer ---
$manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
Write-Log "Manufacturer detected: $manufacturer"

if ($manufacturer -notmatch "Dell") {
    Finish "NO_ACTION | Not Dell hardware"
}

Write-Log "Dell system detected. Checking module presence..."

# --- Check module ---
$mods = Get-Module -ListAvailable -Name "DellBIOSProvider","DellBIOSProviderX86" |
    Sort-Object Version -Descending

if ($mods -and $mods.Count -gt 0) {
    $top = $mods | Select-Object -First 1
    Write-Log "Found module: $($top.Name) v$($top.Version)"
    Finish ("NO_ACTION | DellBIOSProvider module present ({0} v{1})" -f $top.Name, $top.Version)
}

Write-Log "DellBIOSProvider module not found."
Finish "TRIGGER | DellBIOSProvider module missing"