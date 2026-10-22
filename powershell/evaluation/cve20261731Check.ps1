# ============================================================================
# NAME: BeyondTrust / Bomgar Product Detection - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LogDir          = C:\MME\AutoLogs
#   LogFile         = C:\MME\AutoLogs\BeyondTrustBomgar_Eval.log
#   AppRegex        = BeyondTrust/Bomgar application matching
#   SvcNameRegex    = BeyondTrust/Bomgar service name matching
#   SvcDisplayRegex = BeyondTrust/Bomgar service display name matching
# OUTPUT TOKENS:
#   TRIGGER   | BeyondTrust/Bomgar detected
#   NO_ACTION | No BeyondTrust/Bomgar products detected
#   ERROR     | Evaluation failure
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\BeyondTrustBomgar_Eval.log
# DESCRIPTION:
#   Detects BeyondTrust/Bomgar endpoint components through services,
#   installed application registry entries, and common directories.
#   Identifies residual Jump Clients and related products for review
#   and potential remediation by a paired automation.
#
#   SECURITY CONTEXT:
#   CVE-2026-1731 - BeyondTrust Remote Support / Privileged Remote
#   Access pre-authentication remote code execution vulnerability.
#   Detection supports endpoint exposure assessment following potential
#   vendor-side compromise. It does not detect exploitation, establish
#   compromise, or remediate the server-side vulnerability.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "BeyondTrustBomgar_Eval.log"

# Apps: vendor/product-specific only (avoid generic "remote support")
$AppRegex = '(?i)\b(beyondtrust|bomgar)\b|jump\s*client|privileged\s*remote\s*access|\bpra\b'

# Services: vendor-specific only (DO NOT use "bt")
$SvcNameRegex = '(?i)(bomgar|beyondtrust|jumpclient)'
$SvcDisplayRegex = '(?i)(Bomgar|BeyondTrust|Jump Client)'

function Ensure-Dir([string]$p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Log([string]$m) {
    Ensure-Dir $LogDir
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [BTBomgarEval] $m"
}

function Finish([string]$token, [string]$msg) {
    Log "OUTPUT: $token | $msg"
    Write-Output "$token | $msg"
    exit 0
}

try {
    Ensure-Dir $LogDir
    Log "============================================================"
    Log "Starting BeyondTrust/Bomgar evaluation (tight match v2)..."
    Log "Computer: $env:COMPUTERNAME"

    $findings = New-Object System.Collections.Generic.List[string]

    # 1) Services (vendor-specific only)
    $svcHits = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $SvcNameRegex -or
        $_.DisplayName -match $SvcDisplayRegex
    }

    foreach ($s in $svcHits) {
        $findings.Add("Service:$($s.Name)($($s.DisplayName)) Status=$($s.Status)")
    }
    Log "Service hits: $($svcHits.Count)"

    # 2) Installed apps (registry uninstall)
    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $appHits = foreach ($p in $uninstallPaths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.DisplayName -and $_.DisplayName -match $AppRegex) -or
                ($_.Publisher -and $_.Publisher -match '(?i)(BeyondTrust|Bomgar)')
            } |
            Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString, InstallLocation, PSPath
    }

    $appHits = $appHits | Sort-Object DisplayName -Unique
    foreach ($a in $appHits) {
        $ver = if ($a.DisplayVersion) { $a.DisplayVersion } else { "Unknown" }
        $pub = if ($a.Publisher) { $a.Publisher } else { "Unknown" }
        $findings.Add("App:$($a.DisplayName) Ver=$ver Pub=$pub")
    }
    Log "App hits: $($appHits.Count)"

    # 3) Common directories (signal)
    $dirs = @(
        "$env:ProgramFiles\BeyondTrust",
        "$env:ProgramFiles (x86)\BeyondTrust",
        "$env:ProgramFiles\Bomgar",
        "$env:ProgramFiles (x86)\Bomgar",
        "$env:ProgramData\BeyondTrust",
        "$env:ProgramData\Bomgar"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($d in $dirs) {
        $findings.Add("Path:$d")
    }
    Log "Path hits: $($dirs.Count)"

    if ($findings.Count -gt 0) {
        $msg = (($findings | Sort-Object -Unique) -join "; ")
        if ($msg.Length -gt 1800) { $msg = $msg.Substring(0, 1800) + " ...[truncated]" }
        Finish "TRIGGER" "BeyondTrust/Bomgar detected: $msg"
    } else {
        Finish "NO_ACTION" "No BeyondTrust/Bomgar products detected"
    }

} catch {
    Log "ERROR: $($_.Exception.Message)"
    Finish "ERROR" $($_.Exception.Message)
}