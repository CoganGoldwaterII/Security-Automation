# ============================================================================
# NAME: SMBv1 - Emergency Rollback
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Rollback
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir  = C:\MME\AutoLogs
#   LogFile = C:\MME\AutoLogs\SMBv1_Rollback.log
# OUTPUT TOKENS:
#   RESULT    | SMBv1 rollback applied
#   NO_ACTION | SMBv1 optional features already enabled
#   ERROR     | SMBv1 rollback failed
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\SMBv1_Rollback.log
# DESCRIPTION:
#   Emergency rollback to restore SMBv1 compatibility with legacy devices.
#   Enables disabled SMBv1 optional features, attempts to enable SMBv1
#   server support, and restarts the LanmanServer service.
#   Reports whether Windows indicates a reboot is required.
#   Does not initiate a system reboot.
#   Updates the NinjaOne remediation ledger and always exits 0.
# WARNING:
#   EMERGENCY USE ONLY. SMBv1 is deprecated and insecure.
#   Re-enabling it increases exposure to legacy SMB vulnerabilities.
# ============================================================================

$ErrorActionPreference = "Stop"

# ---------------- CONFIG ----------------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "SMBv1_Rollback.log"

# ---------------- HELPERS ----------------
function Ensure-Dir([string]$Path) {
    if (!(Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
}

function Write-Log([string]$Message) {
    Ensure-Dir $LogDir
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts | $Message"
}

function Update-RemediationLedger {
    param(
        [Parameter(Mandatory=$true)][string]$Product,   # e.g. "SMBv1 Rollback"
        [Parameter(Mandatory=$true)][string]$Result,    # RESULT | NO_ACTION | ERROR (or simplified tags)
        [string]$Notes = ""
    )

    try {
        $tsLocal = Get-Date
        $iso     = $tsLocal.ToString("yyyy-MM-ddTHH:mm:sszzz")
        $stamp   = $tsLocal.ToString("yyyy-MM-dd HH:mm")

        $entry = "{0} | {1} | {2}" -f $stamp, $Product, $Result
        if ($Notes) { $entry += " | $Notes" }

        $current = $null
        try { $current = Ninja-Property-Get remediationSummary } catch { $current = "" }
        if ($null -eq $current) { $current = "" }

        $new = if ([string]::IsNullOrWhiteSpace($current)) { $entry } else { ($current.TrimEnd() + "`r`n" + $entry) }

        # Guardrails
        $maxLines = 200
        $lines = $new -split "\r?\n"
        if ($lines.Count -gt $maxLines) {
            $lines = $lines[($lines.Count - $maxLines)..($lines.Count - 1)]
            $new = ($lines -join "`r`n")
        }

        $maxChars = 15000
        if ($new.Length -gt $maxChars) {
            $new = $new.Substring($new.Length - $maxChars)
        }

        Ninja-Property-Set lastRemediationDate $iso
        Ninja-Property-Set remediationSummary  $new

        Write-Log "Ledger updated: $entry"
        return $true
    }
    catch {
        Write-Log "ERROR updating remediation ledger: $($_.Exception.Message)"
        return $false
    }
}

# ---------------- MAIN ----------------
Ensure-Dir $LogDir
Write-Log "=== START SMBv1 rollback (no reboot forced) ==="

try {
    $changed = $false
    $enabledFeatures = @()

    # Enable SMBv1 optional feature(s) if present and not enabled
    $features = @(Get-WindowsOptionalFeature -Online | Where-Object {
        $_.FeatureName -like "SMB1Protocol*" -and $_.State -ne "Enabled"
    })

    if ($features.Count -eq 0) {
        Write-Log "SMB1Protocol* features already enabled (or not present)."
    } else {
        foreach ($f in $features) {
            Write-Log "Enabling optional feature: $($f.FeatureName)"
            Enable-WindowsOptionalFeature -Online -FeatureName $f.FeatureName -All -NoRestart | Out-Null
            $changed = $true
            $enabledFeatures += $f.FeatureName
        }
    }

    # Best-effort: allow SMBv1 at server configuration level
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force | Out-Null
        Write-Log "Set-SmbServerConfiguration: EnableSMB1Protocol=true"
        # Don't mark changed solely on this since it may already be true; keep it simple.
    } catch {
        Write-Log "INFO: Could not set EnableSMB1Protocol via Set-SmbServerConfiguration ($($_.Exception.Message))"
    }

    # Restart Server service to apply ASAP (best effort)
    try {
        Restart-Service lanmanserver -Force
        Write-Log "Restarted service: lanmanserver"
    } catch {
        Write-Log "INFO: Could not restart lanmanserver ($($_.Exception.Message))"
    }

    # Report reboot requirement if Windows indicates it
    $restartNeeded = $false
    try {
        $fMain = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"
        if ($fMain.RestartNeeded -eq $true) { $restartNeeded = $true }
    } catch {}

    $featNote = ""
    if ($enabledFeatures.Count -gt 0) { $featNote = "EnabledFeatures=$($enabledFeatures -join ',')" }

    if ($changed) {
        $notes = "Rollback applied. $featNote RestartNeeded=$restartNeeded"
        [void](Update-RemediationLedger -Product "SMBv1" -Result "RESULT" -Notes $notes)

        $msg = if ($restartNeeded) {
            "RESULT | SMBv1 rollback applied. NOTE: RestartNeeded=True (a reboot may be required for full effect)."
        } else {
            "RESULT | SMBv1 rollback applied. No reboot forced."
        }

        Write-Log $msg
        Write-Output $msg
        exit 0
    }

    # If we didn't enable any features, treat as NO_ACTION
    $notes = "No changes needed. RestartNeeded=$restartNeeded"
    [void](Update-RemediationLedger -Product "SMBv1" -Result "NO_ACTION" -Notes $notes)

    $msg = if ($restartNeeded) {
        "NO_ACTION | SMBv1 already enabled. NOTE: RestartNeeded=True (a reboot may be required for full effect)."
    } else {
        "NO_ACTION | SMBv1 already enabled. No changes made."
    }

    Write-Log $msg
    Write-Output $msg
    exit 0
}
catch {
    $msg = "ERROR | SMBv1 rollback failed: $($_.Exception.Message)"
    Write-Log $msg

    [void](Update-RemediationLedger -Product "SMBv1" -Result "ERROR" -Notes $($_.Exception.Message))

    Write-Output $msg
    exit 0
}