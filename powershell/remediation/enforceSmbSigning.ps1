# ============================================================================
# NAME: SMB Signing Requirement - Enforcement
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir  = C:\MME\AutoLogs
#   LogPath = C:\MME\AutoLogs\SMBSigning_Enforce.log
# OUTPUT TOKENS:
#   RESULT | ENFORCED (Workstation=1, Server=1)
#   RESULT | PARTIAL (Workstation=..., Server=...)
#   NO_ACTION | Not emitted
#   ERROR | Not emitted
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
#   C:\MME\AutoLogs\SMBSigning_Enforce.log
# DESCRIPTION:
#   Enforces SMB signing for Windows client and server by setting
#   RequireSecuritySignature to 1 for both services.
#   Logs before/after registry values and attempts service restarts.
#   Updates the NinjaOne remediation ledger on successful enforcement.
#   Reports partial enforcement when either setting is not applied.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"

$LogDir  = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogDir "SMBSigning_Enforce.log"

function Ensure-Dir($path) {
    $dir = Split-Path $path -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Ensure-Dir $LogPath
    Add-Content $LogPath "$ts | $msg"
}

function Update-RemediationLedger {
    param(
        [Parameter(Mandatory=$true)][string]$Product,   # e.g. "SMB Signing"
        [Parameter(Mandatory=$true)][string]$Result,    # e.g. "ENFORCED" / "PARTIAL"
        [string]$FromVer = "",                          # optional - unused here
        [string]$ToVer   = "",                          # optional - unused here
        [string]$Notes   = ""                           # optional extra context
    )

    try {
        $tsLocal = Get-Date
        $iso     = $tsLocal.ToString("yyyy-MM-ddTHH:mm:sszzz")
        $stamp   = $tsLocal.ToString("yyyy-MM-dd HH:mm")

        # One-line entry for running ledger
        $entry = "{0} | {1} | {2}" -f $stamp, $Product, $Result
        if ($FromVer -or $ToVer) { $entry += " | $FromVer -> $ToVer" }
        if ($Notes) { $entry += " | $Notes" }

        # Read current multi-line ledger (may be blank)
        $current = $null
        try { $current = Ninja-Property-Get remediationSummary } catch { $current = "" }
        if ($null -eq $current) { $current = "" }

        # Append as new line
        $new = if ([string]::IsNullOrWhiteSpace($current)) { $entry } else { ($current.TrimEnd() + "`r`n" + $entry) }

        # Guardrails: keep last N lines
        $maxLines = 200
        $lines = $new -split "\r?\n"
        if ($lines.Count -gt $maxLines) {
            $lines = $lines[($lines.Count - $maxLines)..($lines.Count - 1)]
            $new = ($lines -join "`r`n")
        }

        # Guardrail: cap total chars
        $maxChars = 15000
        if ($new.Length -gt $maxChars) {
            $new = $new.Substring($new.Length - $maxChars)
        }

        # Write custom fields
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

Ensure-Dir $LogPath
"==== START SMB Signing Enforcement ====" | Out-File $LogPath

$wkstPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$srvrPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

# Snapshot current
$wkstBefore = (Get-ItemProperty $wkstPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
$srvrBefore = (Get-ItemProperty $srvrPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
Write-Log "Before: Workstation RequireSecuritySignature=$wkstBefore"
Write-Log "Before: Server      RequireSecuritySignature=$srvrBefore"

# Enforce signing required
Set-ItemProperty -Path $wkstPath -Name RequireSecuritySignature -Value 1 -Type DWord -Force | Out-Null
Set-ItemProperty -Path $srvrPath -Name RequireSecuritySignature -Value 1 -Type DWord -Force | Out-Null

# Verify after
$wkstAfter = (Get-ItemProperty $wkstPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
$srvrAfter = (Get-ItemProperty $srvrPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
Write-Log "After:  Workstation RequireSecuritySignature=$wkstAfter"
Write-Log "After:  Server      RequireSecuritySignature=$srvrAfter"

# Apply quicker (best-effort)
Write-Log "Attempting service restart (best-effort): lanmanworkstation, lanmanserver"
Restart-Service -Name lanmanworkstation -Force -ErrorAction SilentlyContinue
Restart-Service -Name lanmanserver -Force -ErrorAction SilentlyContinue

# Final result token + update Ninja fields on ENFORCED only (billing-friendly)
if (($wkstAfter -eq 1) -and ($srvrAfter -eq 1)) {
    Write-Log "Enforcement complete."

    # Append ledger line + overwrite lastRemediationDate
    $notes = "Workstation=1, Server=1 (Before: W=$wkstBefore, S=$srvrBefore)"
    [void](Update-RemediationLedger -Product "SMB Signing" -Result "ENFORCED" -Notes $notes)

    Write-Output "RESULT | ENFORCED (Workstation=1, Server=1)"
    exit 0
}

Write-Log "Enforcement partial or not applied as expected."
# If you also want PARTIAL attempts logged in the ledger, uncomment below:
# $notes = "Workstation=$wkstAfter, Server=$srvrAfter (Before: W=$wkstBefore, S=$srvrBefore)"
# [void](Update-RemediationLedger -Product "SMB Signing" -Result "PARTIAL" -Notes $notes)

Write-Output "RESULT | PARTIAL (Workstation=$wkstAfter, Server=$srvrAfter)"
exit 0