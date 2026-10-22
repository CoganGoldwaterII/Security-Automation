# ============================================================================
# NAME: Zoom Update - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   ZoomMsiUrl_x64 = https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64
#   ZoomMsiUrl_x86 = https://zoom.us/client/latest/ZoomInstallerFull.msi
#   TempDir        = %TEMP%\MME_Zoom
#   MaxLines       = 200
#   MaxChars       = 4000
#   EnableDedupe   = $true
# OUTPUT TOKENS:
#   RESULT    | Zoom update executed successfully
#   ERROR     | MSI installation or remediation failure
#   NO_ACTION | Not emitted
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: No
#   Files: None
#   MSI downloaded directly from Zoom.
# LOGGING PATH:
#   C:\MME\AutoLogs\Zoom_Remediation.log
#   C:\MME\AutoLogs\Zoom_MSIInstall.log
# DESCRIPTION:
#   Downloads and silently installs the latest Zoom MSI for the detected
#   Windows architecture when invoked by NinjaOne remediation.
#   Relies on a separate evaluation script to determine remediation need.
#   Records installation results in the NinjaOne remediation ledger.
#   Caps ledger length and optionally prevents duplicate entries.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "Zoom_Remediation.log"
$MsiLog  = Join-Path $LogDir "Zoom_MSIInstall.log"

$ZoomMsiUrl_x64 = "https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64"
$ZoomMsiUrl_x86 = "https://zoom.us/client/latest/ZoomInstallerFull.msi"

$TempDir = Join-Path $env:TEMP "MME_Zoom"
$MsiPath = Join-Path $TempDir "ZoomInstallerFull.msi"

# remediationSummary guardrails
$MaxLines = 200
$MaxChars = 4000
$EnableDedupe = $true

# -------- HELPERS --------
function Ensure-Dir($p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts | $Message"
}

function Get-NinjaCmd {
    param([string]$Name)
    return (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Update-RemediationLedger {
    param(
        [string]$SummaryLine
    )

    $setCmd = Get-NinjaCmd "Ninja-Property-Set"
    $getCmd = Get-NinjaCmd "Ninja-Property-Get"

    $nowIso = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"

    try {
        if ($setCmd) {
            & $setCmd -Name "lastRemediationDate" -Value $nowIso | Out-Null
            Write-Log "Updated Ninja field lastRemediationDate=$nowIso"
        } else {
            Write-Log "Ninja-Property-Set not available; cannot set lastRemediationDate"
        }

        if ($setCmd -and $getCmd) {
            $existing = & $getCmd -Name "remediationSummary" -ErrorAction SilentlyContinue
            if ($null -eq $existing) { $existing = "" }

            $existing = [string]$existing
            $newLine = $SummaryLine.Trim()

            if ($EnableDedupe -and $existing -match [regex]::Escape($newLine)) {
                Write-Log "Ledger de-dupe: line already present; not appending duplicate."
                return
            }

            $lines = @()
            if (-not [string]::IsNullOrWhiteSpace($existing)) {
                $lines = $existing -split "(\r?\n)" | Where-Object { $_ -and $_ -notmatch '^\s*$' }
            }

            $lines += $newLine

            # Cap lines
            if ($lines.Count -gt $MaxLines) {
                $lines = $lines[-$MaxLines..-1]
            }

            $combined = ($lines -join "`r`n")

            # Cap chars
            if ($combined.Length -gt $MaxChars) {
                $combined = $combined.Substring($combined.Length - $MaxChars)
            }

            & $setCmd -Name "remediationSummary" -Value $combined | Out-Null
            Write-Log "Appended remediationSummary (guardrailed)."
        } else {
            Write-Log "Ninja-Property-Get/Set not available; cannot append remediationSummary"
        }
    }
    catch {
        Write-Log "WARNING: Failed to update Ninja custom fields: $($_.Exception.Message)"
    }
}

function Finish {
    param(
        [string]$OutputLine,
        [string]$LedgerLine
    )
    if ($LedgerLine) { Update-RemediationLedger -SummaryLine $LedgerLine }
    Write-Output $OutputLine
    Write-Log "FINAL: $OutputLine"
    Write-Log "=== Zoom remediation end ==="
    exit 0
}

# -------- START --------
Ensure-Dir $LogDir
Ensure-Dir $TempDir
Write-Log "=== Zoom remediation start ==="

try {
    $msiUrl = if ([Environment]::Is64BitOperatingSystem) { $ZoomMsiUrl_x64 } else { $ZoomMsiUrl_x86 }
    Write-Log "Downloading MSI from: $msiUrl"

    Invoke-WebRequest -Uri $msiUrl -OutFile $MsiPath -UseBasicParsing

    if (!(Test-Path $MsiPath)) { throw "MSI download failed: $MsiPath not found." }

    Write-Log "Running MSI install (silent)..."
    $args = @(
        "/i", "`"$MsiPath`"",
        "/qn", "/norestart",
        "/log", "`"$MsiLog`""
    )

    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
    Write-Log "msiexec exit code: $($p.ExitCode)"

    $ledger = "Zoom remediation ran. MSIExit=$($p.ExitCode)"
    if ($p.ExitCode -eq 0) {
        Finish -OutputLine "RESULT | Zoom update executed (MSIExit=0)" -LedgerLine $ledger
    } else {
        Finish -OutputLine "ERROR | Zoom update attempted but msiexec returned $($p.ExitCode)" -LedgerLine $ledger
    }
}
catch {
    $msg = $_.Exception.Message
    Write-Log "ERROR: $msg"
    Finish -OutputLine "ERROR | Zoom remediation failure: $msg" -LedgerLine ("Zoom remediation ERROR: " + $msg)
}