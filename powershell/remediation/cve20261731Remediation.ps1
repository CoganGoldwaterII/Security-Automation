# ============================================================================
# NAME: BeyondTrust / Bomgar Complete Removal - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir          = C:\MME\AutoLogs
#   LedgerCharCap   = 4000
#   LedgerLineCap   = 60
#   EnableDedupe    = $true
#   AppRegex        = BeyondTrust/Bomgar application matching
#   PublisherRegex  = BeyondTrust/Bomgar publisher matching
#   SvcNameRegex    = BeyondTrust/Bomgar service name matching
#   SvcDisplayRegex = BeyondTrust/Bomgar service display name matching
#   DirsToRemove    = Common BeyondTrust/Bomgar installation directories
# OUTPUT TOKENS:
#   RESULT    | Removed BeyondTrust/Bomgar artifacts
#   NO_ACTION | No BeyondTrust/Bomgar products detected to remove
#   ERROR     | Remediation failure
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
#   C:\MME\AutoLogs\BeyondTrustBomgar_Remediation.log
# DESCRIPTION:
#   Removes detected BeyondTrust/Bomgar endpoint components using
#   installed application uninstall commands and directory cleanup.
#   Stops matching services and records attempted removal actions.
#   Updates NinjaOne remediation fields only when actions are performed.
#   Uses a date-only, deduplicated, capped remediation ledger.
#
#   SECURITY CONTEXT:
#   CVE-2026-1731 - BeyondTrust Remote Support / Privileged Remote
#   Access server-side vulnerability.
#   Paired with endpoint detection to identify and remove residual
#   remote access components following potential vendor compromise.
#   Does not remediate the server-side vulnerability.
#   Always exits 0.
#
# WARNING:
#   Destructive remediation. Removes remote access software and may
#   interrupt active support sessions or legacy integrations.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "BeyondTrustBomgar_Remediation.log"

# Ledger guardrails
$LedgerCharCap = 4000
$LedgerLineCap = 60
$EnableDedupe  = $true

# Tight matching (avoid generic "remote support")
$AppRegex = '(?i)\b(beyondtrust|bomgar)\b|jump\s*client|privileged\s*remote\s*access|\bpra\b'
$PublisherRegex = '(?i)(BeyondTrust|Bomgar)'

# Services: vendor-specific only (DO NOT use "bt")
$SvcNameRegex    = '(?i)(bomgar|beyondtrust|jumpclient)'
$SvcDisplayRegex = '(?i)(Bomgar|BeyondTrust|Jump Client)'

# Common directories to remove
$DirsToRemove = @(
  "$env:ProgramFiles\BeyondTrust",
  "$env:ProgramFiles (x86)\BeyondTrust",
  "$env:ProgramFiles\Bomgar",
  "$env:ProgramFiles (x86)\Bomgar",
  "$env:ProgramData\BeyondTrust",
  "$env:ProgramData\Bomgar"
)

function Ensure-Dir([string]$p) {
  if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Log([string]$m) {
  Ensure-Dir $LogDir
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Add-Content -Path $LogFile -Value "$ts [BTBomgarRem] $m"
}

function Finish([string]$token, [string]$msg) {
  Log "OUTPUT: $token | $msg"
  Write-Output "$token | $msg"
  exit 0
}

# --- Ninja custom-field helpers ---
function Set-NinjaField([string]$FieldName, [string]$Value) {
  try {
    if (Get-Command -Name "Ninja-Property-Set" -ErrorAction SilentlyContinue) {
      Ninja-Property-Set -Name $FieldName -Value $Value | Out-Null
      return $true
    }
    Log "WARN: Ninja-Property-Set not available; cannot set field '$FieldName' via this method."
    return $false
  } catch {
    Log "WARN: Failed to set Ninja field '$FieldName': $($_.Exception.Message)"
    return $false
  }
}

function Get-NinjaField([string]$FieldName) {
  try {
    if (Get-Command -Name "Ninja-Property-Get" -ErrorAction SilentlyContinue) {
      return (Ninja-Property-Get -Name $FieldName).Value
    }
    $envName = $FieldName.ToUpper()
    return [Environment]::GetEnvironmentVariable($envName)
  } catch {
    Log "WARN: Failed to get Ninja field '$FieldName': $($_.Exception.Message)"
    return $null
  }
}

function Sanitize-LedgerText([string]$text) {
  if ([string]::IsNullOrWhiteSpace($text)) { return "" }
  $lines = $text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
  return ($lines -join "`n")
}

function Build-LedgerUpdate([string]$message) {
  $dateOnly = Get-Date -Format "yyyy-MM-dd"
  $entry    = "$dateOnly | $message"

  $existing = Get-NinjaField "remediationSummary"
  $existing = Sanitize-LedgerText $existing

  $lines = @()
  if ($existing) { $lines = $existing -split "`n" }

  if ($EnableDedupe -and ($lines -contains $entry)) {
    Log "Ledger: entry already present (dedupe enabled)."
  } else {
    $lines += $entry
  }

  if ($LedgerLineCap -gt 0 -and $lines.Count -gt $LedgerLineCap) {
    $lines = $lines[-$LedgerLineCap..-1]
  }

  $joined = ($lines -join "`n")
  if ($LedgerCharCap -gt 0 -and $joined.Length -gt $LedgerCharCap) {
    while ($joined.Length -gt $LedgerCharCap -and $lines.Count -gt 1) {
      $lines = $lines[1..($lines.Count-1)]
      $joined = ($lines -join "`n")
    }
    if ($joined.Length -gt $LedgerCharCap) {
      $joined = $joined.Substring($joined.Length - $LedgerCharCap)
    }
  }

  return @{
    lastRemediationDate = (Get-Date).ToString("o")
    remediationSummary  = $joined
  }
}

function Invoke-Uninstall([string]$displayName, [string]$cmdRaw) {
  if ([string]::IsNullOrWhiteSpace($cmdRaw)) { return $false }

  $cmd = $cmdRaw.Trim()
  Log "Uninstalling '$displayName' using: $cmd"

  $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd -Wait -PassThru -WindowStyle Hidden
  Log "Uninstall exit code for '$displayName': $($p.ExitCode)"

  return ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010)
}

try {
  Ensure-Dir $LogDir
  Log "============================================================"
  Log "Starting BeyondTrust/Bomgar remediation (NUKE - tight match)..."
  Log "Computer: $env:COMPUTERNAME"

  $remediated = $false
  $actions = New-Object System.Collections.Generic.List[string]

  # 1) Identify targets (apps + services) up front
  $uninstallPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  $appHits = foreach ($p in $uninstallPaths) {
    Get-ItemProperty $p -ErrorAction SilentlyContinue |
      Where-Object {
        ($_.DisplayName -and $_.DisplayName -match $AppRegex) -or
        ($_.Publisher   -and $_.Publisher   -match $PublisherRegex)
      } |
      Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString
  }
  $appHits = $appHits | Sort-Object DisplayName -Unique

  $svcHits = Get-Service -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match $SvcNameRegex -or $_.DisplayName -match $SvcDisplayRegex
  }

  Log "Pre-check: app hits: $($appHits.Count)"
  Log "Pre-check: svc hits: $($svcHits.Count)"

  if ($appHits.Count -eq 0 -and $svcHits.Count -eq 0) {
    Finish "NO_ACTION" "No BeyondTrust/Bomgar products detected to remove"
  }

  # 2) Stop related services (best-effort)
  foreach ($s in $svcHits) {
    try {
      if ($s.Status -ne "Stopped") {
        Log "Stopping service: $($s.Name)"
        Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
      }
      $actions.Add("StoppedService:$($s.Name)")
      $remediated = $true
    } catch {
      Log "WARN: Failed stopping service '$($s.Name)': $($_.Exception.Message)"
    }
  }

  # 3) Uninstall apps (quiet preferred)
  foreach ($a in $appHits) {
    $dn  = $a.DisplayName
    $ver = if ($a.DisplayVersion) { $a.DisplayVersion } else { "Unknown" }

    $cmd = if ($a.QuietUninstallString) { $a.QuietUninstallString } else { $a.UninstallString }
    if ([string]::IsNullOrWhiteSpace($cmd)) {
      Log "WARN: No uninstall command found for '$dn' ($ver)."
      continue
    }

    if ($cmd -match '(?i)msiexec\.exe' -and $cmd -notmatch '(?i)\s/(qn|quiet)\b') {
      $cmd = "$cmd /qn /norestart"
    }

    $ok = Invoke-Uninstall -displayName "$dn ($ver)" -cmdRaw $cmd
    $actions.Add( ($(if ($ok) { "Uninstalled" } else { "UninstallAttempted" })) + ":$dn Ver=$ver" )
    $remediated = $true
  }

  # 4) Remove common directories (best-effort)
  foreach ($d in $DirsToRemove) {
    try {
      if ($d -and (Test-Path $d)) {
        Log "Removing directory: $d"
        Remove-Item -Path $d -Recurse -Force -ErrorAction SilentlyContinue
        $actions.Add("RemovedDir:$d")
        $remediated = $true
      }
    } catch {
      Log "WARN: Failed removing '$d': $($_.Exception.Message)"
    }
  }

  if (-not $remediated) {
    Finish "NO_ACTION" "No BeyondTrust/Bomgar products detected to remove"
  }

  # 5) Ledger updates LAST (only because remediation happened)
  $ledger = Build-LedgerUpdate -message "BeyondTrust/Bomgar Removed"
  $set1 = Set-NinjaField -FieldName "lastRemediationDate" -Value $ledger.lastRemediationDate
  $set2 = Set-NinjaField -FieldName "remediationSummary"  -Value $ledger.remediationSummary
  Log "Ledger update attempted. lastRemediationDate set=$set1 remediationSummary set=$set2"

  $actionMsg = ($actions | Sort-Object -Unique) -join "; "
  if ($actionMsg.Length -gt 1800) { $actionMsg = $actionMsg.Substring(0, 1800) + " ...[truncated]" }

  Finish "RESULT" "Removed BeyondTrust/Bomgar artifacts. Actions: $actionMsg"

} catch {
  Log "ERROR: $($_.Exception.Message)"
  Finish "ERROR" "Failure occurred: $($_.Exception.Message)"
}