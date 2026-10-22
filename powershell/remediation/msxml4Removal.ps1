# ============================================================================
# NAME: MSXML 4 Complete Removal - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir        = C:\MME\AutoLogs
#   LogFile       = C:\MME\AutoLogs\MSXML4_Remediation.log
#   LedgerCharCap = 4000
#   LedgerLineCap = 60
# OUTPUT TOKENS:
#   RESULT    | MSXML 4 removal complete
#   NO_ACTION | MSXML 4 not found
#   RESULT    | ERROR (removal failure or remaining footprint)
# CUSTOM FIELDS:
#   Reads: remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line, remediation attempts only)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\MSXML4_Remediation.log
# DESCRIPTION:
#   Removes legacy MSXML 4 installations and associated DLL footprints.
#   Detects installed products through Windows uninstall registry entries.
#   Performs MSI GUID or available command-based uninstall operations.
#   Retries remaining installations, unregisters and deletes MSXML 4 DLLs,
#   and removes orphan uninstall entries when no DLLs remain in scope.
#   Verifies the remaining product and DLL footprint after remediation.
#   Updates lastRemediationDate on every completed run and appends a
#   date-only remediation ledger entry when removal was attempted.
#   Always exits 0.
# WARNING:
#   Destructive remediation. Removes DLLs and registry entries that may
#   still be required by legacy applications.
# ============================================================================

$ErrorActionPreference = "Stop"

$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "MSXML4_Remediation.log"

$LedgerCharCap = 4000
$LedgerLineCap = 60

function Ensure-Dir([string]$p) {
  if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Log([string]$m) {
  Ensure-Dir $LogDir
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Add-Content -Path $LogFile -Value "$ts [MSXML4-REMED] $m"
}

function Update-Ledger([string]$summaryLine) {
  try {
    # lastRemediationDate = full ISO timestamp
    $nowIsoFull  = (Get-Date).ToString("s")
    # remediationSummary prefix = DATE ONLY
    $nowDateOnly = (Get-Date).ToString("yyyy-MM-dd")

    try { & ninja-property-set lastRemediationDate $nowIsoFull | Out-Null } catch {}

    # IMPORTANT: Only append when we have a clean summaryLine (remediation performed)
    if ([string]::IsNullOrWhiteSpace($summaryLine)) {
      return
    }

    $existing = ""
    try { $existing = (& ninja-property-get remediationSummary) -join "`n" } catch {}

    $lines = @()
    if ($existing) {
      $lines = $existing -split "(`r`n|`n|`r)"
    }

    # --- CLEANUP: remove whitespace-only / blank lines to prevent giant gaps ---
    $lines = $lines | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    # Append clean entry
    $lines += "$nowDateOnly | $summaryLine"

    # De-dupe adjacent identical entries
    $deduped = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
      if ($deduped.Count -eq 0 -or $deduped[$deduped.Count-1] -ne $l) { $deduped.Add($l) | Out-Null }
    }

    # Cap lines
    if ($deduped.Count -gt $LedgerLineCap) {
      $deduped = $deduped[($deduped.Count-$LedgerLineCap)..($deduped.Count-1)]
    }

    # Cap chars
    $joined = ($deduped -join "`n")
    if ($joined.Length -gt $LedgerCharCap) {
      $joined = $joined.Substring($joined.Length - $LedgerCharCap)
    }

    try { & ninja-property-set remediationSummary $joined | Out-Null } catch {}
  } catch {}
}

function Finish([string]$out, [string]$ledgerLine = $null) {
  Log $out
  Update-Ledger $ledgerLine
  Write-Output $out
  exit 0
}

function Get-MSXML4Entries() {
  $roots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  $rx = '(?i)(MSXML\s*4|MSXML4|Microsoft XML Core Services\s*4)'

  Get-ItemProperty $roots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match $rx } |
    Select-Object DisplayName, DisplayVersion, UninstallString, QuietUninstallString, PSChildName, PSPath
}

function Invoke-MSIUninstallGuid([string]$guid) {
  Log "Running msiexec uninstall for GUID: $guid"
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $guid /qn /norestart REBOOT=ReallySuppress" -Wait -NoNewWindow -PassThru
  Log "msiexec exit code for $guid : $($p.ExitCode)"
  return $p.ExitCode
}

function Uninstall-Entry($entry) {
  $text = @($entry.QuietUninstallString, $entry.UninstallString, $entry.PSChildName) -join " "
  $m = [regex]::Match($text, "\{[0-9A-Fa-f\-]{36}\}")
  if ($m.Success) {
    return Invoke-MSIUninstallGuid $m.Value
  }

  $cmd = $entry.QuietUninstallString
  if (-not $cmd) { $cmd = $entry.UninstallString }

  if ($cmd) {
    $cmd = $cmd.Trim()
    Log "Fallback uninstall command: $cmd"
    $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -Wait -NoNewWindow -PassThru
    Log "Fallback uninstall exit code: $($p.ExitCode)"
    return $p.ExitCode
  }

  Log "WARN: No uninstall method found for entry: $($entry.DisplayName)"
  return 0
}

function Find-MSXML4DllsInScope() {
  $hits = New-Object System.Collections.Generic.List[string]

  $patterns = @(
    "$env:windir\System32\msxml4*.dll",
    "$env:windir\SysWOW64\msxml4*.dll"
  )
  foreach ($pat in $patterns) {
    Get-ChildItem -Path $pat -Force -ErrorAction SilentlyContinue | ForEach-Object { $hits.Add($_.FullName) | Out-Null }
  }

  $scanRoots = @("C:\Program Files", "C:\Program Files (x86)")
  foreach ($r in $scanRoots) {
    if (Test-Path $r) {
      Get-ChildItem -Path $r -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "msxml4*.dll" -and $_.FullName -notmatch "\\Windows\\WinSxS\\" } |
        ForEach-Object { $hits.Add($_.FullName) | Out-Null }
    }
  }

  return ($hits | Sort-Object -Unique)
}

try {
  Log "============================================================"
  Log "Starting MSXML 4 removal..."

  $entriesPre = @(Get-MSXML4Entries)
  $dllsPre    = @(Find-MSXML4DllsInScope)

  Log "Pre-check: Products=$($entriesPre.Count) DLLs=$($dllsPre.Count)"
  foreach ($e in $entriesPre) { Log ("Pre Product: {0} | Ver={1} | Key={2}" -f $e.DisplayName, $e.DisplayVersion, $e.PSChildName) }
  foreach ($d in $dllsPre)    { Log ("Pre DLL: $d") }

  if ($entriesPre.Count -eq 0 -and $dllsPre.Count -eq 0) {
    # NO_ACTION: do NOT append to remediationSummary (but lastRemediationDate still updates)
    Finish "NO_ACTION | MSXML 4 not found (nothing to remove)" $null
  }

  # --- Uninstall ALL MSXML4 entries ---
  $uninstallOps = 0
  $exitCodes = New-Object System.Collections.Generic.List[string]

  foreach ($e in $entriesPre) {
    Log ("Uninstalling: {0} | Ver={1}" -f $e.DisplayName, $e.DisplayVersion)
    $code = Uninstall-Entry $e
    $exitCodes.Add("$($e.DisplayName)=$code") | Out-Null
    $uninstallOps++
  }

  Start-Sleep -Seconds 8

  # Retry once if anything still present
  $entriesMid = @(Get-MSXML4Entries)
  if ($entriesMid.Count -gt 0) {
    Log "Post-uninstall check still shows $($entriesMid.Count) MSXML4 entries. Retrying uninstall once..."
    foreach ($e in $entriesMid) {
      Log ("Retry uninstall: {0} | Ver={1}" -f $e.DisplayName, $e.DisplayVersion)
      $code = Uninstall-Entry $e
      $exitCodes.Add("RETRY:$($e.DisplayName)=$code") | Out-Null
      Start-Sleep -Seconds 4
    }
  }

  # --- Remove DLLs in scope ---
  $dllTargets = @(Find-MSXML4DllsInScope)
  $deleted = 0
  $unreg   = 0

  foreach ($dll in $dllTargets) {
    try {
      Log "Target DLL: $dll"

      try {
        Start-Process -FilePath "regsvr32.exe" -ArgumentList "/u /s `"$dll`"" -Wait -NoNewWindow | Out-Null
        $unreg++
        Log "Unregistered: $dll"
      } catch {
        Log "WARN: Unregister failed for ${dll}: $($_.Exception.Message)"
      }

      try {
        Remove-Item -Path $dll -Force -ErrorAction Stop
        $deleted++
        Log "Deleted: $dll"
      } catch {
        Log "WARN: Delete failed; attempting ownership fix: $dll"
        Start-Process "cmd.exe" -ArgumentList "/c takeown /f `"$dll`" /a" -Wait -NoNewWindow | Out-Null
        Start-Process "cmd.exe" -ArgumentList "/c icacls `"$dll`" /grant Administrators:F /c" -Wait -NoNewWindow | Out-Null
        Remove-Item -Path $dll -Force -ErrorAction Stop
        $deleted++
        Log "Deleted after permissions fix: $dll"
      }
    } catch {
      Log "ERROR: Failed to remove ${dll}: $($_.Exception.Message)"
    }
  }

  # --- Final verification ---
  Start-Sleep -Seconds 6
  $entriesPost = @(Get-MSXML4Entries)
  $dllsPost    = @(Find-MSXML4DllsInScope)

  Log "Final check: Products=$($entriesPost.Count) DLLs=$($dllsPost.Count)"

  # If DLLs are gone but uninstall keys linger, remove orphan uninstall keys
  $orphansRemoved = 0
  if ($entriesPost.Count -gt 0 -and $dllsPost.Count -eq 0) {
    Log "DLLs are gone but uninstall entries remain. Removing orphan uninstall registry keys..."
    foreach ($e in $entriesPost) {
      try {
        Log ("Removing orphan uninstall key: {0} | Path={1}" -f $e.DisplayName, $e.PSPath)
        Remove-Item -Path $e.PSPath -Recurse -Force -ErrorAction Stop
        $orphansRemoved++
      } catch {
        Log ("ERROR: Failed removing orphan uninstall key for {0}: {1}" -f $e.DisplayName, $_.Exception.Message)
      }
    }
  }

  if ($orphansRemoved -gt 0) {
    Start-Sleep -Seconds 2
    $entriesPost = @(Get-MSXML4Entries)
    Log "After orphan cleanup: Products=$($entriesPost.Count)"
  }

  if ($entriesPost.Count -eq 0 -and $dllsPost.Count -eq 0) {
    $out = "RESULT | MSXML 4 removal complete (UninstallOps=$uninstallOps; DLLsUnregistered=$unreg; DLLsDeleted=$deleted; OrphanKeysRemoved=$orphansRemoved)"
    Finish $out "MSXML4 Removed"
  } else {
    $out = "RESULT | ERROR (MSXML 4 still present) (Products=$($entriesPost.Count); DLLs=$($dllsPost.Count))"
    Log ("ExitCodes: " + ($exitCodes -join "; "))
    Finish $out "MSXML4 Remove FAILED"
  }
}
catch {
  Finish ("RESULT | ERROR (MSXML 4 removal failed): " + $_.Exception.Message) "MSXML4 Remove FAILED"
}