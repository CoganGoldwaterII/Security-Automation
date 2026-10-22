# ============================================================================
# NAME: Fix ERROR_SXS_ASSEMBLY_MISSING
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Manual Repair
# SCOPE: Windows / Component-Based Servicing (CBS)
# VARIABLES:
#   FilePath = C:\Windows\Logs\CBS\CBS.log (Optional)
#   active   = 1 (Internal; 1=Delete, 0=Test Mode)
# OUTPUT TOKENS:
#   None; diagnostic and deletion status messages are written to console.
#   Does not implement RESULT / NO_ACTION / ERROR routing.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None; console output only.
# BACKUP PATH:
#   C:\temp\ComponentBasedServicing-<timestamp>.reg
# DESCRIPTION:
#   Searches CBS.log for ERROR_SXS_ASSEMBLY_MISSING entries.
#   Extracts package/language identifiers from matching entries.
#   Searches Component Based Servicing PackageDetect and Packages
#   registry locations for matching registry property names.
#
#   When active=1, attempts to back up the CBS registry branch,
#   modifies matching registry key permissions, and removes matching
#   registry properties.
#
#   When active=0, uses WhatIf for property deletion but still
#   attempts registry permission changes.
#
#   WARNING:
#   High-risk servicing registry modification.
#   Backup success is not validated before deletion.
#   Original behavior preserved pending functional remediation review.
# ============================================================================

[cmdletbinding()]  # For verbose, debug etc
param (
  [string] $FilePath = 'C:\Windows\Logs\CBS\CBS.log'   # Default value of CBS.log file to read
)

$date = Get-Date -format "yyyy-MM-dd_hh-mm"
$active = 1     # Set this to 0 to NOT remove the registry entries but run in Test mode to see what would be deleted

"#############################################################"
"# Fix-ERROR_SXS_ASSEMBLY_MISSING.PS1"
"# Fixes the problem with SFC/DISM resulting in 0x80073701 = ERROR_SXS_ASSEMBLY_MISSING"
"# Found at https://social.technet.microsoft.com/Forums/ie/en-US/c1d825aa-f946-427c-bd81-cf3a18908651/server-2016-unable-to-add-rsat-role-the-referenced-assembly-could-not-be-found-error?forum=winservermanager"
"# It may be that language packs need to be removed with lpksetup.exe as well."

#Read CBS log file contents into memory
$Contents = ""
while ("" -eq $Contents) {
  try {
    "[.] Trying to read in $filepath .."
    $Contents = Get-Content -Path $filepath
  } catch {
    "[!] File is currently in use.  Re-running script in 10 seconds ... [Paused]"
    Start-Sleep 10
  }
}

"[.] Parse log file for missing assemblies .."
$InterestingLines = $Contents | Select-String -SimpleMatch '(ERROR_SXS_ASSEMBLY_MISSING)'
if ($InterestingLines) {
  "[!] Interesting lines found:"
  $InterestingLines
} else {
  "[!] Nothing of interest found! Exiting .."
  exit
}

if ($active -eq 1) {
    "[.] Creating backup of ALL registry entries in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing .."
    reg save "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" "c:\temp\ComponentBasedServicing-$($date).reg"