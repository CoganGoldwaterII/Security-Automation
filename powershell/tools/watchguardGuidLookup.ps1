# ============================================================================
# NAME: WatchGuard Product GUID Discovery
# AUTHORED BY: Cogan Goldwater
# TYPE: Utility / Discovery
# SCOPE: Windows endpoints / PowerShell
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   None; outputs matching product names and uninstall commands.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# LOGGING PATH:
#   None
# DESCRIPTION:
#   Searches 64-bit and 32-bit Windows uninstall registry locations for
#   installed WatchGuard and AuthPoint products.
#
#   Returns the display name, uninstall command, and quiet uninstall
#   command when available. MSI uninstall strings may contain product GUIDs
#   useful for identifying installed software and performing removals.
#
#   Read-only discovery. Does not modify installed applications.
# ============================================================================

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" , "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
Where-Object { $_.DisplayName -like "*AuthPoint*" -or $_.DisplayName -like "*WatchGuard*" } |
Select-Object DisplayName, UninstallString, QuietUninstallString
