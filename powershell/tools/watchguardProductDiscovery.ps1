# ============================================================================
# NAME: WatchGuard / AuthPoint Installed Version Discovery
# AUTHORED BY: Cogan Goldwater
# TYPE: Utility / Discovery
# SCOPE: Windows endpoints / PowerShell
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   None; outputs matching product names and installed versions.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# LOGGING PATH:
#   None
# DESCRIPTION:
#   Searches 64-bit and 32-bit Windows uninstall registry locations for
#   installed WatchGuard and AuthPoint products.
#
#   Returns the display name and installed version for each matching product.
#   Read-only discovery. Does not modify installed applications.
# ============================================================================

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
Where-Object { $_.DisplayName -like "*AuthPoint*" -or $_.DisplayName -like "*WatchGuard*" } |
Select DisplayName, DisplayVersion