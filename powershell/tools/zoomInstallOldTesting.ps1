# ============================================================================
# NAME: Zoom Legacy Version - Install (Testing Only)
# AUTHORED BY: Cogan Goldwater
# TYPE: Testing Utility / Installation
# SCOPE: Windows endpoints / NinjaOne automation
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   None; msiexec returns its native process exit code.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: Yes
#   Destination: C:\MME\CS
#   Files:
#     OLD-ZoomInstallerFull.msi
# LOGGING PATH:
#   None
# DESCRIPTION:
#   Silently installs an older, potentially vulnerable Zoom version
#   from a locally staged MSI for controlled remediation testing.
#   Suppresses automatic reboot during installation.
#   Requires the MSI to be transferred before execution.
#
# WARNING:
#   TESTING ONLY - DO NOT DEPLOY TO PRODUCTION.
#   Intentionally installs outdated software with known security risks.
#   Use only in an authorized, isolated testing environment.
# ============================================================================

msiexec /i "C:\MME\CS\OLD-ZoomInstallerFull.msi" /qn /norestart