# ============================================================================
# NAME: Staging Directory Cleanup - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   None; script exits 0 without reporting remediation status.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None
# DESCRIPTION:
#   Removes the C:\MME\CS staging directory and all its contents
#   when the directory exists.
#
#   Suppresses deletion errors and does not report individual failures.
#   Intended for scheduled cleanup of temporary automation files.
#
#   Always exits with code 0 for NinjaOne automation compatibility.
#
# WARNING:
#   Deletes all files and subdirectories under C:\MME\CS.
#   Ensure no active automation requires staged files before execution.
# ============================================================================

# ==========================================
# REMEDIATION: Delete C:\MME\CS
# Minimal version for scheduled automation
# Always exits cleanly
# ==========================================

if (Test-Path "C:\MME\CS") {
    Remove-Item "C:\MME\CS" -Recurse -Force -ErrorAction SilentlyContinue
}

exit 0