# ============================================================================
# NAME: RDP Redirection Warning Registry Fix
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Endpoints / Remote Desktop Client
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   SUCCESS: Registry key set correctly.
#   FAIL: Value was not set correctly.
#   FAIL: <error message>
#
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   None; results are written to console output.
#
# DESCRIPTION:
#   Creates or updates the Remote Desktop Client policy registry value
#   controlling the redirection warning dialog behavior for RDP files.
#
#   Registry Path:
#     HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\Client
#
#   Registry Value:
#     RedirectionWarningDialogVersion
#
#   Registry Type:
#     DWORD
#
#   Required Value:
#     1
#
#   Creates the registry path if it does not exist.
#   Creates or updates the DWORD value and verifies the configured value.
#
#   Reports SUCCESS when the value matches the required configuration.
#   Reports FAIL when verification fails or an exception occurs.
#
#   Modifies the local machine registry.
#   Does not configure NinjaOne custom fields or perform additional
#   remediation actions.
#
#   NOTE:
#   Uses existing SUCCESS/FAIL output rather than standard NinjaOne
#   RESULT/NO_ACTION/ERROR tokens. No explicit exit code is implemented.
# ============================================================================

$path = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\Client"
$name = "RedirectionWarningDialogVersion"
$value = 1

try {
   # Create the registry path if it doesn't exist
   if (!(Test-Path $path)) {
       New-Item -Path $path -Force | Out-Null
   }

   # Create or update the DWORD value
   New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWord -Force | Out-Null

   # Verify it was set correctly
   $check = (Get-ItemProperty -Path $path -Name $name).$name

   if ($check -eq $value) {
       Write-Host "SUCCESS: Registry key set correctly." -ForegroundColor Green
   } else {
       Write-Host "FAIL: Value was not set correctly." -ForegroundColor Red
   }
}
catch {
   Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
}