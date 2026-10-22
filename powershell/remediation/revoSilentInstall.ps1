# ============================================================================
# NAME: Revo Uninstaller - Install
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   Installer = C:\MME\CS\revosetup.exe
# OUTPUT TOKENS:
#   ExitCode: <Installer exit code>
#   ERROR | Not emitted as a standardized token
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: Yes
#   Destination: C:\MME\CS
#   Files:
#     revosetup.exe
# LOGGING PATH:
#   C:\Temp\RevoInstall.log
# DESCRIPTION:
#   Installs Revo Uninstaller using the executable staged in C:\MME\CS.
#   Runs the installer silently, suppresses message boxes and automatic
#   restarts, and writes the installer log to C:\Temp.
#
#   If the installer is missing, lists staged files and reports an error.
#   Outputs the installer exit code and the last 80 lines of the installer
#   log when available.
#
#   Returns the installer exit code, or exit code 1 if the file is missing.
# ============================================================================

$Installer = "C:\MME\CS\revosetup.exe"

if (!(Test-Path $Installer)) {
    Write-Host "Contents of C:\Temp:"
    Get-ChildItem "C:\MME\CS" | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
    Write-Error "Revo installer not found at: $Installer"
    exit 1
}

$args = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=C:\Temp\RevoInstall.log"
$p = Start-Process -FilePath $Installer -ArgumentList $args -Wait -PassThru
Write-Output "ExitCode: $($p.ExitCode)"

if (Test-Path "C:\Temp\RevoInstall.log") {
    Get-Content "C:\Temp\RevoInstall.log" -Tail 80
}

exit $p.ExitCode