# ============================================================================
# NAME: Google Chrome - Legacy Version Install (Testing Only)
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Testing Utility
# SCOPE: Windows endpoints / NinjaOne automation
# EXECUTION CONTEXT:
#   SYSTEM / Elevated
# VARIABLES:
#   LogDir    = C:\Temp
#   LogFile   = C:\Temp\Install-Chrome.log
#   Installer = C:\MME\CS\ChromeStandaloneSetup64.exe
# OUTPUT TOKENS:
#   INSTALLED | Chrome installer executed
#   ERROR     | Installer missing or execution failed
#   NO_ACTION | Not emitted by this script
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: Yes
#   Destination: C:\MME\CS
#   Files:
#     ChromeStandaloneSetup64.exe
#   NOTE:
#     Transfer the desired older Chrome installer before execution.
#     The script does not download or retrieve installation files.
# LOGGING PATH:
#   C:\Temp\Install-Chrome.log
# DESCRIPTION:
#   Installs a locally staged Google Chrome installer for controlled
#   testing of outdated browser versions and remediation workflows.
#
#   Attempts to configure policies to prevent Chrome self-updates before
#   installation, then runs the staged installer silently.
#
#   Stops and disables Google Update services (gupdate and gupdatem)
#   and attempts to disable associated Google Update scheduled tasks.
#
#   Google Update service changes may affect other Google applications.
#   The script does not restore services, tasks, or update policies.
#
#   Always exits with code 0 for NinjaOne automation compatibility.
#
# WARNING:
#   TESTING ONLY - DO NOT DEPLOY TO PRODUCTION.
#
#   INTENTIONALLY INSTALLS AN OLDER CHROME VERSION AND ATTEMPTS TO
#   DISABLE AUTOMATIC UPDATES.
#
#   This may leave the endpoint vulnerable to known security exploits.
#   Execute only in an isolated, authorized testing environment.
#
#   DO NOT USE THIS SCRIPT UNLESS YOU FULLY UNDERSTAND ITS EFFECTS.
# ============================================================================

# ==========================================
# Install Google Chrome from local installer
# Source: C:\MME\CS\ChromeStandaloneSetup64.exe
# Silent install + stop Google Update services/tasks (testing)
# ALSO sets Chrome policies to disable self-update BEFORE install
# Logs to C:\Temp
# Always exit 0
# ==========================================

$LogDir    = "C:\Temp"
$LogFile   = "$LogDir\Install-Chrome.log"
$Installer = "C:\MME\CS\ChromeStandaloneSetup64.exe"

if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts | $Message"
}

Write-Log "=== START Chrome install ==="
Write-Log "Installer: $Installer"

# --- Set Chrome policies BEFORE install to prevent Chrome self-update ---
try {
    $policyBase = "HKLM:\SOFTWARE\Policies\Google"
    $policyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"

    if (-not (Test-Path $policyBase)) { New-Item -Path $policyBase -Force | Out-Null }
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }

    # 0 = Updates disabled
    New-ItemProperty -Path $policyPath -Name "UpdateDefault" -PropertyType DWord -Value 0 -Force | Out-Null

    # Extra belt-and-suspenders (harmless if ignored on older versions)
    New-ItemProperty -Path $policyPath -Name "DisableAutoUpdateChecksCheckboxValue" -PropertyType DWord -Value 1 -Force | Out-Null

    Write-Log "Set Chrome policies: UpdateDefault=0; DisableAutoUpdateChecksCheckboxValue=1"
}
catch {
    Write-Log ("ERROR setting Chrome policies: " + $_.Exception.Message)
    # Continue anyway
}

if (-not (Test-Path $Installer)) {
    Write-Log "ERROR: Installer not found."
    Write-Output "ERROR | Chrome installer not found at $Installer"
    exit 0
}

# --- Install Chrome silently ---
try {
    $args = "/silent /install"
    Write-Log "Running installer with args: $args"
    $p = Start-Process -FilePath $Installer -ArgumentList $args -Wait -PassThru -ErrorAction Stop
    Write-Log "Installer completed. ExitCode=$($p.ExitCode)"
    Write-Output "INSTALLED | Chrome installer executed (silent)"
}
catch {
    Write-Log ("ERROR running installer: " + $_.Exception.Message)
    Write-Output "ERROR | Failed to run Chrome installer"
    # Continue to shutdown Google update services anyway (per request)
}

# --- Stop Google Update services (for testing) ---
$serviceNames = @(
    "gupdate",    # Google Update Service (gupdate)
    "gupdatem"    # Google Update Service (gupdatem)
)

foreach ($svcName in $serviceNames) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc) {
            if ($svc.Status -ne "Stopped") {
                Write-Log "Stopping service: $svcName"
                Stop-Service -Name $svcName -Force -ErrorAction Stop
                Write-Log "Stopped service: $svcName"
            } else {
                Write-Log "Service already stopped: $svcName"
            }

            # Disable so it doesn't come back
            try {
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
                Write-Log "Disabled service startup: $svcName"
            } catch {
                Write-Log ("ERROR disabling service startup ${svcName}: " + $_.Exception.Message)
            }
        } else {
            Write-Log "Service not found (ok): $svcName"
        }
    }
    catch {
        Write-Log ("ERROR stopping service ${svcName}: " + $_.Exception.Message)
    }
}

# --- Disable Google Update scheduled tasks so they don't restart services (for testing) ---
$taskNames = @(
    "\GoogleUpdateTaskMachineCore",
    "\GoogleUpdateTaskMachineUA"
)

foreach ($task in $taskNames) {
    try {
        # schtasks returns non-zero if task doesn't exist; we log and continue
        Write-Log "Disabling scheduled task (if present): $task"
        $null = & schtasks.exe /Change /TN $task /Disable 2>&1
        Write-Log "Attempted disable for task: $task"
    }
    catch {
        Write-Log ("ERROR disabling task ${task}: " + $_.Exception.Message)
    }
}

Write-Log "=== END Chrome install + Google Update shutdown ==="
exit 0