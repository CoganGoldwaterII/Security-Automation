
# ============================================================================
# NAME: AutoPlay Disable Rollback
# AUTHORED BY: Cogan Goldwater
# TYPE: Rollback
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   RESULT    | AutoPlay settings rolled back
#   NO_ACTION | AutoPlay remediation settings not present
#   ERROR     | Stage=Rollback | <Message>
#
#   Exit Code: Always 0 after script execution
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
#   %ProgramData%\AutomationPlaybook\Logs\AutoPlay_Rollback.log
#
# DESCRIPTION:
#   Reverses the AutoPlay Disable Remediation by removing the registry
#   values used for machine-wide enforcement and applicable local users.
#
#   Machine-wide policy:
#     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
#     Removes: NoDriveTypeAutoRun
#
#   Per-user AutoPlay master setting:
#     HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\
#     Explorer\AutoplayHandlers
#     Removes: DisableAutoplay
#
#   Enumerates applicable local user profiles, temporarily loads unloaded
#   registry hives when necessary, and removes the target values if present.
#
#   Returns RESULT when at least one registry value was removed.
#   Returns NO_ACTION when none of the target values were present.
#   Returns ERROR when rollback encounters an exception.
#
#   Registry hives loaded by this script are unloaded during cleanup.
#   Unrelated registry values are preserved.
#
#   IMPORTANT:
#   This rollback removes the specified values regardless of their origin.
#   It does not restore previous values or distinguish settings originally
#   created by remediation from settings established through other means.
#   Group Policy or other management systems may subsequently reapply
#   their configurations.
#
#   Requires administrative privileges or LOCAL SYSTEM.
# ============================================================================

$LogDir  = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogPath = Join-Path $LogDir 'AutoPlay_Rollback.log'

$PolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$PolicyName = 'NoDriveTypeAutoRun'

$UserSubKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'
$UserValue  = 'DisableAutoplay'

$Changed = $false

function Write-Log {
    param([string]$Message)

    try {
        if (-not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }

        Add-Content `
            -Path $LogPath `
            -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message" `
            -ErrorAction Stop
    }
    catch {
    }
}

function Get-ApplicableProfiles {
    $profiles = @()

    $profileRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

    foreach ($key in Get-ChildItem $profileRoot -ErrorAction Stop) {
        $sid = $key.PSChildName

        if ($sid -notmatch '^S-1-5-21-.+-\d+$') {
            continue
        }

        $profilePath = (
            Get-ItemProperty `
                $key.PSPath `
                -Name ProfileImagePath `
                -ErrorAction SilentlyContinue
        ).ProfileImagePath

        if (-not $profilePath) {
            continue
        }

        $expanded = [Environment]::ExpandEnvironmentVariables($profilePath)
        $ntUser = Join-Path $expanded 'NTUSER.DAT'

        if (Test-Path $ntUser) {
            $profiles += [pscustomobject]@{
                SID    = $sid
                NTUser = $ntUser
            }
        }
    }

    return $profiles
}

$mounted = @()

try {
    # -----------------------------------------------------------------------
    # REMOVE MACHINE-WIDE AUTOPLAY POLICY VALUE
    # -----------------------------------------------------------------------

    if (Test-Path $PolicyPath) {
        $policy = (
            Get-ItemProperty `
                -Path $PolicyPath `
                -Name $PolicyName `
                -ErrorAction SilentlyContinue
        ).$PolicyName

        if ($null -ne $policy) {
            Remove-ItemProperty `
                -Path $PolicyPath `
                -Name $PolicyName `
                -ErrorAction Stop

            $Changed = $true
        }
    }

    # -----------------------------------------------------------------------
    # REMOVE PER-USER AUTOPLAY MASTER SETTINGS
    # -----------------------------------------------------------------------

    $profiles = @(Get-ApplicableProfiles)

    foreach ($profile in $profiles) {
        $sid = $profile.SID
        $hiveRoot = "Registry::HKEY_USERS\$sid"

        if (-not (Test-Path $hiveRoot)) {
            & reg.exe load "HKU\$sid" "$($profile.NTUser)" | Out-Null

            if ($LASTEXITCODE -ne 0) {
                throw "Unable to load user hive for SID $sid."
            }

            $mounted += $sid
        }

        $path = "Registry::HKEY_USERS\$sid\$UserSubKey"

        if (Test-Path $path) {
            $value = (
                Get-ItemProperty `
                    -Path $path `
                    -Name $UserValue `
                    -ErrorAction SilentlyContinue
            ).$UserValue

            if ($null -ne $value) {
                Remove-ItemProperty `
                    -Path $path `
                    -Name $UserValue `
                    -ErrorAction Stop

                $Changed = $true
            }
        }
    }

    # -----------------------------------------------------------------------
    # FINAL RESULT
    # -----------------------------------------------------------------------

    if ($Changed) {
        $message = "RESULT | AutoPlay settings rolled back | UserProfiles=$($profiles.Count)"
    }
    else {
        $message = "NO_ACTION | AutoPlay remediation settings not present | UserProfiles=$($profiles.Count)"
    }

    Write-Log $message
    Write-Output $message
}
catch {
    $message = "ERROR | Stage=Rollback | $($_.Exception.Message)"

    Write-Log $message
    Write-Output $message
}
finally {
    foreach ($sid in $mounted) {
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()

        & reg.exe unload "HKU\$sid" | Out-Null
    }

    exit 0
}
