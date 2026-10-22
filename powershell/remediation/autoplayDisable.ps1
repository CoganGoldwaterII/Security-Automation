
# ============================================================================
# NAME: AutoPlay Disable Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   RESULT    | AutoPlay disabled
#   NO_ACTION | AutoPlay already disabled
#   ERROR     | Stage=Remediation | <Message>
#
#   Exit Code: Always 0
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
#   %ProgramData%\AutomationPlaybook\Logs\AutoPlay_Remediation.log
#
# DESCRIPTION:
#   Disables AutoPlay at the machine policy layer and disables the
#   user-facing AutoPlay master setting for applicable local user profiles.
#
#   Machine-wide enforcement:
#     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
#     NoDriveTypeAutoRun = 255 (DWORD)
#
#   Per-user AutoPlay master setting:
#     HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\
#     Explorer\AutoplayHandlers
#     DisableAutoplay = 1 (DWORD)
#
#   Enumerates applicable local user profiles, temporarily loads unloaded
#   registry hives when required, and sets the corresponding policy values.
#
#   Returns RESULT when at least one setting required modification.
#   Returns NO_ACTION when all evaluated settings were already compliant.
#   Returns ERROR when remediation encounters an exception.
#
#   Registry hives loaded by this remediation are unloaded during cleanup.
#   Existing unrelated registry settings are preserved.
#
#   Requires administrative privileges or LOCAL SYSTEM.
# ============================================================================

$LogDir  = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogPath = Join-Path $LogDir 'AutoPlay_Remediation.log'

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
    # MACHINE-WIDE AUTOPLAY POLICY
    # -----------------------------------------------------------------------

    if (-not (Test-Path $PolicyPath)) {
        New-Item -Path $PolicyPath -Force | Out-Null
    }

    $currentPolicy = (
        Get-ItemProperty `
            -Path $PolicyPath `
            -Name $PolicyName `
            -ErrorAction SilentlyContinue
    ).$PolicyName

    if ($currentPolicy -ne 255) {
        New-ItemProperty `
            -Path $PolicyPath `
            -Name $PolicyName `
            -PropertyType DWord `
            -Value 255 `
            -Force | Out-Null

        $Changed = $true
    }

    # -----------------------------------------------------------------------
    # PER-USER AUTOPLAY MASTER SETTINGS
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

        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }

        $current = (
            Get-ItemProperty `
                -Path $path `
                -Name $UserValue `
                -ErrorAction SilentlyContinue
        ).$UserValue

        if ($current -ne 1) {
            New-ItemProperty `
                -Path $path `
                -Name $UserValue `
                -PropertyType DWord `
                -Value 1 `
                -Force | Out-Null

            $Changed = $true
        }
    }

    # -----------------------------------------------------------------------
    # FINAL RESULT
    # -----------------------------------------------------------------------

    if ($Changed) {
        $message = "RESULT | AutoPlay disabled | MachinePolicy=255 UserProfiles=$($profiles.Count)"
    }
    else {
        $message = "NO_ACTION | AutoPlay already disabled | MachinePolicy=255 UserProfiles=$($profiles.Count)"
    }

    Write-Log $message
    Write-Output $message
}
catch {
    $message = "ERROR | Stage=Remediation | $($_.Exception.Message)"

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
