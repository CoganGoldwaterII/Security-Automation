# ============================================================================
# NAME: AutoPlay Disable Evaluation
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   TRIGGER   | AutoPlay enabled or not fully disabled
#   NO_ACTION | AutoPlay disabled
#   ERROR     | Stage=Evaluation | <Message>
#
#   Exit Code: Always 0
#   NinjaOne Condition: Output contains TRIGGER and Result Code 0
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
#   %ProgramData%\AutomationPlaybook\Logs\AutoPlay_Eval.log
#
# DESCRIPTION:
#   Evaluates whether AutoPlay is disabled at both the machine and user
#   profile levels.
#
#   Machine-wide enforcement:
#     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
#     NoDriveTypeAutoRun = 255
#
#   Per-user AutoPlay master setting:
#     HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\
#     Explorer\AutoplayHandlers
#     DisableAutoplay = 1
#
#   Enumerates applicable local user profiles, temporarily loads unloaded
#   registry hives as necessary, and checks each user's AutoPlay setting.
#
#   Returns TRIGGER when:
#     - Machine-wide AutoPlay policy is not disabled
#     - One or more user profiles have AutoPlay enabled or unconfigured
#     - No applicable user profiles are found
#
#   Returns NO_ACTION when machine policy and all applicable user profiles
#   are compliant.
#
#   Registry hives loaded by this evaluation are unloaded during cleanup.
#   No AutoPlay settings are modified by this script.
#
#   Requires administrative privileges or LOCAL SYSTEM.
# ============================================================================

$LogDir  = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogPath = Join-Path $LogDir 'AutoPlay_Eval.log'

$PolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$PolicyName = 'NoDriveTypeAutoRun'

$UserSubKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'
$UserValue  = 'DisableAutoplay'

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
    $policy = (
        Get-ItemProperty `
            -Path $PolicyPath `
            -Name $PolicyName `
            -ErrorAction SilentlyContinue
    ).$PolicyName

    $machineDisabled = ($policy -eq 255)

    $profiles = @(Get-ApplicableProfiles)
    $enabledUsers = @()

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

        $value = (
            Get-ItemProperty `
                -Path $path `
                -Name $UserValue `
                -ErrorAction SilentlyContinue
        ).$UserValue

        # Missing or 0 means the user-facing master setting is not
        # explicitly disabled.
        if ($value -ne 1) {
            $enabledUsers += $sid
        }
    }

    $machineState = if ($machineDisabled) {
        'DISABLED'
    }
    else {
        'NOT_DISABLED'
    }

    if ($profiles.Count -eq 0) {
        $sliderState = 'UNKNOWN'
    }
    elseif ($enabledUsers.Count -eq 0) {
        $sliderState = 'OFF'
    }
    elseif ($enabledUsers.Count -eq $profiles.Count) {
        $sliderState = 'ON'
    }
    else {
        $sliderState = 'MIXED'
    }

    if (
        -not $machineDisabled -or
        $enabledUsers.Count -gt 0 -or
        $profiles.Count -eq 0
    ) {
        $message = "TRIGGER | AutoPlay enabled or not fully disabled | MachinePolicy=$machineState Slider=$sliderState EnabledUserProfiles=$($enabledUsers.Count) TotalUserProfiles=$($profiles.Count)"

        Write-Log $message
        Write-Output $message
    }
    else {
        $message = "NO_ACTION | AutoPlay disabled | MachinePolicy=$machineState Slider=$sliderState UserProfiles=$($profiles.Count)"

        Write-Log $message
        Write-Output $message
    }
}
catch {
    $message = "ERROR | Stage=Evaluation | $($_.Exception.Message)"

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