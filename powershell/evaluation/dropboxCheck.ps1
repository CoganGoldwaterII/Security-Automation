# ============================================================================
# NAME: Detect Dropbox
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   TRIGGER   | Dropbox detected
#   NO_ACTION | Dropbox not detected
#   ERROR     | Unexpected script error occurred
#
# EXIT CODE:
#   Always 0 (NinjaOne condition compatibility)
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
#   C:\MME\AutoLogs\Dropbox_Detect.log
#
# DESCRIPTION:
#   Evaluates Windows endpoints for evidence of Dropbox installation
#   or activity using multiple detection methods.
#
#   Detection sources:
#     - Machine-wide installed application registry entries
#     - Installed application entries in loaded user registry hives
#     - Dropbox-related Windows services
#     - Running Dropbox processes
#     - Dropbox scheduled tasks
#     - Known machine-wide Dropbox executable locations
#     - Known per-user Dropbox executable locations
#
#   Records individual findings in the evaluation log.
#
#   Returns TRIGGER when one or more indicators are found.
#   Returns NO_ACTION when no indicators are found.
#   Returns ERROR when an unexpected terminating error occurs.
#
#   Includes a finding count and up to five evidence summaries
#   in the TRIGGER output.
#
#   Read-only evaluation. No remediation is performed.
# ============================================================================

$ErrorActionPreference = 'Stop'

$LogDir  = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogDir 'Dropbox_Detect.log'

function Write-Log {
    param (
        [string]$Message
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogPath -Value "$Timestamp | $Message"
}

function Add-Finding {
    param (
        [string]$Type,
        [string]$Name,
        [string]$Path,
        [string]$Detail
    )

    $Finding = [pscustomobject]@{
        Type   = $Type
        Name   = $Name
        Path   = $Path
        Detail = $Detail
    }

    $script:Findings.Add($Finding) | Out-Null
    Write-Log "$Type | $Name | $Path | $Detail"
}

try {
    if (-not (Test-Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }

    Write-Log '===== Dropbox detection evaluation started ====='

    $Findings = New-Object System.Collections.Generic.List[object]

    # Registry uninstall entries, machine-wide
    $MachineUninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($Root in $MachineUninstallRoots) {
        if (Test-Path $Root) {
            Get-ChildItem -Path $Root -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $Item = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    if ($Item.DisplayName -match '(?i)\bDropbox\b') {
                        Add-Finding `
                            -Type 'Registry' `
                            -Name $Item.DisplayName `
                            -Path $_.PSPath `
                            -Detail "Version=$($Item.DisplayVersion); Publisher=$($Item.Publisher)"
                    }
                }
                catch {
                    Write-Log "WARN | Failed reading registry item $($_.PSPath): $($_.Exception.Message)"
                }
            }
        }
    }

    # Registry uninstall entries, loaded user hives
    $LoadedUserHives = Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object {
            $_.PSChildName -match '^S-1-5-21-' -and
            $_.PSChildName -notmatch '_Classes$'
        }

    foreach ($Hive in $LoadedUserHives) {
        $UserUninstallRoots = @(
            "Registry::HKEY_USERS\$($Hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "Registry::HKEY_USERS\$($Hive.PSChildName)\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        foreach ($Root in $UserUninstallRoots) {
            if (Test-Path $Root) {
                Get-ChildItem -Path $Root -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $Item = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                        if ($Item.DisplayName -match '(?i)\bDropbox\b') {
                            Add-Finding `
                                -Type 'UserRegistry' `
                                -Name $Item.DisplayName `
                                -Path $_.PSPath `
                                -Detail "SID=$($Hive.PSChildName); Version=$($Item.DisplayVersion); Publisher=$($Item.Publisher)"
                        }
                    }
                    catch {
                        Write-Log "WARN | Failed reading user registry item $($_.PSPath): $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    # Services
    Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '(?i)^(DbxSvc|Dropbox.*)$' -or
            $_.DisplayName -match '(?i)\bDropbox\b' -or
            $_.PathName -match '(?i)\\Dropbox\\'
        } |
        ForEach-Object {
            Add-Finding `
                -Type 'Service' `
                -Name $_.Name `
                -Path $_.PathName `
                -Detail "DisplayName=$($_.DisplayName); State=$($_.State); StartMode=$($_.StartMode)"
        }

    # Running processes
    $DropboxProcessNames = @(
        'Dropbox.exe',
        'DropboxUpdate.exe',
        'DropboxCrashHandler.exe',
        'DropboxThumbnailGenerator.exe',
        'DbxSvc.exe'
    )

    Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $DropboxProcessNames -contains $_.Name
        } |
        ForEach-Object {
            Add-Finding `
                -Type 'Process' `
                -Name $_.Name `
                -Path $_.ExecutablePath `
                -Detail "PID=$($_.ProcessId)"
        }

    # Scheduled tasks
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object {
                $_.TaskName -match '(?i)\bDropbox\b' -or
                $_.TaskPath -match '(?i)\bDropbox\b'
            } |
            ForEach-Object {
                Add-Finding `
                    -Type 'ScheduledTask' `
                    -Name $_.TaskName `
                    -Path $_.TaskPath `
                    -Detail "State=$($_.State)"
            }
    }
    catch {
        Write-Log "WARN | Scheduled task check failed: $($_.Exception.Message)"
    }

    # Known executable paths, machine-wide
    $MachineFileCandidates = @()

    if ($env:ProgramFiles) {
        $MachineFileCandidates += Join-Path $env:ProgramFiles 'Dropbox\Client\Dropbox.exe'
        $MachineFileCandidates += Join-Path $env:ProgramFiles 'Dropbox\Update\DropboxUpdate.exe'
    }

    if (${env:ProgramFiles(x86)}) {
        $MachineFileCandidates += Join-Path ${env:ProgramFiles(x86)} 'Dropbox\Client\Dropbox.exe'
        $MachineFileCandidates += Join-Path ${env:ProgramFiles(x86)} 'Dropbox\Update\DropboxUpdate.exe'
    }

    foreach ($Path in $MachineFileCandidates | Sort-Object -Unique) {
        if (Test-Path $Path) {
            $Version = $null
            try {
                $Version = (Get-Item $Path -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
            }
            catch {}

            Add-Finding `
                -Type 'File' `
                -Name (Split-Path $Path -Leaf) `
                -Path $Path `
                -Detail "Version=$Version"
        }
    }

    # Known executable paths, per-user
    $UserProfiles = Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') -and
            $_.Name -notmatch '^defaultuser'
        }

    foreach ($Profile in $UserProfiles) {
        $UserFileCandidates = @(
            (Join-Path $Profile.FullName 'AppData\Roaming\Dropbox\bin\Dropbox.exe'),
            (Join-Path $Profile.FullName 'AppData\Local\Dropbox\Update\DropboxUpdate.exe')
        )

        foreach ($Path in $UserFileCandidates) {
            if (Test-Path $Path) {
                $Version = $null
                try {
                    $Version = (Get-Item $Path -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
                }
                catch {}

                Add-Finding `
                    -Type 'UserFile' `
                    -Name (Split-Path $Path -Leaf) `
                    -Path $Path `
                    -Detail "UserProfile=$($Profile.Name); Version=$Version"
            }
        }
    }

    $UniqueFindings = $Findings |
        Sort-Object Type, Name, Path, Detail -Unique

    if ($UniqueFindings.Count -gt 0) {
        $Evidence = ($UniqueFindings |
            Select-Object -First 5 |
            ForEach-Object { "$($_.Type):$($_.Name)" }) -join '; '

        $Final = "TRIGGER | Dropbox detected. Findings=$($UniqueFindings.Count). Evidence=$Evidence"
    }
    else {
        $Final = 'NO_ACTION | Dropbox not detected.'
    }

    Write-Log $Final
    Write-Log '===== Dropbox detection evaluation completed ====='
    Write-Output $Final
    exit 0
}
catch {
    try {
        if (-not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }

        Write-Log "ERROR | Unexpected script error occurred: $($_.Exception.Message)"
    }
    catch {}

    Write-Output "ERROR | Unexpected script error occurred: $($_.Exception.Message)"
    exit 0
}