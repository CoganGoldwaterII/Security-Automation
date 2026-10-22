# ============================================================================
# NAME: OneBrowser PUP Complete Removal - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir = C:\MME\AutoLogs
# OUTPUT TOKENS:
#   RESULT    | Confirmed OneBrowser artifacts removed
#   NO_ACTION | No confirmed removable artifacts found
#   ERROR     | Cleanup failure or confirmed remnants remain
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\OneBrowser_Nuke.log
# DESCRIPTION:
#   Removes confirmed OneBrowser / OB Browser PUP artifacts without
#   depending on application uninstallers.
#
#   Targets:
#     - OneBrowser and associated updater processes
#     - Matching scheduled tasks and services
#     - Known installation and user-profile directories
#     - Confirmed application and startup registry entries
#     - Matching browser extensions
#     - OneBrowser shortcuts
#
#   Safety:
#     - No full-drive recursive scans
#     - No direct Windows Installer database modification
#     - No arbitrary browser profile file deletion
#     - Short OB/OIB directory names require identity evidence
#     - Unrelated application registrations are preserved
#
#   Logs progress, removal failures, and post-cleanup findings.
#   Always exits 0.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$LogDir  = 'C:\MME\AutoLogs'
$LogFile = Join-Path $LogDir 'OneBrowser_Nuke.log'

$script:Actions  = 0
$script:Failures = New-Object 'System.Collections.Generic.List[string]'
$script:RemovedPaths = New-Object 'System.Collections.Generic.List[string]'

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

try {
    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }
}
catch {
    Write-Output "ERROR | Cannot initialize logging: $($_.Exception.Message)"
    exit 0
}

function Write-Log {
    param([string]$Message)

    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"

    try {
        Add-Content -LiteralPath $LogFile -Value $Line -ErrorAction Stop
    }
    catch {
        Write-Output "LOG_ERROR | $($_.Exception.Message)"
    }
}

function Add-Failure {
    param([string]$Message)

    [void]$script:Failures.Add($Message)
    Write-Log "ERROR | $Message"
}

function Add-Action {
    param([string]$Message)

    $script:Actions++
    Write-Log "REMOVED | $Message"
}

function Finish {
    param(
        [ValidateSet('RESULT','NO_ACTION','ERROR')]
        [string]$Token,

        [string]$Message
    )

    $Line = "$Token | $Message"
    Write-Log $Line
    Write-Output $Line
    exit 0
}

# ---------------------------------------------------------------------------
# Identity matching
# ---------------------------------------------------------------------------

function Test-OneBrowserName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return [regex]::IsMatch(
        $Value,
        '(?i)(?<![a-z0-9])(?:one[\s_-]?browser|onebupdate|obupdateservice|obupdate|oibrowser|oibupdate|ob\s+browser)(?![a-z0-9])'
    )
}

function Test-OneBrowserExecutable {
    param([string]$Name)

    return $Name -match '(?i)^(onebrowser|onebupdate|onebupdateservice|obupdate|obupdateservice|oibrowser|oibupdate)(\.exe)?$'
}

function Test-OneBrowserPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    return $Path -match '(?i)[\\/](OneBrowser|One Browser|OneBUpdate|OBUpdate|OIBrowser)([\\/]|$)'
}

function Test-OneBrowserExtensionName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    return $Name -match '(?i)^(OneBrowser|One Browser|OB Browser|OIBrowser)(\b|$)'
}

# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

function Remove-TargetPath {
    param(
        [string]$Path,
        [string]$Reason
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop

        if (Test-Path -LiteralPath $Path) {
            throw 'Path still exists after deletion.'
        }

        [void]$script:RemovedPaths.Add($Path)
        Add-Action "PATH | $Reason | $Path"
    }
    catch {
        Add-Failure "PATH_REMOVE_FAILED | $Path | $($_.Exception.Message)"
    }
}

function Remove-TargetRegistryKey {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop

        if (Test-Path -LiteralPath $Path) {
            throw 'Registry key still exists.'
        }

        Add-Action "REGISTRY | $Path"
    }
    catch {
        Add-Failure "REGISTRY_REMOVE_FAILED | $Path | $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# User profile discovery
# ---------------------------------------------------------------------------

function Get-UserProfilePaths {

    $Paths = New-Object 'System.Collections.Generic.List[string]'

    try {
        $Profiles = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
            Where-Object {
                -not $_.Special -and
                -not [string]::IsNullOrWhiteSpace($_.LocalPath)
            }

        foreach ($Profile in $Profiles) {
            if (Test-Path -LiteralPath $Profile.LocalPath) {
                [void]$Paths.Add($Profile.LocalPath)
            }
        }
    }
    catch {
        Write-Log "WARN | CIM profile discovery failed: $($_.Exception.Message)"
    }

    $UsersRoot = Join-Path $env:SystemDrive 'Users'

    if (Test-Path -LiteralPath $UsersRoot) {
        $Excluded = @(
            'Public',
            'Default',
            'Default User',
            'All Users',
            'defaultuser0'
        )

        Get-ChildItem -LiteralPath $UsersRoot -Directory -Force `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $Excluded -notcontains $_.Name -and
                -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
            } |
            ForEach-Object {
                [void]$Paths.Add($_.FullName)
            }
    }

    return @($Paths | Select-Object -Unique)
}

# ---------------------------------------------------------------------------
# Short folder identity verification
# ---------------------------------------------------------------------------

function Test-ShortFolderIdentity {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return $false
    }

    $Indicators = @(
        'OneBrowser.exe',
        'OIBrowser.exe',
        'OBUpdateService.exe',
        'OneBUpdateService.exe',
        'OneBUpdate',
        'OBUpdate',
        'Update\OBUpdateService.exe',
        'Update\OneBUpdateService.exe',
        'OneBUpdate\OneBUpdateService.exe',
        'Application\OneBrowser.exe',
        'Application\OIBrowser.exe'
    )

    foreach ($Relative in $Indicators) {
        $Candidate = Join-Path $Path $Relative

        if (Test-Path -LiteralPath $Candidate) {
            return $true
        }
    }

    $ApplicationDir = Join-Path $Path 'Application'

    if (Test-Path -LiteralPath $ApplicationDir) {
        $VersionFolders = Get-ChildItem -LiteralPath $ApplicationDir `
            -Directory -ErrorAction SilentlyContinue

        foreach ($VersionFolder in $VersionFolders) {
            foreach ($Exe in @('OneBrowser.exe', 'OIBrowser.exe')) {
                if (Test-Path -LiteralPath (Join-Path $VersionFolder.FullName $Exe)) {
                    return $true
                }
            }
        }
    }

    return $false
}

# ---------------------------------------------------------------------------
# Scheduled task removal
# ---------------------------------------------------------------------------

function Remove-OneBrowserTasks {

    Write-Log 'PHASE | Scheduled tasks'

    try {
        $Tasks = @(Get-ScheduledTask -ErrorAction Stop)
    }
    catch {
        Add-Failure "TASK_ENUM_FAILED | $($_.Exception.Message)"
        return
    }

    foreach ($Task in $Tasks) {

        $TaskName = [string]$Task.TaskName

        $ActionText = @(
            $Task.Actions | ForEach-Object {
                "$($_.Execute) $($_.Arguments)"
            }
        ) -join ' '

        $Matched = (
            (Test-OneBrowserName $TaskName) -or
            (Test-OneBrowserPath $ActionText)
        )

        if (-not $Matched) {
            continue
        }

        try {
            Unregister-ScheduledTask `
                -TaskName $Task.TaskName `
                -TaskPath $Task.TaskPath `
                -Confirm:$false `
                -ErrorAction Stop

            Add-Action "TASK | $($Task.TaskPath)$($Task.TaskName)"
        }
        catch {
            Add-Failure "TASK_REMOVE_FAILED | $TaskName | $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------------------
# Service removal
# ---------------------------------------------------------------------------

function Remove-OneBrowserServices {

    Write-Log 'PHASE | Services'

    try {
        $Services = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    }
    catch {
        Add-Failure "SERVICE_ENUM_FAILED | $($_.Exception.Message)"
        return
    }

    foreach ($Service in $Services) {

        $Matched = (
            (Test-OneBrowserName $Service.Name) -or
            (Test-OneBrowserName $Service.DisplayName) -or
            (Test-OneBrowserPath $Service.PathName)
        )

        if (-not $Matched) {
            continue
        }

        Write-Log "SERVICE_FOUND | $($Service.Name) | $($Service.PathName)"

        if ($Service.State -ne 'Stopped') {
            try {
                Stop-Service -Name $Service.Name -Force -ErrorAction Stop
                Write-Log "SERVICE_STOPPED | $($Service.Name)"
            }
            catch {
                Write-Log "WARN | Service stop failed: $($Service.Name) | $($_.Exception.Message)"
            }
        }

        try {
            $null = & "$env:SystemRoot\System32\sc.exe" delete $Service.Name 2>&1

            if ($LASTEXITCODE -ne 0) {
                throw "sc.exe returned $LASTEXITCODE"
            }

            Add-Action "SERVICE | $($Service.Name)"
        }
        catch {
            Add-Failure "SERVICE_DELETE_FAILED | $($Service.Name) | $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------------------
# Process termination
# ---------------------------------------------------------------------------

function Stop-OneBrowserProcesses {

    Write-Log 'PHASE | Processes'

    try {
        $Processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    }
    catch {
        Add-Failure "PROCESS_ENUM_FAILED | $($_.Exception.Message)"
        return
    }

    foreach ($Process in $Processes) {

        $Matched = (
            (Test-OneBrowserExecutable $Process.Name) -or
            (Test-OneBrowserPath $Process.ExecutablePath)
        )

        if (-not $Matched) {
            continue
        }

        try {
            Stop-Process -Id $Process.ProcessId -Force -ErrorAction Stop

            Add-Action "PROCESS | $($Process.Name) | PID=$($Process.ProcessId)"
        }
        catch {
            Add-Failure "PROCESS_STOP_FAILED | $($Process.Name) | $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------------------
# Installation and user data removal
# ---------------------------------------------------------------------------

function Remove-OneBrowserFolders {
    param([string[]]$Profiles)

    Write-Log 'PHASE | Filesystem'

    $Roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData
    )

    foreach ($Profile in $Profiles) {
        $Roots += Join-Path $Profile 'AppData\Local'
        $Roots += Join-Path $Profile 'AppData\Roaming'
    }

    $Roots = @($Roots |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Select-Object -Unique)

    foreach ($Root in $Roots) {

        # Explicit OneBrowser folder names.
        foreach ($Name in @('OneBrowser', 'One Browser')) {
            $Target = Join-Path $Root $Name
            Remove-TargetPath -Path $Target -Reason 'Confirmed OneBrowser directory'
        }

        # Short names require supporting artifacts.
        foreach ($Name in @('OB', 'OIB')) {

            $Target = Join-Path $Root $Name

            if (-not (Test-Path -LiteralPath $Target)) {
                continue
            }

            if (Test-ShortFolderIdentity -Path $Target) {
                Remove-TargetPath -Path $Target -Reason 'Verified OB/OIB directory'
            }
            else {
                Write-Log "REVIEW_REQUIRED | Ambiguous short-name directory preserved: $Target"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Targeted registry cleanup
# ---------------------------------------------------------------------------

function Remove-OneBrowserRegistry {

    Write-Log 'PHASE | Registry'

    $SoftwareRoots = @(
        'HKLM:\SOFTWARE',
        'HKLM:\SOFTWARE\WOW6432Node',
        'HKCU:\SOFTWARE'
    )

    # Include already-loaded user hives.
    try {
        $UserHives = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object {
                $_.PSChildName -match '^S-1-5-21-(\d+-){3}\d+$'
            }

        foreach ($Hive in $UserHives) {
            $SoftwareRoots += "Registry::HKEY_USERS\$($Hive.PSChildName)\Software"
        }
    }
    catch {
        Write-Log "WARN | Loaded user hive discovery failed: $($_.Exception.Message)"
    }

    $SoftwareRoots = @($SoftwareRoots | Select-Object -Unique)

    foreach ($Root in $SoftwareRoots) {

        foreach ($Name in @('OneBrowser', 'One Browser')) {
            Remove-TargetRegistryKey -Path (Join-Path $Root $Name)
        }

        # Short-name keys are only removed if corroborating directory
        # evidence exists elsewhere on the endpoint.
        foreach ($Name in @('OB', 'OIB')) {
            $KeyPath = Join-Path $Root $Name

            if (Test-Path -LiteralPath $KeyPath) {
                Write-Log "REVIEW_REQUIRED | Short-name registry key preserved: $KeyPath"
            }
        }

        # Startup entries: remove matching values, not entire Run keys.
        foreach ($RunName in @('Run', 'RunOnce')) {

            $RunPath = Join-Path $Root "Microsoft\Windows\CurrentVersion\$RunName"

            if (-not (Test-Path -LiteralPath $RunPath)) {
                continue
            }

            try {
                $Properties = Get-ItemProperty -LiteralPath $RunPath -ErrorAction Stop

                foreach ($Property in $Properties.PSObject.Properties) {

                    if ($Property.Name -like 'PS*') {
                        continue
                    }

                    $Matched = (
                        (Test-OneBrowserName $Property.Name) -or
                        (Test-OneBrowserPath ([string]$Property.Value))
                    )

                    if (-not $Matched) {
                        continue
                    }

                    try {
                        Remove-ItemProperty `
                            -LiteralPath $RunPath `
                            -Name $Property.Name `
                            -ErrorAction Stop

                        Add-Action "STARTUP | $RunPath | $($Property.Name)"
                    }
                    catch {
                        Add-Failure "STARTUP_REMOVE_FAILED | $RunPath | $($Property.Name)"
                    }
                }
            }
            catch {
                Add-Failure "STARTUP_ENUM_FAILED | $RunPath | $($_.Exception.Message)"
            }
        }
    }

    # Uninstall registry keys.
    # Do not execute an untrusted PUP uninstaller.
    # Do not delete Windows Installer product registration directly.

    $UninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($Root in $UninstallRoots) {

        if (-not (Test-Path -LiteralPath $Root)) {
            continue
        }

        $Keys = Get-ChildItem -LiteralPath $Root -ErrorAction SilentlyContinue

        foreach ($Key in $Keys) {

            try {
                $Properties = Get-ItemProperty -LiteralPath $Key.PSPath -ErrorAction Stop

                $DisplayName = [string]$Properties.DisplayName

                if (-not (Test-OneBrowserExtensionName $DisplayName)) {
                    continue
                }

                $IsMsi = (
                    $Properties.WindowsInstaller -eq 1 -or
                    $Key.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$'
                )

                if ($IsMsi) {
                    Write-Log "REVIEW_REQUIRED | MSI registration preserved: $($Key.PSPath)"
                    continue
                }

                Remove-TargetRegistryKey -Path $Key.PSPath
            }
            catch {
                Add-Failure "UNINSTALL_REGISTRY_FAILED | $($Key.PSPath)"
            }
        }
    }

    # Explicit App Paths entries.
    foreach ($Root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths'
    )) {
        foreach ($Name in @('OneBrowser.exe', 'OIBrowser.exe')) {
            Remove-TargetRegistryKey -Path (Join-Path $Root $Name)
        }
    }
}

# ---------------------------------------------------------------------------
# Shortcut removal
# ---------------------------------------------------------------------------

function Remove-OneBrowserShortcuts {
    param([string[]]$Profiles)

    Write-Log 'PHASE | Shortcuts'

    $Roots = @(
        "$env:PUBLIC\Desktop",
        "$env:ProgramData\Microsoft\Windows\Start Menu"
    )

    foreach ($Profile in $Profiles) {
        $Roots += Join-Path $Profile 'Desktop'
        $Roots += Join-Path $Profile 'AppData\Roaming\Microsoft\Windows\Start Menu'
    }

    foreach ($Root in ($Roots | Select-Object -Unique)) {

        if (-not (Test-Path -LiteralPath $Root)) {
            continue
        }

        $Links = Get-ChildItem -LiteralPath $Root `
            -Recurse -File -Filter '*.lnk' -ErrorAction SilentlyContinue

        foreach ($Link in $Links) {

            if (Test-OneBrowserExtensionName $Link.BaseName) {
                Remove-TargetPath -Path $Link.FullName -Reason 'OneBrowser shortcut'
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Chromium extension removal
# ---------------------------------------------------------------------------

function Remove-OneBrowserChromiumExtensions {
    param([string[]]$Profiles)

    Write-Log 'PHASE | Chromium extensions'

    $BrowserPaths = @(
        'Google\Chrome\User Data',
        'Microsoft\Edge\User Data',
        'BraveSoftware\Brave-Browser\User Data',
        'Vivaldi\User Data',
        'Chromium\User Data'
    )

    foreach ($Profile in $Profiles) {
        foreach ($Relative in $BrowserPaths) {

            $Base = Join-Path (Join-Path $Profile 'AppData\Local') $Relative

            if (-not (Test-Path -LiteralPath $Base)) {
                continue
            }

            $BrowserProfiles = Get-ChildItem -LiteralPath $Base `
                -Directory -ErrorAction SilentlyContinue

            foreach ($BrowserProfile in $BrowserProfiles) {

                $ExtensionsRoot = Join-Path $BrowserProfile.FullName 'Extensions'

                if (-not (Test-Path -LiteralPath $ExtensionsRoot)) {
                    continue
                }

                $Extensions = Get-ChildItem -LiteralPath $ExtensionsRoot `
                    -Directory -ErrorAction SilentlyContinue

                foreach ($Extension in $Extensions) {

                    $Versions = Get-ChildItem -LiteralPath $Extension.FullName `
                        -Directory -ErrorAction SilentlyContinue

                    $Matched = $false

                    foreach ($Version in $Versions) {

                        $ManifestPath = Join-Path $Version.FullName 'manifest.json'

                        if (-not (Test-Path -LiteralPath $ManifestPath)) {
                            continue
                        }

                        try {
                            $Manifest = Get-Content -LiteralPath $ManifestPath `
                                -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

                            if (
                                (Test-OneBrowserExtensionName ([string]$Manifest.name)) -or
                                (Test-OneBrowserExtensionName ([string]$Manifest.short_name))
                            ) {
                                $Matched = $true
                                break
                            }
                        }
                        catch {
                            Write-Log "WARN | Cannot parse extension manifest: $ManifestPath"
                        }
                    }

                    if ($Matched) {
                        Remove-TargetPath -Path $Extension.FullName `
                            -Reason 'Confirmed Chromium OneBrowser extension'
                    }
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Firefox extension cleanup
# ---------------------------------------------------------------------------

function Remove-OneBrowserFirefoxExtensions {
    param([string[]]$Profiles)

    Write-Log 'PHASE | Firefox extensions'

    foreach ($Profile in $Profiles) {

        $FirefoxRoot = Join-Path $Profile `
            'AppData\Roaming\Mozilla\Firefox\Profiles'

        if (-not (Test-Path -LiteralPath $FirefoxRoot)) {
            continue
        }

        $FirefoxProfiles = Get-ChildItem -LiteralPath $FirefoxRoot `
            -Directory -ErrorAction SilentlyContinue

        foreach ($FirefoxProfile in $FirefoxProfiles) {

            $ExtensionsRoot = Join-Path $FirefoxProfile.FullName 'extensions'

            if (-not (Test-Path -LiteralPath $ExtensionsRoot)) {
                continue
            }

            $Items = Get-ChildItem -LiteralPath $ExtensionsRoot `
                -Force -ErrorAction SilentlyContinue

            foreach ($Item in $Items) {

                # Only remove clearly named extension packages/directories.
                # Never remove arbitrary Firefox JSON, JS, or profile files.

                if (
                    (Test-OneBrowserExtensionName $Item.BaseName) -or
                    (Test-OneBrowserExtensionName $Item.Name)
                ) {
                    Remove-TargetPath -Path $Item.FullName `
                        -Reason 'Identified Firefox OneBrowser extension'
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Post-remediation verification
# ---------------------------------------------------------------------------

function Test-OneBrowserRemnants {

    Write-Log 'PHASE | Verification'

    $Remaining = New-Object 'System.Collections.Generic.List[string]'

    foreach ($Path in $script:RemovedPaths) {
        if (Test-Path -LiteralPath $Path) {
            [void]$Remaining.Add("PATH=$Path")
        }
    }

    try {
        $Tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object {
                (Test-OneBrowserName $_.TaskName) -or
                (Test-OneBrowserPath (
                    ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
                ))
            }

        foreach ($Task in $Tasks) {
            [void]$Remaining.Add("TASK=$($Task.TaskName)")
        }
    }
    catch {
        Add-Failure "VERIFY_TASKS_FAILED | $($_.Exception.Message)"
    }

    try {
        $Processes = Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object {
                (Test-OneBrowserExecutable $_.Name) -or
                (Test-OneBrowserPath $_.ExecutablePath)
            }

        foreach ($Process in $Processes) {
            [void]$Remaining.Add("PROCESS=$($Process.Name)")
        }
    }
    catch {
        Add-Failure "VERIFY_PROCESSES_FAILED | $($_.Exception.Message)"
    }

    try {
        $Services = Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object {
                (Test-OneBrowserName $_.Name) -or
                (Test-OneBrowserName $_.DisplayName) -or
                (Test-OneBrowserPath $_.PathName)
            }

        foreach ($Service in $Services) {
            [void]$Remaining.Add("SERVICE=$($Service.Name)")
        }
    }
    catch {
        Add-Failure "VERIFY_SERVICES_FAILED | $($_.Exception.Message)"
    }

    foreach ($Item in $Remaining) {
        Write-Log "REMAINING | $Item"
    }

    return $Remaining.Count
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {
    Write-Log '============================================================'
    Write-Log 'START | OneBrowser PUP complete removal'
    Write-Log "COMPUTER=$env:COMPUTERNAME"

    $Profiles = @(Get-UserProfilePaths)

    Write-Log "PROFILES_FOUND=$($Profiles.Count)"

    # Disable persistence before attempting filesystem cleanup.
    Remove-OneBrowserTasks
    Remove-OneBrowserServices

    # Terminate active browser/updater processes.
    Stop-OneBrowserProcesses

    # Remove confirmed executable and profile artifacts.
    Remove-OneBrowserFolders -Profiles $Profiles

    # Remove targeted application traces.
    Remove-OneBrowserRegistry

    # Remove associated shortcuts and identified extensions.
    Remove-OneBrowserShortcuts -Profiles $Profiles
    Remove-OneBrowserChromiumExtensions -Profiles $Profiles
    Remove-OneBrowserFirefoxExtensions -Profiles $Profiles

    # Verify known high-priority persistence indicators.
    $RemainingCount = Test-OneBrowserRemnants

    Write-Log "ACTIONS=$script:Actions"
    Write-Log "FAILURES=$($script:Failures.Count)"
    Write-Log "REMAINING=$RemainingCount"

    if ($script:Failures.Count -gt 0 -or $RemainingCount -gt 0) {
        Finish 'ERROR' "OneBrowser cleanup incomplete | Actions=$script:Actions Failures=$($script:Failures.Count) Remaining=$RemainingCount"
    }

    if ($script:Actions -eq 0) {
        Finish 'NO_ACTION' 'No confirmed removable OneBrowser artifacts found'
    }

    Finish 'RESULT' "OneBrowser cleanup completed | Actions=$script:Actions Remaining=$RemainingCount"
}
catch {
    Write-Log "FATAL_ERROR | $($_.Exception.Message)"
    Finish 'ERROR' "OneBrowser cleanup failed | $($_.Exception.Message)"
}