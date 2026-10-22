# ============================================================================
# NAME: Remove Dropbox
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Endpoints / NinjaOne Automation
# VARIABLES:
#   Required: None
#   Optional: None
# OUTPUT TOKENS:
#   RESULT    | Dropbox remediation completed
#   RESULT    | Dropbox remediation attempted; remaining findings detected
#   NO_ACTION | Dropbox not detected
#   ERROR     | Unexpected script error occurred
# CUSTOM FIELDS:
#   Reads: remediationSummary
#   Writes: lastRemediationDate, remediationSummary
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\Dropbox_Removal.log
# DESCRIPTION:
#   Removes detected Dropbox installations and artifacts from Windows endpoints.
#   Finds machine-wide and loaded-user uninstall registrations, services,
#   processes, scheduled tasks, and known executable locations before acting.
#   Attempts available uninstall commands, removes services, tasks, startup
#   registrations, app/cache directories, and stale uninstall registry keys.
#   May stop Explorer on workstation OS during cleanup when machine-wide
#   Dropbox folders remain; skips this step on Windows Server.
#   Does not intentionally remove user Dropbox synchronization/data folders
#   such as C:\Users\<user>\Dropbox.
#   Updates Ninja remediation fields if an action is attempted or taken.
#   Does not perform independent remediation gating; Ninja condition is gate.
#   Always exits 0 for NinjaOne compatibility.
# ============================================================================

$ErrorActionPreference = 'Stop'

$LogDir  = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogDir 'Dropbox_Removal.log'

$script:ProcessStoppedCount        = 0
$script:UninstallAttemptCount      = 0
$script:ServiceRemovedCount        = 0
$script:TaskRemovedCount           = 0
$script:StartupRemovedCount        = 0
$script:CleanupRemovedCount        = 0
$script:RegRemovedCount            = 0
$script:ExplorerStoppedCount       = 0
$script:ExplorerSkippedServerCount = 0
$script:WarningCount               = 0
$script:ActionTaken                = $false

function Write-Log {
    param (
        [string]$Message
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogPath -Value "$Timestamp | $Message"
}

function Write-WarnLog {
    param (
        [string]$Message
    )

    $script:WarningCount++
    Write-Log "WARN | $Message"
}

function Test-IsServerOS {
    try {
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

        # ProductType:
        # 1 = Workstation
        # 2 = Domain Controller
        # 3 = Server
        if ($OS.ProductType -ne 1) {
            Write-Log "OS | Server OS detected. Caption=$($OS.Caption); ProductType=$($OS.ProductType)"
            return $true
        }

        Write-Log "OS | Workstation OS detected. Caption=$($OS.Caption); ProductType=$($OS.ProductType)"
        return $false
    }
    catch {
        Write-WarnLog "Failed detecting OS type. Defaulting to server-safe behavior: $($_.Exception.Message)"
        return $true
    }
}

function Set-NinjaPropertySafe {
    param (
        [string]$Name,
        [string]$Value
    )

    try {
        if (Get-Command 'Ninja-Property-Set' -ErrorAction SilentlyContinue) {
            & Ninja-Property-Set $Name $Value
            Write-Log "NINJA | Updated custom field '$Name'."
            return $true
        }

        Write-WarnLog "Ninja-Property-Set not available. Could not update '$Name'."
        return $false
    }
    catch {
        Write-WarnLog "Failed updating Ninja custom field '$Name': $($_.Exception.Message)"
        return $false
    }
}

function Get-NinjaPropertySafe {
    param (
        [string]$Name
    )

    try {
        if (Get-Command 'Ninja-Property-Get' -ErrorAction SilentlyContinue) {
            $Value = & Ninja-Property-Get $Name 2>$null
            return (($Value | Out-String).TrimEnd())
        }

        Write-WarnLog "Ninja-Property-Get not available. Could not read '$Name'."
        return ''
    }
    catch {
        Write-WarnLog "Failed reading Ninja custom field '$Name': $($_.Exception.Message)"
        return ''
    }
}

function Update-RemediationFields {
    param (
        [int]$PreFindings,
        [int]$PostFindings
    )

    $Stamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'

    $SummaryLine = "$Stamp | Dropbox remediation | PreFindings=$PreFindings; UninstallAttempts=$script:UninstallAttemptCount; ProcessesStopped=$script:ProcessStoppedCount; ServicesRemoved=$script:ServiceRemovedCount; TasksRemoved=$script:TaskRemovedCount; StartupEntriesRemoved=$script:StartupRemovedCount; CleanupPathsRemoved=$script:CleanupRemovedCount; RegistryKeysRemoved=$script:RegRemovedCount; ExplorerStopped=$script:ExplorerStoppedCount; ExplorerSkippedServer=$script:ExplorerSkippedServerCount; RemainingFindings=$PostFindings; Warnings=$script:WarningCount"

    Set-NinjaPropertySafe -Name 'lastRemediationDate' -Value $Stamp | Out-Null

    $ExistingSummary = Get-NinjaPropertySafe -Name 'remediationSummary'

    if ([string]::IsNullOrWhiteSpace($ExistingSummary)) {
        $NewSummary = $SummaryLine
    }
    else {
        $NewSummary = "$ExistingSummary`r`n$SummaryLine"
    }

    Set-NinjaPropertySafe -Name 'remediationSummary' -Value $NewSummary | Out-Null
}

function Get-LoadedUserSids {
    try {
        return Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PSChildName -match '^S-1-5-21-' -and
                $_.PSChildName -notmatch '_Classes$'
            } |
            Select-Object -ExpandProperty PSChildName
    }
    catch {
        Write-WarnLog "Failed enumerating loaded user hives: $($_.Exception.Message)"
        return @()
    }
}

function Get-RegistryUninstallRoots {
    $Roots = New-Object System.Collections.Generic.List[string]

    $Roots.Add('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall') | Out-Null
    $Roots.Add('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') | Out-Null

    foreach ($Sid in Get-LoadedUserSids) {
        $Roots.Add("Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows\CurrentVersion\Uninstall") | Out-Null
        $Roots.Add("Registry::HKEY_USERS\$Sid\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") | Out-Null
    }

    return $Roots | Sort-Object -Unique
}

function Get-UserProfiles {
    try {
        return Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') -and
                $_.Name -notmatch '^defaultuser'
            }
    }
    catch {
        Write-WarnLog "Failed enumerating user profiles: $($_.Exception.Message)"
        return @()
    }
}

function Add-Finding {
    param (
        [System.Collections.Generic.List[object]]$List,
        [string]$Type,
        [string]$Name,
        [string]$Path,
        [string]$Detail
    )

    $List.Add([pscustomobject]@{
        Type   = $Type
        Name   = $Name
        Path   = $Path
        Detail = $Detail
    }) | Out-Null
}

function Get-DropboxFindings {
    $Findings = New-Object System.Collections.Generic.List[object]

    foreach ($Root in Get-RegistryUninstallRoots) {
        if (Test-Path $Root) {
            Get-ChildItem -Path $Root -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $Item = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue

                    if ($Item.DisplayName -match '(?i)\bDropbox\b') {
                        Add-Finding `
                            -List $Findings `
                            -Type 'Registry' `
                            -Name $Item.DisplayName `
                            -Path $_.PSPath `
                            -Detail "Version=$($Item.DisplayVersion); Publisher=$($Item.Publisher)"
                    }
                }
                catch {}
            }
        }
    }

    try {
        Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match '(?i)^(DbxSvc|Dropbox.*)$' -or
                $_.DisplayName -match '(?i)\bDropbox\b' -or
                $_.PathName -match '(?i)\\Dropbox\\'
            } |
            ForEach-Object {
                Add-Finding `
                    -List $Findings `
                    -Type 'Service' `
                    -Name $_.Name `
                    -Path $_.PathName `
                    -Detail "DisplayName=$($_.DisplayName); State=$($_.State); StartMode=$($_.StartMode)"
            }
    }
    catch {}

    $DropboxProcessNames = @(
        'Dropbox.exe',
        'DropboxUpdate.exe',
        'DropboxCrashHandler.exe',
        'DropboxThumbnailGenerator.exe',
        'DbxSvc.exe'
    )

    try {
        Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $DropboxProcessNames -contains $_.Name
            } |
            ForEach-Object {
                Add-Finding `
                    -List $Findings `
                    -Type 'Process' `
                    -Name $_.Name `
                    -Path $_.ExecutablePath `
                    -Detail "PID=$($_.ProcessId)"
            }
    }
    catch {}

    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object {
                $_.TaskName -match '(?i)\bDropbox\b' -or
                $_.TaskPath -match '(?i)\bDropbox\b'
            } |
            ForEach-Object {
                Add-Finding `
                    -List $Findings `
                    -Type 'ScheduledTask' `
                    -Name $_.TaskName `
                    -Path $_.TaskPath `
                    -Detail "State=$($_.State)"
            }
    }
    catch {}

    $FileCandidates = New-Object System.Collections.Generic.List[string]

    if ($env:ProgramFiles) {
        $FileCandidates.Add((Join-Path $env:ProgramFiles 'Dropbox\Client\Dropbox.exe')) | Out-Null
        $FileCandidates.Add((Join-Path $env:ProgramFiles 'Dropbox\Client\DropboxUninstaller.exe')) | Out-Null
        $FileCandidates.Add((Join-Path $env:ProgramFiles 'Dropbox\Update\DropboxUpdate.exe')) | Out-Null
    }

    if (${env:ProgramFiles(x86)}) {
        $FileCandidates.Add((Join-Path ${env:ProgramFiles(x86)} 'Dropbox\Client\Dropbox.exe')) | Out-Null
        $FileCandidates.Add((Join-Path ${env:ProgramFiles(x86)} 'Dropbox\Client\DropboxUninstaller.exe')) | Out-Null
        $FileCandidates.Add((Join-Path ${env:ProgramFiles(x86)} 'Dropbox\Update\DropboxUpdate.exe')) | Out-Null
    }

    foreach ($Profile in Get-UserProfiles) {
        $FileCandidates.Add((Join-Path $Profile.FullName 'AppData\Roaming\Dropbox\bin\Dropbox.exe')) | Out-Null
        $FileCandidates.Add((Join-Path $Profile.FullName 'AppData\Roaming\Dropbox\bin\DropboxUninstaller.exe')) | Out-Null
        $FileCandidates.Add((Join-Path $Profile.FullName 'AppData\Local\Dropbox\Update\DropboxUpdate.exe')) | Out-Null
    }

    foreach ($Path in $FileCandidates | Sort-Object -Unique) {
        if (Test-Path -LiteralPath $Path) {
            $Version = ''

            try {
                $Version = (Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
            }
            catch {}

            Add-Finding `
                -List $Findings `
                -Type 'File' `
                -Name (Split-Path $Path -Leaf) `
                -Path $Path `
                -Detail "Version=$Version"
        }
    }

    return $Findings | Sort-Object Type, Name, Path, Detail -Unique
}

function Invoke-CommandWithTimeout {
    param (
        [string]$Command,
        [int]$TimeoutSeconds = 300
    )

    try {
        Write-Log "RUN | $Command"

        $Process = Start-Process `
            -FilePath $env:ComSpec `
            -ArgumentList @('/c', $Command) `
            -PassThru `
            -WindowStyle Hidden `
            -ErrorAction Stop

        $Exited = $Process.WaitForExit($TimeoutSeconds * 1000)

        if (-not $Exited) {
            try {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            }
            catch {}

            Write-WarnLog "Command timed out after $TimeoutSeconds seconds: $Command"
            return $false
        }

        Write-Log "RUN_RESULT | ExitCode=$($Process.ExitCode) | $Command"
        return $true
    }
    catch {
        Write-WarnLog "Command failed: $Command | $($_.Exception.Message)"
        return $false
    }
}

function Get-DropboxUninstallCommands {
    $Commands = New-Object System.Collections.Generic.List[object]

    foreach ($Root in Get-RegistryUninstallRoots) {
        if (Test-Path $Root) {
            Get-ChildItem -Path $Root -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $Item = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue

                    if ($Item.DisplayName -match '(?i)\bDropbox\b') {
                        $Command = $null

                        if ($Item.QuietUninstallString) {
                            $Command = $Item.QuietUninstallString
                        }
                        elseif ($Item.UninstallString) {
                            if ($Item.UninstallString -match '(?i)msiexec') {
                                if ($Item.UninstallString -match '\{[A-Fa-f0-9-]{36}\}') {
                                    $Guid = $Matches[0]
                                    $Command = "msiexec.exe /x $Guid /qn /norestart"
                                }
                            }
                            elseif ($Item.UninstallString -match '(?i)Dropbox') {
                                $Command = "$($Item.UninstallString) /S"
                            }
                        }

                        if ($Command) {
                            $Commands.Add([pscustomobject]@{
                                Source  = 'Registry'
                                Detail  = $Item.DisplayName
                                Command = $Command
                            }) | Out-Null
                        }
                    }
                }
                catch {
                    Write-WarnLog "Failed reading uninstall command from $($_.PSPath): $($_.Exception.Message)"
                }
            }
        }
    }

    $FileUninstallers = New-Object System.Collections.Generic.List[string]
    $UpdaterUninstallers = New-Object System.Collections.Generic.List[string]

    if ($env:ProgramFiles) {
        $FileUninstallers.Add((Join-Path $env:ProgramFiles 'Dropbox\Client\DropboxUninstaller.exe')) | Out-Null
        $UpdaterUninstallers.Add((Join-Path $env:ProgramFiles 'Dropbox\Update\DropboxUpdate.exe')) | Out-Null
    }

    if (${env:ProgramFiles(x86)}) {
        $FileUninstallers.Add((Join-Path ${env:ProgramFiles(x86)} 'Dropbox\Client\DropboxUninstaller.exe')) | Out-Null
        $UpdaterUninstallers.Add((Join-Path ${env:ProgramFiles(x86)} 'Dropbox\Update\DropboxUpdate.exe')) | Out-Null
    }

    foreach ($Profile in Get-UserProfiles) {
        $FileUninstallers.Add((Join-Path $Profile.FullName 'AppData\Roaming\Dropbox\bin\DropboxUninstaller.exe')) | Out-Null
        $UpdaterUninstallers.Add((Join-Path $Profile.FullName 'AppData\Local\Dropbox\Update\DropboxUpdate.exe')) | Out-Null
    }

    foreach ($Path in $FileUninstallers | Sort-Object -Unique) {
        if (Test-Path -LiteralPath $Path) {
            $Commands.Add([pscustomobject]@{
                Source  = 'File'
                Detail  = $Path
                Command = "`"$Path`" /S"
            }) | Out-Null
        }
    }

    foreach ($Path in $UpdaterUninstallers | Sort-Object -Unique) {
        if (Test-Path -LiteralPath $Path) {
            $Commands.Add([pscustomobject]@{
                Source  = 'Updater'
                Detail  = $Path
                Command = "`"$Path`" /uninstall"
            }) | Out-Null
        }
    }

    return $Commands | Sort-Object Command -Unique
}

function Stop-DropboxProcesses {
    $ProcessNames = @(
        'Dropbox',
        'DropboxUpdate',
        'DropboxCrashHandler',
        'DropboxThumbnailGenerator',
        'DbxSvc'
    )

    foreach ($Name in $ProcessNames) {
        try {
            $Processes = Get-Process -Name $Name -ErrorAction SilentlyContinue

            foreach ($Process in $Processes) {
                try {
                    Write-Log "PROCESS | Stopping $($Process.ProcessName) PID=$($Process.Id)"
                    Stop-Process -Id $Process.Id -Force -ErrorAction Stop

                    $script:ProcessStoppedCount++
                    $script:ActionTaken = $true
                }
                catch {
                    Write-WarnLog "Failed stopping process $($Process.ProcessName) PID=$($Process.Id): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-WarnLog "Process check failed for $Name`: $($_.Exception.Message)"
        }
    }
}

function Stop-ExplorerForDropboxCleanup {
    try {
        $ExplorerProcesses = @(Get-Process -Name explorer -ErrorAction SilentlyContinue)

        if ($ExplorerProcesses.Count -eq 0) {
            Write-Log 'EXPLORER | No explorer.exe processes detected.'
            return
        }

        foreach ($Process in $ExplorerProcesses) {
            try {
                Write-Log "EXPLORER | Stopping explorer.exe PID=$($Process.Id) to release Dropbox shell extension locks."
                Stop-Process -Id $Process.Id -Force -ErrorAction Stop

                $script:ExplorerStoppedCount++
                $script:ActionTaken = $true
            }
            catch {
                Write-WarnLog "Failed stopping explorer.exe PID=$($Process.Id): $($_.Exception.Message)"
            }
        }

        Start-Sleep -Seconds 5

        Write-Log 'EXPLORER | Explorer was stopped for cleanup. Script will not manually restart Explorer from SYSTEM.'
    }
    catch {
        Write-WarnLog "Explorer stop routine failed: $($_.Exception.Message)"
    }
}

function Remove-DropboxServices {
    try {
        $Services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match '(?i)^(DbxSvc|Dropbox.*)$' -or
                $_.DisplayName -match '(?i)\bDropbox\b' -or
                $_.PathName -match '(?i)\\Dropbox\\'
            }

        foreach ($Service in $Services) {
            try {
                Write-Log "SERVICE | Removing $($Service.Name) | $($Service.DisplayName)"

                Stop-Service -Name $Service.Name -Force -ErrorAction SilentlyContinue

                $DeleteOutput = & sc.exe delete $Service.Name 2>&1
                Write-Log "SERVICE_DELETE | $($Service.Name) | $($DeleteOutput -join ' ')"

                $script:ServiceRemovedCount++
                $script:ActionTaken = $true
            }
            catch {
                Write-WarnLog "Failed removing service $($Service.Name): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-WarnLog "Service cleanup failed: $($_.Exception.Message)"
    }
}

function Remove-DropboxScheduledTasks {
    try {
        $Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object {
                $_.TaskName -match '(?i)\bDropbox\b' -or
                $_.TaskPath -match '(?i)\bDropbox\b'
            }

        foreach ($Task in $Tasks) {
            try {
                Write-Log "TASK | Removing $($Task.TaskPath)$($Task.TaskName)"
                Unregister-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -Confirm:$false -ErrorAction Stop

                $script:TaskRemovedCount++
                $script:ActionTaken = $true
            }
            catch {
                Write-WarnLog "Failed removing scheduled task $($Task.TaskPath)$($Task.TaskName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-WarnLog "Scheduled task cleanup failed: $($_.Exception.Message)"
    }
}

function Remove-DropboxStartupEntries {
    $StartupRoots = New-Object System.Collections.Generic.List[string]

    $StartupRoots.Add('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') | Out-Null
    $StartupRoots.Add('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') | Out-Null
    $StartupRoots.Add('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') | Out-Null
    $StartupRoots.Add('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce') | Out-Null

    foreach ($Sid in Get-LoadedUserSids) {
        $StartupRoots.Add("Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows\CurrentVersion\Run") | Out-Null
        $StartupRoots.Add("Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows\CurrentVersion\RunOnce") | Out-Null
    }

    foreach ($Root in $StartupRoots | Sort-Object -Unique) {
        if (Test-Path $Root) {
            try {
                $Props = Get-ItemProperty -Path $Root -ErrorAction SilentlyContinue

                foreach ($Prop in $Props.PSObject.Properties) {
                    if ($Prop.Name -match '^PS') {
                        continue
                    }

                    $Value = [string]$Prop.Value

                    if ($Value -match '(?i)Dropbox') {
                        try {
                            Write-Log "STARTUP | Removing $Root\$($Prop.Name) | $Value"
                            Remove-ItemProperty -Path $Root -Name $Prop.Name -Force -ErrorAction Stop

                            $script:StartupRemovedCount++
                            $script:ActionTaken = $true
                        }
                        catch {
                            Write-WarnLog "Failed removing startup entry $Root\$($Prop.Name): $($_.Exception.Message)"
                        }
                    }
                }
            }
            catch {
                Write-WarnLog "Failed reading startup root $Root`: $($_.Exception.Message)"
            }
        }
    }
}

function Remove-DropboxAppPaths {
    param (
        [switch]$ExplorerSafePass
    )

    $CleanupPaths = New-Object System.Collections.Generic.List[string]

    if ($env:ProgramFiles) {
        $CleanupPaths.Add((Join-Path $env:ProgramFiles 'Dropbox')) | Out-Null
    }

    if (${env:ProgramFiles(x86)}) {
        $CleanupPaths.Add((Join-Path ${env:ProgramFiles(x86)} 'Dropbox')) | Out-Null
    }

    $CleanupPaths.Add('C:\ProgramData\Dropbox') | Out-Null

    foreach ($Profile in Get-UserProfiles) {
        $CleanupPaths.Add((Join-Path $Profile.FullName 'AppData\Roaming\Dropbox')) | Out-Null
        $CleanupPaths.Add((Join-Path $Profile.FullName 'AppData\Local\Dropbox')) | Out-Null
        $CleanupPaths.Add((Join-Path $Profile.FullName 'AppData\LocalLow\Dropbox')) | Out-Null

        # Shortcut cleanup only. This does not touch user Dropbox sync/data folders.
        $CleanupPaths.Add((Join-Path $Profile.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Dropbox')) | Out-Null
    }

    foreach ($Path in $CleanupPaths | Sort-Object -Unique) {
        if (Test-Path -LiteralPath $Path) {
            try {
                if ($ExplorerSafePass) {
                    Write-Log "CLEANUP | Explorer-safe pass removing app/cache path: $Path"
                }
                else {
                    Write-Log "CLEANUP | Removing app/cache path: $Path"
                }

                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop

                $script:CleanupRemovedCount++
                $script:ActionTaken = $true
            }
            catch {
                Write-WarnLog "Failed removing app/cache path $Path`: $($_.Exception.Message)"
            }
        }
    }
}

function Remove-DropboxUninstallRegistryKeys {
    foreach ($Root in Get-RegistryUninstallRoots) {
        if (Test-Path $Root) {
            Get-ChildItem -Path $Root -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $Item = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue

                    if ($Item.DisplayName -match '(?i)\bDropbox\b') {
                        Write-Log "REGISTRY | Removing stale Dropbox uninstall key: $($_.PSPath)"
                        Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop

                        $script:RegRemovedCount++
                        $script:ActionTaken = $true
                    }
                }
                catch {
                    Write-WarnLog "Failed removing uninstall registry key $($_.PSPath): $($_.Exception.Message)"
                }
            }
        }
    }
}

function Test-DropboxMachineWidePathExists {
    $Paths = @()

    if ($env:ProgramFiles) {
        $Paths += Join-Path $env:ProgramFiles 'Dropbox'
    }

    if (${env:ProgramFiles(x86)}) {
        $Paths += Join-Path ${env:ProgramFiles(x86)} 'Dropbox'
    }

    foreach ($Path in $Paths) {
        if (Test-Path -LiteralPath $Path) {
            return $true
        }
    }

    return $false
}

try {
    if (-not (Test-Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }

    Write-Log '===== Dropbox remediation started ====='

    $IsServerOS = Test-IsServerOS

    $PreFindings = @(Get-DropboxFindings)
    $PreCount = $PreFindings.Count

    Write-Log "PRECHECK | Dropbox findings detected: $PreCount"

    if ($PreCount -eq 0) {
        $Final = 'NO_ACTION | Dropbox not detected.'
        Write-Log $Final
        Write-Log '===== Dropbox remediation completed ====='
        Write-Output $Final
        exit 0
    }

    Stop-DropboxProcesses

    $UninstallCommands = @(Get-DropboxUninstallCommands)

    Write-Log "UNINSTALL | Commands discovered: $($UninstallCommands.Count)"

    foreach ($CommandItem in $UninstallCommands) {
        $script:UninstallAttemptCount++
        $script:ActionTaken = $true

        Write-Log "UNINSTALL | Source=$($CommandItem.Source) | Detail=$($CommandItem.Detail)"
        Invoke-CommandWithTimeout -Command $CommandItem.Command -TimeoutSeconds 300 | Out-Null
    }

    Start-Sleep -Seconds 5

    Stop-DropboxProcesses
    Remove-DropboxScheduledTasks
    Remove-DropboxServices
    Remove-DropboxStartupEntries

    Remove-DropboxAppPaths

    if (Test-DropboxMachineWidePathExists) {
        if ($IsServerOS) {
            $script:ExplorerSkippedServerCount++
            Write-WarnLog 'Machine-wide Dropbox path still exists, but this is a Server OS. Skipping Explorer stop to avoid disrupting terminal server/RDS users.'
        }
        else {
            Write-Log 'CLEANUP | Machine-wide Dropbox path still exists. Stopping Explorer for shell extension cleanup.'
            Stop-ExplorerForDropboxCleanup
            Start-Sleep -Seconds 3
            Remove-DropboxAppPaths -ExplorerSafePass
        }
    }

    Remove-DropboxUninstallRegistryKeys

    Start-Sleep -Seconds 3

    $PostFindings = @(Get-DropboxFindings)
    $PostCount = $PostFindings.Count

    Write-Log "POSTCHECK | Dropbox findings remaining: $PostCount"

    if ($PostCount -gt 0) {
        foreach ($Finding in ($PostFindings | Select-Object -First 20)) {
            Write-Log "REMAINING | $($Finding.Type) | $($Finding.Name) | $($Finding.Path) | $($Finding.Detail)"
        }
    }

    if ($script:ActionTaken) {
        Update-RemediationFields -PreFindings $PreCount -PostFindings $PostCount
    }

    if ($PostCount -eq 0) {
        $Final = "RESULT | Dropbox remediation completed. PreFindings=$PreCount; RemainingFindings=0; Warnings=$script:WarningCount"
    }
    else {
        $Final = "RESULT | Dropbox remediation attempted; remaining findings detected. PreFindings=$PreCount; RemainingFindings=$PostCount; Warnings=$script:WarningCount"
    }

    Write-Log $Final
    Write-Log '===== Dropbox remediation completed ====='
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
