# ============================================================================
# NAME: Remove ScreenConnect
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne scheduled automation
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   RESULT | ScreenConnect cleanup completed
#   NO_ACTION | No ScreenConnect findings detected
#   ERROR | Unexpected script error occurred
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: Yes (scheduled execution)
#   File: screenConnectRemoval.ps1
#   Destination: C:\MME\CS\screenConnectRemoval.ps1
#   Cleanup: Removes transferred payload after execution
# LOGGING PATH:
#   C:\MME\AutoLogs\ScreenConnect_Removal.log
# DESCRIPTION:
#   Scheduled destructive remediation that removes any detected ScreenConnect
#   presence from a Windows endpoint. ScreenConnect is treated as unauthorized.
#
#   Checks and removes matching running processes, services, uninstall entries,
#   scheduled tasks, Run / RunOnce startup entries, leftover directories, and
#   ScreenConnect EXE/MSI installer artifacts.
#
#   Directory cleanup covers the same common locations used by the evaluation
#   and recursively scans C:\MME so nested ScreenConnect directories are not
#   missed. Installer-artifact cleanup recursively scans all fixed drives while
#   excluding Windows-managed cache/system paths defined in the script.
#
#   This remediation intentionally does not write screenconnectDetected.
#   The paired evaluation script owns that custom field and determines the
#   authoritative YES/NO state when NinjaOne evaluates the condition again.
#
#   Missing ScreenConnect items are normal and are not treated as errors.
#
#   NUCLEAR REMOVAL MODE:
#   In addition to the original cleanup logic, this remediation removes
#   ScreenConnect-named files and directories across fixed drives, matching
#   ScreenConnect registry keys/values from defined software/service hives,
#   residual uninstall registry records, and matching Windows Firewall rules.
#
#   Registry cleanup is targeted for production runtime. Dedicated uninstall,
#   service, and Run/RunOnce cleanup handles those persistence locations
#   directly. A native reg.exe key-name/path sweep then removes residual
#   ScreenConnect-named keys from HKLM\SOFTWARE,
#   HKLM\SYSTEM\CurrentControlSet\Services, and each loaded user's
#   HKU\<SID>\Software hive. Up to two cleanup passes are performed, followed
#   by a verification search for residual ScreenConnect-named keys.
#
#   MME automation logs under C:\MME\AutoLogs and Windows-managed cache/system
#   locations are preserved for auditability and operating-system safety.
#
#   The transferred payload C:\MME\CS\screenConnectRemoval.ps1 is removed
#   after cleanup completes.
#
#   Always exits 0.
# ============================================================================

# =========================
# CONFIG
# =========================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$LogRoot = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogRoot "ScreenConnect_Removal.log"

$TargetRegex = '(?i)screenconnect'

$ScanAllFixedDrives = $true

$InstallerNamePatterns = @(
    '*ScreenConnect*.exe',
    '*ScreenConnect*.msi'
)

$ArtifactExcludePathRegex = '(?i)\\Windows\\(WinSxS|servicing|System32|SysWOW64|Installer|SoftwareDistribution)\\|\\Program Files\\WindowsApps\\'

$UninstallTimeoutSeconds = 300

$ExpectedSelfPath = "C:\MME\CS\screenConnectRemoval.ps1"

# Preserve MME audit logs and Windows-managed cache/system locations.
$NuclearFileExcludePathRegex = '(?i)\\MME\\AutoLogs\\|\\Windows\\(WinSxS|servicing|System32|SysWOW64|Installer|SoftwareDistribution)\\|\\Program Files\\WindowsApps\\|\\System Volume Information\\|\\\$Recycle\.Bin\\'

# Registry locations intentionally excluded from generic value cleanup because
# they are Windows infrastructure stores. Their ScreenConnect objects are
# handled through supported mechanisms elsewhere in this remediation.
$RegistryExcludePathRegex = '(?i)\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache(\\|$)'


# =========================
# GLOBAL STATE
# =========================

$Counters = [ordered]@{
    ProcessesStopped       = 0
    ServicesStopped        = 0
    ServicesDeleted        = 0
    UninstallEntriesFound  = 0
    UninstallAttempts      = 0
    UninstallSuccesses     = 0
    ScheduledTasksRemoved  = 0
    RunEntriesRemoved      = 0
    DirectoriesRemoved     = 0
    InstallerFilesDeleted  = 0
    NamedFilesDeleted      = 0
    NamedDirectoriesRemoved = 0
    RegistryKeysRemoved    = 0
    RegistryValuesRemoved  = 0
    UninstallKeysRemoved   = 0
    FirewallRulesRemoved   = 0
    Warnings               = 0
}

$Warnings = New-Object System.Collections.Generic.List[string]
$ServiceInstallDirs = New-Object System.Collections.Generic.List[string]
$RegistryInstallDirs = New-Object System.Collections.Generic.List[string]

$FinalToken = "ERROR"
$FinalMessage = "Unexpected script termination before completion."


# =========================
# FUNCTIONS
# =========================

function Initialize-Logging {
    <#
    DESCRIPTION:
        Creates the standard automation log directory and starts a new run section.
    #>

    if (-not (Test-Path -LiteralPath $LogRoot)) {
        New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
    }

    $header = @"
============================================================
ScreenConnect Removal
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
User Context: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
Logging Path: $LogPath
============================================================
"@

    $header | Out-File -FilePath $LogPath -Append -Encoding UTF8
    Write-Host $header
}

function Write-Log {
    <#
    DESCRIPTION:
        Writes timestamped output to both Ninja activity output and the local automation log.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message

    try {
        if (-not (Test-Path -LiteralPath $LogRoot)) {
            New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
        }

        $line | Out-File -FilePath $LogPath -Append -Encoding UTF8
    }
    catch {
        Write-Host "WARN | Failed writing to log file: $($_.Exception.Message)"
    }

    Write-Host $line
}

function Add-Warning {
    <#
    DESCRIPTION:
        Tracks non-fatal warnings while keeping the script Ninja-safe.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:Counters.Warnings++
    $script:Warnings.Add($Message) | Out-Null
    Write-Log -Level "WARN" -Message $Message
}

function Test-IsTargetText {
    <#
    DESCRIPTION:
        Returns true when supplied text matches ScreenConnect target patterns.
    #>

    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return ($Text -match $TargetRegex)
}

function Get-ExecutablePathFromCommandLine {
    <#
    DESCRIPTION:
        Extracts an executable path and arguments from a command line string.
        Handles quoted and common unquoted executable paths.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandLine
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine).Trim()

    if ([string]::IsNullOrWhiteSpace($expanded)) {
        return $null
    }

    $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

    $quotedMatch = [regex]::Match($expanded, '^\s*"([^"]+?\.exe)"\s*(.*)$', $options)
    if ($quotedMatch.Success) {
        return [pscustomobject]@{
            FilePath  = $quotedMatch.Groups[1].Value
            Arguments = $quotedMatch.Groups[2].Value.Trim()
        }
    }

    $driveMatch = [regex]::Match($expanded, '^\s*([A-Za-z]:\\.*?\.exe)\s*(.*)$', $options)
    if ($driveMatch.Success) {
        return [pscustomobject]@{
            FilePath  = $driveMatch.Groups[1].Value
            Arguments = $driveMatch.Groups[2].Value.Trim()
        }
    }

    $simpleMatch = [regex]::Match($expanded, '^\s*(\S+?\.exe)\s*(.*)$', $options)
    if ($simpleMatch.Success) {
        return [pscustomobject]@{
            FilePath  = $simpleMatch.Groups[1].Value
            Arguments = $simpleMatch.Groups[2].Value.Trim()
        }
    }

    return $null
}

function Get-MsiProductCode {
    <#
    DESCRIPTION:
        Extracts an MSI product code GUID from text, if present.
    #>

    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $match = [regex]::Match($Text, '\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}')
    if ($match.Success) {
        return $match.Value
    }

    return $null
}

function Invoke-ExternalProcess {
    <#
    DESCRIPTION:
        Runs an external process with timeout handling so uninstallers cannot hang indefinitely.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [AllowNull()]
        [string]$ArgumentList,

        [int]$TimeoutSeconds = 300
    )

    try {
        Write-Log "Executing: $FilePath $ArgumentList"

        $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -WindowStyle Hidden -ErrorAction Stop
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)

        if (-not $completed) {
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
            catch {}

            return [pscustomobject]@{
                Success  = $false
                ExitCode = $null
                TimedOut = $true
                Message  = "Process timed out after $TimeoutSeconds seconds."
            }
        }

        return [pscustomobject]@{
            Success  = $true
            ExitCode = $process.ExitCode
            TimedOut = $false
            Message  = "Process exited with code $($process.ExitCode)."
        }
    }
    catch {
        return [pscustomobject]@{
            Success  = $false
            ExitCode = $null
            TimedOut = $false
            Message  = $_.Exception.Message
        }
    }
}

function Get-TargetProcesses {
    <#
    DESCRIPTION:
        Finds running ScreenConnect processes by process name or executable path.
        Command line matching is intentionally avoided to prevent the script from matching itself.
    #>

    try {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $haystack = @($_.Name, $_.ExecutablePath) -join " "
                (Test-IsTargetText $haystack) -and ($_.ProcessId -ne $PID)
            }
    }
    catch {
        Add-Warning "Failed to enumerate processes: $($_.Exception.Message)"
        return @()
    }
}

function Stop-TargetProcesses {
    <#
    DESCRIPTION:
        Stops running ScreenConnect processes.
    #>

    $processes = @(Get-TargetProcesses)

    foreach ($proc in $processes) {
        try {
            Write-Log "Stopping process: $($proc.Name) PID $($proc.ProcessId)"
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            $script:Counters.ProcessesStopped++
        }
        catch {
            Add-Warning "Failed to stop process $($proc.Name) PID $($proc.ProcessId): $($_.Exception.Message)"
        }
    }
}

function Get-TargetServices {
    <#
    DESCRIPTION:
        Finds ScreenConnect services by service name, display name, or path.
    #>

    try {
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object {
                $haystack = @($_.Name, $_.DisplayName, $_.PathName) -join " "
                Test-IsTargetText $haystack
            }
    }
    catch {
        Add-Warning "Failed to enumerate services: $($_.Exception.Message)"
        return @()
    }
}

function Stop-TargetServices {
    <#
    DESCRIPTION:
        Stops ScreenConnect services and records service executable directories.
    #>

    $services = @(Get-TargetServices)

    foreach ($svc in $services) {
        try {
            $cmd = Get-ExecutablePathFromCommandLine -CommandLine $svc.PathName
            if ($cmd -and (Test-Path -LiteralPath $cmd.FilePath)) {
                $parent = Split-Path -Path $cmd.FilePath -Parent
                if (Test-IsTargetText $parent) {
                    $script:ServiceInstallDirs.Add($parent) | Out-Null
                }
            }

            if ($svc.State -ne "Stopped") {
                Write-Log "Stopping service: $($svc.Name) [$($svc.DisplayName)]"
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop

                try {
                    $serviceObj = Get-Service -Name $svc.Name -ErrorAction Stop
                    $serviceObj.WaitForStatus("Stopped", "00:00:30")
                }
                catch {}

                $script:Counters.ServicesStopped++
            }
        }
        catch {
            Add-Warning "Failed to stop service $($svc.Name): $($_.Exception.Message)"
        }
    }
}

function Remove-TargetServiceRecords {
    <#
    DESCRIPTION:
        Deletes leftover ScreenConnect service records after uninstall attempts.
    #>

    $services = @(Get-TargetServices)

    foreach ($svc in $services) {
        try {
            Write-Log "Deleting leftover service record: $($svc.Name)"
            $result = & sc.exe delete "$($svc.Name)" 2>&1
            Write-Log "sc.exe delete output for $($svc.Name): $result"
            $script:Counters.ServicesDeleted++
        }
        catch {
            Add-Warning "Failed to delete service $($svc.Name): $($_.Exception.Message)"
        }
    }
}

function Get-UninstallRegistryEntries {
    <#
    DESCRIPTION:
        Enumerates machine-wide and loaded-user uninstall registry entries.
    #>

    $paths = New-Object System.Collections.Generic.List[string]

    $paths.Add("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*") | Out-Null
    $paths.Add("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*") | Out-Null

    try {
        $loadedUserHives = @(Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$'
            })

        foreach ($hive in $loadedUserHives) {
            $paths.Add("Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*") | Out-Null
        }
    }
    catch {
        Add-Warning "Failed to enumerate loaded user uninstall hives: $($_.Exception.Message)"
    }

    $entries = New-Object System.Collections.Generic.List[object]

    foreach ($path in $paths) {
        try {
            $items = @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)

            foreach ($item in $items) {
                if (-not [string]::IsNullOrWhiteSpace($item.DisplayName)) {
                    $entries.Add([pscustomobject]@{
                        DisplayName          = $item.DisplayName
                        DisplayVersion       = $item.DisplayVersion
                        Publisher            = $item.Publisher
                        InstallLocation      = $item.InstallLocation
                        UninstallString      = $item.UninstallString
                        QuietUninstallString = $item.QuietUninstallString
                        RegistryPath         = $item.PSPath
                        RegistryKeyName      = $item.PSChildName
                    }) | Out-Null
                }
            }
        }
        catch {
            Add-Warning "Failed reading uninstall path $path : $($_.Exception.Message)"
        }
    }

    return $entries
}

function Get-TargetUninstallEntries {
    <#
    DESCRIPTION:
        Filters uninstall registry entries to ScreenConnect targets only.
    #>

    $entries = @(Get-UninstallRegistryEntries)

    $targetEntries = @($entries | Where-Object {
        $haystack = @(
            $_.DisplayName,
            $_.Publisher,
            $_.InstallLocation,
            $_.UninstallString,
            $_.QuietUninstallString
        ) -join " "

        Test-IsTargetText $haystack
    })

    return $targetEntries
}

function Invoke-TargetUninstalls {
    <#
    DESCRIPTION:
        Attempts silent uninstall of all detected ScreenConnect uninstall entries.
    #>

    $entries = @(Get-TargetUninstallEntries)
    $script:Counters.UninstallEntriesFound = $entries.Count

    if ($entries.Count -eq 0) {
        Write-Log "No matching ScreenConnect uninstall registry entries found."
        return
    }

    $seen = @{}

    foreach ($entry in $entries) {
        $dedupeKey = "$($entry.DisplayName)|$($entry.RegistryPath)"
        if ($seen.ContainsKey($dedupeKey)) {
            continue
        }
        $seen[$dedupeKey] = $true

        Write-Log "Found uninstall entry: $($entry.DisplayName) $($entry.DisplayVersion)"

        if (-not [string]::IsNullOrWhiteSpace($entry.InstallLocation) -and (Test-IsTargetText $entry.InstallLocation)) {
            $script:RegistryInstallDirs.Add($entry.InstallLocation) | Out-Null
        }

        $script:Counters.UninstallAttempts++

        $combinedUninstallText = @(
            $entry.RegistryKeyName,
            $entry.QuietUninstallString,
            $entry.UninstallString
        ) -join " "

        $productCode = Get-MsiProductCode -Text $combinedUninstallText

        if (-not [string]::IsNullOrWhiteSpace($productCode)) {
            $result = Invoke-ExternalProcess -FilePath "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -TimeoutSeconds $UninstallTimeoutSeconds

            if ($result.ExitCode -in @(0, 1605, 1614, 3010)) {
                Write-Log "MSI uninstall completed for $($entry.DisplayName). ExitCode=$($result.ExitCode)"
                $script:Counters.UninstallSuccesses++
            }
            else {
                Add-Warning "MSI uninstall may have failed for $($entry.DisplayName). $($result.Message) ExitCode=$($result.ExitCode)"
            }

            continue
        }

        $rawCommand = $null
        $usedQuietString = $false

        if (-not [string]::IsNullOrWhiteSpace($entry.QuietUninstallString)) {
            $rawCommand = $entry.QuietUninstallString
            $usedQuietString = $true
        }
        elseif (-not [string]::IsNullOrWhiteSpace($entry.UninstallString)) {
            $rawCommand = $entry.UninstallString
        }

        if ([string]::IsNullOrWhiteSpace($rawCommand)) {
            Add-Warning "No uninstall command found for $($entry.DisplayName)."
            continue
        }

        $cmd = Get-ExecutablePathFromCommandLine -CommandLine $rawCommand

        if (-not $cmd) {
            Add-Warning "Could not parse uninstall command for $($entry.DisplayName): $rawCommand"
            continue
        }

        $args = $cmd.Arguments

        if (-not $usedQuietString) {
            if ($args -notmatch '(?i)(/quiet|/qn|/s|/silent|/verysilent|/norestart)') {
                $exeName = Split-Path -Path $cmd.FilePath -Leaf

                if ($exeName -match '(?i)^unins.*\.exe$') {
                    $args = "$args /VERYSILENT /SUPPRESSMSGBOXES /NORESTART".Trim()
                }
                else {
                    $args = "$args /quiet /norestart /S".Trim()
                }
            }
        }

        $result = Invoke-ExternalProcess -FilePath $cmd.FilePath -ArgumentList $args -TimeoutSeconds $UninstallTimeoutSeconds

        if ($result.Success -and ($result.ExitCode -in @(0, 1605, 1614, 3010))) {
            Write-Log "EXE uninstall completed for $($entry.DisplayName). ExitCode=$($result.ExitCode)"
            $script:Counters.UninstallSuccesses++
        }
        else {
            Add-Warning "EXE uninstall may have failed for $($entry.DisplayName). $($result.Message) ExitCode=$($result.ExitCode)"
        }
    }
}

function Remove-TargetScheduledTasks {
    <#
    DESCRIPTION:
        Removes scheduled tasks referencing ScreenConnect.
    #>

    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Write-Log "Get-ScheduledTask is unavailable on this system. Skipping scheduled task cleanup."
        return
    }

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $actionText = ""
            try {
                $actionText = @($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " "
            }
            catch {}

            $haystack = @($_.TaskName, $_.TaskPath, $actionText) -join " "
            Test-IsTargetText $haystack
        })

        foreach ($task in $tasks) {
            try {
                Write-Log "Removing scheduled task: $($task.TaskPath)$($task.TaskName)"
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                $script:Counters.ScheduledTasksRemoved++
            }
            catch {
                Add-Warning "Failed to remove scheduled task $($task.TaskPath)$($task.TaskName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Add-Warning "Failed scheduled task cleanup: $($_.Exception.Message)"
    }
}

function Remove-TargetRunEntries {
    <#
    DESCRIPTION:
        Removes Run and RunOnce registry startup entries referencing ScreenConnect.
    #>

    $runPaths = New-Object System.Collections.Generic.List[string]

    $runPaths.Add("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") | Out-Null
    $runPaths.Add("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce") | Out-Null
    $runPaths.Add("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run") | Out-Null
    $runPaths.Add("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce") | Out-Null

    try {
        $loadedUserHives = @(Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$'
            })

        foreach ($hive in $loadedUserHives) {
            $runPaths.Add("Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run") | Out-Null
            $runPaths.Add("Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce") | Out-Null
        }
    }
    catch {
        Add-Warning "Failed to enumerate loaded user Run hives: $($_.Exception.Message)"
    }

    $systemProps = @(
        "PSPath",
        "PSParentPath",
        "PSChildName",
        "PSDrive",
        "PSProvider"
    )

    foreach ($path in $runPaths) {
        try {
            if (-not (Test-Path -Path $path)) {
                continue
            }

            $item = Get-ItemProperty -Path $path -ErrorAction Stop

            foreach ($prop in $item.PSObject.Properties) {
                if ($prop.Name -in $systemProps) {
                    continue
                }

                $haystack = "$($prop.Name) $($prop.Value)"

                if (Test-IsTargetText $haystack) {
                    Write-Log "Removing startup entry '$($prop.Name)' from $path"
                    Remove-ItemProperty -Path $path -Name $prop.Name -Force -ErrorAction Stop
                    $script:Counters.RunEntriesRemoved++
                }
            }
        }
        catch {
            Add-Warning "Failed processing Run path $path : $($_.Exception.Message)"
        }
    }
}

function Get-CommonCleanupRoots {
    <#
    DESCRIPTION:
        Builds common cleanup locations for leftover ScreenConnect folders.
    #>

    $roots = New-Object System.Collections.Generic.List[string]

    # Keep these locations aligned with the ScreenConnect evaluation script.
    $possibleRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        "$env:SystemRoot\Temp",
        "$env:SystemDrive\Temp",
        "C:\MME",
        "C:\MME\CS"
    )

    foreach ($root in $possibleRoots) {
        if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path -LiteralPath $root)) {
            $roots.Add($root) | Out-Null
        }
    }

    try {
        $userDirs = @(Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue)

        foreach ($userDir in $userDirs) {
            $userRootCandidates = @(
                "$($userDir.FullName)\Downloads",
                "$($userDir.FullName)\Desktop",
                "$($userDir.FullName)\AppData\Local",
                "$($userDir.FullName)\AppData\Local\Temp",
                "$($userDir.FullName)\AppData\Roaming"
            )

            foreach ($candidate in $userRootCandidates) {
                if (Test-Path -LiteralPath $candidate) {
                    $roots.Add($candidate) | Out-Null
                }
            }
        }
    }
    catch {
        Add-Warning "Failed building user cleanup roots: $($_.Exception.Message)"
    }

    return @($roots | Sort-Object -Unique)
}

function Test-ProtectedDeletionPath {
    <#
    DESCRIPTION:
        Prevents accidental deletion of broad system roots.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $full = [System.IO.Path]::GetFullPath($Path).TrimEnd("\")

        $protectedRoots = @(
            $env:SystemDrive.TrimEnd("\"),
            $env:SystemRoot.TrimEnd("\"),
            $env:ProgramFiles.TrimEnd("\"),
            ${env:ProgramFiles(x86)}.TrimEnd("\"),
            $env:ProgramData.TrimEnd("\"),
            "$env:SystemDrive\Users"
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        foreach ($root in $protectedRoots) {
            if ($full -ieq $root.TrimEnd("\")) {
                return $true
            }
        }

        return $false
    }
    catch {
        return $true
    }
}

function Remove-TargetDirectories {
    <#
    DESCRIPTION:
        Removes leftover ScreenConnect directories from known install and user locations.
    #>

    $candidateDirs = @{}

    foreach ($dir in @($script:ServiceInstallDirs + $script:RegistryInstallDirs)) {
        if (-not [string]::IsNullOrWhiteSpace($dir) -and (Test-Path -LiteralPath $dir) -and (Test-IsTargetText $dir)) {
            $candidateDirs[$dir.ToLowerInvariant()] = $dir
        }
    }

    $roots = @(Get-CommonCleanupRoots)
    $dirPatterns = @(
        '*ScreenConnect*'
    )

    foreach ($root in $roots) {
        foreach ($pattern in $dirPatterns) {
            try {
                $matches = @(Get-ChildItem -Path (Join-Path $root $pattern) -Directory -Force -ErrorAction SilentlyContinue)

                foreach ($match in $matches) {
                    if (Test-IsTargetText $match.FullName) {
                        $candidateDirs[$match.FullName.ToLowerInvariant()] = $match.FullName
                    }
                }
            }
            catch {
                Add-Warning "Failed searching directory pattern $pattern under $root : $($_.Exception.Message)"
            }
        }
    }

    # C:\MME is our staging/work tree and may contain ScreenConnect artifacts
    # below non-ScreenConnect-named intermediate folders (for example C:\MME\CS).
    # Recursively search the entire tree so cleanup cannot miss those nested folders.
    $recursiveMmeRoot = "C:\MME"

    if (Test-Path -LiteralPath $recursiveMmeRoot) {
        try {
            Write-Log "Recursively scanning for ScreenConnect directories under: $recursiveMmeRoot"

            $recursiveMatches = @(Get-ChildItem -LiteralPath $recursiveMmeRoot -Directory -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { Test-IsTargetText $_.FullName })

            foreach ($match in $recursiveMatches) {
                $candidateDirs[$match.FullName.ToLowerInvariant()] = $match.FullName
            }
        }
        catch {
            Add-Warning "Failed recursive ScreenConnect directory scan under $recursiveMmeRoot : $($_.Exception.Message)"
        }
    }

    # Delete deepest paths first in case nested ScreenConnect directories were found.
    foreach ($dir in $candidateDirs.Values | Sort-Object { $_.Length } -Descending -Unique) {
        try {
            if (Test-ProtectedDeletionPath -Path $dir) {
                Add-Warning "Skipped protected deletion path: $dir"
                continue
            }

            if (-not (Test-IsTargetText $dir)) {
                Add-Warning "Skipped directory because it no longer matches target pattern: $dir"
                continue
            }

            Write-Log "Removing leftover directory: $dir"
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
            $script:Counters.DirectoriesRemoved++
        }
        catch {
            Add-Warning "Failed removing directory $dir : $($_.Exception.Message)"
        }
    }
}

function Get-ArtifactScanRoots {
    <#
    DESCRIPTION:
        Returns fixed-drive roots for full sweep, or common cleanup roots if full sweep is disabled.
    #>

    if ($ScanAllFixedDrives) {
        try {
            $fixedDrives = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty DeviceID)

            return @($fixedDrives | ForEach-Object { "$_\" })
        }
        catch {
            Add-Warning "Failed to enumerate fixed drives. Falling back to common cleanup roots. $($_.Exception.Message)"
        }
    }

    return @(Get-CommonCleanupRoots)
}

function Remove-TargetInstallerArtifacts {
    <#
    DESCRIPTION:
        Deletes stray ScreenConnect EXE/MSI files by filename.
    #>

    $roots = @(Get-ArtifactScanRoots | Where-Object { Test-Path -LiteralPath $_ })
    $foundFiles = @{}

    foreach ($root in $roots) {
        Write-Log "Scanning for ScreenConnect EXE/MSI artifacts under: $root"

        foreach ($pattern in $InstallerNamePatterns) {
            try {
                $files = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -Filter $pattern -ErrorAction SilentlyContinue)

                foreach ($file in $files) {
                    if ($file.FullName -match $ArtifactExcludePathRegex) {
                        continue
                    }

                    if ($file.Extension -notmatch '(?i)^\.(exe|msi)$') {
                        continue
                    }

                    if (-not (Test-IsTargetText $file.Name)) {
                        continue
                    }

                    $foundFiles[$file.FullName.ToLowerInvariant()] = $file.FullName
                }
            }
            catch {
                Add-Warning "Artifact scan failed under $root with pattern $pattern : $($_.Exception.Message)"
            }
        }
    }

    foreach ($filePath in $foundFiles.Values | Sort-Object -Unique) {
        try {
            Write-Log "Deleting installer artifact: $filePath"
            Remove-Item -LiteralPath $filePath -Force -ErrorAction Stop
            $script:Counters.InstallerFilesDeleted++
        }
        catch {
            Add-Warning "Failed deleting installer artifact $filePath : $($_.Exception.Message)"
        }
    }
}

function Get-ResidualState {
    <#
    DESCRIPTION:
        Performs a lightweight post-remediation check for remaining uninstall entries, services, and processes.
        This is logged for visibility only. The evaluation script owns screenconnectDetected.
    #>

    $remainingUninstallEntries = @(Get-TargetUninstallEntries)
    $remainingServices = @(Get-TargetServices)
    $remainingProcesses = @(Get-TargetProcesses)

    return [pscustomobject]@{
        RemainingUninstallEntries = $remainingUninstallEntries.Count
        RemainingServices         = $remainingServices.Count
        RemainingProcesses        = $remainingProcesses.Count
    }
}



function Remove-ResidualUninstallRegistryKeys {
    <#
    DESCRIPTION:
        Deletes ScreenConnect uninstall registry keys that remain after normal
        uninstall attempts complete.
    #>

    $entries = @(Get-TargetUninstallEntries)

    foreach ($entry in $entries) {
        try {
            if (-not [string]::IsNullOrWhiteSpace($entry.RegistryPath) -and
                (Test-Path -LiteralPath $entry.RegistryPath)) {

                Write-Log "Removing residual uninstall registry key: $($entry.RegistryPath)"
                Remove-Item -LiteralPath $entry.RegistryPath -Recurse -Force -ErrorAction Stop
                $script:Counters.UninstallKeysRemoved++
            }
        }
        catch {
            Add-Warning "Failed removing residual uninstall registry key $($entry.RegistryPath): $($_.Exception.Message)"
        }
    }
}


function Get-NuclearRegistryRoots {
    <#
    DESCRIPTION:
        Returns the native reg.exe registry roots included in the ScreenConnect
        registry scrub.

        Scope is intentionally identical to the prior PowerShell registry walk:
        - HKLM\SOFTWARE
        - HKLM\SYSTEM\CurrentControlSet\Services
        - HKU\<loaded user SID>\Software
    #>

    $roots = New-Object System.Collections.Generic.List[string]

    $roots.Add("HKLM\SOFTWARE") | Out-Null
    $roots.Add("HKLM\SYSTEM\CurrentControlSet\Services") | Out-Null

    try {
        $loadedUserHives = @(Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PSChildName -match '^S-1-5-21-' -and
                $_.PSChildName -notmatch '_Classes$'
            })

        foreach ($hive in $loadedUserHives) {
            $roots.Add("HKU\$($hive.PSChildName)\Software") | Out-Null
        }
    }
    catch {
        Add-Warning "Failed building nuclear registry roots: $($_.Exception.Message)"
    }

    return @($roots | Sort-Object -Unique)
}


function Remove-TargetRegistryArtifacts {
    <#
    DESCRIPTION:
        Performs targeted ScreenConnect registry cleanup without recursively
        inspecting every registry value/data field.

        Thoroughness is preserved through the dedicated cleanup already present
        elsewhere in this remediation:
        - Uninstall entries are discovered and uninstalled directly.
        - Residual uninstall registry keys are deleted directly.
        - ScreenConnect services and service records are removed directly.
        - Run / RunOnce persistence is removed directly.

        This function adds a targeted key-name/path sweep across:
        - HKLM\SOFTWARE
        - HKLM\SYSTEM\CurrentControlSet\Services
        - HKU\<loaded user SID>\Software

        Any registry key whose path contains ScreenConnect is removed.
        Windows Task Scheduler TaskCache remains excluded because tasks are
        removed through Unregister-ScheduledTask.

        Two cleanup passes maximum are allowed, followed by a verification
        search for residual ScreenConnect-named keys.
    #>

    function Test-NativeRegistryPathExcluded {
        param(
            [Parameter(Mandatory = $true)]
            [string]$RegistryPath
        )

        return ($RegistryPath -match $RegistryExcludePathRegex)
    }


    function Get-NativeMatchingKeyPaths {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Root
        )

        $matches = New-Object System.Collections.Generic.List[string]

        try {
            $output = @(& reg.exe query $Root /f ScreenConnect /s /k 2>&1)
            $exitCode = $LASTEXITCODE

            # reg.exe returns 1 when no match is found.
            if ($exitCode -notin @(0, 1)) {
                Add-Warning "reg.exe key search returned unexpected exit code $exitCode for root $Root."
            }

            foreach ($line in $output) {
                $trimmed = ([string]$line).Trim()

                if ($trimmed -notmatch '^HKEY_') {
                    continue
                }

                if (-not (Test-IsTargetText $trimmed)) {
                    continue
                }

                if (Test-NativeRegistryPathExcluded -RegistryPath $trimmed) {
                    continue
                }

                $matches.Add($trimmed) | Out-Null
            }
        }
        catch {
            Add-Warning "Native registry key search failed for root $Root : $($_.Exception.Message)"
        }

        return @($matches | Sort-Object Length -Descending -Unique)
    }


    function Remove-NativeRegistryKey {
        param(
            [Parameter(Mandatory = $true)]
            [string]$KeyPath
        )

        if (-not (Test-IsTargetText $KeyPath)) {
            Add-Warning "Skipped registry key deletion because path no longer matches ScreenConnect: $KeyPath"
            return $false
        }

        if (Test-NativeRegistryPathExcluded -RegistryPath $KeyPath) {
            Add-Warning "Skipped excluded registry key deletion: $KeyPath"
            return $false
        }

        try {
            Write-Log "Removing ScreenConnect registry key: $KeyPath"

            $output = @(& reg.exe delete $KeyPath /f 2>&1)
            $exitCode = $LASTEXITCODE

            if ($exitCode -eq 0) {
                $script:Counters.RegistryKeysRemoved++
                return $true
            }

            Add-Warning "reg.exe failed removing registry key $KeyPath. ExitCode=$exitCode Output=$($output -join ' ')"
            return $false
        }
        catch {
            Add-Warning "Failed removing ScreenConnect registry key $KeyPath : $($_.Exception.Message)"
            return $false
        }
    }


    $roots = @(Get-NuclearRegistryRoots)

    for ($pass = 1; $pass -le 2; $pass++) {
        $removedThisPass = 0

        Write-Log "Targeted registry cleanup pass started | Pass=$pass Roots=$($roots.Count)"

        foreach ($root in $roots) {
            Write-Log "Registry key sweep | Pass=$pass | Root=$root"

            $keyMatches = @(Get-NativeMatchingKeyPaths -Root $root)

            Write-Log "Registry key sweep | Pass=$pass | Root=$root | Matches=$($keyMatches.Count)"

            foreach ($keyPath in $keyMatches) {
                if (Remove-NativeRegistryKey -KeyPath $keyPath) {
                    $removedThisPass++
                }
            }
        }

        Write-Log "Targeted registry cleanup pass completed | Pass=$pass Removed=$removedThisPass"

        if ($removedThisPass -eq 0) {
            break
        }
    }

    $residualKeyMatches = 0

    foreach ($root in $roots) {
        Write-Log "Registry verification | Root=$root"

        $residualKeyMatches += @(Get-NativeMatchingKeyPaths -Root $root).Count
    }

    if ($residualKeyMatches -gt 0) {
        Add-Warning "Registry verification found residual ScreenConnect-named keys | Keys=$residualKeyMatches"
    }
    else {
        Write-Log "Registry verification clean | Residual ScreenConnect-named keys=0"
    }
}


function Remove-TargetFirewallRules {
    <#
    DESCRIPTION:
        Removes Windows Firewall rules whose name, display name, description, or
        associated application path references ScreenConnect.
    #>

    if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        Write-Log "Get-NetFirewallRule is unavailable. Skipping firewall rule cleanup."
        return
    }

    if (-not (Get-Command Remove-NetFirewallRule -ErrorAction SilentlyContinue)) {
        Write-Log "Remove-NetFirewallRule is unavailable. Skipping firewall rule cleanup."
        return
    }

    try {
        $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue)

        foreach ($rule in $rules) {
            $match = $false

            $ruleText = @(
                $rule.Name,
                $rule.DisplayName,
                $rule.Description
            ) -join " "

            if (Test-IsTargetText $ruleText) {
                $match = $true
            }
            elseif (Get-Command Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue) {
                try {
                    $appFilters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue)

                    foreach ($filter in $appFilters) {
                        if (Test-IsTargetText ([string]$filter.Program)) {
                            $match = $true
                            break
                        }
                    }
                }
                catch {}
            }

            if ($match) {
                try {
                    Write-Log "Removing ScreenConnect firewall rule: $($rule.DisplayName) [$($rule.Name)]"
                    Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
                    $script:Counters.FirewallRulesRemoved++
                }
                catch {
                    Add-Warning "Failed removing firewall rule $($rule.DisplayName): $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Add-Warning "Firewall rule cleanup failed: $($_.Exception.Message)"
    }
}


function Remove-NuclearNamedFiles {
    <#
    DESCRIPTION:
        Recursively removes ScreenConnect-named files of any extension from all
        fixed drives except protected Windows paths and MME AutoLogs.

        The currently executing remediation script is skipped here and removed
        by Remove-TransferredPayload in FINALLY.
    #>

    $fixedDrives = @()

    try {
        $fixedDrives = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction Stop |
            Select-Object -ExpandProperty DeviceID)
    }
    catch {
        Add-Warning "Failed enumerating fixed drives for nuclear file sweep: $($_.Exception.Message)"
        return
    }

    $currentScriptPath = $null

    if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
        try {
            $currentScriptPath = [System.IO.Path]::GetFullPath($PSCommandPath)
        }
        catch {}
    }

    foreach ($drive in $fixedDrives) {
        $root = "$drive\"
        Write-Log "Nuclear file sweep for ScreenConnect-named files under: $root"

        try {
            $files = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -Filter "*ScreenConnect*" -ErrorAction SilentlyContinue)

            foreach ($file in $files) {
                try {
                    if ($file.FullName -match $NuclearFileExcludePathRegex) {
                        continue
                    }

                    if (-not (Test-IsTargetText $file.Name)) {
                        continue
                    }

                    if ($null -ne $currentScriptPath -and
                        ([System.IO.Path]::GetFullPath($file.FullName) -ieq $currentScriptPath)) {
                        continue
                    }

                    Write-Log "Removing ScreenConnect-named file: $($file.FullName)"
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    $script:Counters.NamedFilesDeleted++
                }
                catch {
                    Add-Warning "Failed removing ScreenConnect-named file $($file.FullName): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Add-Warning "Nuclear file sweep failed under $root : $($_.Exception.Message)"
        }
    }
}


function Remove-NuclearNamedDirectories {
    <#
    DESCRIPTION:
        Recursively removes ScreenConnect-named directories from all fixed
        drives except protected Windows paths and MME AutoLogs.
    #>

    $fixedDrives = @()

    try {
        $fixedDrives = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction Stop |
            Select-Object -ExpandProperty DeviceID)
    }
    catch {
        Add-Warning "Failed enumerating fixed drives for nuclear directory sweep: $($_.Exception.Message)"
        return
    }

    $candidateDirs = @{}

    foreach ($drive in $fixedDrives) {
        $root = "$drive\"
        Write-Log "Nuclear directory sweep for ScreenConnect-named directories under: $root"

        try {
            $dirs = @(Get-ChildItem -LiteralPath $root -Recurse -Force -Directory -Filter "*ScreenConnect*" -ErrorAction SilentlyContinue)

            foreach ($dir in $dirs) {
                if ($dir.FullName -match $NuclearFileExcludePathRegex) {
                    continue
                }

                if (-not (Test-IsTargetText $dir.Name)) {
                    continue
                }

                $candidateDirs[$dir.FullName.ToLowerInvariant()] = $dir.FullName
            }
        }
        catch {
            Add-Warning "Nuclear directory sweep failed under $root : $($_.Exception.Message)"
        }
    }

    foreach ($dir in @($candidateDirs.Values | Sort-Object Length -Descending -Unique)) {
        try {
            if (Test-ProtectedDeletionPath -Path $dir) {
                Add-Warning "Skipped protected nuclear directory deletion path: $dir"
                continue
            }

            if ($dir -match $NuclearFileExcludePathRegex) {
                continue
            }

            if (-not (Test-IsTargetText $dir)) {
                continue
            }

            if (Test-Path -LiteralPath $dir) {
                Write-Log "Removing ScreenConnect-named directory: $dir"
                Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
                $script:Counters.NamedDirectoriesRemoved++
            }
        }
        catch {
            Add-Warning "Failed removing ScreenConnect-named directory $dir : $($_.Exception.Message)"
        }
    }
}


function Remove-TransferredPayload {
    <#
    DESCRIPTION:
        Removes the known transferred payload and, when applicable, the
        currently executing ScreenConnect-named .ps1 copy.

        No generic .ps1 sweep is performed here.
    #>

    $targets = New-Object System.Collections.Generic.List[string]

    try {
        $expected = [System.IO.Path]::GetFullPath($ExpectedSelfPath)

        if (Test-Path -LiteralPath $expected -PathType Leaf) {
            $targets.Add($expected) | Out-Null
        }

        if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
            try {
                $current = [System.IO.Path]::GetFullPath($PSCommandPath)
                $leaf = Split-Path -Path $current -Leaf

                if ((Test-IsTargetText $leaf) -and
                    ($current -ine $expected) -and
                    (Test-Path -LiteralPath $current -PathType Leaf)) {

                    $targets.Add($current) | Out-Null
                }
            }
            catch {}
        }

        foreach ($target in @($targets | Sort-Object -Unique)) {
            try {
                Write-Log "Removing ScreenConnect remediation payload: $target"
                Remove-Item -LiteralPath $target -Force -ErrorAction Stop
                Write-Log "ScreenConnect remediation payload removed: $target"
            }
            catch {
                Write-Log -Level "WARN" -Message "Failed removing remediation payload '$target': $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Log -Level "WARN" -Message "Transferred payload cleanup failed: $($_.Exception.Message)"
    }
}


# =========================
# MAIN
# =========================

try {
    Initialize-Logging

    Write-Log "Starting ScreenConnect removal."

    $initialUninstallEntries = @(Get-TargetUninstallEntries)
    $initialServices = @(Get-TargetServices)
    $initialProcesses = @(Get-TargetProcesses)

    Write-Log "Initial findings: uninstall entries=$($initialUninstallEntries.Count), services=$($initialServices.Count), processes=$($initialProcesses.Count)."

    Stop-TargetProcesses
    Stop-TargetServices

    Remove-TargetScheduledTasks
    Remove-TargetRunEntries

    Invoke-TargetUninstalls

    Start-Sleep -Seconds 5

    Stop-TargetProcesses
    Stop-TargetServices
    Remove-TargetServiceRecords

    Remove-TargetDirectories
    Remove-TargetInstallerArtifacts

    # Nuclear cleanup passes. Existing removal logic above remains unchanged.
    Remove-ResidualUninstallRegistryKeys
    Remove-TargetRegistryArtifacts
    Remove-TargetFirewallRules
    Remove-NuclearNamedFiles
    Remove-NuclearNamedDirectories

    # Re-check volatile persistence after uninstall/cleanup activity.
    Stop-TargetProcesses
    Stop-TargetServices
    Remove-TargetScheduledTasks
    Remove-TargetRunEntries
    Remove-TargetServiceRecords

    $residual = Get-ResidualState

    $totalActions =
        $Counters.ProcessesStopped +
        $Counters.ServicesStopped +
        $Counters.ServicesDeleted +
        $Counters.UninstallAttempts +
        $Counters.ScheduledTasksRemoved +
        $Counters.RunEntriesRemoved +
        $Counters.DirectoriesRemoved +
        $Counters.InstallerFilesDeleted +
        $Counters.NamedFilesDeleted +
        $Counters.NamedDirectoriesRemoved +
        $Counters.RegistryKeysRemoved +
        $Counters.RegistryValuesRemoved +
        $Counters.UninstallKeysRemoved +
        $Counters.FirewallRulesRemoved

    $summary = "ScreenConnect cleanup completed. Initial uninstall entries=$($initialUninstallEntries.Count), initial services=$($initialServices.Count), initial processes=$($initialProcesses.Count), uninstall attempts=$($Counters.UninstallAttempts), uninstall successes=$($Counters.UninstallSuccesses), processes stopped=$($Counters.ProcessesStopped), services stopped=$($Counters.ServicesStopped), services deleted=$($Counters.ServicesDeleted), scheduled tasks removed=$($Counters.ScheduledTasksRemoved), startup entries removed=$($Counters.RunEntriesRemoved), directories removed=$($Counters.DirectoriesRemoved), installer files deleted=$($Counters.InstallerFilesDeleted), nuclear named files deleted=$($Counters.NamedFilesDeleted), nuclear named directories removed=$($Counters.NamedDirectoriesRemoved), registry keys removed=$($Counters.RegistryKeysRemoved), registry values removed=$($Counters.RegistryValuesRemoved), residual uninstall keys removed=$($Counters.UninstallKeysRemoved), firewall rules removed=$($Counters.FirewallRulesRemoved), residual uninstall entries=$($residual.RemainingUninstallEntries), residual services=$($residual.RemainingServices), residual processes=$($residual.RemainingProcesses), warnings=$($Counters.Warnings)."

    if (($initialUninstallEntries.Count -eq 0) -and
        ($initialServices.Count -eq 0) -and
        ($initialProcesses.Count -eq 0) -and
        ($totalActions -eq 0)) {

        $FinalToken = "NO_ACTION"
        $FinalMessage = "No ScreenConnect findings detected. Installer sweep completed. Warnings=$($Counters.Warnings)."
    }
    else {
        $FinalToken = "RESULT"
        $FinalMessage = $summary
    }

    Write-Log $summary

    if ($Warnings.Count -gt 0) {
        Write-Log "Warnings encountered:"
        foreach ($warning in $Warnings) {
            Write-Log " - $warning" "WARN"
        }
    }
}
catch {
    $FinalToken = "ERROR"
    $FinalMessage = "Unexpected script error: $($_.Exception.Message)"
    Add-Warning $FinalMessage
}
finally {
    Remove-TransferredPayload

    Write-Host "$FinalToken | $FinalMessage"

    exit 0
}