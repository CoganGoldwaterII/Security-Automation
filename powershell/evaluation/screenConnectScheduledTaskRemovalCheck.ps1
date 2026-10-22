
# ============================================================================
# NAME: ScreenConnect Presence and Pending-Removal Task Evaluation
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne scheduled automation
# VARIABLES:
#   Optional NinjaOne script variables:
#     screenConnectRemovalTaskName - Paired scheduler's exact task name
#     screenConnectRemovalPayloadPath - Paired scheduler's exact payload path
#   Defaults use generic AutomationPlaybook paths/names. The paired
#   scheduler MUST use the same task name, task path, payload, and executor.
# OUTPUT TOKENS:
#   TRIGGER   | ScreenConnect presence detected
#   NO_ACTION | No ScreenConnect presence detected or remediation pending
#   ERROR     | Unexpected evaluation error
#   Exit Code: Always 0
#   Ninja Condition: Output contains TRIGGER and Result Code 0
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS: None (eval); paired remediation requires its own payload
# LOGGING PATH:
#   %ProgramData%\AutomationPlaybook\Logs\ScreenConnect_Detect.log
# DESCRIPTION:
#   Checks for a pending ScreenConnect removal scheduled task before normal
#   endpoint detection. Pending task must match the expected name/path,
#   PowerShell executable, referenced payload, SYSTEM/Highest principal,
#   and have a future NextRunTime. A valid future task returns NO_ACTION.
#   The paired scheduler currently targets 00:00 (midnight); this evaluator
#   checks only that NextRunTime is in the future, not the exact clock time.
#
#   Otherwise detects ScreenConnect uninstall entries, services, processes,
#   scheduled tasks, Run/RunOnce entries, directories, and EXE/MSI artifacts.
#   A stale/invalid paired task with ScreenConnect in its name may itself be
#   detected by the general scheduled-task scan and cause a TRIGGER.
#
#   Read-only endpoint evaluation: no removal is performed. No credentials.
#   When publishing with its paired scheduler, align task/payload settings.
# ============================================================================

# =========================
# CONFIG
# =========================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$LogRoot = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogPath = Join-Path $LogRoot 'ScreenConnect_Detect.log'

$TargetRegex = '(?i)screenconnect'

$ScanAllFixedDrivesForInstallerArtifacts = $false

$RemediationTaskName = if (-not [string]::IsNullOrWhiteSpace($env:screenConnectRemovalTaskName)) {
    $env:screenConnectRemovalTaskName
} else {
    'AutomationPlaybook - ScreenConnect Removal'
}
$RemediationTaskPath = '\'
$RemediationPayloadPath = if (-not [string]::IsNullOrWhiteSpace($env:screenConnectRemovalPayloadPath)) {
    $env:screenConnectRemovalPayloadPath
} else {
    Join-Path $env:ProgramData 'AutomationPlaybook\Payloads\screenConnectRemoval.ps1'
}
$RemediationPowerShellPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

$InstallerNamePatterns = @(
    '*ScreenConnect*.exe',
    '*ScreenConnect*.msi'
)

$ArtifactExcludePathRegex = '(?i)\\Windows\\(WinSxS|servicing|System32|SysWOW64|Installer|SoftwareDistribution)\\|\\Program Files\\WindowsApps\\'


# =========================
# GLOBAL STATE
# =========================

$Findings = New-Object System.Collections.Generic.List[string]
$Warnings = New-Object System.Collections.Generic.List[string]


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
ScreenConnect Detection Eval
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
User Context: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
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
        $line | Out-File -FilePath $LogPath -Append -Encoding UTF8
    }
    catch {
        Write-Host "WARN | Failed writing to log file: $($_.Exception.Message)"
    }

    Write-Host $line
}

function Add-Finding {
    <#
    DESCRIPTION:
        Adds a detection finding and writes it to the log.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:Findings.Add($Message) | Out-Null
    Write-Log "Finding: $Message"
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

    $script:Warnings.Add($Message) | Out-Null
    Write-Log -Level "WARN" -Message $Message
}

function Test-PendingRemediationTask {
    <#
    DESCRIPTION:
        Returns task information only when the exact paired ScreenConnect
        remediation task is valid and scheduled for a future run.

        A matching task must:
        - Use the expected task name and task path
        - Invoke Windows PowerShell
        - Reference the expected transferred remediation payload
        - Run as SYSTEM with highest privileges
        - Have a future NextRunTime

        Any missing, stale, or mismatched task is ignored so normal
        ScreenConnect detection can continue.
    #>

    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Write-Log "Get-ScheduledTask is unavailable. Pending-remediation guard skipped."
        return $null
    }

    if (-not (Get-Command Get-ScheduledTaskInfo -ErrorAction SilentlyContinue)) {
        Write-Log "Get-ScheduledTaskInfo is unavailable. Pending-remediation guard skipped."
        return $null
    }

    try {
        $task = Get-ScheduledTask `
            -TaskName $RemediationTaskName `
            -TaskPath $RemediationTaskPath `
            -ErrorAction SilentlyContinue

        if ($null -eq $task) {
            return $null
        }

        $actionMatches = $false

        foreach ($action in @($task.Actions)) {
            if (($action.Execute -ieq $RemediationPowerShellPath) -and
                ($action.Arguments -like "*$RemediationPayloadPath*")) {

                $actionMatches = $true
                break
            }
        }

        if (-not $actionMatches) {
            Write-Log "Pending-remediation guard ignored task because the action does not match the expected payload."
            return $null
        }

        $principalMatches =
            (($task.Principal.UserId -ieq "SYSTEM") -or
             ($task.Principal.UserId -ieq "NT AUTHORITY\SYSTEM")) -and
            ($task.Principal.RunLevel -eq "Highest")

        if (-not $principalMatches) {
            Write-Log "Pending-remediation guard ignored task because the principal does not match SYSTEM / Highest."
            return $null
        }

        $taskInfo = Get-ScheduledTaskInfo `
            -TaskName $RemediationTaskName `
            -TaskPath $RemediationTaskPath `
            -ErrorAction Stop

        if ($taskInfo.NextRunTime -le (Get-Date)) {
            Write-Log "Pending-remediation guard ignored task because NextRunTime is not in the future."
            return $null
        }

        return [pscustomobject]@{
            TaskName    = $RemediationTaskName
            TaskPath    = $RemediationTaskPath
            NextRunTime = $taskInfo.NextRunTime
        }
    }
    catch {
        Add-Warning "Pending-remediation guard check failed: $($_.Exception.Message)"
        return $null
    }
}


function Test-IsTargetText {
    <#
    DESCRIPTION:
        Returns true when supplied text matches the ScreenConnect detection pattern.
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

function Test-UninstallEntries {
    <#
    DESCRIPTION:
        Detects ScreenConnect uninstall registry entries.
    #>

    try {
        $entries = @(Get-UninstallRegistryEntries | Where-Object {
            $haystack = @(
                $_.DisplayName,
                $_.Publisher,
                $_.InstallLocation,
                $_.UninstallString,
                $_.QuietUninstallString
            ) -join " "

            Test-IsTargetText $haystack
        })

        foreach ($entry in $entries) {
            Add-Finding "Uninstall entry detected: $($entry.DisplayName) $($entry.DisplayVersion)"
        }
    }
    catch {
        Add-Warning "Failed uninstall entry detection: $($_.Exception.Message)"
    }
}

function Test-Services {
    <#
    DESCRIPTION:
        Detects ScreenConnect services.
    #>

    try {
        $services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object {
                $haystack = @($_.Name, $_.DisplayName, $_.PathName) -join " "
                Test-IsTargetText $haystack
            })

        foreach ($service in $services) {
            Add-Finding "Service detected: $($service.Name) [$($service.DisplayName)] State=$($service.State)"
        }
    }
    catch {
        Add-Warning "Failed service detection: $($_.Exception.Message)"
    }
}

function Test-Processes {
    <#
    DESCRIPTION:
        Detects running ScreenConnect processes by process name or executable path.
        Command line is intentionally not checked to avoid matching this script's own text.
    #>

    try {
        $processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $haystack = @($_.Name, $_.ExecutablePath) -join " "
                (Test-IsTargetText $haystack) -and ($_.ProcessId -ne $PID)
            })

        foreach ($process in $processes) {
            Add-Finding "Process detected: $($process.Name) PID=$($process.ProcessId)"
        }
    }
    catch {
        Add-Warning "Failed process detection: $($_.Exception.Message)"
    }
}

function Test-ScheduledTasks {
    <#
    DESCRIPTION:
        Detects scheduled tasks referencing ScreenConnect.
    #>

    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Write-Log "Get-ScheduledTask is unavailable on this system. Skipping scheduled task detection."
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
            Add-Finding "Scheduled task detected: $($task.TaskPath)$($task.TaskName)"
        }
    }
    catch {
        Add-Warning "Failed scheduled task detection: $($_.Exception.Message)"
    }
}

function Test-RunEntries {
    <#
    DESCRIPTION:
        Detects Run and RunOnce registry startup entries referencing ScreenConnect.
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
                    Add-Finding "Startup entry detected: $($prop.Name) in $path"
                }
            }
        }
        catch {
            Add-Warning "Failed processing Run path $path : $($_.Exception.Message)"
        }
    }
}

function Get-CommonArtifactRoots {
    <#
    DESCRIPTION:
        Builds common locations to check for ScreenConnect directories and installer artifacts.
    #>

    $roots = New-Object System.Collections.Generic.List[string]

    $possibleRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        "$env:SystemRoot\Temp",
        "$env:SystemDrive\Temp",
        (Join-Path $env:ProgramData 'AutomationPlaybook'),
        (Join-Path $env:ProgramData 'AutomationPlaybook\Payloads')
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
        Add-Warning "Failed building user artifact roots: $($_.Exception.Message)"
    }

    return @($roots | Sort-Object -Unique)
}

function Test-Directories {
    <#
    DESCRIPTION:
        Detects common leftover ScreenConnect directories.
    #>

    $roots = @(Get-CommonArtifactRoots)
    $dirPatterns = @(
        '*ScreenConnect*'
    )

    foreach ($root in $roots) {
        foreach ($pattern in $dirPatterns) {
            try {
                $matches = @(Get-ChildItem -Path (Join-Path $root $pattern) -Directory -Force -ErrorAction SilentlyContinue)

                foreach ($match in $matches) {
                    if (Test-IsTargetText $match.FullName) {
                        Add-Finding "Directory detected: $($match.FullName)"
                    }
                }
            }
            catch {
                Add-Warning "Failed searching directory pattern $pattern under $root : $($_.Exception.Message)"
            }
        }
    }
}

function Get-InstallerArtifactScanRoots {
    <#
    DESCRIPTION:
        Returns locations to scan for ScreenConnect EXE/MSI installer artifacts.
    #>

    if ($ScanAllFixedDrivesForInstallerArtifacts) {
        try {
            $fixedDrives = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty DeviceID)

            return @($fixedDrives | ForEach-Object { "$_\" })
        }
        catch {
            Add-Warning "Failed to enumerate fixed drives. Falling back to common artifact roots. $($_.Exception.Message)"
        }
    }

    return @(Get-CommonArtifactRoots)
}

function Test-InstallerArtifacts {
    <#
    DESCRIPTION:
        Detects ScreenConnect EXE/MSI installer artifacts.
    #>

    $roots = @(Get-InstallerArtifactScanRoots | Where-Object { Test-Path -LiteralPath $_ })
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
        Add-Finding "Installer artifact detected: $filePath"
    }
}


# =========================
# MAIN
# =========================

$FinalToken = "ERROR"
$FinalMessage = "Unexpected evaluation termination before completion."

try {
    Initialize-Logging

    Write-Log "Starting ScreenConnect detection."

    $PendingRemediation = Test-PendingRemediationTask

    if ($null -ne $PendingRemediation) {
        $FinalToken = "NO_ACTION"
        $FinalMessage = "ScreenConnect remediation already scheduled | Task=$($PendingRemediation.TaskName) NextRun=$($PendingRemediation.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss'))"

        Write-Log "$FinalToken | $FinalMessage"
        Write-Host "$FinalToken | $FinalMessage"
        exit 0
    }

    Test-UninstallEntries
    Test-Services
    Test-Processes
    Test-ScheduledTasks
    Test-RunEntries
    Test-Directories
    Test-InstallerArtifacts

    Write-Log "Finding count: $($Findings.Count)"
    Write-Log "Warning count: $($Warnings.Count)"

    if ($Findings.Count -gt 0) {
        Write-Log "Findings summary:"
        foreach ($finding in $Findings) {
            Write-Log " - $finding"
        }
    }

    if ($Warnings.Count -gt 0) {
        Write-Log "Warnings summary:"
        foreach ($warning in $Warnings) {
            Write-Log " - $warning" "WARN"
        }
    }

    if ($Findings.Count -gt 0) {
        $FinalToken = "TRIGGER"
        $FinalMessage = "ScreenConnect presence detected | Findings=$($Findings.Count) Warnings=$($Warnings.Count)"
    }
    else {
        $FinalToken = "NO_ACTION"
        $FinalMessage = "No ScreenConnect presence detected | Findings=0 Warnings=$($Warnings.Count)"
    }

    Write-Log "$FinalToken | $FinalMessage"
}
catch {
    $FinalToken = "ERROR"
    $FinalMessage = "Unexpected evaluation error: $($_.Exception.Message)"

    try {
        Add-Warning $FinalMessage
    }
    catch {
        Write-Host "WARN | Failed to record evaluation error: $($_.Exception.Message)"
    }
}
finally {
    Write-Host "$FinalToken | $FinalMessage"
    exit 0
}
