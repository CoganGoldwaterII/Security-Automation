# ============================================================================
# NAME: Detect ScreenConnect Presence
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne scheduled automation
# VARIABLES:
#   DetectionFieldName = screenconnectDetected
#   ScanAllFixedDrivesForInstallerArtifacts = $false
# OUTPUT TOKENS:
#   YES | ScreenConnect findings detected
#   NO  | No ScreenConnect findings detected
#   NOTE: Final output is the bare YES or NO value.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: screenconnectDetected (YES/NO)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\ScreenConnect_Detect.log
# DESCRIPTION:
#   Evaluates ScreenConnect presence on Windows endpoints.
#
#   Detects:
#     - Installed software uninstall registry entries
#     - Services
#     - Running processes
#     - Scheduled tasks
#     - Startup Run / RunOnce entries
#     - Common leftover directories
#     - Common EXE/MSI installer artifact locations
#
#   Searches machine-wide registry locations and loaded user hives.
#   Installer artifact scanning uses common locations by default,
#   with optional fixed-drive scanning controlled by configuration.
#
#   Writes YES or NO to the screenconnectDetected NinjaOne device
#   custom field. This script does not update remediation fields.
#
#   Logs detection findings and non-fatal warnings.
#   The paired remediation handles ScreenConnect removal.
#   Always exits 0.
# ============================================================================

# =========================
# CONFIG
# =========================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$DetectionFieldName = "screenconnectDetected"

$LogRoot = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogRoot "ScreenConnect_Detect.log"

$TargetRegex = '(?i)screenconnect'

$ScanAllFixedDrivesForInstallerArtifacts = $false

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
Custom Field Name: $DetectionFieldName
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

function Set-DetectionCustomField {
    <#
    DESCRIPTION:
        Writes YES or NO to the configured Ninja custom field.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("YES", "NO")]
        [string]$Value
    )

    try {
        if (-not (Get-Command "Ninja-Property-Set" -ErrorAction SilentlyContinue)) {
            Add-Warning "Ninja-Property-Set is unavailable. Could not update custom field '$DetectionFieldName'."
            return
        }

        Ninja-Property-Set $DetectionFieldName $Value
        Write-Log "Updated Ninja custom field '$DetectionFieldName' to '$Value'."
    }
    catch {
        Add-Warning "Failed to update Ninja custom field '$DetectionFieldName': $($_.Exception.Message)"
    }
}


# =========================
# MAIN
# =========================

$DetectionValue = "NO"

try {
    Initialize-Logging

    Write-Log "Starting ScreenConnect detection."

    Test-UninstallEntries
    Test-Services
    Test-Processes
    Test-ScheduledTasks
    Test-RunEntries
    Test-Directories
    Test-InstallerArtifacts

    if ($Findings.Count -gt 0) {
        $DetectionValue = "YES"
    }
    else {
        $DetectionValue = "NO"
    }

    Write-Log "Detection result: $DetectionValue"
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

    Set-DetectionCustomField -Value $DetectionValue
}
catch {
    Add-Warning "Unexpected script error: $($_.Exception.Message)"

    if ($Findings.Count -gt 0) {
        $DetectionValue = "YES"
    }
    else {
        $DetectionValue = "NO"
    }

    Set-DetectionCustomField -Value $DetectionValue
}
finally {
    Write-Host $DetectionValue
    exit 0
}