# ============================================================================
# NAME: Detect Remote Access Software Presence
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   DetectedFieldName = remoteSoftwareDetected
#   PresentFieldName  = remoteSoftwarePresent
#   ScanAllFixedDrivesForInstallerArtifacts = $false
#   MaxPresenceSummaryCharacters = 3500
# OUTPUT TOKENS:
#   TRIGGER   | Targeted remote access software detected
#   NO_ACTION | No targeted remote access software detected
#   ERROR     | Unexpected script error or custom field update failure
# CUSTOM FIELDS:
#   Reads: None
#   Writes:
#     remoteSoftwareDetected (Yes/No)
#     remoteSoftwarePresent (Multi-line)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\Remote_Access_Software_Detect.log
# DESCRIPTION:
#   Detects targeted third-party remote access software across Windows
#   endpoints using installed application records, services, processes,
#   scheduled tasks, startup entries, directories, and installer artifacts.
#
#   Excludes NinjaOne remote tools, Microsoft-native remote assistance,
#   and designated VPN/tunnel software from detection.
#
#   Uses literal and regular-expression matching for supported products.
#   Collects structured findings, deduplicates results, and generates a
#   concise Name + Path summary for NinjaOne output and custom fields.
#
#   Writes Yes/No to remoteSoftwareDetected and the current findings
#   summary to remoteSoftwarePresent. Clears the summary when no
#   targeted remote access software is detected.
#
#   Detailed findings remain available in the local automation log.
#   Reports custom field update failures using the ERROR token.
#   Always exits 0.
# ============================================================================

# =========================
# CONFIG
# =========================

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$DetectedFieldName = "remoteSoftwareDetected"
$PresentFieldName  = "remoteSoftwarePresent"

$LogRoot = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogRoot "Remote_Access_Software_Detect.log"

$ScanAllFixedDrivesForInstallerArtifacts = $false
$MaxPresenceSummaryCharacters = 3500

$ArtifactExcludePathRegex = '(?i)\\Windows\\(WinSxS|servicing|System32|SysWOW64|Installer|SoftwareDistribution)\\|\\Program Files\\WindowsApps\\'

$LiteralTargets = @(
    "ConnectWise ScreenConnect",
    "ConnectWise Control",
    "ScreenConnect",
    "Chrome Remote Desktop",
    "Distant Desktop",
    "Iperius Remote",
    "Vine Server",
    "RemotePC",
    "SimpleHelp",
    "ScreenMeet",
    "HelpWire",
    "FixMe.IT",
    "Techinline",
    "Supremo",
    "UltraViewer",
    "DWService",
    "RustDesk",
    "NoMachine",
    "Parsec",
    "Ammyy Admin",
    "AeroAdmin",
    "LiteManager",
    "AnyViewer",
    "FleetDeck",
    "pcAnywhere",
    "ShowMyPC",
    "GotoHTTP",
    "RealVNC",
    "TightVNC",
    "UltraVNC",
    "TigerVNC",
    "TurboVNC",
    "WinVNC",
    "x11vnc",
    "EchoVNC",
    "AnyDesk"
)

$RegexTargets = @(
    [PSCustomObject]@{
        Name    = "Radmin"
        Pattern = '(?i)\bRadmin\b(?!\s*VPN\b)'
    },
    [PSCustomObject]@{
        Name    = "Splashtop"
        Pattern = '(?i)\bSplashtop(?:[\s_-]*(?:Streamer|SOS|Business|Remote[\s_-]*Support|Remote[\s_-]*Access|Software[\s_-]*Updater|RemoteService))?\b'
    },
    [PSCustomObject]@{
        Name    = "GoTo/LogMeIn"
        Pattern = '(?i)\b(?:GoTo(?:Assist|MyPC|\s+Resolve)|LogMeIn(?:\s+(?:Rescue|Pro|Central))?)\b'
    },
    [PSCustomObject]@{
        Name    = "TeamViewer"
        Pattern = '(?i)\bTeamViewer(?:[\s_-]*(?:Host|QuickSupport|QS|Service))?\b'
    },
    [PSCustomObject]@{
        Name    = "Zoho Assist"
        Pattern = '(?i)\bZoho\s+Assist(?:\s+Unattended\s+Agent)?\b'
    },
    [PSCustomObject]@{
        Name    = "BeyondTrust/Bomgar"
        Pattern = '(?i)\b(?:BeyondTrust\s+Remote\s+Support|Bomgar(?:\s+Jump\s+Client)?)\b'
    },
    [PSCustomObject]@{
        Name    = "ISL"
        Pattern = '(?i)\bISL\s+(?:Online|Light|AlwaysOn|Pronto)\b'
    },
    [PSCustomObject]@{
        Name    = "Remote Utilities"
        Pattern = '(?i)\bRemote\s+Utilities(?:\s*-\s*(?:Host|Viewer|Agent))?\b'
    },
    [PSCustomObject]@{
        Name    = "NetSupport"
        Pattern = '(?i)\bNetSupport(?:\s+(?:Manager|Client|School|DNA))?\b'
    },
    [PSCustomObject]@{
        Name    = "VNC Connect"
        Pattern = '(?i)\b(?:VNC\s+Connect|VNC\s+Server|VNC\s+Viewer)\b'
    }
)

$ExcludedPatterns = @(
    '(?i)\bNinjaOne\b',
    '(?i)\bNinjaRMM\b',
    '(?i)\bNinjaRMMAgent\b',
    '(?i)\bNinja\s+Remote\b',
    '(?i)\bNinjaRemote\b',
    '(?i)\bNinja\s+Remote\s+Tools\b',

    '(?i)\bQuick\s+Assist\b',
    '(?i)\bQuickAssist\.exe\b',
    '(?i)\bMicrosoft\s+Remote\s+Help\b',
    '(?i)\bRemote\s+Help\b',
    '(?i)\bRemote\s+Desktop\s+Connection\b',
    '(?i)\bmstsc\.exe\b',
    '(?i)\bmsra\.exe\b',
    '(?i)\bWindows\s+Remote\s+Assistance\b',

    '(?i)\bRadmin\s+VPN\b',
    '(?i)\bOpenVPN\b',
    '(?i)\bWireGuard\b',
    '(?i)\bTailscale\b',
    '(?i)\bZeroTier\b',
    '(?i)\bHamachi\b',
    '(?i)\bLogMeIn\s+Hamachi\b',
    '(?i)\bSoftEther\b',
    '(?i)\bCloudflare\s+Tunnel\b',
    '(?i)\bcloudflared\b',
    '(?i)\bngrok\b',
    '(?i)\bRemote\.It\b',
    '(?i)\bTeleport\b',
    '(?i)\bTwingate\b',
    '(?i)\bNetBird\b'
)

# =========================
# GLOBAL STATE
# =========================

$Findings = New-Object System.Collections.Generic.List[object]
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

    $Header = @"
============================================================
Remote Access Software Detection Eval
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
User Context: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
Detection Field: $DetectedFieldName
Presence Field: $PresentFieldName
Summary Character Cap: $MaxPresenceSummaryCharacters
============================================================
"@

    $Header | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

function Write-Log {
    <#
    DESCRIPTION:
        Writes timestamped output to the local automation log only.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $Line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message

    try {
        $Line | Out-File -FilePath $LogPath -Append -Encoding UTF8
    }
    catch {
        # Keep eval output Ninja-safe even if file logging fails.
    }
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

function Test-IsExcludedText {
    <#
    DESCRIPTION:
        Prevents detection of Ninja/Ninja Remote, Microsoft-native remote tools,
        and VPN/tunnel software.
    #>

    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $true
    }

    foreach ($Pattern in $ExcludedPatterns) {
        if ($Text -match $Pattern) {
            return $true
        }
    }

    return $false
}

function Get-TargetMatches {
    <#
    DESCRIPTION:
        Returns approved target names found in a text string.
    #>

    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    if (Test-IsExcludedText -Text $Text) {
        return @()
    }

    $Results = New-Object System.Collections.Generic.List[string]
    $LiteralMatches = New-Object System.Collections.Generic.List[string]

    foreach ($Target in $LiteralTargets) {
        if ($Text.IndexOf($Target, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $LiteralMatches.Add($Target) | Out-Null
        }
    }

    foreach ($MatchName in $LiteralMatches) {
        $IsContainedByLongerMatch = $false

        foreach ($OtherMatch in $LiteralMatches) {
            if (
                $OtherMatch.Length -gt $MatchName.Length -and
                $OtherMatch.IndexOf($MatchName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
            ) {
                $IsContainedByLongerMatch = $true
                break
            }
        }

        if (-not $IsContainedByLongerMatch) {
            $Results.Add($MatchName) | Out-Null
        }
    }

    foreach ($Target in $RegexTargets) {
        if ($Text -match $Target.Pattern) {
            $Results.Add($Target.Name) | Out-Null
        }
    }

    return @($Results | Sort-Object -Unique)
}

function Get-PathFromText {
    <#
    DESCRIPTION:
        Attempts to extract an executable or installer path from registry,
        service, startup, or task action text.
    #>

    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $CleanText = $Text.Trim()

    $QuotedPath = [regex]::Match($CleanText, '"([A-Za-z]:\\[^"]+?\.(?:exe|msi))"', "IgnoreCase")
    if ($QuotedPath.Success) {
        return $QuotedPath.Groups[1].Value
    }

    $LoosePath = [regex]::Match($CleanText, "([A-Za-z]:\\[^\s]+?\.(?:exe|msi))", "IgnoreCase")
    if ($LoosePath.Success) {
        return $LoosePath.Groups[1].Value.TrimEnd(",")
    }

    if ($CleanText -match "^[A-Za-z]:\\") {
        return $CleanText.TrimEnd(",")
    }

    return $null
}

function Add-Finding {
    <#
    DESCRIPTION:
        Adds a structured detection finding and writes detailed evidence to the log.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetName,

        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [string]$Path,

        [AllowNull()]
        [string]$Detail
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = "Unknown"
    }

    if ([string]::IsNullOrWhiteSpace($Detail)) {
        $Detail = "None"
    }

    $Finding = [PSCustomObject]@{
        TargetName = $TargetName
        Source     = $Source
        Name       = $Name
        Path       = $Path
        Detail     = $Detail
    }

    $script:Findings.Add($Finding) | Out-Null
    Write-Log "Finding: Target='$TargetName' Source='$Source' Name='$Name' Path='$Path' Detail='$Detail'"
}

function Get-UninstallRegistryEntries {
    <#
    DESCRIPTION:
        Enumerates machine-wide and loaded-user uninstall registry entries.
    #>

    $Paths = New-Object System.Collections.Generic.List[string]

    $Paths.Add("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*") | Out-Null
    $Paths.Add("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*") | Out-Null

    try {
        $LoadedUserHives = @(Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$'
            })

        foreach ($Hive in $LoadedUserHives) {
            $Paths.Add("Registry::HKEY_USERS\$($Hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*") | Out-Null
            $Paths.Add("Registry::HKEY_USERS\$($Hive.PSChildName)\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*") | Out-Null
        }
    }
    catch {
        Add-Warning "Failed to enumerate loaded user uninstall hives: $($_.Exception.Message)"
    }

    $Entries = New-Object System.Collections.Generic.List[object]

    foreach ($Path in $Paths) {
        try {
            $Items = @(Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue)

            foreach ($Item in $Items) {
                if (-not [string]::IsNullOrWhiteSpace($Item.DisplayName)) {
                    $Entries.Add([PSCustomObject]@{
                        DisplayName          = $Item.DisplayName
                        DisplayVersion       = $Item.DisplayVersion
                        Publisher            = $Item.Publisher
                        InstallLocation      = $Item.InstallLocation
                        DisplayIcon          = $Item.DisplayIcon
                        UninstallString      = $Item.UninstallString
                        QuietUninstallString = $Item.QuietUninstallString
                        RegistryPath         = $Item.PSPath
                    }) | Out-Null
                }
            }
        }
        catch {
            Add-Warning "Failed reading uninstall path $Path : $($_.Exception.Message)"
        }
    }

    return $Entries
}

function Test-UninstallEntries {
    <#
    DESCRIPTION:
        Detects target software from installed application uninstall entries.
    #>

    try {
        $Entries = @(Get-UninstallRegistryEntries)

        foreach ($Entry in $Entries) {
            $Haystack = @(
                $Entry.DisplayName,
                $Entry.Publisher,
                $Entry.InstallLocation,
                $Entry.DisplayIcon,
                $Entry.UninstallString,
                $Entry.QuietUninstallString
            ) -join " "

            $Targets = @(Get-TargetMatches -Text $Haystack)

            foreach ($Target in $Targets) {
                $DetectedPath = $Entry.InstallLocation

                if ([string]::IsNullOrWhiteSpace($DetectedPath)) {
                    $DetectedPath = Get-PathFromText -Text $Entry.DisplayIcon
                }

                if ([string]::IsNullOrWhiteSpace($DetectedPath)) {
                    $DetectedPath = Get-PathFromText -Text $Entry.UninstallString
                }

                $Detail = "DisplayName=$($Entry.DisplayName); Version=$($Entry.DisplayVersion); Publisher=$($Entry.Publisher); RegistryPath=$($Entry.RegistryPath)"

                Add-Finding -TargetName $Target -Source "InstalledApp" -Name $Entry.DisplayName -Path $DetectedPath -Detail $Detail
            }
        }
    }
    catch {
        Add-Warning "Failed uninstall entry detection: $($_.Exception.Message)"
    }
}

function Test-Services {
    <#
    DESCRIPTION:
        Detects target software from Windows services.
    #>

    try {
        $Services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)

        foreach ($Service in $Services) {
            $Haystack = @(
                $Service.Name,
                $Service.DisplayName,
                $Service.PathName
            ) -join " "

            $Targets = @(Get-TargetMatches -Text $Haystack)

            foreach ($Target in $Targets) {
                $DetectedPath = Get-PathFromText -Text $Service.PathName
                $Name = "$($Service.DisplayName) [$($Service.Name)]"
                $Detail = "State=$($Service.State); StartMode=$($Service.StartMode); PathName=$($Service.PathName)"

                Add-Finding -TargetName $Target -Source "Service" -Name $Name -Path $DetectedPath -Detail $Detail
            }
        }
    }
    catch {
        Add-Warning "Failed service detection: $($_.Exception.Message)"
    }
}

function Test-Processes {
    <#
    DESCRIPTION:
        Detects running target processes by process name or executable path.
        Command line is intentionally not checked to avoid matching this script's own text.
    #>

    try {
        $Processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)

        foreach ($Process in $Processes) {
            if ($Process.ProcessId -eq $PID) {
                continue
            }

            $Haystack = @(
                $Process.Name,
                $Process.ExecutablePath
            ) -join " "

            $Targets = @(Get-TargetMatches -Text $Haystack)

            foreach ($Target in $Targets) {
                $Name = "$($Process.Name) PID=$($Process.ProcessId)"
                $Detail = "ExecutablePath=$($Process.ExecutablePath)"

                Add-Finding -TargetName $Target -Source "Process" -Name $Name -Path $Process.ExecutablePath -Detail $Detail
            }
        }
    }
    catch {
        Add-Warning "Failed process detection: $($_.Exception.Message)"
    }
}

function Test-ScheduledTasks {
    <#
    DESCRIPTION:
        Detects scheduled tasks referencing target software.
    #>

    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Write-Log "Get-ScheduledTask is unavailable on this system. Skipping scheduled task detection."
        return
    }

    try {
        $Tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)

        foreach ($Task in $Tasks) {
            $ActionText = ""

            try {
                $ActionText = @($Task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " "
            }
            catch {
                $ActionText = ""
            }

            $Haystack = @(
                $Task.TaskName,
                $Task.TaskPath,
                $ActionText
            ) -join " "

            $Targets = @(Get-TargetMatches -Text $Haystack)

            foreach ($Target in $Targets) {
                $FirstActionPath = $null

                try {
                    $FirstActionPath = @($Task.Actions | Select-Object -First 1).Execute
                }
                catch {
                    $FirstActionPath = $null
                }

                $Name = "$($Task.TaskPath)$($Task.TaskName)"
                $Detail = "Action=$ActionText"

                Add-Finding -TargetName $Target -Source "ScheduledTask" -Name $Name -Path $FirstActionPath -Detail $Detail
            }
        }
    }
    catch {
        Add-Warning "Failed scheduled task detection: $($_.Exception.Message)"
    }
}

function Test-RunEntries {
    <#
    DESCRIPTION:
        Detects Run and RunOnce registry startup entries referencing target software.
    #>

    $RunPaths = New-Object System.Collections.Generic.List[string]

    $RunPaths.Add("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") | Out-Null
    $RunPaths.Add("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce") | Out-Null
    $RunPaths.Add("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run") | Out-Null
    $RunPaths.Add("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce") | Out-Null

    try {
        $LoadedUserHives = @(Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$'
            })

        foreach ($Hive in $LoadedUserHives) {
            $RunPaths.Add("Registry::HKEY_USERS\$($Hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run") | Out-Null
            $RunPaths.Add("Registry::HKEY_USERS\$($Hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce") | Out-Null
        }
    }
    catch {
        Add-Warning "Failed to enumerate loaded user Run hives: $($_.Exception.Message)"
    }

    $SystemProps = @(
        "PSPath",
        "PSParentPath",
        "PSChildName",
        "PSDrive",
        "PSProvider"
    )

    foreach ($Path in $RunPaths) {
        try {
            if (-not (Test-Path -Path $Path)) {
                continue
            }

            $Item = Get-ItemProperty -Path $Path -ErrorAction Stop

            foreach ($Prop in $Item.PSObject.Properties) {
                if ($Prop.Name -in $SystemProps) {
                    continue
                }

                $ValueText = [string]$Prop.Value
                $Haystack = "$($Prop.Name) $ValueText"
                $Targets = @(Get-TargetMatches -Text $Haystack)

                foreach ($Target in $Targets) {
                    $DetectedPath = Get-PathFromText -Text $ValueText
                    $Name = "$($Prop.Name) in $Path"
                    $Detail = "Value=$ValueText"

                    Add-Finding -TargetName $Target -Source "StartupRunEntry" -Name $Name -Path $DetectedPath -Detail $Detail
                }
            }
        }
        catch {
            Add-Warning "Failed processing Run path $Path : $($_.Exception.Message)"
        }
    }
}

function Get-CommonArtifactRoots {
    <#
    DESCRIPTION:
        Builds common locations to check for target software directories.
    #>

    $Roots = New-Object System.Collections.Generic.List[string]

    $PossibleRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        "$env:SystemRoot\Temp",
        "$env:SystemDrive\Temp",
        "C:\MME",
        "C:\MME\CS"
    )

    foreach ($Root in $PossibleRoots) {
        if (-not [string]::IsNullOrWhiteSpace($Root) -and (Test-Path -LiteralPath $Root)) {
            $Roots.Add($Root) | Out-Null
        }
    }

    try {
        $UserDirs = @(Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -notin @("Default", "Default User", "Public", "All Users")
            })

        foreach ($UserDir in $UserDirs) {
            $UserRootCandidates = @(
                "$($UserDir.FullName)\Downloads",
                "$($UserDir.FullName)\Desktop",
                "$($UserDir.FullName)\AppData\Local",
                "$($UserDir.FullName)\AppData\Local\Programs",
                "$($UserDir.FullName)\AppData\Local\Temp",
                "$($UserDir.FullName)\AppData\Roaming"
            )

            foreach ($Candidate in $UserRootCandidates) {
                if (Test-Path -LiteralPath $Candidate) {
                    $Roots.Add($Candidate) | Out-Null
                }
            }
        }
    }
    catch {
        Add-Warning "Failed building user artifact roots: $($_.Exception.Message)"
    }

    return @($Roots | Sort-Object -Unique)
}

function Get-InstallerArtifactScanRoots {
    <#
    DESCRIPTION:
        Returns focused locations to scan recursively for target EXE/MSI artifacts.
    #>

    if ($ScanAllFixedDrivesForInstallerArtifacts) {
        try {
            $FixedDrives = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty DeviceID)

            return @($FixedDrives | ForEach-Object { "$_\" })
        }
        catch {
            Add-Warning "Failed to enumerate fixed drives. Falling back to focused artifact roots. $($_.Exception.Message)"
        }
    }

    $Roots = New-Object System.Collections.Generic.List[string]

    $PossibleRoots = @(
        "$env:SystemRoot\Temp",
        "$env:SystemDrive\Temp",
        "C:\MME",
        "C:\MME\CS"
    )

    foreach ($Root in $PossibleRoots) {
        if (-not [string]::IsNullOrWhiteSpace($Root) -and (Test-Path -LiteralPath $Root)) {
            $Roots.Add($Root) | Out-Null
        }
    }

    try {
        $UserDirs = @(Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -notin @("Default", "Default User", "Public", "All Users")
            })

        foreach ($UserDir in $UserDirs) {
            $UserRootCandidates = @(
                "$($UserDir.FullName)\Downloads",
                "$($UserDir.FullName)\Desktop",
                "$($UserDir.FullName)\AppData\Local\Temp"
            )

            foreach ($Candidate in $UserRootCandidates) {
                if (Test-Path -LiteralPath $Candidate) {
                    $Roots.Add($Candidate) | Out-Null
                }
            }
        }
    }
    catch {
        Add-Warning "Failed building installer artifact roots: $($_.Exception.Message)"
    }

    return @($Roots | Sort-Object -Unique)
}

function Test-Directories {
    <#
    DESCRIPTION:
        Detects common leftover target software directories.
    #>

    $Roots = @(Get-CommonArtifactRoots)

    foreach ($Root in $Roots) {
        try {
            $Items = @(Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction SilentlyContinue)

            foreach ($Item in $Items) {
                $Haystack = @(
                    $Item.Name,
                    $Item.FullName
                ) -join " "

                $Targets = @(Get-TargetMatches -Text $Haystack)

                foreach ($Target in $Targets) {
                    Add-Finding -TargetName $Target -Source "Directory" -Name $Item.Name -Path $Item.FullName -Detail "Directory found under artifact root $Root"
                }
            }
        }
        catch {
            Add-Warning "Failed searching directories under $Root : $($_.Exception.Message)"
        }
    }
}

function Test-InstallerArtifacts {
    <#
    DESCRIPTION:
        Detects target EXE/MSI installer or portable artifacts in focused artifact roots.
    #>

    $Roots = @(Get-InstallerArtifactScanRoots | Where-Object { Test-Path -LiteralPath $_ })
    $FoundFiles = @{}

    foreach ($Root in $Roots) {
        Write-Log "Scanning for target EXE/MSI artifacts under: $Root"

        foreach ($Filter in @("*.exe", "*.msi")) {
            try {
                $Files = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File -Filter $Filter -ErrorAction SilentlyContinue)

                foreach ($File in $Files) {
                    if ($File.FullName -match $ArtifactExcludePathRegex) {
                        continue
                    }

                    $Haystack = @(
                        $File.Name,
                        $File.FullName
                    ) -join " "

                    $Targets = @(Get-TargetMatches -Text $Haystack)

                    foreach ($Target in $Targets) {
                        $Key = "$Target|$($File.FullName.ToLowerInvariant())"

                        if (-not $FoundFiles.ContainsKey($Key)) {
                            $FoundFiles[$Key] = [PSCustomObject]@{
                                Target = $Target
                                File   = $File
                            }
                        }
                    }
                }
            }
            catch {
                Add-Warning "Artifact scan failed under $Root with filter $Filter : $($_.Exception.Message)"
            }
        }
    }

    foreach ($Entry in $FoundFiles.Values | Sort-Object { $_.Target }, { $_.File.FullName }) {
        Add-Finding -TargetName $Entry.Target -Source "InstallerArtifact" -Name $Entry.File.Name -Path $Entry.File.FullName -Detail "File artifact detected"
    }
}

function Get-DeduplicatedFindings {
    <#
    DESCRIPTION:
        Removes duplicate findings caused by overlapping detection surfaces.
    #>

    return @($script:Findings | Sort-Object TargetName, Source, Name, Path -Unique)
}

function Get-PresenceSummaryLines {
    <#
    DESCRIPTION:
        Builds the concise Name + Path summary used for both Ninja output and
        remoteSoftwarePresent. Full source/detail data remains in the log.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [array]$FinalFindings
    )

    if ($FinalFindings.Count -eq 0) {
        return @()
    }

    $KnownPathFindings = @(
        $FinalFindings |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.Path) -and
                $_.Path -ne "Unknown"
            }
    )

    $UnknownOnlyFindings = @(
        $FinalFindings |
            Where-Object {
                [string]::IsNullOrWhiteSpace($_.Path) -or
                $_.Path -eq "Unknown"
            }
    )

    $SummaryObjects = New-Object System.Collections.Generic.List[object]

    foreach ($Finding in $KnownPathFindings) {
        $NormalizedPath = $Finding.Path.Trim().TrimEnd([char]'\')

        $SummaryObjects.Add([PSCustomObject]@{
            TargetName = $Finding.TargetName.Trim()
            Path       = $NormalizedPath
        }) | Out-Null
    }

    $TargetsWithKnownPaths = @(
        $SummaryObjects |
            Select-Object -ExpandProperty TargetName -Unique
    )

    foreach ($Finding in $UnknownOnlyFindings) {
        if ($Finding.TargetName -in $TargetsWithKnownPaths) {
            continue
        }

        $SummaryObjects.Add([PSCustomObject]@{
            TargetName = $Finding.TargetName.Trim()
            Path       = "Unknown"
        }) | Out-Null
    }

    $Deduped = @(
        $SummaryObjects |
            Sort-Object TargetName, Path -Unique
    )

    $Pruned = New-Object System.Collections.Generic.List[object]

    foreach ($Item in $Deduped) {
        $IsChildOfExistingPath = $false

        foreach ($Other in $Deduped) {
            if ($Other.TargetName -ne $Item.TargetName) {
                continue
            }

            if ($Other.Path -eq $Item.Path) {
                continue
            }

            if ($Item.Path -eq "Unknown" -or $Other.Path -eq "Unknown") {
                continue
            }

            if ($Item.Path.StartsWith($Other.Path + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
                $IsChildOfExistingPath = $true
                break
            }
        }

        if (-not $IsChildOfExistingPath) {
            $Pruned.Add($Item) | Out-Null
        }
    }

    $Lines = @(
        $Pruned |
            Sort-Object TargetName, Path |
            ForEach-Object {
                "$($_.TargetName) | Path: $($_.Path)"
            }
    )

    if ($MaxPresenceSummaryCharacters -gt 0) {
        $CappedLines = New-Object System.Collections.Generic.List[string]
        $CurrentLength = 0
        $OmittedCount = 0

        foreach ($Line in $Lines) {
            $ProjectedLength = $CurrentLength + $Line.Length + 1

            if ($ProjectedLength -le $MaxPresenceSummaryCharacters) {
                $CappedLines.Add($Line) | Out-Null
                $CurrentLength = $ProjectedLength
            }
            else {
                $OmittedCount++
            }
        }

        if ($OmittedCount -gt 0) {
            $CappedLines.Add("Additional findings omitted from summary. Review log for full details.") | Out-Null
        }

        return @($CappedLines)
    }

    return @($Lines)
}

function Set-NinjaField {
    <#
    DESCRIPTION:
        Updates a Ninja custom field using the standard Ninja PowerShell cmdlet
        and detects non-terminating Ninja output errors.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    try {
        if (-not (Get-Command "Ninja-Property-Set" -ErrorAction SilentlyContinue)) {
            Add-Warning "Ninja-Property-Set is unavailable. Could not update '$Name'."
            return $false
        }

        $Output = (& Ninja-Property-Set $Name $Value 2>&1 | Out-String).Trim()

        if ($Output) {
            Write-Log "Ninja-Property-Set output for '$Name': $Output"
        }

        if ($Output -match '(?i)(unable to find the specified field|field.*not.*found|wrong value format|failed|error|exception|invalid)') {
            Add-Warning "Ninja-Property-Set reported failure while updating '$Name'. Output: $Output"
            return $false
        }

        Write-Log "Updated Ninja custom field '$Name'. Value length: $($Value.Length)"
        return $true
    }
    catch {
        Add-Warning "Failed to update Ninja custom field '$Name': $($_.Exception.Message)"
        return $false
    }
}

function Update-RemoteSoftwareFields {
    <#
    DESCRIPTION:
        Writes current detection state to remoteSoftwareDetected and current
        concise findings to remoteSoftwarePresent.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [array]$FinalFindings,

        [Parameter(Mandatory = $true)]
        [array]$PresenceSummaryLines
    )

    if ($FinalFindings.Count -gt 0) {
        $PresentValue = ($PresenceSummaryLines -join "`r`n").Trim()

        Write-Log "remoteSoftwarePresent summary line count: $($PresenceSummaryLines.Count)"
        Write-Log "remoteSoftwarePresent summary character count: $($PresentValue.Length)"

        $DetectedUpdated = Set-NinjaField -Name $DetectedFieldName -Value "Yes"
        $PresentUpdated  = Set-NinjaField -Name $PresentFieldName -Value $PresentValue

        return ($DetectedUpdated -and $PresentUpdated)
    }

    $DetectedUpdated = Set-NinjaField -Name $DetectedFieldName -Value "No"
    $PresentUpdated  = Set-NinjaField -Name $PresentFieldName -Value ""

    return ($DetectedUpdated -and $PresentUpdated)
}

function Finish {
    <#
    DESCRIPTION:
        Centralizes final Ninja output token and exit behavior.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [array]$PresenceSummaryLines = @()
    )

    foreach ($Line in $PresenceSummaryLines) {
        Write-Host $Line
    }

    Write-Log "$Token | $Message"
    Write-Host "$Token | $Message"
    exit 0
}

# =========================
# MAIN
# =========================

try {
    Initialize-Logging

    Write-Log "Starting targeted remote access software detection."

    Test-UninstallEntries
    Test-Services
    Test-Processes
    Test-ScheduledTasks
    Test-RunEntries
    Test-Directories
    Test-InstallerArtifacts

    $FinalFindings = @(Get-DeduplicatedFindings)
    $PresenceSummaryLines = @(Get-PresenceSummaryLines -FinalFindings $FinalFindings)

    Write-Log "Finding count after deduplication: $($FinalFindings.Count)"
    Write-Log "Warning count: $($Warnings.Count)"

    if ($FinalFindings.Count -gt 0) {
        Write-Log "Full findings summary:"
        foreach ($Finding in $FinalFindings) {
            Write-Log " - Target=$($Finding.TargetName); Source=$($Finding.Source); Name=$($Finding.Name); Path=$($Finding.Path); Detail=$($Finding.Detail)"
        }
    }

    if ($Warnings.Count -gt 0) {
        Write-Log "Warnings summary:"
        foreach ($Warning in $Warnings) {
            Write-Log -Level "WARN" -Message " - $Warning"
        }
    }

    $FieldsUpdated = Update-RemoteSoftwareFields -FinalFindings $FinalFindings -PresenceSummaryLines $PresenceSummaryLines

    if (-not $FieldsUpdated) {
        Finish -Token "ERROR" -Message "Unexpected script error occurred: failed to update one or more Ninja custom fields." -PresenceSummaryLines $PresenceSummaryLines
    }

    if ($FinalFindings.Count -gt 0) {
        $DetectedTargets = (($FinalFindings | Select-Object -ExpandProperty TargetName -Unique | Sort-Object) -join ", ")
        Finish -Token "TRIGGER" -Message "Targeted remote access software detected: $DetectedTargets" -PresenceSummaryLines $PresenceSummaryLines
    }

    Finish -Token "NO_ACTION" -Message "No targeted remote access software detected."
}
catch {
    $ErrorMessage = $_.Exception.Message

    try {
        Write-Log -Level "ERROR" -Message "Unexpected script error: $ErrorMessage"
    }
    catch {
        # Keep final output Ninja-safe.
    }

    Write-Host "ERROR | Unexpected script error occurred: $ErrorMessage"
    exit 0
}