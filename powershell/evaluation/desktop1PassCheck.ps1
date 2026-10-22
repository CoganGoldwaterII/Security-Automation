# ============================================================================
# NAME: 1Password Installation/Versioning
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   TRIGGER   | Installed 1Password Desktop is older than the latest stable version
#   NO_ACTION | 1Password Desktop is current or is not installed
#   ERROR     | Latest stable version could not be retrieved or evaluated
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
#   C:\MME\AutoLogs\1Password_Installation_Versioning.log
#
# DESCRIPTION:
#   Reads the latest stable Windows version from the official 1Password release
#   page, detects installed desktop-client versions, and triggers when any
#   detected installation is older than the latest stable version.
#
#   Checks application executables, AppX packages, and uninstall registry
#   entries. Uses executable results first, then AppX, then registry records.
#
#   Requires access to the official 1Password Windows stable-release page.
#   Makes no application changes and always exits 0.
# ============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ReleaseUrl = 'https://releases.1password.com/windows/stable/'
$LogDirectory = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogDirectory '1Password_Installation_Versioning.log'

$Stage = 'Initialize'
$FinalOutput = $null

function ConvertTo-SafeOutput {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return (([string]$Value) -replace '[\r\n|]+', ' ').Trim()
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -LiteralPath $LogPath -Value "$Timestamp | $Message" -Encoding UTF8
}

function ConvertTo-NormalizedVersion {
    param(
        [Parameter(Mandatory)]
        [string]$VersionText
    )

    $VersionMatch = [regex]::Match(
        $VersionText,
        '(?<!\d)(\d+(?:\.\d+){1,3})(?![\d.-])'
    )

    if (-not $VersionMatch.Success) {
        throw "No usable version was found in '$VersionText'."
    }

    $Parts = @($VersionMatch.Groups[1].Value -split '\.')

    while ($Parts.Count -lt 4) {
        $Parts += '0'
    }

    return [version]($Parts -join '.')
}

function Get-InstallRecord {
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Location,

        [Parameter(Mandatory)]
        [string]$VersionText
    )

    try {
        $Version = ConvertTo-NormalizedVersion -VersionText $VersionText

        return [PSCustomObject]@{
            Source = $Source
            Location = $Location
            Version = $Version
        }
    }
    catch {
        Write-Log (
            'DETECTION_WARNING | Source={0} Location="{1}" Version="{2}" Error="{3}"' -f
                $Source,
                (ConvertTo-SafeOutput $Location),
                (ConvertTo-SafeOutput $VersionText),
                (ConvertTo-SafeOutput $_.Exception.Message)
        )

        return $null
    }
}

try {
    $Stage = 'Logging'

    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    Write-Log 'START | 1Password installation/version evaluation'

    $Stage = 'LatestVersion'

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $ReleaseResponse = Invoke-WebRequest `
        -Uri $ReleaseUrl `
        -UseBasicParsing `
        -TimeoutSec 30

    if ([string]::IsNullOrWhiteSpace($ReleaseResponse.Content)) {
        throw 'The official 1Password release page returned no content.'
    }

    $LatestMatch = [regex]::Match(
        $ReleaseResponse.Content,
        'Updated\s+to\s+(\d+(?:\.\d+){2,3})\s+on',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if (-not $LatestMatch.Success) {
        throw 'The latest stable Windows version was not found on the official 1Password release page.'
    }

    $LatestVersionText = $LatestMatch.Groups[1].Value
    $LatestVersion = ConvertTo-NormalizedVersion -VersionText $LatestVersionText

    Write-Log "LATEST | Version=$LatestVersionText Url=$ReleaseUrl"

    $Stage = 'InstalledVersion'

    $ExecutableInstalls = @()
    $AppxInstalls = @()
    $RegistryInstalls = @()
    $ExecutablePatterns = @()

    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $ExecutablePatterns += "$env:ProgramFiles\1Password\app\*\1Password.exe"
    }

    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $ExecutablePatterns += "${env:ProgramFiles(x86)}\1Password\app\*\1Password.exe"
    }

    if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
        $ExecutablePatterns += "$env:SystemDrive\Users\*\AppData\Local\1Password\app\*\1Password.exe"
    }

    foreach ($ExecutablePattern in $ExecutablePatterns) {
        $ExecutableFiles = @(
            Get-Item -Path $ExecutablePattern -ErrorAction SilentlyContinue
        )

        foreach ($ExecutableFile in $ExecutableFiles) {
            $VersionText = $ExecutableFile.VersionInfo.ProductVersion

            if ([string]::IsNullOrWhiteSpace($VersionText)) {
                $VersionText = $ExecutableFile.VersionInfo.FileVersion
            }

            if (-not [string]::IsNullOrWhiteSpace($VersionText)) {
                $Record = Get-InstallRecord `
                    -Source 'Executable' `
                    -Location $ExecutableFile.FullName `
                    -VersionText $VersionText

                if ($null -ne $Record) {
                    $ExecutableInstalls += $Record
                }
            }
        }
    }

    if (Get-Command -Name 'Get-AppxPackage' -ErrorAction SilentlyContinue) {
        try {
            $AppxPackages = @(
                Get-AppxPackage -AllUsers -ErrorAction Stop |
                    Where-Object { $_.Name -match '(?i)1Password' }
            )

            foreach ($AppxPackage in $AppxPackages) {
                $Record = Get-InstallRecord `
                    -Source 'AppX' `
                    -Location $AppxPackage.PackageFullName `
                    -VersionText ([string]$AppxPackage.Version)

                if ($null -ne $Record) {
                    $AppxInstalls += $Record
                }
            }
        }
        catch {
            Write-Log (
                'DETECTION_WARNING | Source=AppX Error="{0}"' -f
                    (ConvertTo-SafeOutput $_.Exception.Message)
            )
        }
    }

    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($RegistryPath in $RegistryPaths) {
        $RegistryEntries = @(
            Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.DisplayName -match '(?i)^1Password(?:\s+for\s+Windows)?$' -and
                    -not [string]::IsNullOrWhiteSpace($_.DisplayVersion)
                }
        )

        foreach ($RegistryEntry in $RegistryEntries) {
            $Record = Get-InstallRecord `
                -Source 'Registry' `
                -Location $RegistryEntry.PSPath `
                -VersionText ([string]$RegistryEntry.DisplayVersion)

            if ($null -ne $Record) {
                $RegistryInstalls += $Record
            }
        }
    }

    if ($ExecutableInstalls.Count -gt 0) {
        $DetectedInstalls = @($ExecutableInstalls)
    }
    elseif ($AppxInstalls.Count -gt 0) {
        $DetectedInstalls = @($AppxInstalls)
    }
    else {
        $DetectedInstalls = @($RegistryInstalls)
    }

    if ($DetectedInstalls.Count -eq 0) {
        Write-Log "RESULT | Installed=False LatestVersion=$LatestVersionText"
        $FinalOutput = "NO_ACTION | Installed=False LatestVersion=$LatestVersionText"
    }
    else {
        $DetectedInstalls = @(
            $DetectedInstalls |
                Sort-Object Source, Location, Version -Unique
        )

        $InstalledVersionText = @(
            $DetectedInstalls |
                ForEach-Object { $_.Version.ToString(3) } |
                Sort-Object -Unique
        ) -join ','

        $OutdatedInstalls = @(
            $DetectedInstalls |
                Where-Object { $_.Version -lt $LatestVersion }
        )

        foreach ($DetectedInstall in $DetectedInstalls) {
            Write-Log (
                'DETECTED | Source={0} Version={1} Location="{2}"' -f
                    $DetectedInstall.Source,
                    $DetectedInstall.Version.ToString(3),
                    (ConvertTo-SafeOutput $DetectedInstall.Location)
            )
        }

        if ($OutdatedInstalls.Count -gt 0) {
            Write-Log (
                'RESULT | Installed=True Outdated=True InstalledVersions={0} LatestVersion={1}' -f
                    $InstalledVersionText,
                    $LatestVersionText
            )

            $FinalOutput =
                'TRIGGER | Installed=True InstalledVersions={0} LatestVersion={1}' -f
                    $InstalledVersionText,
                    $LatestVersionText
        }
        else {
            Write-Log (
                'RESULT | Installed=True Outdated=False InstalledVersions={0} LatestVersion={1}' -f
                    $InstalledVersionText,
                    $LatestVersionText
            )

            $FinalOutput =
                'NO_ACTION | Installed=True InstalledVersions={0} LatestVersion={1}' -f
                    $InstalledVersionText,
                    $LatestVersionText
        }
    }
}
catch {
    $SafeError = ConvertTo-SafeOutput $_.Exception.Message

    if (Test-Path -LiteralPath $LogDirectory) {
        try {
            Write-Log (
                'ERROR | Stage={0} Error="{1}"' -f
                    $Stage,
                    $SafeError
            )
        }
        catch {
        }
    }

    $FinalOutput =
        'ERROR | Stage={0} Error="{1}"' -f
            $Stage,
            $SafeError
}

Write-Output $FinalOutput
exit 0