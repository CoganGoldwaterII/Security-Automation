# ============================================================================
# NAME: AuthPoint Gateway - Update
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   RequiredVersion = 7.5.1.834
#   InstallerPath   = C:\MME\CS\AuthPoint_Gateway-7.5.1-834.msi
# OUTPUT TOKENS:
#   RESULT    | AuthPoint Gateway remediation complete
#   ERROR     | AuthPoint Gateway remediation failed
#   NO_ACTION | Not emitted
# CUSTOM FIELDS:
#   Reads: remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: Yes
#   File: AuthPoint_Gateway-7.5.1-834.msi
#   Destination: C:\MME\CS
# LOGGING PATH:
#   C:\MME\AutoLogs\AuthPointGateway_Remediation.log
#   C:\MME\AutoLogs\AuthPointGateway_MSI.log
# DESCRIPTION:
#   Deterministic remediation for the WatchGuard AuthPoint Gateway.
#   Runs the staged MSI without independently gating on installed version.
#   Passes the existing Gateway version as CURRENT_VERSION when available
#   to support the WatchGuard upgrade migration path.
#   Suppresses automatic reboot, accepts MSI exit codes 0 and 3010,
#   and verifies the installed version against the required baseline.
#   Updates the NinjaOne remediation ledger after successful installation.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = 'Stop'

$LogRoot         = 'C:\MME\AutoLogs'
$CacheRoot       = 'C:\MME\CS'
$LogFile         = Join-Path $LogRoot 'AuthPointGateway_Remediation.log'
$MsiLog          = Join-Path $LogRoot 'AuthPointGateway_MSI.log'

$AppName         = 'WatchGuard AuthPoint Gateway'
$RequiredVersion = [version]'7.5.1.834'
$InstallerName   = 'AuthPoint_Gateway-7.5.1-834.msi'
$InstallerPath   = Join-Path $CacheRoot $InstallerName

if (-not (Test-Path -LiteralPath $LogRoot)) {
    New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message)

    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"
    Write-Output $Line
    Add-Content -Path $LogFile -Value $Line
}

function Set-NinjaField {
    param(
        [string]$Name,
        [string]$Value
    )

    if (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue) {
        try {
            Ninja-Property-Set $Name $Value
        }
        catch {
            Write-Log "NINJA_FIELD_SET_FAILED | $Name | $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "NINJA_FIELD_SET_SKIPPED | $Name"
    }
}

function Get-NinjaField {
    param([string]$Name)

    if (Get-Command Ninja-Property-Get -ErrorAction SilentlyContinue) {
        try {
            return (Ninja-Property-Get $Name)
        }
        catch {
            Write-Log "NINJA_FIELD_GET_FAILED | $Name | $($_.Exception.Message)"
        }
    }

    return $null
}

function Update-RemediationLedger {
    param([string]$Message)

    $DateOnly = Get-Date -Format 'yyyy-MM-dd'
    $IsoStamp = (Get-Date).ToString('o')
    $NewLine  = "$DateOnly | $Message"

    $Existing = Get-NinjaField 'remediationSummary'
    $Lines = @()

    if (-not [string]::IsNullOrWhiteSpace($Existing)) {
        $Lines = ($Existing -split "(`r`n|`n|`r)") |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    $Lines += $NewLine
    $Lines = $Lines | Select-Object -Unique

    if ($Lines.Count -gt 60) {
        $Lines = $Lines[-60..-1]
    }

    $Joined = $Lines -join "`r`n"

    while ($Joined.Length -gt 4000 -and $Lines.Count -gt 1) {
        $Lines = $Lines[1..($Lines.Count - 1)]
        $Joined = $Lines -join "`r`n"
    }

    Set-NinjaField 'lastRemediationDate' $IsoStamp
    Set-NinjaField 'remediationSummary' $Joined
}

function Get-InstalledApp {
    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    Get-ItemProperty -Path $RegistryPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $AppName } |
        Select-Object -First 1
}

function Write-Result {
    param(
        [ValidateSet('RESULT','NO_ACTION','ERROR')]
        [string]$Token,

        [string]$Message
    )

    $ResultLine = "$Token | $Message"
    Write-Log $ResultLine
    Write-Output $ResultLine
}

$ResultToken   = $null
$ResultMessage = $null

try {
    Write-Log '===== AuthPoint Gateway Remediation START ====='
    Write-Log "INSTALLER=$InstallerPath"
    Write-Log "REQUIRED_VERSION=$RequiredVersion"
    Write-Log "MSI_LOG=$MsiLog"

    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        throw "Installer not found: $InstallerPath"
    }

    $PreApp                = Get-InstalledApp
    $PreVersion            = $null
    $CurrentVersionForMsi  = $null

    if ($PreApp) {
        $RawPreVersion = [string]$PreApp.DisplayVersion

        if (-not [string]::IsNullOrWhiteSpace($RawPreVersion)) {
            $CurrentVersionForMsi = $RawPreVersion.Trim()

            try {
                $PreVersion = [version]$CurrentVersionForMsi
                Write-Log "PRE_VERSION=$PreVersion"
            }
            catch {
                Write-Log "PRE_VERSION=UNREADABLE | Raw=$CurrentVersionForMsi"
            }

            Write-Log "MSI_CURRENT_VERSION=$CurrentVersionForMsi"
        }
        else {
            Write-Log 'PRE_VERSION=UNREADABLE | Raw=<empty>'
            Write-Log 'MSI_CURRENT_VERSION=NOT_SUPPLIED'
        }
    }
    else {
        Write-Log 'PRE_VERSION=NOT_INSTALLED'
        Write-Log 'MSI_CURRENT_VERSION=NOT_SUPPLIED'
    }

    Write-Log 'INSTALL=STARTING'

    $Arguments = @(
        '/i'
        "`"$InstallerPath`""
        '/qn'
        '/norestart'
        'REBOOT=ReallySuppress'
    )

    if (-not [string]::IsNullOrWhiteSpace($CurrentVersionForMsi)) {
        $Arguments += "CURRENT_VERSION=$CurrentVersionForMsi"
    }

    $Arguments += @(
        '/l*v'
        "`"$MsiLog`""
    )

    $Process = Start-Process `
        -FilePath 'msiexec.exe' `
        -ArgumentList $Arguments `
        -Wait `
        -PassThru `
        -ErrorAction Stop

    Write-Log "MSI_EXIT_CODE=$($Process.ExitCode)"

    switch ($Process.ExitCode) {
        0 {
            Write-Log 'INSTALL=SUCCESS'
        }

        3010 {
            Write-Log 'INSTALL=SUCCESS_REBOOT_REQUIRED_NOT_INITIATED'
        }

        1641 {
            throw 'Installer reported reboot initiated despite reboot suppression.'
        }

        default {
            throw "MSI install failed with exit code $($Process.ExitCode)."
        }
    }

    Start-Sleep -Seconds 3

    $PostApp = Get-InstalledApp

    if (-not $PostApp) {
        throw "Install completed but '$AppName' was not detected afterward."
    }

    try {
        $PostVersion = [version]$PostApp.DisplayVersion
    }
    catch {
        throw "Installed application detected but DisplayVersion '$($PostApp.DisplayVersion)' could not be parsed."
    }

    Write-Log "POST_VERSION=$PostVersion"

    if ($PostVersion -lt $RequiredVersion) {
        throw "Post-install version $PostVersion is below required version $RequiredVersion."
    }

    Update-RemediationLedger "AuthPoint Gateway updated to $PostVersion"

    $FromVersion = if ($PreVersion) {
        $PreVersion.ToString()
    }
    elseif ($CurrentVersionForMsi) {
        $CurrentVersionForMsi
    }
    else {
        'NotInstalled'
    }

    $ResultToken   = 'RESULT'
    $ResultMessage = "AuthPoint Gateway remediation complete | From=$FromVersion To=$PostVersion"
}
catch {
    $ResultToken   = 'ERROR'
    $ResultMessage = "AuthPoint Gateway remediation failed | $($_.Exception.Message)"
}

Write-Result -Token $ResultToken -Message $ResultMessage
exit 0