# ============================================================================
# NAME: ConnectWise Manage Client 64-bit - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   ExpectedName  = ConnectWise Manage Client 64-bit
#   InstallerPath = C:\MME\CS\ConnectWise-Manage-Internet-Client-x64.msi
#   LogRoot       = C:\MME\AutoLogs
# OUTPUT TOKENS:
#   REMEDIATION=COMPLETE     | Installation verified
#   PREREQ_CHECK=FAILED     | Required installer missing
#   INSTALL=FAILED_TO_START | MSI process could not start
#   INSTALL=FAILED          | MSI failed or application not detected
#   ERROR                   | Other remediation failure
#   NOTE: Does not emit standard RESULT / NO_ACTION tokens.
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: Yes
#   File: ConnectWise-Manage-Internet-Client-x64.msi
#   Destination: C:\MME\CS
# LOGGING PATH:
#   C:\MME\AutoLogs\ConnectWise_Manage_Client_64bit_Remediation.log
#   C:\MME\AutoLogs\ConnectWise_Manage_Client_64bit_MSI.log
# DESCRIPTION:
#   Installs the staged ConnectWise Manage Client 64-bit MSI silently.
#   Accepts MSI exit codes 0, 3010, and 1641.
#   Verifies installation using the exact application display name
#   in the Windows uninstall registry.
#   Updates NinjaOne remediation fields only when installation
#   completes with an accepted MSI exit code and the application
#   is detected afterward.
#   Maintains a date-only remediation ledger with line and
#   character limits.
#   Logs installation failures and exits 0 on all handled paths.
# ============================================================================

$ErrorActionPreference = 'Stop'

$ExpectedName  = 'ConnectWise Manage Client 64-bit'
$InstallerPath = 'C:\MME\CS\ConnectWise-Manage-Internet-Client-x64.msi'
$LogRoot       = 'C:\MME\AutoLogs'
$LogFile       = Join-Path $LogRoot 'ConnectWise_Manage_Client_64bit_Remediation.log'
$MsiLog        = Join-Path $LogRoot 'ConnectWise_Manage_Client_64bit_MSI.log'

$DidRemediate = $false

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-Log {
    param([string]$Message)

    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"
    Write-Output $Line
    Add-Content -Path $LogFile -Value $Line
}

function Get-InstalledApp {
    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($Path in $RegistryPaths) {
        Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -and $_.DisplayName -eq $ExpectedName
            } |
            Select-Object DisplayName, DisplayVersion, Publisher, PSChildName
    }
}

function Set-NinjaField {
    param(
        [string]$Name,
        [string]$Value
    )

    if (Get-Command 'Ninja-Property-Set' -ErrorAction SilentlyContinue) {
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

    if (Get-Command 'Ninja-Property-Get' -ErrorAction SilentlyContinue) {
        try {
            return (Ninja-Property-Get $Name)
        }
        catch {
            Write-Log "NINJA_FIELD_GET_FAILED | $Name | $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "NINJA_FIELD_GET_SKIPPED | $Name"
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

    if ($Lines.Count -gt 60) {
        $Lines = $Lines[-60..-1]
    }

    $Joined = $Lines -join "`r`n"

    while ($Joined.Length -gt 4000 -and $Lines.Count -gt 1) {
        $Lines = $Lines[1..($Lines.Count - 1)]
        $Joined = $Lines -join "`r`n"
    }

    Set-NinjaField 'lastRemediationDate' $IsoStamp
    Set-NinjaField 'remediationSummary'  $Joined
}

function Finish {
    param([string]$Message)

    if ($DidRemediate -and $Message -eq 'REMEDIATION=COMPLETE') {
        Update-RemediationLedger 'ConnectWise Manage Client Installed'
    }

    Write-Log $Message
    Write-Log 'SCRIPT=COMPLETE'
    exit 0
}

try {
    Ensure-Directory -Path $LogRoot

    Write-Log '===== ConnectWise Manage Client Remediation START ====='
    Write-Log "EXPECTED_NAME=$ExpectedName"
    Write-Log "INSTALLER_PATH=$InstallerPath"
    Write-Log "MSI_LOG=$MsiLog"

    if (-not (Test-Path -LiteralPath $InstallerPath)) {
        Finish "PREREQ_CHECK=FAILED | Installer not found: $InstallerPath"
    }

    if (Test-Path -LiteralPath $MsiLog) {
        Remove-Item -LiteralPath $MsiLog -Force -ErrorAction SilentlyContinue
    }

    $Arguments = @(
        '/i',
        "`"$InstallerPath`"",
        '/qn',
        '/norestart',
        '/l*v',
        "`"$MsiLog`""
    )

    Write-Log 'INSTALL=STARTING'

    try {
        $Proc = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    }
    catch {
        Finish "INSTALL=FAILED_TO_START | $($_.Exception.Message)"
    }

    Write-Log "MSI_EXIT_CODE=$($Proc.ExitCode)"

    if ($Proc.ExitCode -notin @(0, 3010, 1641)) {
        Finish "INSTALL=FAILED | ExitCode=$($Proc.ExitCode)"
    }

    Start-Sleep -Seconds 2

    $Installed = @(Get-InstalledApp)

    if (-not $Installed) {
        Finish "INSTALL=FAILED | $ExpectedName not detected after install"
    }

    $DidRemediate = $true

    if ($Proc.ExitCode -eq 3010) {
        Write-Log 'INSTALL=SUCCESS_REBOOT_REQUIRED'
    }
    elseif ($Proc.ExitCode -eq 1641) {
        Write-Log 'INSTALL=SUCCESS_REBOOT_INITIATED'
    }
    else {
        Write-Log 'INSTALL=SUCCESS'
    }

    Finish 'REMEDIATION=COMPLETE'
}
catch {
    Finish "ERROR | $($_.Exception.Message)"
}