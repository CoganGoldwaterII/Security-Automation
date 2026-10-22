# ============================================================================
# NAME: 1Password - Install Latest
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   RESULT    | Latest stable 1Password Desktop MSI installed and verified
#   NO_ACTION | Not emitted; remediation does not self-gate
#   ERROR     | Download, signature validation, installation, verification,
#               or remediation ledger update failed
#
# CUSTOM FIELDS:
#   Reads: remediationSummary
#   Writes: lastRemediationDate, remediationSummary
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   C:\MME\AutoLogs\1Password_Install_Latest.log
#   C:\MME\AutoLogs\1Password_Install_Latest_MSI.log
#
# DESCRIPTION:
#   Downloads the latest stable 1Password Windows MSI directly from the
#   official distribution URL to C:\MME\CS.
#
#   Retrieves the latest stable version from the official release page.
#   Validates the downloaded MSI using its Authenticode signature.
#   Silently installs the MSI using msiexec with /qn /norestart.
#
#   Accepts MSI exit codes 0, 1641, and 3010 as successful.
#   Reports whether a restart is required without explicitly rebooting.
#
#   Verifies the installed executable version is at least the latest
#   stable version reported by the release page.
#
#   Following successful verification:
#     - Updates lastRemediationDate with a UTC ISO 8601 timestamp.
#     - Appends a date-prefixed entry to remediationSummary.
#
#   Removes the downloaded MSI during cleanup.
#   Does not remove the MSI installation log.
#
#   Requires network access to the official 1Password release and
#   distribution endpoints.
#
#   Does not independently check whether remediation is necessary.
#   Intended to run after NinjaOne evaluation gating.
#   Always exits 0 and reports its result through output tokens.
# ============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ReleaseUrl = 'https://releases.1password.com/windows/stable/'
$InstallerUrl = 'https://c.1password.com/dist/1P/win8/1PasswordSetup-latest.msi'

$StageDirectory = 'C:\MME\CS'
$InstallerPath = Join-Path $StageDirectory '1PasswordSetup-latest.msi'

$LogDirectory = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogDirectory '1Password_Install_Latest.log'
$MsiLogPath = Join-Path $LogDirectory '1Password_Install_Latest_MSI.log'

$Stage = 'Initialize'
$FinalOutput = $null
$InstallerDownloaded = $false

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

function Get-Installed1PasswordVersion {
    $ExecutablePatterns = @()

    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $ExecutablePatterns += "$env:ProgramFiles\1Password\app\*\1Password.exe"
    }

    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $ExecutablePatterns += "${env:ProgramFiles(x86)}\1Password\app\*\1Password.exe"
    }

    $Versions = @()

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
                try {
                    $Versions += ConvertTo-NormalizedVersion -VersionText $VersionText
                }
                catch {
                }
            }
        }
    }

    if ($Versions.Count -eq 0) {
        return $null
    }

    return @($Versions | Sort-Object -Descending)[0]
}

function Update-RemediationLedger {
    param(
        [Parameter(Mandatory)]
        [string]$InstalledVersionText
    )

    if (-not (Get-Command -Name 'Ninja-Property-Set' -ErrorAction SilentlyContinue)) {
        throw 'Ninja-Property-Set is unavailable.'
    }

    if (-not (Get-Command -Name 'Ninja-Property-Get' -ErrorAction SilentlyContinue)) {
        throw 'Ninja-Property-Get is unavailable.'
    }

    $UtcTimestamp = (Get-Date).ToUniversalTime().ToString('o')
    $SummaryLine = '{0} | 1Password Desktop installed or updated to {1}.' -f
        (Get-Date -Format 'yyyy-MM-dd'),
        $InstalledVersionText

    $ExistingSummary = Ninja-Property-Get 'remediationSummary'
    $ExistingSummaryText = ([string]$ExistingSummary).Trim()

    if ([string]::IsNullOrWhiteSpace($ExistingSummaryText)) {
        $UpdatedSummary = $SummaryLine
    }
    else {
        $UpdatedSummary = "$ExistingSummaryText`r`n$SummaryLine"
    }

    Ninja-Property-Set 'lastRemediationDate' $UtcTimestamp
    Ninja-Property-Set 'remediationSummary' $UpdatedSummary
}

try {
    $Stage = 'Directories'

    foreach ($Directory in @($StageDirectory, $LogDirectory)) {
        if (-not (Test-Path -LiteralPath $Directory)) {
            New-Item -Path $Directory -ItemType Directory -Force | Out-Null
        }
    }

    Write-Log 'START | 1Password latest-version remediation'

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

    Write-Log "LATEST | Version=$LatestVersionText"

    $Stage = 'Download'

    if (Test-Path -LiteralPath $InstallerPath) {
        Remove-Item -LiteralPath $InstallerPath -Force
    }

    Invoke-WebRequest `
        -Uri $InstallerUrl `
        -OutFile $InstallerPath `
        -UseBasicParsing `
        -TimeoutSec 300

    $InstallerDownloaded = $true

    if (-not (Test-Path -LiteralPath $InstallerPath)) {
        throw 'The 1Password MSI was not downloaded.'
    }

    $InstallerFile = Get-Item -LiteralPath $InstallerPath

    if ($InstallerFile.Length -le 0) {
        throw 'The downloaded 1Password MSI is empty.'
    }

    Write-Log "DOWNLOAD | Bytes=$($InstallerFile.Length) Url=$InstallerUrl"

    $Stage = 'SignatureValidation'

    $Signature = Get-AuthenticodeSignature -FilePath $InstallerPath

    if ($Signature.Status -ne 'Valid') {
        throw "The downloaded 1Password MSI signature is not valid. Status=$($Signature.Status)"
    }

    Write-Log (
        'SIGNATURE | Status={0} Signer="{1}"' -f
            $Signature.Status,
            (ConvertTo-SafeOutput $Signature.SignerCertificate.Subject)
    )

    $Stage = 'Install'

    $MsiArguments = '/i "{0}" /qn /norestart /L*v "{1}"' -f
        $InstallerPath,
        $MsiLogPath

    $InstallProcess = Start-Process `
        -FilePath 'msiexec.exe' `
        -ArgumentList $MsiArguments `
        -Wait `
        -PassThru

    $InstallExitCode = $InstallProcess.ExitCode

    if ($InstallExitCode -notin @(0, 1641, 3010)) {
        throw "1Password MSI installation failed. ExitCode=$InstallExitCode"
    }

    $RestartRequired = $InstallExitCode -in @(1641, 3010)

    Write-Log "INSTALL | ExitCode=$InstallExitCode RestartRequired=$RestartRequired"

    $Stage = 'Verification'

    $InstalledVersion = $null

    for ($Attempt = 1; $Attempt -le 12; $Attempt++) {
        $InstalledVersion = Get-Installed1PasswordVersion

        if ($null -ne $InstalledVersion -and $InstalledVersion -ge $LatestVersion) {
            break
        }

        Start-Sleep -Seconds 5
    }

    if ($null -eq $InstalledVersion) {
        throw '1Password Desktop was not detected after installation.'
    }

    $InstalledVersionText = $InstalledVersion.ToString(3)

    if ($InstalledVersion -lt $LatestVersion) {
        throw "Installed version verification failed. Installed=$InstalledVersionText Latest=$LatestVersionText"
    }

    Write-Log "VERIFY | InstalledVersion=$InstalledVersionText LatestVersion=$LatestVersionText"

    $Stage = 'Ledger'

    Update-RemediationLedger -InstalledVersionText $InstalledVersionText

    Write-Log 'LEDGER | Updated=True'

    $FinalOutput =
        'RESULT | InstalledVersion={0} LatestVersion={1} RestartRequired={2}' -f
            $InstalledVersionText,
            $LatestVersionText,
            $RestartRequired
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
finally {
    if ($InstallerDownloaded -and (Test-Path -LiteralPath $InstallerPath)) {
        try {
            Remove-Item -LiteralPath $InstallerPath -Force
        }
        catch {
            if (Test-Path -LiteralPath $LogDirectory) {
                try {
                    Write-Log (
                        'CLEANUP_WARNING | File="{0}" Error="{1}"' -f
                            $InstallerPath,
                            (ConvertTo-SafeOutput $_.Exception.Message)
                    )
                }
                catch {
                }
            }
        }
    }
}

Write-Output $FinalOutput
exit 0