# ============================================================================
# NAME: AuthPoint Gateway + Corretto - Version Check
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   RequiredGatewayVersion = 7.5.1.834
#   RequiredCorrettoMajor  = 17
# OUTPUT TOKENS:
#   TRIGGER   | Gateway outdated and/or required Corretto major absent
#   NO_ACTION | Installed components meet requirements or are not found
#   ERROR     | Evaluation or version parsing failure
# ROUTING MARKERS:
#   CORRETTO_TRIGGER | Corretto installed but version 17 absent
#   GATEWAY_TICKET  | AuthPoint Gateway installed but outdated
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\AuthPointGateway_Corretto_Eval.log
# DESCRIPTION:
#   Evaluates installed WatchGuard AuthPoint Gateway and Amazon Corretto
#   versions using Windows uninstall registry entries.
#   Flags Gateway installations older than 7.5.1.834 and Corretto
#   installations missing major version 17.
#   Emits distinct routing markers for Gateway ticketing and Corretto
#   remediation. Missing applications do not independently trigger.
#   Produces one final NinjaOne output line and always exits 0.
# ============================================================================

$ErrorActionPreference = 'Stop'

$LogRoot                = 'C:\MME\AutoLogs'
$LogFile                = Join-Path $LogRoot 'AuthPointGateway_Corretto_Eval.log'

$GatewayAppName         = 'WatchGuard AuthPoint Gateway'
$RequiredGatewayVersion = [version]'7.5.1.834'
$RequiredCorrettoMajor  = 17

if (-not (Test-Path -LiteralPath $LogRoot)) {
    New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message)

    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"
    Add-Content -Path $LogFile -Value $Line
}

function Get-UninstallEntries {
    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    Get-ItemProperty -Path $RegistryPaths -ErrorAction SilentlyContinue
}

function Get-GatewayApp {
    param([array]$Entries)

    $Entries |
        Where-Object { $_.DisplayName -eq $GatewayAppName } |
        Select-Object -First 1
}

function Get-CorrettoInfo {
    param([array]$Entries)

    $CorrettoEntries = @(
        $Entries |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_.DisplayName) -and
                $_.DisplayName -match '(?i)\bCorretto\b'
            }
    )

    if ($CorrettoEntries.Count -eq 0) {
        return $null
    }

    $Parsed = @(
        foreach ($Entry in $CorrettoEntries) {
            $RawVersion   = [string]$Entry.DisplayVersion
            $VersionMatch = [regex]::Match($RawVersion, '^\s*(\d+)')

            if ($VersionMatch.Success) {
                [pscustomobject]@{
                    DisplayName    = [string]$Entry.DisplayName
                    DisplayVersion = $RawVersion.Trim()
                    Major          = [int]$VersionMatch.Groups[1].Value
                }
            }
        }
    )

    if ($Parsed.Count -eq 0) {
        throw 'Corretto detected but installed version could not be parsed.'
    }

    $Required = $Parsed |
        Where-Object { $_.Major -eq $RequiredCorrettoMajor } |
        Select-Object -First 1

    [pscustomobject]@{
        RequiredPresent   = [bool]$Required
        RequiredVersion   = if ($Required) { $Required.DisplayVersion } else { $null }
        InstalledVersions = @(
            $Parsed.DisplayVersion |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )
    }
}

$ResultToken   = $null
$ResultMessage = $null

try {
    Write-Log '===== AuthPoint Gateway + Corretto Evaluation START ====='
    Write-Log "REQUIRED_GATEWAY_VERSION=$RequiredGatewayVersion"
    Write-Log "REQUIRED_CORRETTO_MAJOR=$RequiredCorrettoMajor"

    $Entries = @(Get-UninstallEntries)

    # ------------------------------------------------------------------------
    # Gateway
    # ------------------------------------------------------------------------
    $GatewayApp     = Get-GatewayApp -Entries $Entries
    $GatewayStatus  = 'NotFound'
    $GatewayTrigger = $false

    if ($GatewayApp) {
        $RawGatewayVersion = [string]$GatewayApp.DisplayVersion

        try {
            $GatewayVersion = [version]$RawGatewayVersion
        }
        catch {
            throw "Gateway detected but DisplayVersion '$RawGatewayVersion' could not be parsed."
        }

        $GatewayStatus  = $GatewayVersion.ToString()
        $GatewayTrigger = ($GatewayVersion -lt $RequiredGatewayVersion)

        Write-Log "GATEWAY_VERSION=$GatewayStatus"
        Write-Log "GATEWAY_TICKET=$GatewayTrigger"
    }
    else {
        Write-Log 'GATEWAY_VERSION=NOT_FOUND'
    }

    # ------------------------------------------------------------------------
    # Corretto
    # ------------------------------------------------------------------------
    $CorrettoInfo    = Get-CorrettoInfo -Entries $Entries
    $CorrettoStatus  = 'NotFound'
    $CorrettoTrigger = $false

    if ($CorrettoInfo) {
        $InstalledCorrettoVersions = $CorrettoInfo.InstalledVersions -join ','

        if ($CorrettoInfo.RequiredPresent) {
            $CorrettoStatus = $CorrettoInfo.RequiredVersion
        }
        else {
            $CorrettoStatus  = $InstalledCorrettoVersions
            $CorrettoTrigger = $true
        }

        Write-Log "CORRETTO_VERSIONS=$InstalledCorrettoVersions"
        Write-Log "CORRETTO_17_PRESENT=$($CorrettoInfo.RequiredPresent)"
        Write-Log "CORRETTO_TRIGGER=$CorrettoTrigger"
    }
    else {
        Write-Log 'CORRETTO_VERSION=NOT_FOUND'
    }

    # ------------------------------------------------------------------------
    # Minimal Ninja output / routing
    # ------------------------------------------------------------------------
    $Markers = @()

    if ($CorrettoTrigger) {
        $Markers += 'CORRETTO_TRIGGER'
    }

    if ($GatewayTrigger) {
        $Markers += 'GATEWAY_TICKET'
    }

    if ($Markers.Count -gt 0) {
        $ResultToken = 'TRIGGER'

        $Parts = @($ResultToken) + $Markers
        $ResultMessage = (($Parts -join ' | ') +
            " | Gateway=$GatewayStatus Corretto=$CorrettoStatus")
    }
    else {
        $ResultToken   = 'NO_ACTION'
        $ResultMessage = "NO_ACTION | Gateway=$GatewayStatus Corretto=$CorrettoStatus"
    }
}
catch {
    Write-Log "ERROR=$($_.Exception.Message)"
    $ResultToken   = 'ERROR'
    $ResultMessage = "ERROR | $($_.Exception.Message)"
}

Write-Log $ResultMessage
Write-Output $ResultMessage
exit 0