# ============================================================================
# NAME: CVE-2026-41089 Netlogon Evaluation
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows Server Domain Controllers / NinjaOne automation
# VARIABLES:
#   Required: None
#   Optional: None
# OUTPUT TOKENS:
#   TRIGGER   | CVE-2026-41089 patch level missing or requires verification
#   NO_ACTION | Not applicable or patched
#   ERROR     | Unexpected script error occurred
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\CVE_2026_41089_Eval.log
# DESCRIPTION:
#   Evaluates Windows domain controllers for CVE-2026-41089 Netlogon
#   patch compliance.
#
#   Identifies domain controllers using Windows ProductType and
#   ComputerSystem DomainRole.
#
#   Evaluates Windows Server 2012 through Windows Server 2025 against
#   verified May 2026 security update build thresholds.
#
#   Windows Server 2022 and 2025 support separate cumulative-update
#   and hotpatch build thresholds.
#
#   Installed KB identifiers provide supplemental evidence.
#   If a matching KB is reported but the current build does not meet
#   an applicable threshold, Windows servicing restart indicators
#   are checked and the endpoint is flagged for verification.
#
#   Unknown server builds are flagged for manual verification.
#   No updates, reboots, or other remediation actions are performed.
#
#   All results use TRIGGER, NO_ACTION, or ERROR with exit code 0.
# ============================================================================

$ErrorActionPreference = 'Stop'

# ============================================================================
# CONFIGURATION
# ============================================================================

$LogPath = 'C:\MME\AutoLogs\CVE_2026_41089_Eval.log'
$LogDir = Split-Path -Path $LogPath -Parent

# ============================================================================
# LOGGING
# ============================================================================

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    try {
        $Stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -LiteralPath $LogPath -Value "$Stamp | $Message" -ErrorAction Stop
    }
    catch {
        # Logging must not prevent a NinjaOne result from being emitted.
    }
}

function Finish {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('TRIGGER', 'NO_ACTION', 'ERROR')]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Result = "$Token | $Message"

    Write-Log $Result
    Write-Output $Result

    exit 0
}

# ============================================================================
# INSTALLED HOTFIX DISCOVERY
# ============================================================================

function Get-InstalledHotFixIds {
    try {
        $HotFixIds = @(
            Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop |
                Where-Object { $_.HotFixID } |
                ForEach-Object { $_.HotFixID.ToUpperInvariant() }
        )

        Write-Log "Installed hotfix identifiers retrieved: $($HotFixIds.Count)"

        return $HotFixIds
    }
    catch {
        Write-Log "WARN | Failed to read Win32_QuickFixEngineering: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# OPERATING SYSTEM BUILD DISCOVERY
# ============================================================================

function Get-DetectedOsBuild {
    param (
        [Parameter(Mandatory = $true)]
        [object]$OperatingSystem
    )

    $CurrentVersionPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $CurrentVersion = Get-ItemProperty -Path $CurrentVersionPath -ErrorAction Stop

    $OsVersion = [version]$OperatingSystem.Version

    $Major = $OsVersion.Major
    $Minor = $OsVersion.Minor

    $BuildText = $CurrentVersion.CurrentBuildNumber

    if ([string]::IsNullOrWhiteSpace($BuildText)) {
        $BuildText = $CurrentVersion.CurrentBuild
    }

    if ([string]::IsNullOrWhiteSpace($BuildText)) {
        $Build = $OsVersion.Build
    }
    else {
        $Build = [int]$BuildText
    }

    $Revision = $null

    if ($null -ne $CurrentVersion.UBR) {
        $Revision = [int]$CurrentVersion.UBR
        Write-Log "Build revision source: UBR"
    }

    if (
        $null -eq $Revision -and
        $CurrentVersion.BuildLabEx -match '^\d+\.(\d+)'
    ) {
        $Revision = [int]$Matches[1]
        Write-Log "Build revision source: BuildLabEx (fallback)"
    }

    if ($null -eq $Revision) {
        $Revision = 0
        Write-Log "WARN | Build revision unavailable. Defaulting to 0."
    }

    return [version]"$Major.$Minor.$Build.$Revision"
}

# ============================================================================
# WINDOWS SERVICING RESTART STATE
# ============================================================================

function Get-PendingServicingRebootState {
    $Indicators = New-Object System.Collections.Generic.List[string]
    $QueryErrors = New-Object System.Collections.Generic.List[string]

    $RebootPaths = @(
        @{
            Name = 'CBS_RebootPending'
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        },
        @{
            Name = 'WindowsUpdate_RebootRequired'
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        }
    )

    foreach ($Entry in $RebootPaths) {
        try {
            if (Test-Path -LiteralPath $Entry.Path -ErrorAction Stop) {
                [void]$Indicators.Add($Entry.Name)
            }
        }
        catch {
            [void]$QueryErrors.Add(
                "$($Entry.Name): $($_.Exception.Message)"
            )
        }
    }

    $Pending = ($Indicators.Count -gt 0)

    Write-Log "ServicingRebootPending=$Pending"

    if ($Indicators.Count -gt 0) {
        Write-Log "ServicingRebootIndicators=$($Indicators -join ', ')"
    }

    if ($QueryErrors.Count -gt 0) {
        Write-Log "WARN | Servicing reboot query errors: $($QueryErrors -join ' | ')"
    }

    return [PSCustomObject]@{
        IsPending   = $Pending
        Indicators  = @($Indicators.ToArray())
        QueryErrors = @($QueryErrors.ToArray())
    }
}

# ============================================================================
# MAIN EVALUATION
# ============================================================================

try {
    New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction Stop |
        Out-Null

    Write-Log '============================================================'
    Write-Log 'START | CVE-2026-41089 Netlogon evaluation'
    Write-Log "Computer=$env:COMPUTERNAME"

    # ------------------------------------------------------------------------
    # Operating system and domain controller identification
    # ------------------------------------------------------------------------

    $OperatingSystem = Get-CimInstance `
        -ClassName Win32_OperatingSystem `
        -ErrorAction Stop

    $ComputerSystem = Get-CimInstance `
        -ClassName Win32_ComputerSystem `
        -ErrorAction Stop

    $IsServer = ($OperatingSystem.ProductType -ne 1)

    $IsDomainController = (
        $OperatingSystem.ProductType -eq 2 -or
        $ComputerSystem.DomainRole -eq 4 -or
        $ComputerSystem.DomainRole -eq 5
    )

    Write-Log "OS=$($OperatingSystem.Caption)"
    Write-Log "ProductType=$($OperatingSystem.ProductType)"
    Write-Log "DomainRole=$($ComputerSystem.DomainRole)"
    Write-Log "IsDomainController=$IsDomainController"

    if (-not $IsServer) {
        Finish -Token 'NO_ACTION' -Message 'Not Windows Server.'
    }

    if (-not $IsDomainController) {
        Finish `
            -Token 'NO_ACTION' `
            -Message "Windows Server detected, but not a domain controller. OS=$($OperatingSystem.Caption)"
    }

    # ------------------------------------------------------------------------
    # Build and hotfix discovery
    # ------------------------------------------------------------------------

    $DetectedBuild = Get-DetectedOsBuild -OperatingSystem $OperatingSystem

    $BaseBuild = "$($DetectedBuild.Major).$($DetectedBuild.Minor).$($DetectedBuild.Build)"

    $InstalledHotFixIds = @(Get-InstalledHotFixIds)

    # ------------------------------------------------------------------------
    # May 2026 CVE-2026-41089 patch baselines
    #
    # MinBuild:
    #   Standard cumulative-update threshold.
    #
    # HotpatchMinBuild:
    #   Alternative hotpatch threshold for eligible editions.
    #
    # KBs:
    #   Expected May 2026 cumulative and hotpatch KB identifiers.
    # ------------------------------------------------------------------------

    $PatchMap = @{
        '6.2.9200' = @{
            Name = 'Windows Server 2012'
            MinBuild = [version]'6.2.9200.26079'
            HotpatchMinBuild = $null
            KBs = @('KB5087470')
        }

        '6.3.9600' = @{
            Name = 'Windows Server 2012 R2'
            MinBuild = [version]'6.3.9600.23181'
            HotpatchMinBuild = $null
            KBs = @('KB5087471')
        }

        '10.0.14393' = @{
            Name = 'Windows Server 2016'
            MinBuild = [version]'10.0.14393.9140'
            HotpatchMinBuild = $null
            KBs = @('KB5087537')
        }

        '10.0.17763' = @{
            Name = 'Windows Server 2019'
            MinBuild = [version]'10.0.17763.8755'
            HotpatchMinBuild = $null
            KBs = @('KB5087538')
        }

        '10.0.20348' = @{
            Name = 'Windows Server 2022'
            MinBuild = [version]'10.0.20348.5139'
            HotpatchMinBuild = [version]'10.0.20348.5074'
            KBs = @('KB5087545', 'KB5087424')
        }

        '10.0.25398' = @{
            Name = 'Windows Server 2022 23H2'
            MinBuild = [version]'10.0.25398.2330'
            HotpatchMinBuild = $null
            KBs = @('KB5087541')
        }

        '10.0.26100' = @{
            Name = 'Windows Server 2025'
            MinBuild = [version]'10.0.26100.32860'
            HotpatchMinBuild = [version]'10.0.26100.32772'
            KBs = @('KB5087539', 'KB5087423')
        }
    }

    # ------------------------------------------------------------------------
    # Unknown build handling
    # ------------------------------------------------------------------------

    if (-not $PatchMap.ContainsKey($BaseBuild)) {
        Finish `
            -Token 'TRIGGER' `
            -Message "Domain controller detected on unsupported or unrecognized build $DetectedBuild. Manually verify CVE-2026-41089 patch state. OS=$($OperatingSystem.Caption)"
    }

    $PatchInfo = $PatchMap[$BaseBuild]

    $ExpectedKbs = @($PatchInfo.KBs)

    # ------------------------------------------------------------------------
    # Expected KB comparison
    # ------------------------------------------------------------------------

    $InstalledExpectedKbs = @(
        foreach ($Kb in $ExpectedKbs) {
            if ($InstalledHotFixIds -contains $Kb.ToUpperInvariant()) {
                $Kb
            }
        }
    )

    $InstalledExpectedKb = ($InstalledExpectedKbs.Count -gt 0)

    # ------------------------------------------------------------------------
    # Cumulative and hotpatch build comparison
    # ------------------------------------------------------------------------

    $MeetsCumulativeBuild = (
        $DetectedBuild -ge $PatchInfo.MinBuild
    )

    $MeetsHotpatchBuild = $false

    if ($null -ne $PatchInfo.HotpatchMinBuild) {
        $MeetsHotpatchBuild = (
            $DetectedBuild -ge $PatchInfo.HotpatchMinBuild
        )
    }

    # ------------------------------------------------------------------------
    # Evaluation diagnostics
    # ------------------------------------------------------------------------

    Write-Log "PatchFamily=$($PatchInfo.Name)"
    Write-Log "DetectedBuild=$DetectedBuild"
    Write-Log "RequiredCumulativeBuild=$($PatchInfo.MinBuild)"
    Write-Log "RequiredHotpatchBuild=$($PatchInfo.HotpatchMinBuild)"
    Write-Log "ExpectedKBs=$($ExpectedKbs -join ', ')"
    Write-Log "InstalledExpectedKB=$InstalledExpectedKb"
    Write-Log "InstalledExpectedKBs=$($InstalledExpectedKbs -join ', ')"
    Write-Log "MeetsCumulativeBuild=$MeetsCumulativeBuild"
    Write-Log "MeetsHotpatchBuild=$MeetsHotpatchBuild"

    # ------------------------------------------------------------------------
    # Standard cumulative-update compliance
    # ------------------------------------------------------------------------

    if ($MeetsCumulativeBuild) {
        Finish `
            -Token 'NO_ACTION' `
            -Message "Domain controller meets CVE-2026-41089 cumulative patch baseline. OS=$($PatchInfo.Name); Build=$DetectedBuild; RequiredBuild=$($PatchInfo.MinBuild)"
    }

    # ------------------------------------------------------------------------
    # Hotpatch-aware compliance
    #
    # Hotpatch releases use different build thresholds.
    # A valid hotpatch build must not be classified as vulnerable simply
    # because it is below the standard cumulative-update build.
    #
    # Build evidence is used independently because QuickFixEngineering
    # does not guarantee visibility of every installed update.
    # ------------------------------------------------------------------------

    if ($MeetsHotpatchBuild) {
        Finish `
            -Token 'NO_ACTION' `
            -Message "Domain controller meets CVE-2026-41089 hotpatch build baseline. OS=$($PatchInfo.Name); Build=$DetectedBuild; RequiredHotpatchBuild=$($PatchInfo.HotpatchMinBuild); ExpectedKBs=$($ExpectedKbs -join ',')"
    }

    # ------------------------------------------------------------------------
    # Build is below all applicable baselines.
    #
    # A matching installed KB is not sufficient to mark the endpoint
    # compliant when the detected active build remains below threshold.
    # ------------------------------------------------------------------------

    if ($InstalledExpectedKb) {

        Write-Log 'KB/build mismatch detected. Checking servicing reboot state.'

        $RebootState = Get-PendingServicingRebootState

        if ($RebootState.IsPending) {

            $RebootIndicators = $RebootState.Indicators -join ','

            Finish `
                -Token 'TRIGGER' `
                -Message "CVE-2026-41089 KB recorded but active build is below required patch level; servicing restart pending. OS=$($PatchInfo.Name); Build=$DetectedBuild; InstalledKBs=$($InstalledExpectedKbs -join ','); RebootIndicators=$RebootIndicators. Verify update activation after restart."
        }

        if ($RebootState.QueryErrors.Count -gt 0) {

            Finish `
                -Token 'TRIGGER' `
                -Message "CVE-2026-41089 KB recorded but active build is below required patch level; servicing reboot status could not be fully determined. OS=$($PatchInfo.Name); Build=$DetectedBuild; InstalledKBs=$($InstalledExpectedKbs -join ','). Manual verification required."
        }

        Finish `
            -Token 'TRIGGER' `
            -Message "CVE-2026-41089 KB recorded but active build remains below required patch level; no servicing restart indicator detected. OS=$($PatchInfo.Name); Build=$DetectedBuild; InstalledKBs=$($InstalledExpectedKbs -join ','). Manual verification required."
    }

    # ------------------------------------------------------------------------
    # No matching build or expected KB evidence
    # ------------------------------------------------------------------------

    $RequiredBuildText = [string]$PatchInfo.MinBuild

    if ($null -ne $PatchInfo.HotpatchMinBuild) {
        $RequiredBuildText += " or Hotpatch=$($PatchInfo.HotpatchMinBuild)"
    }

    Finish `
        -Token 'TRIGGER' `
        -Message "Domain controller appears missing CVE-2026-41089 patch level. OS=$($PatchInfo.Name); Build=$DetectedBuild; RequiredBuild=$RequiredBuildText; ExpectedKBs=$($ExpectedKbs -join ',')"
}
catch {
    $ErrorMessage = $_.Exception.Message

    Write-Log "ERROR | $ErrorMessage"

    Write-Output "ERROR | Unexpected script error occurred: $ErrorMessage"

    exit 0
}