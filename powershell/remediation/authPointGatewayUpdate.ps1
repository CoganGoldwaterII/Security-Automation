# ============================================================================
# NAME: AuthPoint Gateway - Update to 7.6.0.8
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows (Ninja, SYSTEM context, Windows PowerShell 5.1)
# VARIABLES:
#   RequiredVersion = 7.6.0.8
#   InstallerName   = AuthPoint_Gateway-7.6.0-8.msi
#   InstallerPath   = C:\MME\CS\AuthPoint_Gateway-7.6.0-8.msi
#   InstallTimeoutSeconds = 1200
#   ServiceStartupTimeoutSeconds = 60
# OUTPUT TOKENS:
#   RESULT | ...
#   NO_ACTION | ... (reserved; this is a blind-fire remediation)
#   ERROR | ...
# CUSTOM FIELDS:
#   Reads:  remediationSummary
#   Writes: lastRemediationDate (overwrite), remediationSummary (append)
# LOGGING PATH:
#   C:\MME\AutoLogs\AuthPointGateway_Remediation.log
#   C:\MME\AutoLogs\AuthPointGateway_MSI.log
# DESCRIPTION:
#   Runs an explicitly staged WatchGuard AuthPoint Gateway MSI. No independent
#   version-compliance gate, no Corretto changes, no online version lookup.
#   Preserves the proven CURRENT_VERSION migration property, runs MSI silently
#   with reboot suppressed, checks the installer signature, verifies the final
#   installed version and local service health, and updates the Ninja ledger
#   only after verified success. Does not restart/delete services or reboot.
#   Exactly one final Ninja result line; always exits 0.
# IMPORTANT:
#   Verify InstallerName matches the file-transfer destination before testing.
#   A 3010 result is NOT recorded as complete; review/reboot/reverify manually.
# ============================================================================

$ErrorActionPreference = 'Stop'

$LogRoot                      = 'C:\MME\AutoLogs'
$CacheRoot                    = 'C:\MME\CS'
$LogFile                      = Join-Path $LogRoot 'AuthPointGateway_Remediation.log'
$MsiLog                       = Join-Path $LogRoot 'AuthPointGateway_MSI.log'
$AppName                      = 'WatchGuard AuthPoint Gateway'
$RequiredVersion              = [version]'7.6.0.8'
$InstallerName                = 'AuthPoint_Gateway-7.6.0-8.msi'
$InstallerPath                = Join-Path $CacheRoot $InstallerName
$InstallTimeoutSeconds        = 1200
$ServiceStartupTimeoutSeconds = 60
$ServiceNames                 = @('AuthPointGateway', 'AuthPointRADIUS', 'AuthPointLDAP', 'AuthPointADFS')
$FailurePrefix                = 'AUTHPOINT_REMEDIATION::'
$FinalLine                    = $null
$CurrentStage                 = 'Initialize'

function Write-Log {
    param([string]$Message)
    $Line = '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -LiteralPath $LogFile -Value $Line -Encoding UTF8 -ErrorAction Stop
}

function Stop-Remediation {
    param(
        [string]$Stage,
        [string]$Reason,
        [string]$Action
    )
    throw ($FailurePrefix + 'Stage=' + $Stage + ' | Reason=' + $Reason + ' | Action=' + $Action)
}

function Get-InstalledGateway {
    $Paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $Matches = @(Get-ItemProperty -Path $Paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $AppName })

    if ($Matches.Count -gt 1) {
        Stop-Remediation -Stage 'InstalledGatewayInventory' `
            -Reason "Found $($Matches.Count) uninstall entries for the Gateway; installed version is ambiguous" `
            -Action 'Review both Windows uninstall registry views and resolve duplicate entries before upgrading'
    }
    if ($Matches.Count -eq 0) { return $null }
    return $Matches[0]
}

function Get-GatewayVersion {
    param([object]$Entry, [string]$Stage)
    $Raw = [string]$Entry.DisplayVersion
    if ([string]::IsNullOrWhiteSpace($Raw)) {
        Stop-Remediation -Stage $Stage `
            -Reason 'Gateway uninstall entry has no DisplayVersion; CURRENT_VERSION cannot be determined safely' `
            -Action 'Inspect the installed Gateway version in Programs and Features and its uninstall registry entry'
    }
    $Raw = $Raw.Trim()
    try { return [version]$Raw }
    catch {
        Stop-Remediation -Stage $Stage `
            -Reason "Gateway DisplayVersion '$Raw' is not a supported numeric version" `
            -Action 'Review the Windows uninstall entry and the installed Gateway before attempting an unattended migration'
    }
}

function Get-ServiceSnapshot {
    $Snapshot = @{}
    foreach ($Name in $ServiceNames) {
        $Svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $Svc) {
            $Snapshot[$Name] = [pscustomobject]@{ Present = $false; Status = 'Missing'; StartType = 'Unknown' }
        }
        else {
            $Snapshot[$Name] = [pscustomobject]@{
                Present   = $true
                Status    = [string]$Svc.Status
                StartType = [string]$Svc.StartType
            }
        }
    }
    return $Snapshot
}

function Write-ServiceSnapshot {
    param([string]$Label, [hashtable]$Snapshot)
    foreach ($Name in $ServiceNames) {
        $Item = $Snapshot[$Name]
        Write-Log ("SERVICE_{0} | Name={1} Present={2} Status={3} Startup={4}" -f
            $Label, $Name, $Item.Present, $Item.Status, $Item.StartType)
    }
}

function Test-ServiceHealth {
    param([hashtable]$Before, [hashtable]$After)
    $Problems = @()
    foreach ($Name in $ServiceNames) {
        $Current = $After[$Name]
        $Previous = $Before[$Name]
        if (-not $Current.Present) {
            $Problems += "$Name=Missing"
            continue
        }
        # The core Gateway must run. Components that were running, or were
        # configured for automatic startup, must run after the MSI as well.
        # Deliberately stopped/manual/disabled components are not started here.
        $MustRun = ($Name -eq 'AuthPointGateway') -or
            ($Previous.Present -and $Previous.Status -eq 'Running') -or
            ($Previous.Present -and $Previous.StartType -eq 'Automatic') -or
            ($Current.StartType -eq 'Automatic')
        if ($MustRun -and $Current.Status -ne 'Running') {
            $Problems += "$Name=$($Current.Status)(Startup=$($Current.StartType))"
        }
    }
    return @($Problems)
}

function Get-NinjaField {
    param([string]$Name)
    if (-not (Get-Command Ninja-Property-Get -ErrorAction SilentlyContinue)) {
        Stop-Remediation -Stage 'LedgerUpdate' `
            -Reason 'Ninja-Property-Get is unavailable; installation may have succeeded but the remediation ledger cannot be read' `
            -Action 'Verify this script runs in the Ninja device scripting context and review the local remediation log'
    }
    try {
        $Value = Ninja-Property-Get $Name -ErrorAction Stop
        return [string]$Value
    }
    catch {
        Write-Log "NINJA_READ_FAILURE | Field=$Name Technical=$($_.Exception.Message)"
        Stop-Remediation -Stage 'LedgerUpdate' `
            -Reason "Cannot read Ninja custom field '$Name' after successful installation" `
            -Action 'Check field permissions/definition in Ninja; do not re-run the MSI solely to repair the ledger'
    }
}

function Set-NinjaField {
    param([string]$Name, [string]$Value)
    if (-not (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) {
        Stop-Remediation -Stage 'LedgerUpdate' `
            -Reason 'Ninja-Property-Set is unavailable; installation may have succeeded but the ledger cannot be updated' `
            -Action 'Verify Ninja script execution context and custom-field permissions'
    }
    try {
        Ninja-Property-Set $Name $Value -ErrorAction Stop | Out-Null
        Write-Log "NINJA_FIELD_WRITTEN | Field=$Name"
    }
    catch {
        Write-Log "NINJA_WRITE_FAILURE | Field=$Name Technical=$($_.Exception.Message)"
        Stop-Remediation -Stage 'LedgerUpdate' `
            -Reason "Ninja custom field '$Name' could not be written after successful installation" `
            -Action 'Verify the field type/permissions and reconcile the ledger manually; do not reinstall solely to repair the ledger'
    }
}

function Update-RemediationLedger {
    param([string]$Message)
    $DateOnly = Get-Date -Format 'yyyy-MM-dd'
    $IsoStamp = (Get-Date).ToString('o')
    $NewLine = "$DateOnly | $Message"
    $Existing = Get-NinjaField 'remediationSummary'
    $Lines = @()
    if (-not [string]::IsNullOrWhiteSpace($Existing)) {
        $Lines = @($Existing -split "(`r`n|`n|`r)" |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $Lines += $NewLine
    $Lines = @($Lines | Select-Object -Unique)
    if ($Lines.Count -gt 60) {
        $Lines = @($Lines | Select-Object -Last 60)
    }
    $Joined = $Lines -join "`r`n"
    while ($Joined.Length -gt 4000 -and $Lines.Count -gt 1) {
        $Lines = @($Lines | Select-Object -Skip 1)
        $Joined = $Lines -join "`r`n"
    }
    if ($Joined.Length -gt 4000) {
        Stop-Remediation -Stage 'LedgerUpdate' `
            -Reason 'Remediation summary exceeds the 4000-character field limit' `
            -Action 'Review the Ninja remediationSummary field limit before writing the ledger'
    }
    # Record the summary first; date is written only after summary succeeds.
    Set-NinjaField -Name 'remediationSummary' -Value $Joined
    Set-NinjaField -Name 'lastRemediationDate' -Value $IsoStamp
}

try {
    New-Item -Path $LogRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Log '===== AuthPoint Gateway Remediation START ====='
    Write-Log "INSTALLER=$InstallerPath REQUIRED_VERSION=$RequiredVersion"
    Write-Log "MSI_LOG=$MsiLog TIMEOUT_SECONDS=$InstallTimeoutSeconds"

    $CurrentStage = 'InstallerStaging'
    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        $StagedNames = @(Get-ChildItem -LiteralPath $CacheRoot -Filter '*AuthPoint*Gateway*.msi' -File -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name)
        Write-Log "STAGED_GATEWAY_MSI_CANDIDATES=$($StagedNames -join ',')"
        Stop-Remediation -Stage 'InstallerStaging' `
            -Reason "Approved MSI '$InstallerName' was not found in $CacheRoot" `
            -Action 'Confirm the Ninja file-transfer destination and update InstallerName to the exact staged MSI filename'
    }

    $FileInfo = Get-Item -LiteralPath $InstallerPath -ErrorAction Stop
    if ($FileInfo.Length -le 0) {
        Stop-Remediation -Stage 'InstallerStaging' `
            -Reason 'Staged Gateway MSI is empty' `
            -Action 'Restage the approved WatchGuard Gateway installer using Ninja file transfer'
    }
    $Hash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256 -ErrorAction Stop).Hash
    Write-Log "INSTALLER_SHA256=$Hash BYTES=$($FileInfo.Length)"

    # Refuse a modified, unsigned, untrusted, or unexpected-publisher MSI.
    # If the official download is not Authenticode-signed, review that fact
    # separately; do not weaken this check silently during global rollout.
    $CurrentStage = 'InstallerTrust'
    $Signature = Get-AuthenticodeSignature -LiteralPath $InstallerPath -ErrorAction Stop
    $SignerSubject = if ($Signature.SignerCertificate) { [string]$Signature.SignerCertificate.Subject } else { '<none>' }
    Write-Log "INSTALLER_SIGNATURE_STATUS=$($Signature.Status) SIGNER_SUBJECT=$SignerSubject"
    if ($Signature.Status -ne 'Valid') {
        Stop-Remediation -Stage 'InstallerTrust' `
            -Reason "Staged MSI Authenticode signature is '$($Signature.Status)', not Valid" `
            -Action 'Verify the official downloaded MSI and its digital signature before approving unattended installation'
    }
    if ($SignerSubject -notmatch '(?i)WatchGuard') {
        Stop-Remediation -Stage 'InstallerTrust' `
            -Reason 'Staged MSI is signed, but its publisher does not identify WatchGuard' `
            -Action 'Verify installer provenance and signing certificate against the official WatchGuard download'
    }

    $CurrentStage = 'PreInstallInventory'
    $PreApp = Get-InstalledGateway
    if (-not $PreApp) {
        Stop-Remediation -Stage 'InstalledGatewayInventory' `
            -Reason 'WatchGuard AuthPoint Gateway is not installed; this script is for in-place upgrades only' `
            -Action 'Review device targeting; installation of a new Gateway requires a separate registration workflow'
    }
    $PreVersion = Get-GatewayVersion -Entry $PreApp -Stage 'PreInstallVersion'
    $CurrentVersionForMsi = ([string]$PreApp.DisplayVersion).Trim()
    Write-Log "PRE_VERSION=$PreVersion CURRENT_VERSION_PROPERTY=$CurrentVersionForMsi"

    # Not a compliance decision: only a safety interlock against downgrade.
    if ($PreVersion -gt $RequiredVersion) {
        Stop-Remediation -Stage 'DowngradeProtection' `
            -Reason "Installed Gateway $PreVersion is newer than staged deployment target $RequiredVersion" `
            -Action 'Check the release approval and staged installer; do not downgrade an AuthPoint Gateway automatically'
    }

    $BeforeServices = Get-ServiceSnapshot
    Write-ServiceSnapshot -Label 'BEFORE' -Snapshot $BeforeServices

    $CurrentStage = 'MSIInstall'
    Write-Log 'MSI_INSTALL=STARTING'
    $Arguments = @(
        '/i', "`"$InstallerPath`"",
        '/qn', '/norestart', 'REBOOT=ReallySuppress',
        "CURRENT_VERSION=$CurrentVersionForMsi",
        '/l*v', "`"$MsiLog`""
    )
    Write-Log "MSI_ARGUMENTS=/i <approved-staged-MSI> /qn /norestart REBOOT=ReallySuppress CURRENT_VERSION=$CurrentVersionForMsi /l*v <local-MSI-log>"

    $Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $Arguments -PassThru -ErrorAction Stop
    Write-Log "MSI_PID=$($Process.Id)"
    $Completed = $Process.WaitForExit($InstallTimeoutSeconds * 1000)
    if (-not $Completed) {
        Stop-Remediation -Stage 'MSIInstallTimeout' `
            -Reason "Windows Installer did not finish within $InstallTimeoutSeconds seconds; MSI process PID=$($Process.Id) may still be running" `
            -Action 'Inspect the process and local MSI log; do not interrupt or launch a second installation until its state is known'
    }
    $MsiExitCode = [int]$Process.ExitCode
    Write-Log "MSI_EXIT_CODE=$MsiExitCode"

    if ($MsiExitCode -eq 3010) {
        Stop-Remediation -Stage 'RebootPending' `
            -Reason 'MSI completed but reports a Windows restart is required (3010); upgrade is not certified complete' `
            -Action 'Coordinate a controlled restart, verify Gateway services/authentication, and rerun the standalone evaluation'
    }
    if ($MsiExitCode -eq 1641) {
        Stop-Remediation -Stage 'UnexpectedReboot' `
            -Reason 'MSI reported a reboot was initiated (1641) despite reboot-suppression options' `
            -Action 'Check endpoint availability and the MSI log, then verify Gateway state after the restart'
    }
    if ($MsiExitCode -ne 0) {
        $Description = switch ($MsiExitCode) {
            1603 { 'Windows Installer reported a fatal install error' }
            1618 { 'Another Windows Installer operation was already in progress' }
            1619 { 'Windows Installer could not open the staged package' }
            1620 { 'Windows Installer reported an invalid installation package' }
            1638 { 'Another version of this product is already installed and blocked this operation' }
            default { 'Windows Installer reported a non-success exit code' }
        }
        Stop-Remediation -Stage 'MSIInstall' `
            -Reason "$Description (exit $MsiExitCode)" `
            -Action 'Review C:\MME\AutoLogs\AuthPointGateway_MSI.log around Return value 3 and preceding installer errors; check migration/service permissions'
    }

    $CurrentStage = 'PostInstallVersion'
    $PostApp = Get-InstalledGateway
    if (-not $PostApp) {
        Stop-Remediation -Stage 'PostInstallVersion' `
            -Reason 'MSI exited successfully but no AuthPoint Gateway uninstall entry was found' `
            -Action 'Inspect the MSI log and installed programs before considering this deployment complete'
    }
    $PostVersion = Get-GatewayVersion -Entry $PostApp -Stage 'PostInstallVersion'
    Write-Log "POST_VERSION=$PostVersion"
    if ($PostVersion -lt $RequiredVersion) {
        Stop-Remediation -Stage 'PostInstallVersion' `
            -Reason "MSI exited successfully but installed version $PostVersion is below required $RequiredVersion" `
            -Action 'Review the MSI migration log and confirm the correct approved installer was staged'
    }

    $CurrentStage = 'ServiceHealth'
    $Deadline = (Get-Date).AddSeconds($ServiceStartupTimeoutSeconds)
    $ServiceProblems = @()
    do {
        $AfterServices = Get-ServiceSnapshot
        $ServiceProblems = @(Test-ServiceHealth -Before $BeforeServices -After $AfterServices)
        if ($ServiceProblems.Count -eq 0) { break }
        if ((Get-Date) -ge $Deadline) { break }
        Start-Sleep -Seconds 5
    } while ($true)
    Write-ServiceSnapshot -Label 'AFTER' -Snapshot $AfterServices
    if ($ServiceProblems.Count -gt 0) {
        Stop-Remediation -Stage 'ServiceHealth' `
            -Reason "Gateway $PostVersion installed but required services did not become healthy: $($ServiceProblems -join ', ')" `
            -Action 'Review Windows Service Control Manager events and local Gateway/MSI logs; do not assume authentication is working'
    }
    Write-Log 'SERVICE_HEALTH=VERIFIED_LOCAL (Cloud registration/authentication are separate operational checks)'

    $CurrentStage = 'LedgerUpdate'
    Update-RemediationLedger -Message "AuthPoint Gateway updated from $PreVersion to $PostVersion"
    $FinalLine = "RESULT | AuthPoint Gateway remediation verified | From=$PreVersion To=$PostVersion Services=HealthyLocal"
    Write-Log $FinalLine
}
catch {
    $ErrorMessage = [string]$_.Exception.Message
    try { Write-Log ("FAILURE_TECHNICAL=" + $_.ToString().Replace("`r", ' ').Replace("`n", ' ')) } catch { }
    if ($ErrorMessage.StartsWith($FailurePrefix, [System.StringComparison]::Ordinal)) {
        $FinalLine = 'ERROR | ' + $ErrorMessage.Substring($FailurePrefix.Length)
    }
    else {
        $FinalLine = 'ERROR | Stage=' + $CurrentStage + ' | Reason=An unexpected Windows or PowerShell error interrupted remediation' +
            ' | Action=Review C:\MME\AutoLogs\AuthPointGateway_Remediation.log for FAILURE_TECHNICAL; inspect this stage before retrying'
    }
    try { Write-Log $FinalLine } catch { }
}

# Only this final line reaches the Ninja output parser.
if ([string]::IsNullOrWhiteSpace($FinalLine)) {
    $FinalLine = 'ERROR | Stage=Output | Reason=No final remediation result was generated | Action=Review the local remediation log'
}
Write-Output $FinalLine
exit 0
