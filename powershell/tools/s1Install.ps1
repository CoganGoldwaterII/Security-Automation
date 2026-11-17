# ============================================================================
# NAME: SentinelOne Staged Agent Install
# AUTHORED BY:
# TYPE: INSTALL
# SCOPE: Windows endpoint, manual/on-demand NinjaOne automation, runs as SYSTEM
# VARIABLES: Required: scopeToken, installerName | Optional: None
# OUTPUT TOKENS: RESULT / ERROR (always exit 0)
# CUSTOM FIELDS: Reads: remediationSummary | Writes: remediationSummary, lastRemediationDate
# LOGGING PATH: C:\MME\AutoLogs\SentinelOne_Staged_Install.log
# DESCRIPTION: Installs the exact staged SentinelOne Windows EXE from C:\MME\CS
#              using the supplied scope token, only when no agent is installed.
#              Returns ERROR if an existing agent/service is detected. Verifies
#              trusted publisher, resulting agent version, and running service.
#              No download, uninstall, automatic reboot or staged-file deletion.
#              Uses --dont_preserve_agent_uid when invoking the installer.
#              Scope token is passed to the vendor installer CLI but is never
#              intentionally written to stdout or this script's log.
# ============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$LogRoot = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogRoot 'SentinelOne_Staged_Install.log'
$StageRoot = 'C:\MME\CS'
$Stage = 'Initialize'
$Outcome = 'ERROR'
$Detail = 'NotCompleted'
$ScopeToken = [string]$env:scopeToken
$InstallerName = [string]$env:installerName

function Write-Log {
    param([string]$Message)
    try {
        if (-not (Test-Path -LiteralPath $LogRoot -PathType Container)) {
            New-Item -Path $LogRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $SafeMessage = $Message -replace '[\r\n|]+', ' '
        if (-not [string]::IsNullOrEmpty($ScopeToken)) {
            $SafeMessage = $SafeMessage.Replace($ScopeToken, '[REDACTED]')
        }
        Add-Content -LiteralPath $LogPath -Value ('{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $SafeMessage) -ErrorAction Stop
    }
    catch { }
}

function Get-SentinelAgentVersion {
    $Roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $Entries = @(Get-ItemProperty -Path $Roots -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq 'Sentinel Agent' })
    if ($Entries.Count -eq 0) { return $null }
    $Versions = @($Entries | Where-Object { $_.DisplayVersion } |
        ForEach-Object { [string]$_.DisplayVersion } | Select-Object -Unique)
    if ($Versions.Count -gt 1) {
        throw ('Multiple Sentinel Agent versions found in uninstall registry: {0}' -f ($Versions -join ', '))
    }
    if ($Versions.Count -eq 0) { return 'Unknown' }
    return $Versions[0]
}

function Update-RemediationLedger {
    param([string]$Version)
    $Date = Get-Date -Format 'yyyy-MM-dd'
    $Timestamp = (Get-Date).ToUniversalTime().ToString('o')
    $Entry = '{0} | SentinelOne agent installed and verified version {1}' -f $Date, $Version

    $Existing = [string](Ninja-Property-Get 'remediationSummary')
    $Lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($Line in ($Existing -split '\r\n|\n|\r')) {
        $CleanLine = $Line.Trim()
        if ($CleanLine) { $Lines.Add($CleanLine) }
    }
    if (-not $Lines.Contains($Entry)) { $Lines.Add($Entry) }
    while ($Lines.Count -gt 200) { $Lines.RemoveAt(0) }
    while (($Lines -join "`r`n").Length -gt 15000 -and $Lines.Count -gt 1) {
        $Lines.RemoveAt(0)
    }
    if (($Lines -join "`r`n").Length -gt 15000) {
        throw 'remediationSummary entry exceeds maximum length.'
    }

    Ninja-Property-Set -Name 'remediationSummary' -Value ($Lines -join "`r`n") | Out-Null
    Ninja-Property-Set -Name 'lastRemediationDate' -Value $Timestamp | Out-Null
    Write-Log ('Ledger updated: lastRemediationDate={0}, Version={1}' -f $Timestamp, $Version)
}

try {
    Write-Log 'START | SentinelOne staged installation (on-demand)'
    $Stage = 'ValidateInputs'
    if ([string]::IsNullOrWhiteSpace($ScopeToken)) { throw 'Required Ninja variable scopeToken is empty.' }
    if ([string]::IsNullOrWhiteSpace($InstallerName)) { throw 'Required Ninja variable installerName is empty.' }
    if ($InstallerName -ne [IO.Path]::GetFileName($InstallerName) -or
        $InstallerName -match '[\\/]' -or $InstallerName -in @('.', '..')) {
        throw 'installerName must be a filename only, not a path.'
    }
    if ([IO.Path]::GetExtension($InstallerName) -ine '.exe') {
        throw 'This first version supports SentinelOne EXE installers only.'
    }
    Write-Log ('Inputs validated | Installer={0} | TokenPresent=True' -f $InstallerName)

    $Stage = 'InspectInstalledState'
    $BeforeVersion = Get-SentinelAgentVersion
    $BeforeService = Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue
    $BeforeServiceStatus = if ($BeforeService) { [string]$BeforeService.Status } else { 'NotFound' }
    Write-Log ('Before | AgentVersion={0} | SentinelAgentService={1}' -f $BeforeVersion, $BeforeServiceStatus)
    if ($BeforeVersion -or $BeforeService) {
        $ExistingVersion = if ($BeforeVersion) { $BeforeVersion } else { 'Unknown' }
        throw ('AnotherVersionInstalled Version={0} Service={1}; installation not attempted.' -f $ExistingVersion, $BeforeServiceStatus)
    }

    $Stage = 'VerifyInstaller'
    $InstallerPath = Join-Path $StageRoot $InstallerName
    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        throw ('Exact staged installer not found: {0}' -f $InstallerPath)
    }
    $Signature = Get-AuthenticodeSignature -LiteralPath $InstallerPath
    $Publisher = if ($Signature.SignerCertificate) { [string]$Signature.SignerCertificate.Subject } else { 'None' }
    if ($Signature.Status -ne 'Valid' -or $Publisher -notmatch '(?i)(SentinelOne|Sentinel Labs)') {
        throw ('Installer signature/publisher validation failed: Status={0}, Publisher={1}' -f $Signature.Status, $Publisher)
    }
    Write-Log ('Signature verified | Status=Valid | Publisher={0}' -f $Publisher)

    $Stage = 'ExecuteInstaller'
    Write-Log ('Launch | File={0} | Silent=True | AutoReboot=False' -f $InstallerName)
    # Vendor-documented EXE syntax: -t <site/group scope token> -q.
    # Retry code 2009 without preserving a prior agent UID.
    # The token is unavoidable on the vendor process command line.
    $Process = Start-Process -FilePath $InstallerPath -ArgumentList @('-t', $ScopeToken, '-q', '--dont_preserve_agent_uid') -Wait -PassThru -ErrorAction Stop
    $InstallerExit = [int]$Process.ExitCode
    Write-Log ('Installer completed | ExitCode={0}' -f $InstallerExit)

    $Stage = 'VerifyInstallation'
    if ($InstallerExit -ne 0) {
        throw ('InstallerExit={0}; successful completed installation not established. A reboot may be required for certain codes; no reboot was initiated.' -f $InstallerExit)
    }
    $AfterVersion = Get-SentinelAgentVersion
    $AfterService = Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue
    $AfterServiceStatus = if ($AfterService) { [string]$AfterService.Status } else { 'NotFound' }
    Write-Log ('After | AgentVersion={0} | SentinelAgentService={1}' -f $AfterVersion, $AfterServiceStatus)
    if (-not $AfterVersion -or $AfterVersion -eq 'Unknown' -or $AfterServiceStatus -ne 'Running') {
        throw ('Post-install verification failed: InstalledVersion={0}, Service={1}' -f $AfterVersion, $AfterServiceStatus)
    }

    $Stage = 'UpdateLedger'
    Update-RemediationLedger -Version $AfterVersion
    $Outcome = 'RESULT'
    $Detail = ('InstalledAndVerified Version={0} Service=Running InstallerExit=0' -f $AfterVersion)
}
catch {
    $Outcome = 'ERROR'
    $SafeError = ([string]$_.Exception.Message -replace '[\r\n|]+', ' ').Trim()
    if ($ScopeToken) { $SafeError = $SafeError.Replace($ScopeToken, '[REDACTED]') }
    $Detail = ('Stage={0} {1}' -f $Stage, $SafeError)
}
finally {
    Write-Log ('FINAL | {0} | {1}' -f $Outcome, $Detail)
    $ScopeToken = $null
    $env:scopeToken = $null
}

Write-Output ('{0} | {1}' -f $Outcome, ($Detail -replace '[\r\n|]+', ' '))
exit 0
