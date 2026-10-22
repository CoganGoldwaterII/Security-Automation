# ============================================================================
# NAME: Remove WatchGuard Logon App
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Endpoints / NinjaOne Automation
# VARIABLES:
#   Required: None
#   Optional: None
# OUTPUT TOKENS:
#   RESULT: WatchGuard Logon App is not installed.
#   RESULT: WatchGuard Logon App removed successfully
#   ERROR:  Unexpected script error or uninstall failure
# CUSTOM FIELDS:
#   Reads: remediationSummary
#   Writes: lastRemediationDate, remediationSummary
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\WatchGuard_Logon_App_Removal.log
# DESCRIPTION:
#   Locates the installed WatchGuard Logon App or AuthPoint Agent
#   for Windows using machine-wide uninstall registry entries.
#
#   Extracts the MSI product code and silently uninstalls the
#   application using msiexec with /qn /norestart.
#
#   Accepts MSI exit codes 0, 1641, and 3010 as successful.
#
#   Following successful removal:
#     - Updates lastRemediationDate with an ISO 8601 timestamp.
#     - Appends a deduplicated, date-prefixed remediation entry
#       to remediationSummary.
#     - Forces an immediate system reboot.
#
#   If the application is absent, returns RESULT without rebooting.
#
#   Requires SYSTEM execution in 64-bit PowerShell through NinjaOne.
#   Does not use independent remediation gating.
#
#   WARNING:
#   Successful removal forces an immediate reboot without prompting.
#   Existing output uses RESULT: / ERROR: rather than the standard
#   RESULT | / ERROR | format.
# ============================================================================

$ErrorActionPreference = 'Stop'

$LogDirectory = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogDirectory 'WatchGuard_Logon_App_Removal.log'

New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null

try {
    Add-Content $LogPath "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Starting WatchGuard Logon App removal."

    $App = Get-ItemProperty `
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -in @(
                'Logon App',
                'AuthPoint Agent for Windows'
            )
        } |
        Select-Object -First 1

    if (-not $App) {
        $Message = 'WatchGuard Logon App is not installed.'

        Add-Content $LogPath "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] $Message"
        Write-Output "RESULT: $Message"
        exit 0
    }

    $ProductCode = [regex]::Match(
        "$($App.PSChildName) $($App.UninstallString)",
        '\{[0-9A-Fa-f-]{36}\}'
    ).Value

    if ([string]::IsNullOrWhiteSpace($ProductCode)) {
        throw 'WatchGuard Logon App was found, but its MSI product code could not be determined.'
    }

    Add-Content $LogPath "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Found product code $ProductCode."

    $p = Start-Process msiexec.exe -ArgumentList "/x $ProductCode /qn /norestart" -Wait -PassThru

    if ($p.ExitCode -in 0, 1641, 3010) {
        $Timestamp = (Get-Date).ToString('o')
        $LedgerLine = "$(Get-Date -Format 'yyyy-MM-dd') | Removed WatchGuard Logon App; ProductCode=$ProductCode"

        Ninja-Property-Set lastRemediationDate $Timestamp

        $ExistingSummary = [string](Ninja-Property-Get remediationSummary)

        if (($ExistingSummary -split '\r?\n') -notcontains $LedgerLine) {
            if ([string]::IsNullOrWhiteSpace($ExistingSummary)) {
                $UpdatedSummary = $LedgerLine
            }
            else {
                $UpdatedSummary = "$($ExistingSummary.TrimEnd())`r`n$LedgerLine"
            }

            Ninja-Property-Set remediationSummary $UpdatedSummary
        }

        Add-Content $LogPath "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Logon App removed successfully. Forcing reboot."
        Write-Output "RESULT: WatchGuard Logon App removed successfully; ProductCode=$ProductCode; forcing reboot."

        Restart-Computer -Force
    }
    else {
        throw "Logon App uninstall failed with MSI exit code $($p.ExitCode)."
    }
}
catch {
    $Message = $_.Exception.Message

    Add-Content $LogPath "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [ERROR] $Message"
    Write-Output "ERROR: $Message"
    exit 0
}
