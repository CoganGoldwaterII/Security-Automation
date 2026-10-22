# ============================================================================
# NAME: Amazon Corretto - Remove Non-17 Versions
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
#   Internal configuration:
#     RequiredCorrettoMajor = 17
#
# OUTPUT TOKENS:
#   RESULT    | Non-17 Corretto versions successfully removed
#   NO_ACTION | Corretto not found or only version 17 present
#   ERROR     | Detection, uninstall, or verification failed
#
#   Exit Code: Always 0 after normal script execution
#
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
#
#   Ledger Format:
#     yyyy-MM-dd | Removed non-17 Corretto version(s): <versions>
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   C:\MME\AutoLogs\Corretto17_Cleanup_Remediation.log
#
# DESCRIPTION:
#   Detects installed Amazon Corretto versions using Windows uninstall
#   registry entries from both 64-bit and 32-bit registry locations.
#
#   Preserves Corretto 17 and removes detected non-17 versions using
#   Windows Installer (msiexec.exe).
#
#   Uses silent MSI uninstall with reboot suppression and accepts
#   MSI exit codes 0, 3010, and 1605 as successful outcomes.
#
#   Performs post-remediation verification to ensure no non-17
#   Corretto installations remain.
#
#   Updates the NinjaOne remediation ledger only after successful
#   uninstall and verification.
#
#   Field update failures are logged without terminating remediation.
#   Version detection failures and unexpected MSI results emit ERROR.
#
#   Does not remove Corretto 17.
#   Does not intentionally initiate a reboot.
# ============================================================================

$ErrorActionPreference = 'Stop'

$LogRoot               = 'C:\MME\AutoLogs'
$LogFile               = Join-Path $LogRoot 'Corretto17_Cleanup_Remediation.log'
$RequiredCorrettoMajor = 17

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

function Get-CorrettoEntries {
    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    Get-ItemProperty -Path $RegistryPaths -ErrorAction SilentlyContinue |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_.DisplayName) -and
            $_.DisplayName -match '(?i)\bCorretto\b'
        }
}

function Get-CorrettoMajor {
    param([string]$DisplayVersion)

    if ([string]::IsNullOrWhiteSpace($DisplayVersion)) {
        return $null
    }

    $Match = [regex]::Match($DisplayVersion, '^\s*(\d+)')

    if (-not $Match.Success) {
        return $null
    }

    return [int]$Match.Groups[1].Value
}

function Get-MsiProductCode {
    param($Entry)

    $Candidates = @(
        [string]$Entry.PSChildName
        [string]$Entry.UninstallString
        [string]$Entry.QuietUninstallString
    )

    foreach ($Candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($Candidate)) {
            continue
        }

        $Match = [regex]::Match(
            $Candidate,
            '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
        )

        if ($Match.Success) {
            return $Match.Value
        }
    }

    return $null
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
    Write-Log '===== Amazon Corretto Cleanup Remediation START ====='
    Write-Log "REQUIRED_CORRETTO_MAJOR=$RequiredCorrettoMajor"

    $Entries = @(Get-CorrettoEntries)

    if ($Entries.Count -eq 0) {
        $ResultToken   = 'NO_ACTION'
        $ResultMessage = 'Corretto=NotFound'
    }
    else {
        $Targets = @()
        $Preserved = @()

        foreach ($Entry in $Entries) {
            $RawVersion = [string]$Entry.DisplayVersion
            $Major      = Get-CorrettoMajor -DisplayVersion $RawVersion

            if ($null -eq $Major) {
                throw "Corretto detected but version could not be parsed | Name=$($Entry.DisplayName) Version=$RawVersion"
            }

            Write-Log "FOUND | Name=$($Entry.DisplayName) Version=$RawVersion Major=$Major"

            if ($Major -eq $RequiredCorrettoMajor) {
                $Preserved += $RawVersion
            }
            else {
                $Targets += [pscustomobject]@{
                    Entry       = $Entry
                    Version     = $RawVersion
                    Major       = $Major
                    ProductCode = Get-MsiProductCode -Entry $Entry
                }
            }
        }

        if ($Targets.Count -eq 0) {
            $ResultToken   = 'NO_ACTION'
            $ResultMessage = "OnlyCorretto17Present=$($Preserved -join ',')"
        }
        else {
            $RemovedVersions = @()

            foreach ($Target in $Targets) {
                if ([string]::IsNullOrWhiteSpace($Target.ProductCode)) {
                    throw "No safe MSI product code found for Corretto version $($Target.Version)."
                }

                Write-Log "UNINSTALL=STARTING | Version=$($Target.Version) ProductCode=$($Target.ProductCode)"

                $Arguments = @(
                    '/x'
                    $Target.ProductCode
                    '/qn'
                    '/norestart'
                    'REBOOT=ReallySuppress'
                )

                $Process = Start-Process `
                    -FilePath 'msiexec.exe' `
                    -ArgumentList $Arguments `
                    -Wait `
                    -PassThru `
                    -ErrorAction Stop

                Write-Log "MSI_EXIT_CODE=$($Process.ExitCode) | Version=$($Target.Version)"

                switch ($Process.ExitCode) {
                    0 {
                        Write-Log "UNINSTALL=SUCCESS | Version=$($Target.Version)"
                    }

                    3010 {
                        Write-Log "UNINSTALL=SUCCESS_REBOOT_REQUIRED_NOT_INITIATED | Version=$($Target.Version)"
                    }

                    1605 {
                        Write-Log "UNINSTALL=ALREADY_ABSENT | Version=$($Target.Version)"
                    }

                    1641 {
                        throw "Installer initiated a reboot while removing Corretto $($Target.Version)."
                    }

                    default {
                        throw "Failed to remove Corretto $($Target.Version) | MSIExit=$($Process.ExitCode)"
                    }
                }

                $RemovedVersions += $Target.Version
            }

            Start-Sleep -Seconds 2

            $RemainingNon17 = @(
                Get-CorrettoEntries |
                    ForEach-Object {
                        $Version = [string]$_.DisplayVersion
                        $Major   = Get-CorrettoMajor -DisplayVersion $Version

                        if ($null -eq $Major) {
                            throw "Post-check found Corretto with unreadable version | Name=$($_.DisplayName) Version=$Version"
                        }

                        if ($Major -ne $RequiredCorrettoMajor) {
                            $Version
                        }
                    }
            )

            if ($RemainingNon17.Count -gt 0) {
                throw "Non-17 Corretto remains after remediation: $($RemainingNon17 -join ',')"
            }

            $RemovedSummary = ($RemovedVersions | Select-Object -Unique) -join ','
            Update-RemediationLedger "Removed non-17 Corretto version(s): $RemovedSummary"

            $ResultToken   = 'RESULT'
            $ResultMessage = "Removed=$RemovedSummary PreservedMajor=$RequiredCorrettoMajor"
        }
    }
}
catch {
    $ResultToken   = 'ERROR'
    $ResultMessage = "Corretto cleanup failed | $($_.Exception.Message)"
}

Write-Result -Token $ResultToken -Message $ResultMessage
exit 0