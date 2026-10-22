# ============================================================================
# NAME: AuthPoint Logon App - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   TargetVersion = 4.1.2.128
#   NamePattern   = (?i)^Logon\s+App$
# OUTPUT TOKENS:
#   TRIGGER   | Application missing, outdated, or version unreadable
#   NO_ACTION | Installed application meets or exceeds target version
#   ERROR     | Evaluation failure
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\AuthPoint_Logon_App_Eval.log
# DESCRIPTION:
#   Detects the installed WatchGuard AuthPoint Logon App from Windows uninstall
#   registry locations, including 32-bit, 64-bit, and user registry entries.
#
#   Compares the highest readable installed version against the required
#   target version.
#
#   Triggers remediation when the application is missing, its version is
#   unreadable, or the installed version is below the required version.
#
#   Reports NO_ACTION when the installed version meets or exceeds the target.
#   Always exits with code 0 for NinjaOne automation compatibility.
# ============================================================================

$ErrorActionPreference = 'Stop'

$TargetVersion = [version]'4.1.2.128'
$NamePattern   = '(?i)^Logon\s+App$'

$LogRoot = 'C:\MME\AutoLogs'
$LogFile = Join-Path $LogRoot 'AuthPoint_Logon_App_Eval.log'

if (-not (Test-Path -LiteralPath $LogRoot)) {
    New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message)

    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"
    Add-Content -Path $LogFile -Value $Line
}

function Write-EvalResult {
    param(
        [ValidateSet('TRIGGER','NO_ACTION','ERROR')]
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
    Write-Log '===== AuthPoint Logon App Eval START ====='
    Write-Log "TARGET_VERSION=$TargetVersion"
    Write-Log "NAME_PATTERN=$NamePattern"

    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'Registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'Registry::HKEY_USERS\*\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $Hits = @()

    foreach ($Path in $RegistryPaths) {
        Write-Log "CHECKING_PATH=$Path"

        Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            ForEach-Object {
                $DisplayName    = $_.DisplayName
                $DisplayVersion = $_.DisplayVersion
                $ParsedVersion  = $null

                if ($DisplayName -match $NamePattern) {
                    try {
                        if (-not [string]::IsNullOrWhiteSpace($DisplayVersion)) {
                            $ParsedVersion = [version]$DisplayVersion
                        }
                    }
                    catch {
                        $ParsedVersion = $null
                    }

                    $Hits += [pscustomobject]@{
                        DisplayName    = $DisplayName
                        DisplayVersion = $DisplayVersion
                        ParsedVersion  = $ParsedVersion
                        RegPath        = $Path
                    }
                }
            }
    }

    Write-Log "MATCH_COUNT=$($Hits.Count)"

    if ($Hits.Count -eq 0) {
        $ResultToken   = 'TRIGGER'
        $ResultMessage = 'Logon App not found; install/remediate'
    }
    else {
        $BestHit = $Hits |
            Sort-Object @{
                Expression = {
                    if ($_.ParsedVersion) {
                        $_.ParsedVersion
                    }
                    else {
                        [version]'0.0.0.0'
                    }
                }
                Descending = $true
            } |
            Select-Object -First 1

        $Details = ($Hits | ForEach-Object {
            "'$($_.DisplayName)' v$($_.DisplayVersion)"
        }) -join '; '

        if (-not $BestHit.ParsedVersion) {
            $ResultToken   = 'TRIGGER'
            $ResultMessage = "Logon App found but version unreadable ($Details); remediate"
        }
        elseif ($BestHit.ParsedVersion -lt $TargetVersion) {
            $ResultToken   = 'TRIGGER'
            $ResultMessage = "Logon App outdated (installed=$($BestHit.ParsedVersion) target=$TargetVersion) ($Details); remediate"
        }
        else {
            $ResultToken   = 'NO_ACTION'
            $ResultMessage = "Logon App current (installed=$($BestHit.ParsedVersion) target=$TargetVersion) ($Details)"
        }
    }
}
catch {
    $ResultToken   = 'ERROR'
    $ResultMessage = "AuthPoint Logon App evaluation failed: $($_.Exception.Message)"
}

Write-EvalResult -Token $ResultToken -Message $ResultMessage
exit 0