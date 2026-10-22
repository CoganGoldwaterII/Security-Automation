
# ============================================================================
# NAME: AuthPoint Logon App - Install
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   StagePath = C:\MME\CS
#   MSI       = AuthPoint_Logon_App-4.1.2.128_x64.msi
#   Config    = wlconfig.cfg
# OUTPUT TOKENS:
#   RESULT    | Installation/update succeeded
#   NO_ACTION | Not emitted by this script
#   ERROR     | Installation or prerequisite failure
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# LOGGING PATH:
#   C:\MME\AutoLogs\AuthPoint_Logon_App_Remediation.log
#   C:\MME\AutoLogs\AuthPoint_Logon_App_MSI.log
# DESCRIPTION:
#   Installs or updates the WatchGuard AuthPoint Logon App using the exact MSI
#   and configuration file staged in C:\MME\CS. Seeds legacy WatchGuard paths
#   expected by the installer, copies wlconfig.cfg into the legacy Resources
#   path, suppresses reboot behavior, updates the Ninja remediation ledger only
#   when remediation succeeds, does not delete files, and always exits 0.
# ============================================================================

$ErrorActionPreference = 'Stop'

$StagePath        = 'C:\MME\CS'
$LogRoot          = 'C:\MME\AutoLogs'
$LogFile          = Join-Path $LogRoot 'AuthPoint_Logon_App_Remediation.log'
$MsiLog           = Join-Path $LogRoot 'AuthPoint_Logon_App_MSI.log'

$MsiName          = 'AuthPoint_Logon_App-4.1.2.128_x64.msi'
$CfgName          = 'wlconfig.cfg'
$MsiPath          = Join-Path $StagePath $MsiName
$CfgPath          = Join-Path $StagePath $CfgName

$LegacyDataDir    = 'C:\ProgramData\WatchGuard\Logon App'
$LegacyResDir     = 'C:\Program Files\WatchGuard\Logon App\Resources'
$LegacyCfgPath    = Join-Path $LegacyResDir 'wlconfig.cfg'

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

$ResultToken   = $null
$ResultMessage = $null

try {
    Write-Log '===== AuthPoint Logon App Install START ====='
    Write-Log "STAGE_PATH=$StagePath"
    Write-Log "MSI=$MsiName"
    Write-Log "CONFIG=$CfgName"
    Write-Log "MSI_LOG=$MsiLog"
    Write-Log "LEGACY_DATA_DIR=$LegacyDataDir"
    Write-Log "LEGACY_RES_DIR=$LegacyResDir"
    Write-Log "LEGACY_CFG_PATH=$LegacyCfgPath"

    if (-not (Test-Path -LiteralPath $StagePath)) {
        throw "Stage path not found: $StagePath"
    }

    if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
        throw "Missing MSI: $MsiPath"
    }

    if (-not (Test-Path -LiteralPath $CfgPath -PathType Leaf)) {
        throw "Missing config: $CfgPath"
    }

    if (-not (Test-Path -LiteralPath $LegacyDataDir)) {
        New-Item -Path $LegacyDataDir -ItemType Directory -Force | Out-Null
        Write-Log "SEED_DIR=CREATED | $LegacyDataDir"
    }
    else {
        Write-Log "SEED_DIR=ALREADY_PRESENT | $LegacyDataDir"
    }

    if (-not (Test-Path -LiteralPath $LegacyResDir)) {
        New-Item -Path $LegacyResDir -ItemType Directory -Force | Out-Null
        Write-Log "SEED_DIR=CREATED | $LegacyResDir"
    }
    else {
        Write-Log "SEED_DIR=ALREADY_PRESENT | $LegacyResDir"
    }

    Copy-Item -LiteralPath $CfgPath -Destination $LegacyCfgPath -Force -ErrorAction Stop
    Write-Log "SEED_CFG=COPIED | Source=$CfgPath | Dest=$LegacyCfgPath"

    Write-Log "PREREQ_CHECK=OK | MSI=$MsiName | CFG=$CfgName"
    Write-Log 'INSTALL=STARTING'

    $Arguments = @(
        '/i'
        "`"$MsiPath`""
        '/qn'
        '/norestart'
        'REBOOT=ReallySuppress'
        "CONFIG_PATH=`"$CfgPath`""
        '/l*v'
        "`"$MsiLog`""
    )

    $Proc = Start-Process `
        -FilePath 'msiexec.exe' `
        -ArgumentList $Arguments `
        -Wait `
        -PassThru `
        -ErrorAction Stop

    Write-Log "MSI_EXIT_CODE=$($Proc.ExitCode)"

    switch ($Proc.ExitCode) {
        0 {
            Write-Log 'INSTALL=SUCCESS'
            Update-RemediationLedger 'AuthPoint Logon App 4.1.2.128 Installed/Updated'
            $ResultToken   = 'RESULT'
            $ResultMessage = 'AuthPoint Logon App 4.1.2.128 installed/updated successfully'
        }

        3010 {
            Write-Log 'INSTALL=SUCCESS_REBOOT_REQUIRED_NOT_INITIATED'
            Update-RemediationLedger 'AuthPoint Logon App 4.1.2.128 Installed/Updated'
            $ResultToken   = 'RESULT'
            $ResultMessage = 'AuthPoint Logon App 4.1.2.128 installed/updated successfully; reboot required but not initiated'
        }

        1641 {
            throw 'Installer reported reboot initiated unexpectedly despite reboot suppression'
        }

        default {
            throw "Install failed | ExitCode=$($Proc.ExitCode)"
        }
    }
}
catch {
    $ResultToken   = 'ERROR'
    $ResultMessage = "AuthPoint Logon App remediation failed | $($_.Exception.Message)"
}

Write-Log "$ResultToken | $ResultMessage"
Write-Log 'SCRIPT=COMPLETE'
exit 0
