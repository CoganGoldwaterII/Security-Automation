# ============================================================================
# NAME: AuthPoint Logon App Uninstall
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   REMEDIATION=COMPLETE | Logon App removal performed; no traces detected
#   NO_ACTION            | No Logon App traces found
#   UNINSTALL=PARTIAL    | Logon App traces still detected after removal
#   Additional diagnostic status lines are written to console and log.
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# LOGGING PATH:
#   C:\MME\AutoLogs\AuthPoint_Logon_App_Uninstall.log
#   C:\MME\AutoLogs\AuthPoint_Logon_App_Uninstall_<ProductCode>.log
# DESCRIPTION:
#   Removes WatchGuard AuthPoint Logon App traces only. Identifies exact
#   "Logon App" / "LogonApp" uninstall entries, attempts MSI uninstallation,
#   removes matching/orphaned MSI registration and upgrade-code references,
#   and deletes known Logon App folders and configuration-file locations.
#   Does not intentionally remove C:\MME\CS, the parent WatchGuard
#   ProgramData directory, or other WatchGuard product folders.
#   Updates the NinjaOne remediation ledger when remediation is completed.
#   Normal completion paths exit 0.
# ============================================================================

$ErrorActionPreference = 'Stop'

$LogRoot      = 'C:\MME\AutoLogs'
$LogFile      = Join-Path $LogRoot 'AuthPoint_Logon_App_Uninstall.log'
$DidRemediate = $false

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

    if ($Lines -notcontains $NewLine) {
        $Lines += $NewLine
    }

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
        Update-RemediationLedger 'AuthPoint Logon App Removed'
    }

    Write-Log $Message
    Write-Log 'SCRIPT=COMPLETE'
    exit 0
}

function Is-TargetDisplayName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($Name -match '(?i)^Logon\s*App$')
}

function Reverse-Chars {
    param([string]$Value)
    return (-join ([char[]]$Value)[($Value.Length - 1)..0])
}

function Swap-CharPairs {
    param([string]$Value)

    $Out = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Value.Length; $i += 2) {
        if (($i + 1) -lt $Value.Length) {
            [void]$Out.Add($Value[$i + 1])
            [void]$Out.Add($Value[$i])
        }
        else {
            [void]$Out.Add($Value[$i])
        }
    }

    return ($Out -join '')
}

function Convert-GuidToPackedCode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Guid
    )

    $Parts = $Guid.Trim('{}').ToUpper().Split('-')
    if ($Parts.Count -ne 5) {
        throw "Invalid GUID format: $Guid"
    }

    return (
        (Reverse-Chars  $Parts[0]) +
        (Reverse-Chars  $Parts[1]) +
        (Reverse-Chars  $Parts[2]) +
        (Swap-CharPairs $Parts[3]) +
        (Swap-CharPairs $Parts[4])
    )
}

function Convert-PackedCodeToGuid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackedCode
    )

    $Packed = $PackedCode.Trim().ToUpper()
    if ($Packed.Length -ne 32 -or $Packed -notmatch '^[A-F0-9]{32}$') {
        throw "Invalid packed product code: $PackedCode"
    }

    $P1 = $Packed.Substring(0,8)
    $P2 = $Packed.Substring(8,4)
    $P3 = $Packed.Substring(12,4)
    $P4 = $Packed.Substring(16,4)
    $P5 = $Packed.Substring(20,12)

    $Guid = '{0}-{1}-{2}-{3}-{4}' -f `
        (Reverse-Chars  $P1),
        (Reverse-Chars  $P2),
        (Reverse-Chars  $P3),
        (Swap-CharPairs $P4),
        (Swap-CharPairs $P5)

    return "{${Guid}}"
}

function Get-UninstallEvidence {
    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKEY_USERS\*\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($Path in $RegistryPaths) {
        Get-ItemProperty -Path $Path -ErrorAction