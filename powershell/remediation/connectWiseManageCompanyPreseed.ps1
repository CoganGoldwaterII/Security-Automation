# ============================================================================
# NAME: ConnectWise Manage Client - Site/Company Preseed (All Profiles)
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Configuration
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   TargetSite    = https://na.myconnectwise.net
#   TargetCompany = mme
#   LogRoot       = C:\MME\AutoLogs
#   ProfilePath   = C:\Users\<username>
#   ConfigPath    = AppData\Roaming\ConnectWise\cache\application.xml
# OUTPUT TOKENS:
#   REMEDIATION=COMPLETE | One or more profiles updated
#   NO_ACTION            | No eligible profiles or no changes reported
#   ERROR                | Script-level exception
#   NOTE: Does not emit the standard RESULT token.
# CUSTOM FIELDS:
#   Reads:
#     remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\ConnectWise_Manage_Preseed_AllProfiles.log
# DESCRIPTION:
#   Enumerates eligible local user profile directories under C:\Users.
#   Creates or updates the ConnectWise Manage Client application.xml
#   configuration with the specified site and company name.
#   Preserves existing XML when it can be read and modified.
#   Rebuilds missing or unreadable configuration files.
#   Updates NinjaOne remediation fields when profile changes occur.
#   Maintains the date-only remediation ledger with line and
#   character limits.
#   Processes profiles individually and logs per-profile failures.
#   Always exits 0 on handled execution paths.
# ============================================================================

$ErrorActionPreference = 'Stop'

$TargetSite    = 'https://na.myconnectwise.net'
$TargetCompany = 'mme'

$LogRoot = 'C:\MME\AutoLogs'
$LogFile = Join-Path $LogRoot 'ConnectWise_Manage_Preseed_AllProfiles.log'

$DidRemediate = $false
$ChangedCount = 0

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
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

    if (Get-Command 'Ninja-Property-Set' -ErrorAction SilentlyContinue) {
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

    if (Get-Command 'Ninja-Property-Get' -ErrorAction SilentlyContinue) {
        try {
            return (Ninja-Property-Get $Name)
        }
        catch {
            Write-Log "NINJA_FIELD_GET_FAILED | $Name | $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "NINJA_FIELD_GET_SKIPPED | $Name"
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

    if ($DidRemediate -and $ChangedCount -gt 0) {
        Update-RemediationLedger "ConnectWise Site/Company Preseeded ($ChangedCount profile(s))"
    }

    Write-Log $Message
    Write-Log 'SCRIPT=COMPLETE'
    exit 0
}

function Get-TargetProfiles {
    $Excluded = @(
        'Public',
        'Default',
        'Default User',
        'defaultuser0',
        'All Users'
    )

    Get-ChildItem -Path 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $Excluded -notcontains $_.Name
        }
}

function Update-ConnectWiseApplicationXml {
    param(
        [string]$ProfilePath,
        [string]$UserName
    )

    $CacheDir = Join-Path $ProfilePath 'AppData\Roaming\ConnectWise\cache'
    $XmlPath  = Join-Path $CacheDir 'application.xml'

    Ensure-Directory -Path $CacheDir

    if (Test-Path -LiteralPath $XmlPath) {
        try {
            [xml]$Xml = Get-Content -LiteralPath $XmlPath -Raw -ErrorAction Stop

            if (-not $Xml.config) {
                throw 'Missing <config> root element'
            }

            $Changed = $false

            if ($Xml.config.companyname -ne $TargetCompany) {
                $Xml.config.companyname = $TargetCompany
                $Changed = $true
            }

            if ($Xml.config.site -ne $TargetSite) {
                $Xml.config.site = $TargetSite
                $Changed = $true
            }

            if (-not $Xml.config.login) {
                $Xml.config.SetAttribute('login', '')
                $Changed = $true
            }

            if (-not $Xml.config.username) {
                $Xml.config.SetAttribute('username', '')
                $Changed = $true
            }

            if ($Changed) {
                $Xml.Save($XmlPath)
                Write-Log "PROFILE_UPDATED | User=$UserName | Path=$XmlPath"
                return $true
            }

            Write-Log "PROFILE_NO_CHANGE | User=$UserName | Path=$XmlPath"
            return $false
        }
        catch {
            Write-Log "XML_READ_FAILED | User=$UserName | Path=$XmlPath | Rebuilding file | $($_.Exception.Message)"
        }
    }

    $Doc = New-Object System.Xml.XmlDocument
    $Decl = $Doc.CreateXmlDeclaration('1.0', 'utf-8', $null)
    [void]$Doc.AppendChild($Decl)

    $Root = $Doc.CreateElement('config')
    [void]$Root.SetAttribute('login', '')
    [void]$Root.SetAttribute('username', '')
    [void]$Root.SetAttribute('companyname', $TargetCompany)
    [void]$Root.SetAttribute('site', $TargetSite)
    [void]$Doc.AppendChild($Root)

    $Doc.Save($XmlPath)
    Write-Log "PROFILE_CREATED | User=$UserName | Path=$XmlPath"
    return $true
}

try {
    Ensure-Directory -Path $LogRoot

    Write-Log '===== ConnectWise Manage Preseed START ====='
    Write-Log "TARGET_SITE=$TargetSite"
    Write-Log "TARGET_COMPANY=$TargetCompany"

    $Profiles = @(Get-TargetProfiles)

    if ($Profiles.Count -eq 0) {
        Finish 'NO_ACTION | No eligible user profiles found under C:\Users'
    }

    foreach ($Profile in $Profiles) {
        try {
            $Changed = Update-ConnectWiseApplicationXml -ProfilePath $Profile.FullName -UserName $Profile.Name
            if ($Changed) {
                $DidRemediate = $true
                $ChangedCount++
            }
        }
        catch {
            Write-Log "PROFILE_PROCESS_FAILED | User=$($Profile.Name) | Path=$($Profile.FullName) | $($_.Exception.Message)"
        }
    }

    if ($ChangedCount -gt 0) {
        Finish "REMEDIATION=COMPLETE | Updated $ChangedCount profile(s)"
    }

    Finish 'NO_ACTION | All eligible profiles already had target Site/Company values'
}
catch {
    Write-Log "ERROR | $($_.Exception.Message)"
    Finish 'ERROR | Script encountered an exception'
}'