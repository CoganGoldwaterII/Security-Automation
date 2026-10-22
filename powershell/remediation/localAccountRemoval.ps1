# ============================================================================
# NAME: Disable Unapproved Local User Accounts
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Endpoints / Elevated or LOCAL SYSTEM
#
# VARIABLES:
#   Required:
#     ProtectedLocalUserName - Approved local account to preserve
#
#   Optional: None
#
# OUTPUT TOKENS:
#   RESULT    | LocalUserDisable=Success Disabled=<Count>
#   NO_ACTION | LocalUserDisable=NoChanges
#   ERROR     | Stage=<Stage> Error="<Message>"
#
#   Exit Code: Always 0 after script execution
#
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   %ProgramData%\AutomationPlaybook\Logs\Disable_Unapproved_Local_Users.log
#
# DESCRIPTION:
#   Disables all enabled local user accounts except:
#     - The built-in Administrator account identified by SID ending in -500
#     - The approved local account specified by ProtectedLocalUserName
#
#   Validates that both protected accounts exist before disabling users.
#   Identifies protected accounts by SID rather than display name.
#
#   Domain accounts are not affected.
#   Accounts are disabled only; they are not deleted.
#
#   Requires administrative privileges or LOCAL SYSTEM.
#   Does not update NinjaOne custom fields.
#
#   WARNING:
#   All other enabled local user accounts are subject to disablement,
#   including legitimate Windows-managed or service accounts.
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ProtectedLocalUserName
)

$ErrorActionPreference = 'Stop'

$LogDirectory = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogPath      = Join-Path $LogDirectory 'Disable_Unapproved_Local_Users.log'

$FinalOutput = $null
$Stage = 'Initialization'
$DisabledCount = 0

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogPath -Value "$Timestamp | $Message"
}

try {
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    Write-Log 'Remediation started.'

    # -----------------------------------------------------------------------
    # RESOLVE PROTECTED LOCAL ACCOUNTS
    # -----------------------------------------------------------------------

    $Stage = 'ResolveProtectedAccounts'

    $BuiltInAdministrator = Get-LocalUser |
        Where-Object { $_.SID.Value -match '-500$' } |
        Select-Object -First 1

    if (-not $BuiltInAdministrator) {
        throw 'Built-in Administrator account (SID ending in -500) was not found.'
    }

    $ApprovedLocalUser = Get-LocalUser -Name $ProtectedLocalUserName -ErrorAction SilentlyContinue

    if (-not $ApprovedLocalUser) {
        throw "Required local account '$ProtectedLocalUserName' was not found."
    }

    $ProtectedSids = @(
        $BuiltInAdministrator.SID.Value
        $ApprovedLocalUser.SID.Value
    )

    # -----------------------------------------------------------------------
    # DISABLE ALL OTHER ENABLED LOCAL USERS
    # -----------------------------------------------------------------------

    $Stage = 'DisableLocalUsers'

    foreach ($LocalUser in Get-LocalUser) {
        if ($ProtectedSids -contains $LocalUser.SID.Value) {
            Write-Log "Preserved protected local account '$($LocalUser.Name)'."
            continue
        }

        if (-not $LocalUser.Enabled) {
            Write-Log "Local account '$($LocalUser.Name)' is already disabled."
            continue
        }

        Disable-LocalUser -SID $LocalUser.SID -ErrorAction Stop
        $DisabledCount++

        Write-Log "Disabled local account '$($LocalUser.Name)'."
    }

    if ($DisabledCount -gt 0) {
        $FinalOutput = "RESULT | LocalUserDisable=Success Disabled=$DisabledCount"
    }
    else {
        $FinalOutput = 'NO_ACTION | LocalUserDisable=NoChanges'
    }

    Write-Log $FinalOutput
}
catch {
    $SafeError = $_.Exception.Message -replace '"', "'"
    $FinalOutput = "ERROR | Stage=$Stage Error=""$SafeError"""

    try {
        if (-not (Test-Path -LiteralPath $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }

        Write-Log $FinalOutput
    }
    catch {
        # Preserve the primary remediation error if logging itself fails.
    }
}

Write-Output $FinalOutput
exit 0