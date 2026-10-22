# ============================================================================
# NAME: Local Administrator Provisioning and Account Removal - Secure Field
# AUTHORED BY: Cogan Goldwater
# TYPE: Manual Remediation
# SCOPE: Windows Endpoints / Elevated or LOCAL SYSTEM / NinjaOne
#
# VARIABLES:
#   Required NinjaOne String/Text:
#     accountName                  - New local administrator username
#     localAdminPasswordFieldName - Name of inherited secure custom field
#   Optional NinjaOne String/Text:
#     accountsToRemove            - Comma-separated local usernames to DELETE
#
# OUTPUT TOKENS:
#   RESULT    | Local administrator created; optional accounts removed
#   NO_ACTION | Reserved (current version does not emit this token)
#   ERROR     | Stage=<stage> | <error message>
#   Exit Code: Always 0 after script execution
#
# CUSTOM FIELDS:
#   Reads:
#     Secure field named by localAdminPasswordFieldName
#     remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
#   Ledger format: yyyy-MM-dd | <action summary>
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   %ProgramData%\AutomationPlaybook\Logs\Local_Admin_Provisioning.log
#
# DESCRIPTION:
#   Reads a secure inherited NinjaOne device field at runtime and uses the
#   password in memory to create and enable the requested local account.
#   Adds the account to the built-in Administrators group, verifying group
#   membership with net.exe without passing the password as an argument.
#   Permanently removes only the local accounts explicitly specified in
#   accountsToRemove and verifies the resulting state.
#
#   Refuses to proceed when accountName already exists; existing credentials
#   are never silently rotated. Does not interact with Ninja Documentation.
#   The password is not intentionally logged, displayed, passed to a child
#   process, saved in the ledger, or written to disk by this script.
#
#   WARNING:
#   Account removal is PERMANENT and can affect dependent services or access.
#   Confirm removal targets before execution. This version does not enforce
#   a built-in-Administrator SID exclusion for accountsToRemove.
# ============================================================================

$ErrorActionPreference = 'Stop'

$LogDirectory = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogPath = Join-Path $LogDirectory 'Local_Admin_Provisioning.log'


$LedgerMaxLines = 50
$LedgerMaxCharacters = 8000

$BuildId = 'SecureField_v1_5_LocalOnly'
$Stage = 'Initialize'
$FinalToken = 'ERROR'
$FinalSummary = 'Automation did not complete.'
$PlainTextPassword = $null
$SecurePassword = $null

function ConvertTo-SafeText {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return (([string]$Value) -replace '[\r\n|]+', ' ').Trim()
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    try {
        if (-not (Test-Path -LiteralPath $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -LiteralPath $LogPath -Value "$Timestamp | $Message" -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Logging failure must never corrupt the final NinjaOne output contract.
    }
}

function Get-AdministratorsGroup {
    $Group = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop

    if ($null -eq $Group) {
        throw 'Built-in local Administrators group could not be resolved.'
    }

    return $Group
}

function Test-LocalAdminMembership {
    param(
        [Parameter(Mandatory)]
        [object]$User,

        [Parameter(Mandatory)]
        [object]$AdministratorsGroup
    )

    $NetExe = Join-Path $env:SystemRoot 'System32\net.exe'

    $Output = @(
        & $NetExe localgroup $AdministratorsGroup.Name 2>&1
    )

    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        $SafeOutput = ConvertTo-SafeText -Value ($Output -join ' ')
        throw "Unable to enumerate local Administrators group with net.exe. ExitCode=$ExitCode Output=$SafeOutput"
    }

    $LocalName = [string]$User.Name
    $QualifiedName = "$env:COMPUTERNAME\$LocalName"

    foreach ($Line in $Output) {
        $Member = ([string]$Line).Trim()

        if (
            $Member -ieq $LocalName -or
            $Member -ieq $QualifiedName
        ) {
            return $true
        }
    }

    return $false
}

function Add-LocalAdminMembership {
    param(
        [Parameter(Mandatory)]
        [object]$User,

        [Parameter(Mandatory)]
        [object]$AdministratorsGroup
    )

    $NetExe = Join-Path $env:SystemRoot 'System32\net.exe'

    $Output = @(
        & $NetExe localgroup $AdministratorsGroup.Name $User.Name /add 2>&1
    )

    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        $SafeOutput = ConvertTo-SafeText -Value ($Output -join ' ')
        throw "Unable to add '$($User.Name)' to local Administrators group. ExitCode=$ExitCode Output=$SafeOutput"
    }
}

function Update-RemediationLedger {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not (Get-Command -Name 'Ninja-Property-Set' -ErrorAction SilentlyContinue)) {
        throw 'Ninja-Property-Set is unavailable.'
    }

    if (-not (Get-Command -Name 'Ninja-Property-Get' -ErrorAction SilentlyContinue)) {
        throw 'Ninja-Property-Get is unavailable.'
    }

    $Date = Get-Date -Format 'yyyy-MM-dd'
    $SafeMessage = ConvertTo-SafeText -Value $Message
    $Entry = "$Date | $SafeMessage"

    $ExistingText = ''

    try {
        $ExistingText = [string](Ninja-Property-Get 'remediationSummary')
    }
    catch {
        Write-Log "WARNING | Could not read remediationSummary before append | $(ConvertTo-SafeText -Value $_.Exception.Message)"
        $ExistingText = ''
    }

    $Lines = @()

    if (-not [string]::IsNullOrWhiteSpace($ExistingText)) {
        $Lines = @(
            $ExistingText -split '\r?\n' |
                ForEach-Object { $_.Trim() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }

    if ($Lines -notcontains $Entry) {
        $Lines += $Entry
    }

    if ($Lines.Count -gt $LedgerMaxLines) {
        $Lines = @($Lines | Select-Object -Last $LedgerMaxLines)
    }

    while (
        $Lines.Count -gt 1 -and
        (($Lines -join "`r`n").Length -gt $LedgerMaxCharacters)
    ) {
        $Lines = @($Lines | Select-Object -Skip 1)
    }

    $UpdatedSummary = $Lines -join "`r`n"

    if ($UpdatedSummary.Length -gt $LedgerMaxCharacters) {
        throw 'remediationSummary exceeds the configured character cap.'
    }

    Ninja-Property-Set -Name 'lastRemediationDate' -Value $Date
    Ninja-Property-Set -Name 'remediationSummary' -Value $UpdatedSummary

    Write-Log "LEDGER | Updated | Entry=$Entry"
}

try {
    $Stage = 'Preconditions'
    Write-Log "START | Manual local admin provisioning | Build=$BuildId"

    foreach ($RequiredCommand in @(
        'Get-LocalUser',
        'New-LocalUser',
        'Enable-LocalUser',
        'Remove-LocalUser',
        'Get-LocalGroup'
    )) {
        if (-not (Get-Command -Name $RequiredCommand -ErrorAction SilentlyContinue)) {
            throw "Required command is unavailable: $RequiredCommand"
        }
    }

    $PasswordFieldName = ([string]$env:localAdminPasswordFieldName).Trim()

    if ([string]::IsNullOrWhiteSpace($PasswordFieldName)) {
        throw 'Required configuration localAdminPasswordFieldName is empty.'
    }

    $Username = ([string]$env:accountName).Trim()
    $AccountsInput = ([string]$env:accountsToRemove).Trim()

    if ([string]::IsNullOrWhiteSpace($Username)) {
        throw 'Required script variable accountName is empty.'
    }

    if ($Username -match '\[|\]|:|;|\||=|\+|\*|\?|<|>|/|\\|,|"|@') {
        throw 'username contains one or more unsupported local-account characters.'
    }

    if ($Username -match '\s') {
        throw 'username must not contain whitespace.'
    }

    if ($Username.Length -gt 20) {
        throw 'username must be 20 characters or fewer.'
    }

    $ExistingUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue

    if ($null -ne $ExistingUser) {
        throw "Safety check failed: local account '$Username' already exists. V1 does not rotate existing credentials."
    }

    $AccountsToRemove = @()

    if (-not [string]::IsNullOrWhiteSpace($AccountsInput)) {
        $AccountsToRemove = @(
            $AccountsInput -split ',' |
                ForEach-Object { $_.Trim() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )
    }

    foreach ($Target in $AccountsToRemove) {
        if ($Target -ieq $Username) {
            throw 'Safety check failed: username is also present in accountsToRemove.'
        }
    }

    Write-Log "PRECONDITION | Username=$Username | RemoveTargetCount=$($AccountsToRemove.Count)"

    $Stage = 'SecureFieldRead'

    if (-not (Get-Command -Name 'Ninja-Property-Get' -ErrorAction SilentlyContinue)) {
        throw 'Ninja-Property-Get is unavailable.'
    }

    $PlainTextPassword = [string](Ninja-Property-Get -Name $PasswordFieldName)

    if ([string]::IsNullOrWhiteSpace($PlainTextPassword)) {
        throw "Secure custom field '$PasswordFieldName' is empty or unavailable."
    }

    $SecurePassword = ConvertTo-SecureString `
        -String $PlainTextPassword `
        -AsPlainText `
        -Force

    Write-Log "SECURE_FIELD | Effective inherited value retrieved | Field=$PasswordFieldName"

    $Stage = 'CreateAccount'

    Write-Log "ACTION | Creating local account | Name=$Username"

    New-LocalUser `
        -Name $Username `
        -Password $SecurePassword `
        -Description 'Managed local administrator account' `
        -ErrorAction Stop | Out-Null

    $CreatedUser = Get-LocalUser -Name $Username -ErrorAction Stop

    if ($null -eq $CreatedUser) {
        throw "Local account creation could not be verified for '$Username'."
    }

    Write-Log "VERIFY | Local account exists | Name=$Username"

    if (-not $CreatedUser.Enabled) {
        Write-Log "ACTION | Enabling local account | Name=$Username"

        Enable-LocalUser -Name $Username -ErrorAction Stop
        $CreatedUser = Get-LocalUser -Name $Username -ErrorAction Stop

        if (-not $CreatedUser.Enabled) {
            throw "Local account enablement could not be verified for '$Username'."
        }
    }

    Write-Log "VERIFY | Local account enabled | Name=$Username"

    $Stage = 'LocalAdministrators'

    $AdministratorsGroup = Get-AdministratorsGroup

    if (-not (Test-LocalAdminMembership -User $CreatedUser -AdministratorsGroup $AdministratorsGroup)) {
        Write-Log "ACTION | Adding local account to Administrators | Name=$Username"

        Add-LocalAdminMembership `
            -User $CreatedUser `
            -AdministratorsGroup $AdministratorsGroup
    }

    if (-not (Test-LocalAdminMembership -User $CreatedUser -AdministratorsGroup $AdministratorsGroup)) {
        throw "Local Administrators membership could not be verified for '$Username'."
    }

    Write-Log "VERIFY | Local Administrators membership confirmed | Name=$Username"

    $Stage = 'RemoveAccounts'

    $RemovedNow = New-Object System.Collections.Generic.List[string]
        $NotPresent = New-Object System.Collections.Generic.List[string]

    foreach ($Target in $AccountsToRemove) {
        $TargetUser = Get-LocalUser -Name $Target -ErrorAction SilentlyContinue

        if ($null -eq $TargetUser) {
            $NotPresent.Add($Target)
            Write-Log "NO_CHANGE | Removal target not present | Name=$Target"
            continue
        }

        Write-Log "ACTION | Removing local account | Name=$Target"

        Remove-LocalUser -Name $Target -ErrorAction Stop

        $VerifiedTarget = Get-LocalUser -Name $Target -ErrorAction SilentlyContinue

        if ($null -ne $VerifiedTarget) {
            throw "Local account removal could not be verified for '$Target'."
        }

        $RemovedNow.Add($Target)
        Write-Log "VERIFY | Local account removed | Name=$Target"
    }

    $Stage = 'FinalVerification'

    $VerifiedUser = Get-LocalUser -Name $Username -ErrorAction Stop

    if (-not $VerifiedUser.Enabled) {
        throw "Final verification failed: '$Username' is not enabled."
    }

    if (-not (Test-LocalAdminMembership -User $VerifiedUser -AdministratorsGroup $AdministratorsGroup)) {
        throw "Final verification failed: '$Username' is not a local Administrator."
    }

    foreach ($Target in $AccountsToRemove) {
        $VerifiedTarget = Get-LocalUser -Name $Target -ErrorAction SilentlyContinue

        if ($null -ne $VerifiedTarget) {
            throw "Final verification failed: removal target '$Target' still exists."
        }
    }

    Write-Log "VERIFY | Final local state confirmed | Admin=$Username | RemoveTargets=$($AccountsToRemove.Count)"

    $Stage = 'Ledger'

    $LedgerMessage = "Local admin '$Username' created; removed $($RemovedNow.Count) specified local account(s)."

    Update-RemediationLedger -Message $LedgerMessage

    $FinalToken = 'RESULT'
    $FinalSummary = "Local admin created. Admin=$Username Removed=$($RemovedNow.Count) NotPresent=$($NotPresent.Count)"
}
catch {
    $SafeError = ConvertTo-SafeText -Value $_.Exception.Message

    Write-Log "ERROR | Stage=$Stage | $SafeError"

    $FinalToken = 'ERROR'
    $FinalSummary = "Stage=$Stage | $SafeError"
}
finally {
    # Reduce the lifetime of secret references. This is not cryptographic memory erasure.
    $PlainTextPassword = $null
    $SecurePassword = $null

    $SafeFinalSummary = ConvertTo-SafeText -Value $FinalSummary
    Write-Log "FINAL | $FinalToken | $SafeFinalSummary"

    Write-Output "$FinalToken | $SafeFinalSummary"
}

exit 0
