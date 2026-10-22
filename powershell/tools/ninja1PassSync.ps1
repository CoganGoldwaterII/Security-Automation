# ============================================================================
# NAME: Ninja to 1Password Organization Sync POC
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows / NinjaOne / Approved Credential Broker / One Organization
#
# VARIABLES:
#   Required (script parameters, no built-in environment-specific values):
#     OrganizationName           - NinjaOne organization display name
#     OrganizationId             - NinjaOne organization numeric ID
#     OnePasswordVaultName       - matching destination vault name
#     AutomationVaultName        - 1Password vault for OAuth source credentials
#     OAuthAppItemName           - OAuth app credential item in source vault
#     RefreshTokenItemName      - delegated refresh-token item in source vault
#     AutomationTokenFieldName   - Ninja secure field for source-vault account
#     DestinationTokenFieldName  - Ninja secure field for destination-vault account
#   Optional:
#     LogRoot                    - defaults to ProgramData\AutomationPlaybook\Logs
#
# OUTPUT TOKENS:
#   RESULT    | One or more 1Password items created or passwords corrected
#   NO_ACTION | Existing destination passwords already matched Ninja
#   ERROR     | Configuration, authentication, sync, or verification failure
#   Exit Code: Always 0 after script execution
#
# CUSTOM FIELDS:
#   Reads: Secure Ninja fields specified by AutomationTokenFieldName and
#          DestinationTokenFieldName
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   <LogRoot>\Ninja_1Password_Org_Sync_POC.log
#
# DESCRIPTION:
#   Performs a NinjaOne-authoritative, single-organization sync of Passwords
#   documents to 1Password. Creates missing destination items, corrects
#   mismatched passwords, and verifies changed passwords by read-back.
#   Existing item title, username, URL, and notes are preserved on updates.
#
#   Retrieves source OAuth credentials and the delegated refresh token from
#   a configured 1Password vault. Source Ninja reads use the delegated token.
#   A separate service account is used for destination vault writes.
#   The refresh token is never exported by this sync; a separate bootstrap
#   utility is required if the token is invalid or rotates.
#
#   Uses an in-memory native stdin transport for 1Password JSON payloads and
#   performs dry-runs before writes. Requests Windows Error Reporting NOHEAP
#   for the running PowerShell process, without making its success mandatory.
#
#   PUBLIC-REPOSITORY COPY:
#   Contains no customer name, customer organization ID, customer vault name,
#   private vault/item names, secure-field identifiers, or broker device ID.
#   Configuration validation stops processing before any credential access
#   if required values are missing. Run only from an approved broker.
# ============================================================================

[CmdletBinding()]
param(
    # Supply values through the approved automation's parameter configuration.
    # This public example intentionally contains no real organization or vault IDs.
    [string]$OrganizationName = '',
    [int]$OrganizationId = 0,
    [string]$OnePasswordVaultName = '',
    [string]$AutomationVaultName = '',
    [string]$OAuthAppItemName = '',
    [string]$RefreshTokenItemName = '',
    [string]$AutomationTokenFieldName = '',
    [string]$DestinationTokenFieldName = '',
    [string]$LogRoot = (Join-Path $env:ProgramData 'AutomationPlaybook\Logs')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$BuildId = 'NINJA-1PASSWORD-ORG-SYNC-POC-v8.5-20260918'
$NinjaConsoleUrl = $null
$NinjaOAuthUrl = 'https://app.ninjarmm.com'

$OAuthConsoleUrlFieldLabel = 'consoleUrl'
$OAuthClientIdFieldLabel = 'clientId'
$OAuthClientSecretFieldLabel = 'clientSecret'
$RefreshTokenFieldLabel = 'refreshToken'
$TemplateName = 'Passwords'

$LogPath = Join-Path $LogRoot 'Ninja_1Password_Org_Sync_POC.log'
$CurrentStage = 'Initialize'

$AutomationOnePasswordToken = $null
$DestinationOnePasswordToken = $null
$NinjaClientId = $null
$NinjaClientSecret = $null
$AccessToken = $null
$RefreshToken = $null
$RotatedRefreshToken = $null
$SourcePassword = $null
$DestinationPassword = $null
$VerificationPassword = $null
$ItemJson = $null
$CreatedCount = 0
$UpdatedCount = 0
$VerifiedCount = 0
$UnchangedCount = 0
$RefreshTokenManualUpdateRequired = $false
$WerNoHeapSuppressed = $false

function Initialize-Logging {
    if (-not (Test-Path -LiteralPath $LogRoot)) {
        New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $LogPath)) {
        New-Item -ItemType File -Path $LogPath -Force | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff zzz'
    "$Timestamp | $Message" | Add-Content -LiteralPath $LogPath -Encoding UTF8
}

function Enable-WerHeapSuppression {
    $TypeDefinition = @'
using System;
using System.Runtime.InteropServices;

public static class AutomationWerNative
{
    [DllImport("kernel32.dll")]
    public static extern int WerSetFlags(uint dwFlags);

    [DllImport("kernel32.dll")]
    public static extern int WerGetFlags(IntPtr hProcess, out uint pdwFlags);
}
'@

    if ($null -eq ('AutomationWerNative' -as [type])) {
        Add-Type -TypeDefinition $TypeDefinition -Language CSharp -ErrorAction Stop
    }

    [uint32]$NoHeapFlag = 1
    [uint32]$ExistingFlags = 0
    [uint32]$VerifiedFlags = 0
    $CurrentProcess = [System.Diagnostics.Process]::GetCurrentProcess()

    try {
        $GetResult = [AutomationWerNative]::WerGetFlags($CurrentProcess.Handle, [ref]$ExistingFlags)

        if ($GetResult -ne 0) {
            throw "WerGetFlags failed before NOHEAP enablement. HRESULT=$GetResult"
        }

        [uint32]$DesiredFlags = $ExistingFlags -bor $NoHeapFlag
        $SetResult = [AutomationWerNative]::WerSetFlags($DesiredFlags)

        if ($SetResult -ne 0) {
            throw "WerSetFlags failed while enabling WER NOHEAP. HRESULT=$SetResult"
        }

        $VerifyResult = [AutomationWerNative]::WerGetFlags($CurrentProcess.Handle, [ref]$VerifiedFlags)

        if ($VerifyResult -ne 0) {
            throw "WerGetFlags failed while verifying WER NOHEAP. HRESULT=$VerifyResult"
        }

        if (($VerifiedFlags -band $NoHeapFlag) -ne $NoHeapFlag) {
            throw "WER NOHEAP verification failed. ReturnedFlags=$VerifiedFlags"
        }

        return $true
    }
    finally {
        if ($null -ne $CurrentProcess) {
            $CurrentProcess.Dispose()
        }
    }
}

function Convert-SafeOutput {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $Text = [string]$Value

    foreach ($Secret in @(
        $AutomationOnePasswordToken,
        $DestinationOnePasswordToken,
        $NinjaClientId,
        $NinjaClientSecret,
        $AccessToken,
        $RefreshToken,
        $RotatedRefreshToken,
        $SourcePassword,
        $DestinationPassword,
        $VerificationPassword,
        $ItemJson
    )) {
        if (-not [string]::IsNullOrEmpty([string]$Secret)) {
            $Text = $Text.Replace([string]$Secret, '[REDACTED]')
        }
    }

    $Text = $Text `
        -replace '[\r\n]+', ' ' `
        -replace '(?i)(access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|authorization[_ -]?code|password|credential|secret)\s*[:=]\s*["'']?[^,\s;"'']+', '$1=[REDACTED]'

    if ($Text.Length -gt 700) {
        $Text = $Text.Substring(0, 700)
    }

    return $Text
}

function ConvertTo-ObjectArray {
    param(
        [AllowNull()]
        [object]$Response
    )

    if ($null -eq $Response) {
        return @()
    }

    if ($Response -is [Array]) {
        return @($Response)
    }

    foreach ($PropertyName in @('results', 'data', 'items')) {
        if ($Response.PSObject.Properties.Name -contains $PropertyName) {
            return @($Response.$PropertyName)
        }
    }

    return @($Response)
}

function Get-OpExecutable {
    $Command = Get-Command 'op.exe' -ErrorAction SilentlyContinue

    if ($null -ne $Command) {
        return $Command.Source
    }

    foreach ($Candidate in @(
        'C:\Program Files\1Password CLI\op.exe',
        'C:\Program Files\1Password\op.exe',
        'C:\Windows\System32\op.exe'
    )) {
        if (Test-Path -LiteralPath $Candidate) {
            return $Candidate
        }
    }

    throw '1Password CLI op.exe was not found.'
}


function Get-OnePasswordFieldByExactLabel {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$FieldLabel,

        [Parameter(Mandatory)]
        [string]$ItemName
    )

    $Matches = @(
        $Item.fields |
            Where-Object { [string]$_.label -ceq $FieldLabel }
    )

    if ($Matches.Count -ne 1) {
        throw "Expected exactly one field labeled '$FieldLabel' on 1Password item '$ItemName'. Matches=$($Matches.Count)"
    }

    return $Matches[0]
}

function Get-OnePasswordPasswordField {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$ItemName
    )

    $Matches = @(
        $Item.fields |
            Where-Object {
                [string]$_.id -ieq 'password' -or
                [string]$_.purpose -ieq 'PASSWORD'
            }
    )

    if ($Matches.Count -ne 1) {
        throw "Expected exactly one password field on 1Password item '$ItemName'. Matches=$($Matches.Count)"
    }

    return $Matches[0]
}

function ConvertTo-NormalizedName {
    param(
        [AllowNull()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    return [regex]::Replace($Name.Trim().ToLowerInvariant(), '[^\p{L}\p{Nd}]', '')
}

function Get-NinjaFieldScalar {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [ValueType]) {
        return [string]$Value
    }

    foreach ($PropertyName in @('value', 'text', 'content', 'url', 'secret')) {
        if ($Value.PSObject.Properties.Name -contains $PropertyName) {
            return [string]$Value.$PropertyName
        }
    }

    return $null
}

function Get-NinjaDocumentCredential {
    param(
        [Parameter(Mandatory)]
        [object]$Document,

        [Parameter(Mandatory)]
        [object]$Template
    )

    $Records = @()

    foreach ($TemplateField in @($Template.fields)) {
        $Name = [string]$TemplateField.fieldName

        if ([string]::IsNullOrWhiteSpace($Name)) {
            continue
        }

        $RawValue = $null
        $Matched = $false

        if ($Document.fields.PSObject.Properties.Name -ccontains $Name) {
            $RawValue = $Document.fields.$Name
            $Matched = $true
        }
        else {
            $FieldMatches = @(
                $Document.fields |
                    Where-Object { [string]$_.name -ceq $Name }
            )

            if ($FieldMatches.Count -gt 1) {
                throw "Document '$([string]$Document.documentName)' returned duplicate field '$Name'."
            }

            if ($FieldMatches.Count -eq 1) {
                $RawValue = $FieldMatches[0].value
                $Matched = $true
            }
        }

        if (-not $Matched) {
            continue
        }

        $Label = [string]$TemplateField.fieldLabel

        if ([string]::IsNullOrWhiteSpace($Label)) {
            $Label = $Name
        }

        $Records += [PSCustomObject]@{
            Name = $Name
            Label = $Label
            Type = [string]$TemplateField.fieldType
            Value = Get-NinjaFieldScalar -Value $RawValue
        }
    }

    $PasswordFields = @(
        $Records |
            Where-Object {
                $_.Type -ieq 'TEXT_ENCRYPTED' -and
                -not [string]::IsNullOrWhiteSpace([string]$_.Value)
            }
    )

    if ($PasswordFields.Count -ne 1) {
        throw "Document '$([string]$Document.documentName)' must contain exactly one populated TEXT_ENCRYPTED field. Matches=$($PasswordFields.Count)"
    }

    $Password = [string]$PasswordFields[0].Value

    if ($Password -match '^SECURE_VALUE_PLACEHOLDER_[0-9a-fA-F-]+$') {
        throw "Ninja returned a secure-value placeholder for document '$([string]$Document.documentName)'."
    }

    $UsernameFields = @(
        $Records |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_.Value) -and
                ("$($_.Name) $($_.Label)" -match '(?i)\b(username|user.?name|user.?id|login|login.?name)\b')
            }
    )

    if ($UsernameFields.Count -gt 1) {
        throw "Document '$([string]$Document.documentName)' has multiple possible username fields."
    }

    $UrlFields = @(
        $Records |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_.Value) -and
                (
                    $_.Type -ieq 'URL' -or
                    "$($_.Name) $($_.Label)" -match '(?i)\b(url|website|portal|site|web.?address)\b'
                )
            }
    )

    if ($UrlFields.Count -gt 1) {
        throw "Document '$([string]$Document.documentName)' has multiple possible URL fields."
    }

    $NotesFields = @(
        $Records |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_.Value) -and
                ("$($_.Name) $($_.Label)" -match '(?i)\b(note|notes|description)\b')
            }
    )

    if ($NotesFields.Count -gt 1) {
        throw "Document '$([string]$Document.documentName)' has multiple possible notes fields."
    }

    return [PSCustomObject]@{
        Password = $Password
        Username = if ($UsernameFields.Count -eq 1) { [string]$UsernameFields[0].Value } else { $null }
        Url = if ($UrlFields.Count -eq 1) { [string]$UrlFields[0].Value } else { $null }
        Notes = if ($NotesFields.Count -eq 1) { [string]$NotesFields[0].Value } else { $null }
    }
}

function Set-OnePasswordItemField {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$FieldId,

        [AllowNull()]
        [string]$Value
    )

    $Field = @(
        $Item.fields |
            Where-Object { [string]$_.id -ieq $FieldId }
    ) | Select-Object -First 1

    if ($null -eq $Field) {
        return $false
    }

    $Field.value = if ($null -eq $Value) { '' } else { $Value }
    return $true
}

function Set-OnePasswordItemFromCredential {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [object]$Credential,

        [Parameter(Mandatory)]
        [object]$Document
    )

    $Title = [string]$Document.documentName
    $Item.title = $Title

    if (-not (Set-OnePasswordItemField -Item $Item -FieldId 'password' -Value ([string]$Credential.Password))) {
        throw "1Password template for '$Title' does not expose a password field."
    }

    [void](Set-OnePasswordItemField -Item $Item -FieldId 'username' -Value ([string]$Credential.Username))

    if ($Item.PSObject.Properties.Name -contains 'urls') {
        if ([string]::IsNullOrWhiteSpace([string]$Credential.Url)) {
            $Item.urls = @()
        }
        else {
            $Item.urls = @([PSCustomObject]@{ primary = $true; href = [string]$Credential.Url })
        }
    }

    $DestinationNotes = @(
        if (-not [string]::IsNullOrWhiteSpace([string]$Credential.Notes)) {
            [string]$Credential.Notes
        }

        ''
        '--- Ninja Sync Metadata ---'
        'Synced from NinjaOne.'
        "Organization: $OrganizationName"
        "Ninja Organization ID: $OrganizationId"
        "Ninja Document: $Title"
        "Ninja Document ID: $([string]$Document.documentId)"
        "Ninja Template: $([string]$Document.documentTemplateName)"
        "Ninja Template ID: $([string]$Document.documentTemplateId)"
        'Ninja is authoritative.'
    ) -join "`n"

    [void](Set-OnePasswordItemField -Item $Item -FieldId 'notesPlain' -Value $DestinationNotes)
    return $Item
}

function Set-OnePasswordItemVaultId {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$VaultId
    )

    if (-not ($Item.PSObject.Properties.Name -contains 'vault') -or $null -eq $Item.vault) {
        $Item | Add-Member -MemberType NoteProperty -Name 'vault' -Value ([PSCustomObject]@{}) -Force
    }

    if ($Item.vault.PSObject.Properties.Name -contains 'id') {
        $Item.vault.id = $VaultId
    }
    else {
        $Item.vault | Add-Member -MemberType NoteProperty -Name 'id' -Value $VaultId -Force
    }

    return $Item
}


function ConvertTo-OnePasswordStdinJson {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$DocumentName
    )

    # Preserve the complete 1Password template/item schema. This is the same object
    # shape used by the known-good v7; only the transport changes.
    $Json = ($Item | ConvertTo-Json -Depth 25 -Compress).Trim()

    if ([string]::IsNullOrWhiteSpace($Json)) {
        throw "Generated 1Password stdin JSON was empty for '$DocumentName'."
    }

    if ($Json[0] -ne '{' -or $Json[$Json.Length - 1] -ne '}') {
        throw "Generated 1Password stdin JSON was not a single JSON object for '$DocumentName'."
    }

    if ($Json.IndexOf([char]0xFEFF) -ge 0) {
        throw "Generated 1Password stdin JSON contained a BOM character for '$DocumentName'."
    }

    if ($Json.IndexOf([char]0x0000) -ge 0) {
        throw "Generated 1Password stdin JSON contained a NUL character for '$DocumentName'."
    }

    if ($Json.Contains("`r") -or $Json.Contains("`n")) {
        throw "Generated 1Password stdin JSON was not single-line for '$DocumentName'."
    }

    try {
        $RoundTrip = $Json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Generated 1Password stdin JSON failed local validation for '$DocumentName'."
    }

    if ([string]$RoundTrip.title -cne [string]$Item.title) {
        throw "Generated 1Password stdin JSON title failed round-trip validation for '$DocumentName'."
    }

    if ([string]$RoundTrip.category -cne [string]$Item.category) {
        throw "Generated 1Password stdin JSON category failed round-trip validation for '$DocumentName'."
    }

    $RoundTrip = $null
    return $Json
}


function Invoke-OpJsonViaNativeStdin {
    param(
        [Parameter(Mandatory)]
        [string]$OpExe,

        [Parameter(Mandatory)]
        [string]$Json,

        [Parameter(Mandatory)]
        [string]$OpArguments,

        [Parameter(Mandatory)]
        [string]$Context
    )

    if ([string]::IsNullOrWhiteSpace($Json)) {
        throw "1Password stdin payload was empty for '$Context'."
    }

    if ($Json.Contains("`r") -or $Json.Contains("`n")) {
        throw "1Password stdin payload was not single-line before native relay for '$Context'."
    }

    # The child PowerShell receives the JSON only through stdin. It validates one
    # object, compacts it again, and writes UTF-8 without BOM to stdout. cmd.exe owns
    # the pipe from that stdout directly into op.exe stdin, avoiding the Windows
    # PowerShell 5.1 native-command pipeline as the final transport.
    $ProducerCode = @'
$ErrorActionPreference = 'Stop'
$Raw = [Console]::In.ReadToEnd()
$Object = $Raw | ConvertFrom-Json -ErrorAction Stop
$Json = $Object | ConvertTo-Json -Depth 25 -Compress
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::Out.Write($Json)
'@

    $ProducerEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($ProducerCode)
    )

    $PowerShellExe = Join-Path $PSHOME 'powershell.exe'

    if (-not (Test-Path -LiteralPath $PowerShellExe)) {
        throw "Windows PowerShell executable was not found for native stdin relay."
    }

    $NativeCommand = (
        '"{0}" -NoProfile -NonInteractive -EncodedCommand {1} | "{2}" {3}' -f
        $PowerShellExe,
        $ProducerEncoded,
        $OpExe,
        $OpArguments
    )

    $PreviousOutputEncoding = $OutputEncoding
    try {
        $OutputEncoding = New-Object Text.UTF8Encoding($false)
        $OutputRaw = $Json | & $env:ComSpec /d /s /c $NativeCommand 2>&1
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $OutputEncoding = $PreviousOutputEncoding
        $PreviousOutputEncoding = $null
        $ProducerEncoded = $null
        $ProducerCode = $null
        $NativeCommand = $null
    }

    return [PSCustomObject]@{
        ExitCode = $ExitCode
        Output = @($OutputRaw)
    }
}

function Write-OnePasswordItemEdit {
    param(
        [Parameter(Mandatory)]
        [string]$OpExe,

        [Parameter(Mandatory)]
        [string]$VaultId,

        [Parameter(Mandatory)]
        [string]$ItemId,

        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$DocumentName
    )

    if ($ItemId -notmatch '^[A-Za-z0-9]+$' -or $VaultId -notmatch '^[A-Za-z0-9]+$') {
        throw "1Password item or vault ID contained an unexpected character for '$DocumentName'."
    }

    $script:ItemJson = ConvertTo-OnePasswordStdinJson -Item $Item -DocumentName $DocumentName
    Write-Log "PASS | 1Password edit JSON prepared for stdin Document='$DocumentName' FullTemplate=True SingleObject=True SingleLine=True Bom=False Nul=False ValuesLogged=False"

    $EditDryRun = Invoke-OpJsonViaNativeStdin `
        -OpExe $OpExe `
        -Json $script:ItemJson `
        -OpArguments "item edit $ItemId --vault $VaultId --dry-run --format json" `
        -Context "edit dry-run $DocumentName"

    if ($EditDryRun.ExitCode -ne 0) {
        throw "1Password edit stdin dry-run failed for '$DocumentName': " + (Convert-SafeOutput -Value ($EditDryRun.Output -join ' '))
    }

    Write-Log "PASS | 1Password edit native-stdin dry-run accepted client JSON Document='$DocumentName' ValuesLogged=False"
    $EditDryRun = $null

    $EditResult = Invoke-OpJsonViaNativeStdin `
        -OpExe $OpExe `
        -Json $script:ItemJson `
        -OpArguments "item edit $ItemId --vault $VaultId --format json" `
        -Context "edit $DocumentName"

    if ($EditResult.ExitCode -ne 0) {
        throw "1Password item update failed for '$DocumentName': " + (Convert-SafeOutput -Value ($EditResult.Output -join ' '))
    }

    $EditResult = $null
    $script:ItemJson = $null
}

Initialize-Logging
[Console]::WriteLine("BUILD | $BuildId")
Write-Log "START | Build=$BuildId Ninja-to-1Password unattended organization sync POC"

try {
    $CurrentStage = 'ConfigurationValidation'

    $RequiredSettings = @(
        @{ Name = 'OrganizationName';          Value = $OrganizationName }
        @{ Name = 'OnePasswordVaultName';     Value = $OnePasswordVaultName }
        @{ Name = 'AutomationVaultName';      Value = $AutomationVaultName }
        @{ Name = 'OAuthAppItemName';         Value = $OAuthAppItemName }
        @{ Name = 'RefreshTokenItemName';     Value = $RefreshTokenItemName }
        @{ Name = 'AutomationTokenFieldName'; Value = $AutomationTokenFieldName }
        @{ Name = 'DestinationTokenFieldName';Value = $DestinationTokenFieldName }
    )

    foreach ($Setting in $RequiredSettings) {
        if ([string]::IsNullOrWhiteSpace([string]$Setting.Value)) {
            throw "Required configuration parameter '$($Setting.Name)' is missing."
        }
    }

    if ($OrganizationId -le 0) {
        throw 'Required configuration parameter OrganizationId must be greater than zero.'
    }

    $CurrentStage = 'WerHeapSuppression'

    try {
        $WerNoHeapSuppressed = [bool](Enable-WerHeapSuppression)
        Write-Log 'PASS | Windows Error Reporting heap collection suppressed for current PowerShell process Flag=WER_FAULT_REPORTING_FLAG_NOHEAP Verified=True'
    }
    catch {
        $WerNoHeapSuppressed = $false
        $WerError = Convert-SafeOutput -Value $_.Exception.Message
        Write-Log "WARN | Unable to suppress Windows Error Reporting heap collection for current PowerShell process; sync will continue Error='$WerError'"
        $WerError = $null
    }

    $CurrentStage = 'NinjaSecureFieldBootstrap'

    if ($null -eq (Get-Command 'Ninja-Property-Get' -ErrorAction SilentlyContinue)) {
        throw 'Ninja-Property-Get is unavailable. This build must run through NinjaOne on approved credential broker.'
    }

    $AutomationOnePasswordToken = (Ninja-Property-Get -Name $AutomationTokenFieldName).Trim()

    if ([string]::IsNullOrWhiteSpace($AutomationOnePasswordToken)) {
        throw 'Ninja secure custom field configured automation token field returned no value.'
    }

    Write-Log 'PASS | Ninja secure field configured automation token field retrieved for Automation-vault reads ValuesLogged=False'

    $CurrentStage = 'OnePasswordCLI'
    $OpExe = Get-OpExecutable
    Write-Log 'PASS | 1Password CLI located'

    $CurrentStage = 'AutomationVaultAuthentication'
    $env:OP_SERVICE_ACCOUNT_TOKEN = $AutomationOnePasswordToken
    $AutomationWhoAmIRaw = & $OpExe whoami --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw 'Automation-vault 1Password service-account authentication failed: ' + (Convert-SafeOutput -Value ($AutomationWhoAmIRaw -join ' '))
    }

    Write-Log "PASS | Automation-vault 1Password service account authenticated Vault='$AutomationVaultName' ValuesLogged=False"
    $AutomationWhoAmIRaw = $null

    $CurrentStage = 'OAuthAppCredentialRead'
    $OAuthAppItemRaw = & $OpExe item get $OAuthAppItemName --vault $AutomationVaultName --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read 1Password item '$OAuthAppItemName' from vault '$AutomationVaultName': " + (Convert-SafeOutput -Value ($OAuthAppItemRaw -join ' '))
    }

    $OAuthAppItem = ($OAuthAppItemRaw -join "`n") | ConvertFrom-Json
    $NinjaConsoleUrl = ([string](Get-OnePasswordFieldByExactLabel -Item $OAuthAppItem -FieldLabel $OAuthConsoleUrlFieldLabel -ItemName $OAuthAppItemName).value).TrimEnd('/')
    $NinjaClientId = [string](Get-OnePasswordFieldByExactLabel -Item $OAuthAppItem -FieldLabel $OAuthClientIdFieldLabel -ItemName $OAuthAppItemName).value
    $NinjaClientSecret = [string](Get-OnePasswordFieldByExactLabel -Item $OAuthAppItem -FieldLabel $OAuthClientSecretFieldLabel -ItemName $OAuthAppItemName).value

    if (
        [string]::IsNullOrWhiteSpace($NinjaConsoleUrl) -or
        [string]::IsNullOrWhiteSpace($NinjaClientId) -or
        [string]::IsNullOrWhiteSpace($NinjaClientSecret)
    ) {
        throw "OAuth app item '$OAuthAppItemName' did not return populated '$OAuthConsoleUrlFieldLabel', '$OAuthClientIdFieldLabel', and '$OAuthClientSecretFieldLabel' fields."
    }

    if ($NinjaConsoleUrl -notmatch '^https://') {
        throw "OAuth app item '$OAuthAppItemName' returned an invalid consoleUrl. HTTPS is required."
    }

    Write-Log "PASS | Configured Ninja OAuth app configuration retrieved from 1Password Item='$OAuthAppItemName' ValuesLogged=False"
    $OAuthAppItemRaw = $null
    $OAuthAppItem = $null

    $CurrentStage = 'RefreshTokenRead'
    $RefreshTokenItemRaw = & $OpExe item get $RefreshTokenItemName --vault $AutomationVaultName --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read 1Password item '$RefreshTokenItemName' from vault '$AutomationVaultName': " + (Convert-SafeOutput -Value ($RefreshTokenItemRaw -join ' '))
    }

    $RefreshTokenItem = ($RefreshTokenItemRaw -join "`n") | ConvertFrom-Json
    $RefreshToken = [string](Get-OnePasswordFieldByExactLabel -Item $RefreshTokenItem -FieldLabel $RefreshTokenFieldLabel -ItemName $RefreshTokenItemName).value

    if ([string]::IsNullOrWhiteSpace($RefreshToken)) {
        $RefreshTokenManualUpdateRequired = $true
        Write-Log "ACTION_REQUIRED | Stored Ninja OAuth refresh token is empty. Run the standalone Ninja OAuth Refresh Token Bootstrap utility, then manually update Vault='$AutomationVaultName' Item='$RefreshTokenItemName' Field='$RefreshTokenFieldLabel' ValuesLogged=False"
        throw "Stored Ninja OAuth refresh token is empty. Run the standalone Ninja OAuth Refresh Token Bootstrap utility before unattended Ninja execution."
    }

    Write-Log "PASS | Stored Ninja OAuth refresh token retrieved Vault='$AutomationVaultName' Item='$RefreshTokenItemName' Field='$RefreshTokenFieldLabel' ValuesLogged=False"
    $RefreshTokenItemRaw = $null
    $RefreshTokenItem = $null

    $CurrentStage = 'RefreshTokenExchange'

    try {
        $TokenHttpResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Post `
            -Uri "$NinjaOAuthUrl/ws/oauth/token" `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body @{
                grant_type = 'refresh_token'
                client_id = $NinjaClientId
                client_secret = $NinjaClientSecret
                refresh_token = $RefreshToken
            } `
            -TimeoutSec 60
    }
    catch {
        $RefreshTokenManualUpdateRequired = $true
        $RefreshExchangeError = Convert-SafeOutput -Value $_.Exception.Message
        Write-Log "ACTION_REQUIRED | Stored Ninja OAuth refresh token exchange failed. Run the standalone Ninja OAuth Refresh Token Bootstrap utility, then manually update Vault='$AutomationVaultName' Item='$RefreshTokenItemName' Field='$RefreshTokenFieldLabel' ValuesLogged=False"
        throw "Stored Ninja OAuth refresh token could not be exchanged. Run the standalone Ninja OAuth Refresh Token Bootstrap utility. Details: $RefreshExchangeError"
    }

    $TokenResponse = $TokenHttpResponse.Content | ConvertFrom-Json
    $AccessToken = [string]$TokenResponse.access_token
    $RotatedRefreshToken = [string]$TokenResponse.refresh_token

    if ([string]::IsNullOrWhiteSpace($AccessToken)) {
        throw 'Ninja refresh-token response did not contain an access token.'
    }

    $ReturnedScopes = @(([string]$TokenResponse.scope) -split '\s+' | Where-Object { $_ })

    if ($ReturnedScopes -notcontains 'monitoring') {
        throw "Ninja refreshed token did not include monitoring scope. ReturnedScope='$([string]$TokenResponse.scope)'"
    }

    if (-not [string]::IsNullOrWhiteSpace($RotatedRefreshToken) -and $RotatedRefreshToken -cne $RefreshToken) {
        $RefreshTokenManualUpdateRequired = $true
        Write-Log "ACTION_REQUIRED | Ninja returned a replacement OAuth refresh token. Main sync will not persist or export it. Run the standalone Ninja OAuth Refresh Token Bootstrap utility, then manually update Vault='$AutomationVaultName' Item='$RefreshTokenItemName' Field='$RefreshTokenFieldLabel' before the next unattended run ValuesLogged=False"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($RotatedRefreshToken)) {
        Write-Log 'PASS | Ninja returned the existing refresh token unchanged; no manual update required ValuesLogged=False'
    }
    else {
        Write-Log 'INFO | Ninja refresh response did not return a replacement refresh token; stored token retained ValuesLogged=False'
    }

    Write-Log "PASS | Ninja delegated access token issued by refresh_token HTTP=$([int]$TokenHttpResponse.StatusCode) ReturnedScope='$([string]$TokenResponse.scope)' ValuesLogged=False"

    $TokenHttpResponse = $null
    $TokenResponse = $null
    $RotatedRefreshToken = $null
    $RefreshToken = $null
    $NinjaClientSecret = $null
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $AutomationOnePasswordToken = $null

    $CurrentStage = 'NinjaDocumentRead'
    $DocumentHttpResponse = Invoke-WebRequest `
        -UseBasicParsing `
        -Method Get `
        -Uri "$NinjaConsoleUrl/v2/organization/$OrganizationId/documents" `
        -Headers @{
            Accept = 'application/json'
            Authorization = "Bearer $AccessToken"
        } `
        -TimeoutSec 60

    $DocumentsResponse = $DocumentHttpResponse.Content | ConvertFrom-Json
    $Documents = @(ConvertTo-ObjectArray -Response $DocumentsResponse)
    $PasswordDocuments = @(
        $Documents |
            Where-Object { [string]$_.documentTemplateName -ceq $TemplateName }
    )

    if ($PasswordDocuments.Count -eq 0) {
        throw "Ninja returned no '$TemplateName' documents for organization ID $OrganizationId."
    }

    $DuplicateDocumentNames = @(
        $PasswordDocuments |
            Group-Object { ConvertTo-NormalizedName -Name ([string]$_.documentName) } |
            Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Name) -or $_.Count -gt 1 }
    )

    if ($DuplicateDocumentNames.Count -gt 0) {
        throw 'Ninja Passwords documents contain an empty or duplicate normalized title. No 1Password write was attempted.'
    }

    Write-Log "PASS | Ninja Passwords documents read HTTP=$([int]$DocumentHttpResponse.StatusCode) OrganizationId=$OrganizationId Count=$($PasswordDocuments.Count) ValuesLogged=False"
    $DocumentHttpResponse = $null
    $DocumentsResponse = $null
    $Documents = $null

    $CurrentStage = 'NinjaSyncSecureField'
    $DestinationOnePasswordToken = (Ninja-Property-Get -Name $DestinationTokenFieldName).Trim()

    if ([string]::IsNullOrWhiteSpace($DestinationOnePasswordToken)) {
        throw 'Ninja secure custom field configured destination token field returned no value.'
    }

    Write-Log 'PASS | Ninja secure field configured destination token field retrieved for destination-vault operations ValuesLogged=False'

    $CurrentStage = 'DestinationOnePasswordAuthentication'
    $env:OP_SERVICE_ACCOUNT_TOKEN = $DestinationOnePasswordToken
    $WhoAmIRaw = & $OpExe whoami --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw 'Destination service account authentication failed: ' + (Convert-SafeOutput -Value ($WhoAmIRaw -join ' '))
    }

    Write-Log 'PASS | Destination service account authenticated for destination-vault operations ExitCode=0 ValuesLogged=False'
    $WhoAmIRaw = $null
    $DestinationOnePasswordToken = $null

    $CurrentStage = 'OnePasswordVaultMatch'
    $VaultListRaw = & $OpExe vault list --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to list 1Password vaults: ' + (Convert-SafeOutput -Value ($VaultListRaw -join ' '))
    }

    $VaultList = @((($VaultListRaw -join "`n") | ConvertFrom-Json))
    $VaultMatches = @($VaultList | Where-Object { [string]$_.name -ceq $OnePasswordVaultName })

    if ($VaultMatches.Count -ne 1) {
        throw "Expected exactly one 1Password vault named '$OnePasswordVaultName'. Matches=$($VaultMatches.Count)"
    }

    $VaultId = [string]$VaultMatches[0].id
    Write-Log "PASS | Exact 1Password vault matched Name='$OnePasswordVaultName' Id=$VaultId"

    $CurrentStage = 'OnePasswordItemInventory'
    $ItemListRaw = & $OpExe item list --vault $VaultId --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to list 1Password items: ' + (Convert-SafeOutput -Value ($ItemListRaw -join ' '))
    }

    $ExistingItems = @((($ItemListRaw -join "`n") | ConvertFrom-Json))
    $TemplateCache = @{}

    foreach ($Document in $PasswordDocuments) {
        $DocumentId = [int]$Document.documentId
        $DocumentName = [string]$Document.documentName
        $DocumentTemplateId = [int]$Document.documentTemplateId
        $NormalizedDocumentName = ConvertTo-NormalizedName -Name $DocumentName
        $CurrentStage = "NinjaCredentialRead:$DocumentId"

        $MatchingItems = @(
            $ExistingItems |
                Where-Object {
                    (ConvertTo-NormalizedName -Name ([string]$_.title)) -ceq $NormalizedDocumentName
                }
        )

        if ($MatchingItems.Count -gt 1) {
            throw "Multiple 1Password items matched Ninja document '$DocumentName' after normalization. No further writes were attempted."
        }

        if (-not $TemplateCache.ContainsKey($DocumentTemplateId)) {
            $TemplateHttpResponse = Invoke-WebRequest `
                -UseBasicParsing `
                -Method Get `
                -Uri "$NinjaConsoleUrl/v2/document-templates/$DocumentTemplateId" `
                -Headers @{
                    Accept = 'application/json'
                    Authorization = "Bearer $AccessToken"
                } `
                -TimeoutSec 60

            $DocumentTemplate = $TemplateHttpResponse.Content | ConvertFrom-Json

            if ([string]$DocumentTemplate.name -cne $TemplateName) {
                throw "Document '$DocumentName' template ID $DocumentTemplateId resolved to '$([string]$DocumentTemplate.name)', not '$TemplateName'."
            }

            $TemplateCache[$DocumentTemplateId] = $DocumentTemplate
            Write-Log "PASS | Ninja document template read HTTP=$([int]$TemplateHttpResponse.StatusCode) TemplateId=$DocumentTemplateId Name='$TemplateName'"
            $TemplateHttpResponse = $null
        }

        $Credential = Get-NinjaDocumentCredential -Document $Document -Template $TemplateCache[$DocumentTemplateId]
        $SourcePassword = [string]$Credential.Password
        Write-Log "PASS | Ninja credential mapped Document='$DocumentName' DocumentId=$DocumentId Password=True Username=$(-not [string]::IsNullOrWhiteSpace([string]$Credential.Username)) Url=$(-not [string]::IsNullOrWhiteSpace([string]$Credential.Url)) Notes=$(-not [string]::IsNullOrWhiteSpace([string]$Credential.Notes)) ValuesLogged=False"

        if ($MatchingItems.Count -eq 0) {
            $ItemCategory = if (
                -not [string]::IsNullOrWhiteSpace([string]$Credential.Username) -or
                -not [string]::IsNullOrWhiteSpace([string]$Credential.Url)
            ) { 'Login' } else { 'Password' }

            $CurrentStage = "OnePasswordItemCreate:$DocumentId"
            $ItemTemplateRaw = & $OpExe item template get $ItemCategory 2>&1

            if ($LASTEXITCODE -ne 0) {
                throw "Unable to retrieve 1Password '$ItemCategory' template for '$DocumentName': " + (Convert-SafeOutput -Value ($ItemTemplateRaw -join ' '))
            }

            # First prove the native-stdin relay using the untouched 1Password category
            # template. No client secret is present and --dry-run prevents a write.
            $PristineTemplateObject = ($ItemTemplateRaw -join "`n") | ConvertFrom-Json
            $PristineTemplateJson = ConvertTo-OnePasswordStdinJson `
                -Item $PristineTemplateObject `
                -DocumentName "$ItemCategory pristine template"

            $PristineDryRun = Invoke-OpJsonViaNativeStdin `
                -OpExe $OpExe `
                -Json $PristineTemplateJson `
                -OpArguments "item create --vault $VaultId - --dry-run --format json" `
                -Context "$ItemCategory pristine create dry-run"

            if ($PristineDryRun.ExitCode -ne 0) {
                throw "1Password pristine '$ItemCategory' template failed native-stdin dry-run before client JSON was sent: " + (Convert-SafeOutput -Value ($PristineDryRun.Output -join ' '))
            }

            Write-Log "PASS | 1Password pristine template accepted through native stdin dry-run Category=$ItemCategory ValuesLogged=False"
            $PristineDryRun = $null
            $PristineTemplateJson = $null
            $PristineTemplateObject = $null

            $DestinationItem = ($ItemTemplateRaw -join "`n") | ConvertFrom-Json
            $DestinationItem = Set-OnePasswordItemFromCredential -Item $DestinationItem -Credential $Credential -Document $Document

            $ItemJson = ConvertTo-OnePasswordStdinJson -Item $DestinationItem -DocumentName $DocumentName
            Write-Log "PASS | 1Password create JSON prepared for stdin Document='$DocumentName' FullTemplate=True SingleObject=True SingleLine=True Bom=False Nul=False ValuesLogged=False"

            $CreateDryRun = Invoke-OpJsonViaNativeStdin `
                -OpExe $OpExe `
                -Json $ItemJson `
                -OpArguments "item create --vault $VaultId - --dry-run --format json" `
                -Context "create dry-run $DocumentName"

            if ($CreateDryRun.ExitCode -ne 0) {
                throw "1Password create native-stdin dry-run rejected client JSON for '$DocumentName': " + (Convert-SafeOutput -Value ($CreateDryRun.Output -join ' '))
            }

            Write-Log "PASS | 1Password create native-stdin dry-run accepted client JSON Document='$DocumentName' ValuesLogged=False"
            $CreateDryRun = $null

            $CreateResult = Invoke-OpJsonViaNativeStdin `
                -OpExe $OpExe `
                -Json $ItemJson `
                -OpArguments "item create --vault $VaultId - --format json" `
                -Context "create $DocumentName"

            if ($CreateResult.ExitCode -ne 0) {
                throw "1Password item creation failed for '$DocumentName': " + (Convert-SafeOutput -Value ($CreateResult.Output -join ' '))
            }

            $CreateOutputRaw = @($CreateResult.Output)
            $CreateResult = $null
            $CreatedItem = $CreateOutputRaw | ConvertFrom-Json
            $CreatedItemId = [string]$CreatedItem.id

            if ([string]::IsNullOrWhiteSpace($CreatedItemId)) {
                throw "1Password item creation returned no item ID for '$DocumentName'."
            }

            $CreatedCount++
            Write-Log "PASS | Missing 1Password item created Document='$DocumentName' DocumentId=$DocumentId ItemId=$CreatedItemId Category=$ItemCategory ValuesLogged=False"

            $CurrentStage = "OnePasswordCreateVerification:$DocumentId"
            $VerificationItemRaw = & $OpExe item get $CreatedItemId --vault $VaultId --format json 2>&1

            if ($LASTEXITCODE -ne 0) {
                throw "1Password read-back verification failed for '$DocumentName': " + (Convert-SafeOutput -Value ($VerificationItemRaw -join ' '))
            }

            $VerificationItem = ($VerificationItemRaw -join "`n") | ConvertFrom-Json
            $VerificationPassword = [string](Get-OnePasswordPasswordField -Item $VerificationItem -ItemName $DocumentName).value

            if ($VerificationPassword -cne $SourcePassword) {
                throw "1Password read-back password did not exactly match Ninja for '$DocumentName'."
            }

            $VerifiedCount++
            Write-Log "PASS | Created item password verified Document='$DocumentName' DocumentId=$DocumentId ItemId=$CreatedItemId ValuesLogged=False"
            $ExistingItems += [PSCustomObject]@{ id = $CreatedItemId; title = $DocumentName }

            $CreatedItem = $null
            $CreateOutputRaw = $null
            $DestinationItem = $null
            $VerificationItem = $null
            $VerificationItemRaw = $null
            $ItemJson = $null
        }
        else {
            $ExistingItemId = [string]$MatchingItems[0].id
            $CurrentStage = "OnePasswordExistingItemRead:$DocumentId"
            $ExistingItemRaw = & $OpExe item get $ExistingItemId --vault $VaultId --format json 2>&1

            if ($LASTEXITCODE -ne 0) {
                throw "Unable to read existing 1Password item '$DocumentName': " + (Convert-SafeOutput -Value ($ExistingItemRaw -join ' '))
            }

            $ExistingItem = ($ExistingItemRaw -join "`n") | ConvertFrom-Json
            $ExistingPasswordField = Get-OnePasswordPasswordField -Item $ExistingItem -ItemName $DocumentName
            $DestinationPassword = [string]$ExistingPasswordField.value

            if ($DestinationPassword -ceq $SourcePassword) {
                $UnchangedCount++
                Write-Log "NO_ACTION | Existing item password already matches Ninja Document='$DocumentName' DocumentId=$DocumentId ItemId=$ExistingItemId ValuesLogged=False"
            }
            else {
                $CurrentStage = "OnePasswordExistingItemUpdate:$DocumentId"
                $ExistingPasswordField.value = $SourcePassword
                Write-OnePasswordItemEdit -OpExe $OpExe -VaultId $VaultId -ItemId $ExistingItemId -Item $ExistingItem -DocumentName $DocumentName

                $CurrentStage = "OnePasswordUpdateVerification:$DocumentId"
                $VerificationItemRaw = & $OpExe item get $ExistingItemId --vault $VaultId --format json 2>&1

                if ($LASTEXITCODE -ne 0) {
                    throw "1Password update read-back verification failed for '$DocumentName': " + (Convert-SafeOutput -Value ($VerificationItemRaw -join ' '))
                }

                $VerificationItem = ($VerificationItemRaw -join "`n") | ConvertFrom-Json
                $VerificationPassword = [string](Get-OnePasswordPasswordField -Item $VerificationItem -ItemName $DocumentName).value

                if ($VerificationPassword -cne $SourcePassword) {
                    throw "Updated 1Password password did not exactly match Ninja for '$DocumentName'."
                }

                $UpdatedCount++
                $VerifiedCount++
                Write-Log "PASS | Existing item password corrected from Ninja and verified Document='$DocumentName' DocumentId=$DocumentId ItemId=$ExistingItemId ValuesLogged=False"

                $VerificationItem = $null
                $VerificationItemRaw = $null
            }

            $ExistingItemRaw = $null
            $ExistingItem = $null
            $ExistingPasswordField = $null
            $DestinationPassword = $null
        }

        $SourcePassword = $null
        $VerificationPassword = $null
        $Credential = $null
    }

    $AccessToken = $null
    $WorkPerformed = ($CreatedCount -gt 0 -or $UpdatedCount -gt 0)

    if ($WorkPerformed) {
        Write-Log "END | Build=$BuildId Result=SUCCESS Created=$CreatedCount Updated=$UpdatedCount Verified=$VerifiedCount Unchanged=$UnchangedCount RefreshTokenManualUpdateRequired=$RefreshTokenManualUpdateRequired WerNoHeapSuppressed=$WerNoHeapSuppressed"
        Write-Output (
            'RESULT | Build={0} Direction=Ninja-to-1Password OrganizationId={1} Vault="{2}" PasswordDocuments={3} Created={4} Updated={5} Verified={6} Unchanged={7} RefreshTokenManualUpdateRequired={8} RefreshTokenAction="{9}" WerNoHeapSuppressed={10} SecretsLogged=False LogPath="{11}"' -f
            $BuildId,
            $OrganizationId,
            $OnePasswordVaultName,
            $PasswordDocuments.Count,
            $CreatedCount,
            $UpdatedCount,
            $VerifiedCount,
            $UnchangedCount,
            $RefreshTokenManualUpdateRequired,
            $(if ($RefreshTokenManualUpdateRequired) { 'Run standalone Ninja OAuth Refresh Token Bootstrap utility' } else { '' }),
            $WerNoHeapSuppressed,
            $LogPath
        )
    }
    else {
        Write-Log "END | Build=$BuildId Result=NO_ACTION Created=0 Updated=0 Verified=0 Unchanged=$UnchangedCount RefreshTokenManualUpdateRequired=$RefreshTokenManualUpdateRequired WerNoHeapSuppressed=$WerNoHeapSuppressed"
        Write-Output (
            'NO_ACTION | Build={0} Direction=Ninja-to-1Password OrganizationId={1} Vault="{2}" PasswordDocuments={3} Created=0 Updated=0 Verified=0 Unchanged={4} RefreshTokenManualUpdateRequired={5} RefreshTokenAction="{6}" WerNoHeapSuppressed={7} SecretsLogged=False LogPath="{8}"' -f
            $BuildId,
            $OrganizationId,
            $OnePasswordVaultName,
            $PasswordDocuments.Count,
            $UnchangedCount,
            $RefreshTokenManualUpdateRequired,
            $(if ($RefreshTokenManualUpdateRequired) { 'Run standalone Ninja OAuth Refresh Token Bootstrap utility' } else { '' }),
            $WerNoHeapSuppressed,
            $LogPath
        )
    }
}
catch {
    $SafeError = Convert-SafeOutput -Value $_.Exception.Message
    $SafeLogError = $SafeError.Replace("'", '')

    try {
        Write-Log "FAIL | Build=$BuildId Stage=$CurrentStage Error='$SafeLogError' ValuesLogged=False"
        Write-Log "END | Build=$BuildId Result=ERROR"
    }
    catch {
    }

    Write-Output (
        'ERROR | Build={0} Stage={1} CreatedBeforeFailure={2} UpdatedBeforeFailure={3} VerifiedBeforeFailure={4} RefreshTokenManualUpdateRequired={5} RefreshTokenAction="{6}" WerNoHeapSuppressed={7} Error="{8}" LogPath="{9}"' -f
        $BuildId,
        $CurrentStage,
        $CreatedCount,
        $UpdatedCount,
        $VerifiedCount,
        $RefreshTokenManualUpdateRequired,
        $(if ($RefreshTokenManualUpdateRequired) { 'Run standalone Ninja OAuth Refresh Token Bootstrap utility' } else { '' }),
        $WerNoHeapSuppressed,
        $SafeError.Replace('"', "'"),
        $LogPath
    )
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $AutomationOnePasswordToken = $null
    $DestinationOnePasswordToken = $null
    $NinjaConsoleUrl = $null
    $NinjaClientId = $null
    $NinjaClientSecret = $null
    $AccessToken = $null
    $RefreshToken = $null
    $RotatedRefreshToken = $null
    $SourcePassword = $null
    $DestinationPassword = $null
    $VerificationPassword = $null
    $ItemJson = $null
    $WerNoHeapSuppressed = $false
}

exit 0
