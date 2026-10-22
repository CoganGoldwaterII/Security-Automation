# ============================================================================
# NAME: NinjaOne Local Administrator Documentation Evaluation - Single Organization
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation / Read-Only Documentation Compliance Check
# SCOPE: Authorized Credential Broker / NinjaOne / One Target Organization
# VARIABLES:
#   organizationName        - Required NinjaOne String/Text: exact organization name
#   brokerComputerName      - Required NinjaOne String/Text: authorized broker hostname
#   automationVaultName     - Required NinjaOne String/Text: 1Password vault
#   delegatedOAuthItemName  - Required NinjaOne String/Text: delegated OAuth app item
#   refreshTokenItemName    - Required NinjaOne String/Text: stored refresh token item
#   bootstrapTokenField     - Required NinjaOne String/Text: secure Ninja field name
#   orgPasswordFieldName    - Required NinjaOne String/Text: org secure field name
#   m2mItemName             - Optional (default: NinjaRMM)
# OUTPUT TOKENS:
#   TRIGGER   | Missing document (CREATE) or password mismatch (UPDATE_PASSWORD)
#   NO_ACTION | Compliant document or missing/unavailable source password
#   ERROR     | Failed evaluation or manifest/logging operation
#   Exit Code: Always 0; Ninja condition: TRIGGER and result code 0
# CUSTOM FIELDS:
#   Reads: Secure Ninja field specified by bootstrapTokenField;
#          org field specified by orgPasswordFieldName via delegated API
#   Writes: None
# FILE TRANSFERS: None
# LOGGING PATH:
#   %ProgramData%\AutomationPlaybook\Logs\Ninja_Local_Admin_Document_Eval.log
# MANIFEST PATH:
#   %ProgramData%\AutomationPlaybook\Reports\Ninja_Local_Admin_Document_Eval_Manifest.json
# DESCRIPTION:
#   Read-only evaluation of one exact Ninja organization. Compares its
#   authoritative secure organization password field with the Passwords
#   template's Local Administrator Account document password. Determines
#   CREATE / UPDATE_PASSWORD / NONE and writes a non-secret JSON manifest.
#   Username is out of scope. No Documentation, custom-field, or 1Password
#   writes are performed.
# SECURITY / LIMITATION:
#   Exchanges a stored delegated OAuth refresh token for an access token.
#   If the server rotates the refresh token, this script does NOT persist
#   its replacement. Operator must update approved token storage before
#   another run. Manifest/log may include organization names and IDs.
# ============================================================================

[CmdletBinding()]
param(
    [string]$BrokerComputerName = [string]$env:brokerComputerName,
    [string]$AutomationVaultName = [string]$env:automationVaultName,
    [string]$DelegatedOAuthItemName = [string]$env:delegatedOAuthItemName,
    [string]$RefreshTokenItemName = [string]$env:refreshTokenItemName,
    [string]$BootstrapTokenField = [string]$env:bootstrapTokenField,
    [string]$OrgPasswordFieldName = [string]$env:orgPasswordFieldName,
    [string]$M2MItemName = 'NinjaRMM'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$BuildId = 'NINJA-LOCAL-ADMIN-DOC-EVAL-SINGLE-v1-20261008'
$NinjaOAuthUrl = 'https://app.ninjarmm.com'

# Credential item names and secure field names are runtime configuration.
$TemplateName = 'Passwords'
$DocumentName = 'Local Administrator Account'
$DocumentPasswordFieldName = 'password'

$LogRoot = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'
$LogPath = Join-Path $LogRoot 'Ninja_Local_Admin_Document_Eval.log'
$WorkRoot = Join-Path $env:ProgramData 'AutomationPlaybook\Reports'
$ManifestPath = Join-Path $WorkRoot 'Ninja_Local_Admin_Document_Eval_Manifest.json'

$CurrentStage = 'Initialize'
$FinalToken = 'ERROR'
$FinalSummary = 'Evaluation did not complete.'
$LoggingReady = $false
$RefreshTokenManualUpdateRequired = $false

$AutomationOnePasswordToken = $null
$M2MClientSecret = $null
$M2MAccessToken = $null
$DelegatedClientSecret = $null
$DelegatedAccessToken = $null
$RefreshToken = $null
$RotatedRefreshToken = $null
$OrgPassword = $null
$DocumentPassword = $null

$OrganizationId = 0
$TargetOrganizationName = $null

$Result = [ordered]@{
    organizationId = $null
    organizationName = $null
    sourceField = $OrgPasswordFieldName
    sourceState = 'NOT_EVALUATED'
    templateName = $TemplateName
    documentName = $DocumentName
    documentId = $null
    documentState = 'NOT_EVALUATED'
    passwordState = 'NOT_EVALUATED'
    action = 'ERROR'
    errorStage = $null
    error = $null
}

function Convert-SafeOutput {
    param(
        [AllowNull()]
        [object]$Value,
        [int]$MaximumLength = 900
    )

    if ($null -eq $Value) {
        return ''
    }

    $Text = [string]$Value

    foreach ($Secret in @(
        $AutomationOnePasswordToken
        $M2MClientSecret
        $M2MAccessToken
        $DelegatedClientSecret
        $DelegatedAccessToken
        $RefreshToken
        $RotatedRefreshToken
        $OrgPassword
        $DocumentPassword
    )) {
        if (-not [string]::IsNullOrEmpty([string]$Secret)) {
            $Text = $Text.Replace([string]$Secret, '[REDACTED]')
        }
    }

    $Text = $Text `
        -replace '[\r\n]+', ' ' `
        -replace '\|', '/' `
        -replace '(?i)("(?:access_token|refresh_token|client_secret|password|credential|secret)"\s*:\s*")[^"]*"', '$1[REDACTED]"' `
        -replace '(?i)((?:access_token|refresh_token|client_secret|password|credential|secret)\s*=\s*)[^&\s;]+', '$1[REDACTED]'

    $Text = $Text.Trim()

    if ($Text.Length -gt $MaximumLength) {
        $Text = $Text.Substring(0, $MaximumLength)
    }

    return $Text
}

function Initialize-Logging {
    if (-not (Test-Path -LiteralPath $LogRoot)) {
        New-Item -ItemType Directory -Path $LogRoot -Force -ErrorAction Stop | Out-Null
    }

    if (-not (Test-Path -LiteralPath $WorkRoot)) {
        New-Item -ItemType Directory -Path $WorkRoot -Force -ErrorAction Stop | Out-Null
    }

    if (-not (Test-Path -LiteralPath $LogPath)) {
        New-Item -ItemType File -Path $LogPath -Force -ErrorAction Stop | Out-Null
    }

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff zzz'
    Add-Content `
        -LiteralPath $LogPath `
        -Value "$Timestamp | INIT | Build=$BuildId | Logging verified" `
        -Encoding UTF8 `
        -ErrorAction Stop

    $script:LoggingReady = $true
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $LoggingReady) {
        throw 'Logging has not been initialized.'
    }

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff zzz'
    Add-Content `
        -LiteralPath $LogPath `
        -Value "$Timestamp | $Message" `
        -Encoding UTF8 `
        -ErrorAction Stop
}

function Get-HttpErrorText {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $Parts = New-Object System.Collections.Generic.List[string]

    try {
        if ($null -ne $ErrorRecord.Exception.Response) {
            try {
                $Parts.Add("HTTP=$([int]$ErrorRecord.Exception.Response.StatusCode)")
            }
            catch {
            }

            try {
                $Stream = $ErrorRecord.Exception.Response.GetResponseStream()

                if ($null -ne $Stream) {
                    $Reader = New-Object System.IO.StreamReader($Stream)

                    try {
                        $Body = $Reader.ReadToEnd()

                        if (-not [string]::IsNullOrWhiteSpace($Body)) {
                            $Parts.Add($Body)
                        }
                    }
                    finally {
                        $Reader.Dispose()
                        $Stream.Dispose()
                    }
                }
            }
            catch {
            }
        }
    }
    catch {
    }

    if ($Parts.Count -eq 0) {
        $Parts.Add([string]$ErrorRecord.Exception.Message)
    }

    return Convert-SafeOutput -Value ($Parts -join ' ')
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

    foreach ($PropertyName in @('results','data','items')) {
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
        'C:\Program Files\1Password CLI\op.exe'
        'C:\Program Files\1Password\op.exe'
        'C:\Windows\System32\op.exe'
    )) {
        if (Test-Path -LiteralPath $Candidate) {
            return $Candidate
        }
    }

    throw '1Password CLI op.exe was not found.'
}

function Get-OnePasswordField {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string[]]$Ids,

        [AllowNull()]
        [string[]]$Purposes,

        [AllowNull()]
        [string[]]$Labels
    )

    $Match =
        @(
            $Item.fields |
            Where-Object {
                ($Ids -contains [string]$_.id) -or
                ($null -ne $Purposes -and $Purposes -contains [string]$_.purpose) -or
                ($null -ne $Labels -and $Labels -contains [string]$_.label)
            }
        ) |
        Select-Object -First 1

    if ($null -eq $Match) {
        throw "Required 1Password field not found. IDs=$($Ids -join ',')"
    }

    $Value = [string]$Match.value

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Required 1Password field is empty. IDs=$($Ids -join ',')"
    }

    return $Value
}

function Invoke-NinjaGet {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    $ParsedUri = [Uri]$Uri
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $Response = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Get `
            -Uri $Uri `
            -Headers @{
                Accept = 'application/json'
                Authorization = "Bearer $AccessToken"
            } `
            -TimeoutSec 120 `
            -ErrorAction Stop

        $Stopwatch.Stop()

        $Json = $null

        if (-not [string]::IsNullOrWhiteSpace([string]$Response.Content)) {
            $Json = $Response.Content | ConvertFrom-Json -ErrorAction Stop
        }

        Write-Log (
            'HTTP | Method=GET Path={0} Status={1} ElapsedMs={2}' -f
            $ParsedUri.AbsolutePath,
            [int]$Response.StatusCode,
            $Stopwatch.ElapsedMilliseconds
        )

        return [PSCustomObject]@{
            StatusCode = [int]$Response.StatusCode
            Content = $Json
        }
    }
    catch {
        $Stopwatch.Stop()
        $SafeError = Get-HttpErrorText -ErrorRecord $_

        try {
            Write-Log (
                'HTTP_FAIL | Method=GET Path={0} ElapsedMs={1} Error={2}' -f
                $ParsedUri.AbsolutePath,
                $Stopwatch.ElapsedMilliseconds,
                $SafeError
            )
        }
        catch {
        }

        throw
    }
}

function Write-Manifest {
    $Manifest = [ordered]@{
        manifestVersion = 1
        buildId = $BuildId
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        auditScope = 'SingleOrganization'
        refreshTokenManualUpdateRequired = [bool]$RefreshTokenManualUpdateRequired
        results = @($Result)
    }

    $Manifest |
        ConvertTo-Json -Depth 10 |
        Set-Content `
            -LiteralPath $ManifestPath `
            -Encoding UTF8 `
            -ErrorAction Stop
}

try {
    $CurrentStage = 'Logging'
    Initialize-Logging
    Write-Log "START | Build=$BuildId | ReadOnly=True"

    $CurrentStage = 'ConfigurationValidation'
    foreach ($RequiredInput in @(
        @{ Name = 'brokerComputerName'; Value = $BrokerComputerName }
        @{ Name = 'automationVaultName'; Value = $AutomationVaultName }
        @{ Name = 'delegatedOAuthItemName'; Value = $DelegatedOAuthItemName }
        @{ Name = 'refreshTokenItemName'; Value = $RefreshTokenItemName }
        @{ Name = 'bootstrapTokenField'; Value = $BootstrapTokenField }
        @{ Name = 'orgPasswordFieldName'; Value = $OrgPasswordFieldName }
        @{ Name = 'm2mItemName'; Value = $M2MItemName }
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$RequiredInput.Value)) {
            throw "Required configuration '$($RequiredInput.Name)' is missing."
        }
    }

    $CurrentStage = 'BrokerValidation'

    if ($env:COMPUTERNAME -ine $BrokerComputerName) {
        throw "This evaluation is restricted to Credential Broker computer '$BrokerComputerName'. CurrentComputer='$env:COMPUTERNAME'"
    }

    if ($null -eq (Get-Command 'Ninja-Property-Get' -ErrorAction SilentlyContinue)) {
        throw 'Ninja-Property-Get is unavailable. Run this evaluation through NinjaOne on the authorized broker.'
    }

    $CurrentStage = 'InputValidation'
    $TargetOrganizationName = ([string]$env:organizationName).Trim()

    if ([string]::IsNullOrWhiteSpace($TargetOrganizationName)) {
        throw 'Required Ninja script variable organizationName is empty.'
    }

    $SafeOrgName = Convert-SafeOutput -Value $TargetOrganizationName -MaximumLength 200
    Write-Log "INPUT | OrganizationName='$SafeOrgName'"

    $CurrentStage = 'BrokerBootstrap'
    $AutomationOnePasswordToken = [string](Ninja-Property-Get -Name $BootstrapTokenField)
    $AutomationOnePasswordToken = $AutomationOnePasswordToken.Trim()

    if ([string]::IsNullOrWhiteSpace($AutomationOnePasswordToken)) {
        throw "Ninja secure custom field $BootstrapTokenField returned no value."
    }

    Write-Log "PASS | Ninja secure field $BootstrapTokenField retrieved ValuesLogged=False"

    $CurrentStage = 'OnePasswordCLI'
    $OpExe = Get-OpExecutable
    Write-Log 'PASS | 1Password CLI located'

    $CurrentStage = 'AutomationVaultAuthentication'
    $env:OP_SERVICE_ACCOUNT_TOKEN = $AutomationOnePasswordToken

    $WhoAmIRaw = & $OpExe whoami --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw '1Password service-account authentication failed: ' + (Convert-SafeOutput -Value ($WhoAmIRaw -join ' '))
    }

    Write-Log "PASS | 1Password service account authenticated Vault='$AutomationVaultName' ValuesLogged=False"
    $WhoAmIRaw = $null

    $CurrentStage = 'M2MCredentialRead'
    $M2MItemRaw = & $OpExe item get $M2MItemName --vault $AutomationVaultName --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read 1Password item '$M2MItemName': " + (Convert-SafeOutput -Value ($M2MItemRaw -join ' '))
    }

    $M2MItem = ($M2MItemRaw -join "`n") | ConvertFrom-Json

    $NinjaConsoleUrl = (
        Get-OnePasswordField `
            -Item $M2MItem `
            -Ids @('consoleUrl') `
            -Labels @('consoleUrl')
    ).TrimEnd('/')

    $M2MClientId = Get-OnePasswordField `
        -Item $M2MItem `
        -Ids @('clientId') `
        -Labels @('clientId')

    $M2MClientSecret = Get-OnePasswordField `
        -Item $M2MItem `
        -Ids @('clientSecret') `
        -Labels @('clientSecret')

    $M2MItem = $null
    $M2MItemRaw = $null

    $CurrentStage = 'DelegatedCredentialRead'
    $DelegatedItemRaw = & $OpExe item get $DelegatedOAuthItemName --vault $AutomationVaultName --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read 1Password item '$DelegatedOAuthItemName': " + (Convert-SafeOutput -Value ($DelegatedItemRaw -join ' '))
    }

    $DelegatedItem = ($DelegatedItemRaw -join "`n") | ConvertFrom-Json

    $DelegatedConsoleUrl = (
        Get-OnePasswordField `
            -Item $DelegatedItem `
            -Ids @('consoleUrl') `
            -Labels @('consoleUrl')
    ).TrimEnd('/')

    $DelegatedClientId = Get-OnePasswordField `
        -Item $DelegatedItem `
        -Ids @('clientId') `
        -Labels @('clientId')

    $DelegatedClientSecret = Get-OnePasswordField `
        -Item $DelegatedItem `
        -Ids @('clientSecret') `
        -Labels @('clientSecret')

    if ($DelegatedConsoleUrl -cne $NinjaConsoleUrl) {
        throw "Ninja consoleUrl mismatch between '$M2MItemName' and '$DelegatedOAuthItemName'."
    }

    $DelegatedItem = $null
    $DelegatedItemRaw = $null

    $CurrentStage = 'RefreshTokenRead'
    $RefreshTokenItemRaw = & $OpExe item get $RefreshTokenItemName --vault $AutomationVaultName --format json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read 1Password item '$RefreshTokenItemName': " + (Convert-SafeOutput -Value ($RefreshTokenItemRaw -join ' '))
    }

    $RefreshTokenItem = ($RefreshTokenItemRaw -join "`n") | ConvertFrom-Json

    $RefreshToken = Get-OnePasswordField `
        -Item $RefreshTokenItem `
        -Ids @('refreshToken') `
        -Labels @('refreshToken')

    $RefreshTokenItem = $null
    $RefreshTokenItemRaw = $null

    Write-Log "PASS | Ninja API credentials and stored refresh token retrieved from 1Password ValuesLogged=False"

    $CurrentStage = 'M2MToken'

    try {
        $M2MTokenHttp = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Post `
            -Uri "$NinjaOAuthUrl/ws/oauth/token" `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body @{
                grant_type = 'client_credentials'
                client_id = $M2MClientId
                client_secret = $M2MClientSecret
                scope = 'monitoring'
            } `
            -TimeoutSec 60 `
            -ErrorAction Stop
    }
    catch {
        throw "Ninja M2M token request failed: $(Get-HttpErrorText -ErrorRecord $_)"
    }

    $M2MTokenResponse = $M2MTokenHttp.Content | ConvertFrom-Json
    $M2MAccessToken = [string]$M2MTokenResponse.access_token

    if ([string]::IsNullOrWhiteSpace($M2MAccessToken)) {
        throw 'Ninja M2M token response did not contain an access token.'
    }

    Write-Log "PASS | Ninja M2M token issued Scope='$([string]$M2MTokenResponse.scope)' ValuesLogged=False"

    $M2MTokenHttp = $null
    $M2MTokenResponse = $null
    $M2MClientSecret = $null

    $CurrentStage = 'OrganizationLookup'

    $OrgResponse = Invoke-NinjaGet `
        -Uri "$NinjaConsoleUrl/v2/organizations" `
        -AccessToken $M2MAccessToken

    $Organizations = @(ConvertTo-ObjectArray -Response $OrgResponse.Content)
    $OrgMatches = @(
        $Organizations |
            Where-Object { [string]$_.name -ceq $TargetOrganizationName }
    )

    if ($OrgMatches.Count -eq 0) {
        throw "Organization '$SafeOrgName' was not found."
    }

    if ($OrgMatches.Count -gt 1) {
        throw "Organization lookup returned multiple exact matches for '$SafeOrgName'. Matches=$($OrgMatches.Count)"
    }

    $OrganizationId = [int]$OrgMatches[0].id

    if ($OrganizationId -le 0) {
        throw "Organization '$SafeOrgName' resolved to an invalid organization ID."
    }

    $Result['organizationId'] = $OrganizationId
    $Result['organizationName'] = $TargetOrganizationName

    Write-Log "PASS | Target organization resolved Name='$SafeOrgName' OrganizationId=$OrganizationId"

    $OrgResponse = $null
    $Organizations = $null
    $OrgMatches = $null
    $M2MAccessToken = $null
    $M2MClientId = $null

    $CurrentStage = 'RefreshTokenExchange'

    try {
        $TokenHttpResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Post `
            -Uri "$NinjaOAuthUrl/ws/oauth/token" `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body @{
                grant_type = 'refresh_token'
                client_id = $DelegatedClientId
                client_secret = $DelegatedClientSecret
                refresh_token = $RefreshToken
            } `
            -TimeoutSec 60 `
            -ErrorAction Stop
    }
    catch {
        throw "Stored Ninja OAuth refresh token could not be exchanged: $(Get-HttpErrorText -ErrorRecord $_)"
    }

    $TokenResponse = $TokenHttpResponse.Content | ConvertFrom-Json
    $DelegatedAccessToken = [string]$TokenResponse.access_token
    $RotatedRefreshToken = [string]$TokenResponse.refresh_token

    if ([string]::IsNullOrWhiteSpace($DelegatedAccessToken)) {
        throw 'Ninja refresh-token response did not contain an access token.'
    }

    $ReturnedScopes = @(
        ([string]$TokenResponse.scope) -split '\s+' |
            Where-Object { $_ }
    )

    if ($ReturnedScopes -notcontains 'monitoring') {
        throw "Ninja refreshed token did not include monitoring scope. ReturnedScope='$([string]$TokenResponse.scope)'"
    }

    if ($ReturnedScopes -notcontains 'management') {
        throw "Ninja refreshed token did not include management scope. ReturnedScope='$([string]$TokenResponse.scope)'"
    }

    if (
        -not [string]::IsNullOrWhiteSpace($RotatedRefreshToken) -and
        $RotatedRefreshToken -cne $RefreshToken
    ) {
        $RefreshTokenManualUpdateRequired = $true
        Write-Log 'ACTION_REQUIRED | Ninja returned a replacement refresh token. Current eval will finish, but the stored token must be replaced before the next unattended run. ValuesLogged=False'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($RotatedRefreshToken)) {
        Write-Log 'PASS | Ninja returned the existing refresh token unchanged ValuesLogged=False'
    }
    else {
        Write-Log 'INFO | Ninja refresh response did not include a replacement refresh token ValuesLogged=False'
    }

    Write-Log "PASS | Delegated Ninja token issued by refresh_token HTTP=$([int]$TokenHttpResponse.StatusCode) ReturnedScope='$([string]$TokenResponse.scope)' ValuesLogged=False"

    $TokenHttpResponse = $null
    $TokenResponse = $null
    $RotatedRefreshToken = $null
    $RefreshToken = $null
    $DelegatedClientSecret = $null
    $DelegatedClientId = $null
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $AutomationOnePasswordToken = $null

    $CurrentStage = 'OrganizationSecureFieldRead'

    # Retain the previously validated delegated scoped-custom-field read pattern.
    $FieldQuery = [Uri]::EscapeDataString($OrgPasswordFieldName)
    $SecureFieldUri = "$NinjaConsoleUrl/v2/queries/scoped-custom-fields-detailed?fields=$FieldQuery&scopes=organization&showSecureValues=true&pageSize=1000"

    $FieldResponse = Invoke-NinjaGet `
        -Uri $SecureFieldUri `
        -AccessToken $DelegatedAccessToken

    $ScopedResults = @($FieldResponse.Content.results)
    $OrgFieldResults = @(
        $ScopedResults |
            Where-Object {
                [string]$_.scope -ieq 'ORGANIZATION' -and
                [int]$_.entityId -eq $OrganizationId
            }
    )

    if ($OrgFieldResults.Count -gt 1) {
        throw "Expected at most one organization-scoped custom-field result for '$SafeOrgName'. Matches=$($OrgFieldResults.Count)"
    }

    if ($OrgFieldResults.Count -eq 0) {
        $Result['sourceState'] = 'MISSING'
        $Result['documentState'] = 'NOT_EVALUATED'
        $Result['passwordState'] = 'NOT_APPLICABLE'
        $Result['action'] = 'SKIP_SOURCE_MISSING'

        Write-Log "SKIP | Org='$SafeOrgName' OrganizationId=$OrganizationId Reason=$OrgPasswordFieldName missing"
        $FinalToken = 'NO_ACTION'
        $FinalSummary = "Org=`"$SafeOrgName`" OrganizationId=$OrganizationId Action=SKIP_SOURCE_MISSING"
    }
    else {
        $PasswordFieldMatches = @(
            $OrgFieldResults[0].fields |
                Where-Object { [string]$_.name -ceq $OrgPasswordFieldName }
        )

        if ($PasswordFieldMatches.Count -gt 1) {
            throw "Organization custom field '$OrgPasswordFieldName' was returned more than once. Matches=$($PasswordFieldMatches.Count)"
        }

        if ($PasswordFieldMatches.Count -eq 0) {
            $Result['sourceState'] = 'MISSING'
            $Result['documentState'] = 'NOT_EVALUATED'
            $Result['passwordState'] = 'NOT_APPLICABLE'
            $Result['action'] = 'SKIP_SOURCE_MISSING'

            Write-Log "SKIP | Org='$SafeOrgName' OrganizationId=$OrganizationId Reason=$OrgPasswordFieldName field missing"
            $FinalToken = 'NO_ACTION'
            $FinalSummary = "Org=`"$SafeOrgName`" OrganizationId=$OrganizationId Action=SKIP_SOURCE_MISSING"
        }
        else {
            $OrgPassword = [string]$PasswordFieldMatches[0].value

            if ([string]::IsNullOrWhiteSpace($OrgPassword)) {
                $Result['sourceState'] = 'MISSING'
                $Result['documentState'] = 'NOT_EVALUATED'
                $Result['passwordState'] = 'NOT_APPLICABLE'
                $Result['action'] = 'SKIP_SOURCE_MISSING'

                Write-Log "SKIP | Org='$SafeOrgName' OrganizationId=$OrganizationId Reason=$OrgPasswordFieldName blank"
                $FinalToken = 'NO_ACTION'
                $FinalSummary = "Org=`"$SafeOrgName`" OrganizationId=$OrganizationId Action=SKIP_SOURCE_MISSING"
            }
            elseif (
                $OrgPassword -ceq 'SECURE_VALUE' -or
                $OrgPassword -match '^SECURE_VALUE_PLACEHOLDER_'
            ) {
                $Result['sourceState'] = 'UNAVAILABLE'
                $Result['documentState'] = 'NOT_EVALUATED'
                $Result['passwordState'] = 'NOT_APPLICABLE'
                $Result['action'] = 'SKIP_SOURCE_UNAVAILABLE'

                Write-Log "SKIP | Org='$SafeOrgName' OrganizationId=$OrganizationId Reason=$OrgPasswordFieldName unavailable ValuesLogged=False"
                $FinalToken = 'NO_ACTION'
                $FinalSummary = "Org=`"$SafeOrgName`" OrganizationId=$OrganizationId Action=SKIP_SOURCE_UNAVAILABLE"
            }
            else {
                $Result['sourceState'] = 'AVAILABLE'
                Write-Log "PASS | Organization Secure custom field retrieved Field='$OrgPasswordFieldName' HasValue=True PlaintextAvailable=True ValuesLogged=False"

                $CurrentStage = 'DocumentationRead'

                $DocumentsResponse = Invoke-NinjaGet `
                    -Uri "$NinjaConsoleUrl/v2/organization/$OrganizationId/documents" `
                    -AccessToken $DelegatedAccessToken

                $Documents = @(ConvertTo-ObjectArray -Response $DocumentsResponse.Content)
                $TargetDocuments = @(
                    $Documents |
                        Where-Object {
                            [string]$_.documentName -ceq $DocumentName -and
                            [string]$_.documentTemplateName -ceq $TemplateName
                        }
                )

                if ($TargetDocuments.Count -gt 1) {
                    throw "Multiple exact '$DocumentName' documents were found under template '$TemplateName'. Count=$($TargetDocuments.Count)"
                }

                if ($TargetDocuments.Count -eq 0) {
                    $Result['documentState'] = 'MISSING'
                    $Result['passwordState'] = 'NOT_APPLICABLE'
                    $Result['action'] = 'CREATE'

                    Write-Log "TRIGGER | Org='$SafeOrgName' OrganizationId=$OrganizationId Action=CREATE Document='$DocumentName' Template='$TemplateName'"
                    $FinalToken = 'TRIGGER'
                    $FinalSummary = "Org=`"$SafeOrgName`" OrganizationId=$OrganizationId Action=CREATE"
                }
                else {
                    $ExistingDocument = $TargetDocuments[0]
                    $ExistingDocumentId = [int]$ExistingDocument.documentId

                    if ($ExistingDocumentId -le 0) {
                        throw "Existing '$DocumentName' returned an invalid documentId."
                    }

                    $Result['documentId'] = $ExistingDocumentId
                    $Result['documentState'] = 'PRESENT'

                    $ExistingPasswordFields = @(
                        @($ExistingDocument.fields) |
                            Where-Object { [string]$_.name -ceq $DocumentPasswordFieldName }
                    )

                    if ($ExistingPasswordFields.Count -ne 1) {
                        throw "Existing document password field '$DocumentPasswordFieldName' was not returned exactly once. DocumentId=$ExistingDocumentId Matches=$($ExistingPasswordFields.Count)"
                    }

                    $DocumentPassword = [string]$ExistingPasswordFields[0].value

                    if (
                        $DocumentPassword -ceq 'SECURE_VALUE' -or
                        $DocumentPassword -match '^SECURE_VALUE_PLACEHOLDER_'
                    ) {
                        $Result['passwordState'] = 'UNAVAILABLE'
                        throw "Existing document password returned an unavailable secure value. DocumentId=$ExistingDocumentId"
                    }

                    if ($DocumentPassword -ceq $OrgPassword) {
                        $Result['passwordState'] = 'MATCH'
                        $Result['action'] = 'NONE'

                        Write-Log "NO_ACTION | Org='$SafeOrgName' OrganizationId=$OrganizationId DocumentId=$ExistingDocumentId PasswordExactMatch=True ValuesLogged=False"
                        $FinalToken = 'NO_ACTION'
                        $FinalSummary = "Org=`"$SafeOrgName`" OrganizationId=$OrganizationId Action=NONE Password=COMPLIANT"
                    }
                    else {
                        $Result['passwordState'] = 'MISMATCH'
                        $Result['action'] = 'UPDATE_PASSWORD'

                        Write-Log "TRIGGER | Org='$SafeOrgName' OrganizationId=$OrganizationId DocumentId=$ExistingDocumentId Action=UPDATE_PASSWORD ValuesLogged=False"
                        $FinalToken = 'TRIGGER'
                        $FinalSummary = "Org=`"$SafeOrgName`" OrganizationId=$OrganizationId Action=UPDATE_PASSWORD"
                    }
                }
            }
        }
    }
}
catch {
    $SafeError = Convert-SafeOutput -Value $_.Exception.Message

    $Result['action'] = 'ERROR'
    $Result['errorStage'] = $CurrentStage
    $Result['error'] = $SafeError

    if ($Result['sourceState'] -eq 'NOT_EVALUATED') {
        $Result['sourceState'] = 'ERROR'
    }

    if ($LoggingReady) {
        try {
            Write-Log "ERROR | Stage=$CurrentStage | $SafeError"
        }
        catch {
        }
    }

    $FinalToken = 'ERROR'
    $FinalSummary = "Stage=$CurrentStage Org=`"$([string]$TargetOrganizationName)`" OrganizationId=$OrganizationId $SafeError"
}
finally {
    try {
        $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    }
    catch {
    }

    foreach ($Name in @(
        'AutomationOnePasswordToken'
        'M2MClientSecret'
        'M2MAccessToken'
        'DelegatedClientSecret'
        'DelegatedAccessToken'
        'RefreshToken'
        'RotatedRefreshToken'
        'OrgPassword'
        'DocumentPassword'
    )) {
        Set-Variable -Name $Name -Value $null -Scope Script -ErrorAction SilentlyContinue
    }

    try {
        $CurrentStage = 'ManifestWrite'
        Write-Manifest

        if ($LoggingReady) {
            Write-Log "MANIFEST | Written | Path=$ManifestPath | Action=$($Result['action'])"
        }
    }
    catch {
        $ManifestError = Convert-SafeOutput -Value $_.Exception.Message

        if ($LoggingReady) {
            try {
                Write-Log "ERROR | Stage=ManifestWrite | $ManifestError"
            }
            catch {
            }
        }

        $FinalToken = 'ERROR'
        $FinalSummary = "Stage=ManifestWrite Org=`"$([string]$TargetOrganizationName)`" OrganizationId=$OrganizationId $ManifestError"
    }

    $FinalSummary = Convert-SafeOutput -Value $FinalSummary -MaximumLength 780

    if ($RefreshTokenManualUpdateRequired) {
        $FinalSummary += ' RefreshTokenManualUpdateRequired=True'
    }

    $FinalSummary += " Manifest=`"$ManifestPath`""

    if ($LoggingReady) {
        try {
            Write-Log "FINAL | $FinalToken | $FinalSummary"
        }
        catch {
            $FinalToken = 'ERROR'
            $FinalSummary = 'Stage=Logging | Final log write failed.'
        }
    }

    Write-Output "$FinalToken | $FinalSummary"
}

exit 0
