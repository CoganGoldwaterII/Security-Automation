# ============================================================================
# NAME: WatchGuard TEST Set Web Server Certificate Default No Deploy
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation / Saved-Configuration Test
# SCOPE: Authorized Credential Broker / WatchGuard Single Account and Device
#
# VARIABLES:
#   Required: TargetAccountId, TargetDeviceId, VaultName, ServiceTokenFieldName
#   Optional: WatchGuardItemName (default WatchGuard)
#             LogRoot (default ProgramData\AutomationPlaybook\Logs)
#
# OUTPUT TOKENS:
#   RESULT | WatchGuard Web Server Certificate Defaulting |
#            Status=AlreadyDefault or Status=SavedDefault
#   ERROR  | WatchGuard Web Server Certificate Defaulting |
#            Stage=<stage> Account=<id> Device=<id>
#            HTTP=<status> Reason=<reason>
#   NO_ACTION | Not emitted
#   Exit Code: Always 0 after script execution
#
# CUSTOM FIELDS:
#   Reads: Secure field specified by ServiceTokenFieldName
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   <LogRoot>\WatchGuard_WebServer_Set_Default_NoDeploy_TEST.log
#
# DESCRIPTION:
#   Tests saved Web Server certificate defaulting for a single WatchGuard
#   account and device supplied at execution time. The script retrieves
#   credentials from the configured 1Password vault and item, using a
#   secure NinjaOne device field selected by ServiceTokenFieldName.
#
#   Required WatchGuard item fields:
#     credential, readWriteAccessId, readWritePassword,
#     authenticationUrl, baseApiUrl
#
#   Reads the target Firebox certificate state. If a referenced third-party
#   web_server certificate exists, attempts to clear the saved certificate
#   selector and verifies saved state with up to three reads.
#
#   TEST RESTRICTIONS:
#     - Changes saved configuration only; does not explicitly deploy.
#     - Does not delete or upload certificates or explicitly reboot.
#     - The empty certificate selector is an unverified API assumption.
#     - Not read-only: the test may issue a configuration-changing POST.
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetAccountId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetDeviceId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$VaultName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceTokenFieldName,

    [string]$WatchGuardItemName = 'WatchGuard',
    [string]$LogRoot = (Join-Path $env:ProgramData 'AutomationPlaybook\Logs')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$LogPath = Join-Path $LogRoot 'WatchGuard_WebServer_Set_Default_NoDeploy_TEST.log'

$Stage = 'Initialize'
$FinalOutput = $null
$ApiKey = $null
$ReadWriteAccessId = $null
$ReadWritePassword = $null
$ProviderToken = $null
$SubscriberToken = $null
$Audience = $null

function Safe {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value -replace '[\r\n]+',' ' -replace '\|','/' -replace '\s{2,}',' ').Trim()
}

function Log {
    param([Parameter(Mandatory)][string]$Message)
    try {
        '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message |
            Add-Content -LiteralPath $LogPath -Encoding UTF8
    } catch {}
}

function OpField {
    param([Parameter(Mandatory)][object]$Item,[Parameter(Mandatory)][string]$Name)
    $Field = $Item.fields | Where-Object { $_.label -eq $Name -or $_.id -eq $Name } | Select-Object -First 1
    if ($null -eq $Field -or [string]::IsNullOrWhiteSpace([string]$Field.value)) {
        throw "1Password field '$Name' missing or empty."
    }
    return ([string]$Field.value).Trim()
}

function WgToken {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Password,
        [AllowNull()][string]$AudienceValue
    )
    $Basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$Id`:$Password"))
    $Headers = @{ Accept='application/json'; Authorization="Basic $Basic" }
    $Body = @{ grant_type='client_credentials'; scope='api-access' }
    if (-not [string]::IsNullOrWhiteSpace($AudienceValue)) { $Body.audience = $AudienceValue }

    $Response = Invoke-RestMethod -Method Post -Uri $Url -Headers $Headers `
        -ContentType 'application/x-www-form-urlencoded' -Body $Body -TimeoutSec 60

    if ([string]::IsNullOrWhiteSpace([string]$Response.access_token)) {
        throw 'WatchGuard authentication returned no access_token.'
    }
    return [string]$Response.access_token
}

function CertArray {
    param([AllowNull()][object]$Response)
    if ($null -eq $Response) { return @() }
    if ($Response -is [System.Array]) { return @($Response) }

    foreach ($Name in @('certificates','items','data','results')) {
        if ($Response.PSObject.Properties.Name -contains $Name) { return @($Response.$Name) }
    }
    return @($Response)
}

function DeviceWebState {
    param(
        [Parameter(Mandatory)][string]$BaseUri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$DeviceId
    )

    $Uri = '{0}?device={1}' -f $BaseUri,[uri]::EscapeDataString($DeviceId)
    $Response = Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -TimeoutSec 60
    $Certificates = @(CertArray $Response)

    if ($Certificates.Count -eq 0) { throw 'WatchGuard returned no certificates for target Firebox.' }

    $Referenced = @(
        foreach ($Cert in $Certificates) {
            if ([string]$Cert.cert_type -ine 'web_server') { continue }

            $Refs = @()
            if ($Cert.PSObject.Properties.Name -contains 'referencedby' -and $null -ne $Cert.referencedby) {
                $Refs = @(
                    $Cert.referencedby |
                    ForEach-Object { [string]$_ } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                )
            }

            if ($Refs.Count -gt 0) {
                [PSCustomObject]@{
                    Id = [string]$Cert.id
                    Name = [string]$Cert.name
                    Fingerprint = [string]$Cert.cert_fingerprint
                    References = @($Refs)
                }
            }
        }
    )

    if ($Referenced.Count -gt 1) {
        throw "Multiple referenced web_server certificates found: $($Referenced.Count)."
    }

    if ($Referenced.Count -eq 0) {
        return [PSCustomObject]@{
            Mode='DefaultFirebox'
            Name='Default certificate signed by Firebox'
            Id=$null
            Fingerprint=$null
            References=@()
        }
    }

    return [PSCustomObject]@{
        Mode='ThirdParty'
        Name=[string]$Referenced[0].Name
        Id=[string]$Referenced[0].Id
        Fingerprint=[string]$Referenced[0].Fingerprint
        References=@($Referenced[0].References)
    }
}

function HttpDetail {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$Record)

    $Status = 'N/A'
    $Body = ''
    try {
        if ($Record.Exception.Response) {
            $Status = [int]$Record.Exception.Response.StatusCode
            $Stream = $Record.Exception.Response.GetResponseStream()
            if ($Stream) {
                $Reader = New-Object System.IO.StreamReader($Stream)
                try { $Body = $Reader.ReadToEnd() } finally { $Reader.Dispose() }
            }
        }
    } catch {}

    $Message = if ([string]::IsNullOrWhiteSpace($Body)) { Safe $Record.Exception.Message } else { Safe $Body }
    return [PSCustomObject]@{ Status=$Status; Message=$Message }
}

try {
    if (-not (Test-Path -LiteralPath $LogRoot)) {
        New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
    }
    "WatchGuard Web Server Set Default NO DEPLOY TEST - $(Get-Date -Format s)" |
        Set-Content -LiteralPath $LogPath -Encoding UTF8
    Log "START | Account=$TargetAccountId Device=$TargetDeviceId Deployment=Disabled"

    $Stage = 'NinjaCredentialBootstrap'
    $ServiceToken = Ninja-Property-Get $ServiceTokenFieldName
    if ([string]::IsNullOrWhiteSpace([string]$ServiceToken)) {
        throw "Ninja secure field '$ServiceTokenFieldName' returned no value."
    }
    $env:OP_SERVICE_ACCOUNT_TOKEN = ([string]$ServiceToken).Trim()

    $Stage = 'OnePasswordCLI'
    $OpExe = $null
    foreach ($Candidate in @('C:\Program Files\1Password CLI\op.exe','C:\Program Files\1Password\op.exe')) {
        if (Test-Path -LiteralPath $Candidate) { $OpExe = $Candidate; break }
    }
    if (-not $OpExe) {
        $Cmd = Get-Command op.exe -ErrorAction SilentlyContinue
        if ($Cmd) { $OpExe = $Cmd.Source }
    }
    if (-not $OpExe) { throw 'Unable to locate op.exe.' }

    $Stage = 'OnePasswordAuth'
    $null = & $OpExe whoami --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw '1Password service-account authentication failed.' }

    $Stage = 'WatchGuardConfiguration'
    $Raw = & $OpExe item get $WatchGuardItemName --vault $VaultName --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Unable to retrieve WatchGuard item from 1Password.' }
    $Item = ($Raw -join "`n") | ConvertFrom-Json

    $ApiKey = OpField $Item 'credential'
    $ReadWriteAccessId = OpField $Item 'readWriteAccessId'
    $ReadWritePassword = OpField $Item 'readWritePassword'
    $AuthenticationUrl = (OpField $Item 'authenticationUrl').TrimEnd('/')
    $BaseApiUrl = (OpField $Item 'baseApiUrl').TrimEnd('/')

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $ServiceToken = $null
    $Item = $null

    $Stage = 'ProviderAuth'
    $ProviderToken = WgToken $AuthenticationUrl $ReadWriteAccessId $ReadWritePassword $null

    $Stage = 'Audience'
    $AudienceHeaders = @{
        Accept='application/json'
        'Content-Type'='application/json'
        Authorization="Bearer $ProviderToken"
        'WatchGuard-API-Key'=$ApiKey
    }
    $AudienceResponse = Invoke-RestMethod -Method Post `
        -Uri "$BaseApiUrl/platform/authorization/v1/audiences" `
        -Headers $AudienceHeaders `
        -Body (@{accountId=$TargetAccountId} | ConvertTo-Json -Compress) `
        -TimeoutSec 60
    $Audience = [string]$AudienceResponse.audience
    if ([string]::IsNullOrWhiteSpace($Audience)) { throw 'WatchGuard returned no Subscriber audience.' }

    $Stage = 'SubscriberAuth'
    $SubscriberToken = WgToken $AuthenticationUrl $ReadWriteAccessId $ReadWritePassword $Audience
    $Headers = @{
        Accept='application/json'
        'Content-Type'='application/json'
        Authorization="Bearer $SubscriberToken"
        'WatchGuard-API-Key'=$ApiKey
    }

    $CertUri = "$BaseApiUrl/firebox/management/v1/configuration/$TargetAccountId/system/certificates"

    $Stage = 'ReadCurrentState'
    $Before = DeviceWebState $CertUri $Headers $TargetDeviceId
    Log ("STATE_BEFORE | Mode={0} Name={1} Id={2} Fingerprint={3} References={4}" -f `
        $Before.Mode,(Safe $Before.Name),(Safe $Before.Id),(Safe $Before.Fingerprint),(Safe ($Before.References -join ',')))

    if ($Before.Mode -eq 'DefaultFirebox') {
        $FinalOutput = 'RESULT | WatchGuard Web Server Certificate Defaulting | Account={0} Device={1} Status=AlreadyDefault Previous={2}' -f `
            $TargetAccountId,$TargetDeviceId,(Safe $Before.Name)
    }
    else {
        $Stage = 'SetDefaultSavedConfiguration'

        # Raw v1.27 schema defines "certificate" as string with no minLength.
        # Saved Default state is represented by no referenced third-party web_server cert.
        # Empty selector is therefore the narrow test used here.
        $SetDefaultUri = "$BaseApiUrl/firebox/management/v1/commands/$TargetAccountId/system/certificates/install"
        $Body = @{ certificate=''; device=$TargetDeviceId } | ConvertTo-Json -Compress

        Log ("WRITE | ClearWebServerCertificateSelector Previous={0} PreviousId={1}" -f (Safe $Before.Name),(Safe $Before.Id))
        $null = Invoke-RestMethod -Method Post -Uri $SetDefaultUri -Headers $Headers -Body $Body -TimeoutSec 60

        $Stage = 'VerifySavedDefault'
        $After = $null
        for ($Attempt=1; $Attempt -le 3; $Attempt++) {
            if ($Attempt -gt 1) { Start-Sleep -Seconds 2 }
            $After = DeviceWebState $CertUri $Headers $TargetDeviceId
            Log ("STATE_AFTER | Attempt={0} Mode={1} Name={2} Id={3}" -f $Attempt,$After.Mode,(Safe $After.Name),(Safe $After.Id))
            if ($After.Mode -eq 'DefaultFirebox') { break }
        }

        if ($After.Mode -ne 'DefaultFirebox') {
            throw "Saved configuration still references third-party Web Server certificate '$($After.Name)' Id='$($After.Id)'."
        }

        $FinalOutput = 'RESULT | WatchGuard Web Server Certificate Defaulting | Account={0} Device={1} Status=SavedDefault Previous={2}' -f `
            $TargetAccountId,$TargetDeviceId,(Safe $Before.Name)
    }
}
catch {
    $Detail = HttpDetail $_
    Log ("ERROR | Stage={0} HTTP={1} Reason={2}" -f $Stage,$Detail.Status,(Safe $Detail.Message))
    $FinalOutput = 'ERROR | WatchGuard Web Server Certificate Defaulting | Stage={0} Account={1} Device={2} HTTP={3} Reason={4}' -f `
        $Stage,$TargetAccountId,$TargetDeviceId,$Detail.Status,(Safe $Detail.Message)
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $ApiKey = $null
    $ReadWriteAccessId = $null
    $ReadWritePassword = $null
    $ProviderToken = $null
    $SubscriberToken = $null
    $Audience = $null
}

Write-Output $FinalOutput
exit 0