# ============================================================================
# NAME: Device WatchGuard TLS Certificate Check
# AUTHORED BY: Cogan Goldwater
# TYPE: Manual, read-only multi-endpoint certificate audit
# SCOPE: One operator-selected WGC Subscriber account with eligible cloud-
#        managed Firebox(es), matched to Ninja organization and all locations.
# VARIABLES:
#   Mode = Audit | Probe | Copy. Audit only is launched manually on your dedicated Ninja credential-broker device.
#   RunId / Arg1..Arg4 = internal Ninja script parameters for Probe/Copy workers.
#   Ninja script variable (Text): watchguardCloudAccount
#      Required: supply an explicit account ID for each Audit-mode run.
#      No hardcoded default or fallback account.
#   MaxProbeDevices = 0 (no per-organization cap)
#   WaitForProbeSeconds = 300 (controller polling window)
#   CopyReportToNinjaDeviceId = REQUIRED; configure before running
#   SavedScriptIdOverride = 0 (autodiscover same approved saved Ninja automation)
# OUTPUT TOKENS:
#   RESULT    | Manual audit completed; NEEDS_CERT/UNVERIFIED findings may be present
#   NO_ACTION | No eligible cloud-managed WatchGuard accounts/endpoints
#   ERROR     | Operational/inventory/verification failure or copy failure;
#             | UNVERIFIED endpoint evidence alone does not trigger ERROR
# CUSTOM FIELDS:
#   Reads: YOUR_BROKER_TOKEN_CUSTOM_FIELD (credential broker/controller only)
#   Writes: None
#   1Password (controller): YOUR_WATCHGUARD_ITEM; YOUR_NINJA_OAUTH_ITEM;
#      YOUR_NINJA_REFRESH_TOKEN_ITEM (refreshToken)
# LOGGING PATH: C:\MME\AutoLogs\WatchGuard_Ninja_ProxyCA_Manual_Audit.log
# MANIFEST PATH: C:\MME\CS\WatchGuard_Ninja_ProxyCA_Audit_<RunId>.txt
# NINJA OUTPUT: OFFLINE: count | machine names; NEEDS_CERT: count | machine
#               names; COMPLIANT: count | machine names; UNVERIFIED: count |
#               machine names. No display-only name
#               truncation. Final RESULT / NO_ACTION / ERROR token retained.
#               Operational details remain in the log and manifest.
# DESCRIPTION:
#   One manual launch on your dedicated Ninja credential-broker device. WatchGuard Account API v2 discovers
#   Subscribers. One lightweight Firebox device-details request per selected
#   Subscriber checks for at least one CLOUD-MANAGED, non-cluster Firebox;
#   locally managed boxes alone do NOT qualify that customer.
#   ONLY account names and eligibility/counts are kept; no Firebox LAN
#   configurations, certificates or per-Firebox identity crosswalk are queried.
#   Match eligible WatchGuard account name to Ninja organization exactly
#   (ignoring case and extra whitespace), then enumerate its Ninja locations
#   and Windows devices. Ninja runs this saved script in Probe mode on eligible
#   online devices. Probe selects its effective IPv4 default gateway, downloads
#   the CA served at http://<gateway>:4126/ProxyCA.cer, validates the X.509
#   object and time, and compares the certificate's SHA-256 DER fingerprint
#   against LocalMachine Root store. No certificates are installed or removed.
#   Gateway source is NOT cryptographically authenticated to a particular WGC
#   Firebox, and an unavailable gateway portal is UNKNOWN (never MISSING).
#   Controller obtains completed probe evidence from Ninja device activities,
#   records per-device subject, issuer, SHA-1 thumbprint, SHA-256 fingerprint,
#   expiration, gateway, LAN and Ninja location in a human-readable manifest.
#   Copy mode transfers the manifest via this same automation to the
#   configured Ninja collector device, C:\MME\CS, verifying a SHA-256 receipt.
#   If the saved Ninja script ID cannot be resolved, the inventory still
#   appears in the local manifest, but endpoint dispatch is not attempted.
#   Uses existing user-delegated Ninja OAuth (NOT M2M). No permission preflight;
#   failed Ninja API operations log method/path/HTTP code (never token values).
#   Refresh token rotation follows existing broker manual-update convention.
# PREREQUISITES:
#   Save this as the existing "Device WatchGuard TLS Certificate Check"
#   PowerShell automation in Ninja. Run MANUALLY as SYSTEM on your dedicated Ninja credential-broker device.
#   Do not schedule. The script runs itself remotely in Probe and Copy modes.
#   Only your dedicated Ninja credential-broker device retrieves broker credentials; Probe/Copy hold no secrets.
#   Set the watchguardCloudAccount Ninja script variable for each account to audit.
#   One account is processed per manual run; no automatic global expansion.
# ============================================================================


param(
    [string]$Mode = 'Audit',
    [string]$RunId = '',
    [string]$Arg1 = '',
    [string]$Arg2 = '',
    [string]$Arg3 = '',
    [string]$Arg4 = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Controller scope is selected through one Ninja Automation Library Text variable.
# Ninja exposes script variables as environment variables for this run only.
# Add a String/Text variable named watchguardCloudAccount in the Ninja script editor.
# Worker modes ignore this variable. No fallback account is configured.
$PilotWatchGuardAccountId = ([string]$env:watchguardCloudAccount).Trim()
$PilotNinjaOrgId = 0
$MaxProbeDevices = 0
$WaitForProbeSeconds = 300
# REQUIRED: replace -1 with the Ninja device ID that stores verified manifests.
$CopyReportToNinjaDeviceId = -1
$SameScriptLibraryNames = @(
    'Device WatchGuard TLS Certificate Check',
    'WatchGuard - Ninja Cloud-Managed ProxyCA Multi-Location Audit (Manual)'
)
# Leave at zero to resolve the existing Ninja automation automatically.
# A numeric override is only for an independently verified library script ID.
$SavedScriptIdOverride = 0
# Configure this copy with the names used in your own 1Password vault.
$OnePasswordVault = 'YOUR_1PASSWORD_VAULT'
$LogRoot = 'C:\MME\AutoLogs'
$WorkRoot = 'C:\MME\CS'
$LogPath = Join-Path $LogRoot 'WatchGuard_Ninja_ProxyCA_Manual_Audit.log'
$Stage = 'Initialize'

function Clean-Text {
    param([object]$Value,[int]$MaxLength=240)
    $x = [string]$Value
    $x = ($x -replace '[\x00-\x1F\|]+',' ').Trim()
    if ($x.Length -gt $MaxLength) { $x = $x.Substring(0,$MaxLength) }
    return $x
}
function Write-Log {
    param([string]$Message)
    try {
        if (-not (Test-Path -LiteralPath $LogRoot)) {
            New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
        }
        ('{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),(Clean-Text $Message 450)) |
            Add-Content -LiteralPath $LogPath -Encoding UTF8
    }
    catch { }
}
function Ensure-WorkRoot {
    if (-not (Test-Path -LiteralPath $WorkRoot)) {
        New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
    }
}
function Check-RunId {
    param([string]$Id)
    if ($Id -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid audit RunId argument' }
}
function Normalize-OrgName {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    return (($Text.Trim() -replace '\s+',' ').ToUpperInvariant())
}
function Normalize-NinjaScriptName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    # Ninja Run Automation UI may display "AUTOMATION -" as a type prefix.
    # The API script name is not guaranteed to contain that UI prefix.
    $normalized = $Name.Trim() -replace '^(?i:AUTOMATION)\s*[-:]\s*', ''
    return (($normalized -replace '\s+', ' ').Trim().ToUpperInvariant())
}
function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','') }
    finally { $hash.Dispose() }
}
function Get-GatewayAddress {
    $metricByInterface = @{}
    foreach ($i in @(Get-NetIPInterface -AddressFamily IPv4)) {
        $metricByInterface[[int]$i.InterfaceIndex] = [int]$i.InterfaceMetric
    }
    $candidates = @(
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
        ForEach-Object {
            $im = 999999
            if ($metricByInterface.ContainsKey([int]$_.InterfaceIndex)) {
                $im = $metricByInterface[[int]$_.InterfaceIndex]
            }
            [PSCustomObject]@{ Gateway=[string]$_.NextHop; Score=([int]$_.RouteMetric+$im); IfIndex=[int]$_.InterfaceIndex }
        } | Sort-Object Score,Gateway
    )
    if ($candidates.Count -eq 0) { throw 'No usable IPv4 default gateway' }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($candidates[0].Gateway,[ref]$address)) {
        throw 'Gateway address is invalid'
    }
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Default gateway is not IPv4'
    }
    $script:BestGatewayInterfaceIndex = [int]$candidates[0].IfIndex
    return [string]$candidates[0].Gateway
}
function Get-GatewayProxyCA {
    param([string]$Gateway)
    # Deliberately no proxy, redirection, or HTML content. Inherits no trust.
    $url = 'http://{0}:4126/ProxyCA.cer' -f $Gateway
    $req = [Net.HttpWebRequest][Net.WebRequest]::Create($url)
    $req.Method = 'GET'
    $req.Proxy = $null
    $req.AllowAutoRedirect = $false
    $req.Timeout = 20000
    $req.ReadWriteTimeout = 20000
    $resp = $null; $stream = $null
    $memory = New-Object System.IO.MemoryStream
    try {
        $resp = [Net.HttpWebResponse]$req.GetResponse()
        if ([int]$resp.StatusCode -ne 200) { throw 'Certificate portal HTTP status was not 200' }
        if ($resp.ContentType -match 'text/html') { throw 'Gateway returned HTML, not a certificate' }
        if ($resp.ContentLength -gt 262144) { throw 'Certificate exceeds 256KB limit' }
        $stream = $resp.GetResponseStream()
        $buffer = New-Object byte[] 8192
        while (($n = $stream.Read($buffer,0,$buffer.Length)) -gt 0) {
            if ($memory.Length + $n -gt 262144) { throw 'Certificate exceeds 256KB limit' }
            $memory.Write($buffer,0,$n)
        }
        $bytes = $memory.ToArray()
        if ($bytes.Length -lt 64) { throw 'Certificate payload was too small' }
        # Windows X509Certificate2 supports DER; handle PEM text explicitly.
        $text = [Text.Encoding]::ASCII.GetString($bytes)
        if ($text -match '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----') {
            $base64 = ($Matches[1] -replace '\s','')
            $bytes = [Convert]::FromBase64String($base64)
        }
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import([byte[]]$bytes)
        if ($cert.HasPrivateKey) { throw 'Unexpected private key returned' }
        $bc = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
        if ($bc.Count -ne 1) { throw 'Expected certificate has no unambiguous CA extension' }
        $constraints = New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension `
            -ArgumentList @($bc[0],[bool]$bc[0].Critical)
        if (-not $constraints.CertificateAuthority) { throw 'Expected certificate is not a CA' }
        return $cert
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $resp) { $resp.Dispose() }
        $memory.Dispose()
    }
}
function Convert-Info64 {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return 'NONE' }
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value))
}
function Invoke-Probe {
    param([string]$AuditId,[string]$ExpectedDeviceId)
    $state='ERROR'; $why='UNKNOWN'; $gateway='NONE'; $lan='NONE'; $sha='NONE'
    $expiry='NONE'; $thumb='NONE'; $subject='NONE'; $issuer='NONE'; $location='NONE'
    try {
        Check-RunId $AuditId
        if ($ExpectedDeviceId -notmatch '^\d+$' -or [int64]$ExpectedDeviceId -lt 1) {
            throw 'Invalid target device ID'
        }
        $localId = [string]$env:NINJA_AGENT_NODE_ID
        if ($localId -ne $ExpectedDeviceId) { throw 'Ninja agent/device identity mismatch' }
        $location = [string]$env:NINJA_LOCATION_ID
        if ($location -notmatch '^\d+$') { $location='NONE' }
        $gateway = Get-GatewayAddress
        $hostIps=@(Get-NetIPAddress -InterfaceIndex $script:BestGatewayInterfaceIndex `
            -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
            Select-Object -ExpandProperty IPAddress)
        if ($hostIps.Count -lt 1) { throw 'Selected gateway interface has no usable IPv4 addresses' }
        $lan=(@($hostIps | Sort-Object -Unique) -join ',')
        $certificate = Get-GatewayProxyCA -Gateway $gateway
        $sha = Get-Sha256Hex -Bytes $certificate.RawData
        $thumb=([string]$certificate.Thumbprint -replace '[^A-Fa-f0-9]','').ToUpperInvariant()
        $subject=Convert-Info64 ([string]$certificate.Subject)
        $issuer=Convert-Info64 ([string]$certificate.Issuer)
        $expiry = $certificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')
        if ($certificate.NotBefore.ToUniversalTime() -gt [datetime]::UtcNow -or
            $certificate.NotAfter.ToUniversalTime() -le [datetime]::UtcNow) {
            $state='SOURCE_INVALID'; $why='GATEWAY_CA_NOT_TIME_VALID'
        }
        else {
            $matched=$false
            foreach ($installed in @(Get-ChildItem 'Cert:\LocalMachine\Root')) {
                if ((Get-Sha256Hex -Bytes $installed.RawData) -ceq $sha) { $matched=$true;break }
            }
            if ($matched) { $state='LOCAL_MATCH'; $why='EXACT_ROOT_MATCH' }
            else { $state='LOCAL_MISSING'; $why='EXACT_ROOT_ABSENT' }
        }
    }
    catch {
        $state=if ($gateway -eq 'NONE' -or $sha -eq 'NONE') { 'SOURCE_UNAVAILABLE' }
               else { 'LOCAL_CHECK_ERROR' }
        $why=if ($gateway -eq 'NONE') { 'GATEWAY_DETECTION_FAILED' }
             elseif ($sha -eq 'NONE') { 'GATEWAY_CERT_UNAVAILABLE_OR_INVALID' }
             else { 'LOCAL_CERT_CHECK_FAILED' }
        Write-Log ('PROBE_ERROR | Run={0} Device={1} Reason={2}' -f $AuditId,$ExpectedDeviceId,(Clean-Text $_.Exception.Message))
    }
    finally {
        $line='WGPROBEv2 Run={0} Device={1} State={2} Gateway={3} LAN={4} LocationId={5} SHA256={6} Thumbprint={7} Expires={8} Reason={9} Subject64={10} Issuer64={11}' -f `
            $AuditId,$ExpectedDeviceId,$state,$gateway,$lan,$location,$sha,$thumb,$expiry,$why,$subject,$issuer
        $token = if ($state -in @('SOURCE_UNAVAILABLE','LOCAL_CHECK_ERROR')) { 'ERROR' } else { 'RESULT' }
        Write-Log $line
        Write-Output ('{0} | {1}' -f $token,$line)
    }
}
function Invoke-CopyChunk {
    param([string]$AuditId,[string]$IndexText,[string]$TotalText,
          [string]$ExpectedDigest,[string]$Fragment)
    $result='ERROR'; $status='COPY_FAILED'; $localNode=[string]$env:NINJA_AGENT_NODE_ID
    try {
        Check-RunId $AuditId
        if ($localNode -ne [string]$CopyReportToNinjaDeviceId) { throw 'Copy target Ninja device identity mismatch' }
        $partNum=0; $total=0
        if (-not [int]::TryParse($IndexText,[ref]$partNum) -or
            -not [int]::TryParse($TotalText,[ref]$total)) { throw 'Bad copy part indices' }
        if ($total -lt 1 -or $total -gt 600 -or $partNum -lt 0 -or $partNum -ge $total) {
            throw 'Copy part number/range invalid'
        }
        if ($ExpectedDigest -cnotmatch '^[A-F0-9]{64}$') { throw 'Bad expected SHA256' }
        if ($Fragment -cnotmatch '^[A-Za-z0-9+/=]{1,1600}$') { throw 'Invalid base64 fragment' }
        Ensure-WorkRoot
        $dir=Join-Path $WorkRoot ('WGProxyCA_Transfer_{0}' -f $AuditId)
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        $file=Join-Path $dir ('chunk_{0:D4}.txt' -f $partNum)
        [IO.File]::WriteAllText($file,$Fragment,[Text.Encoding]::ASCII)
        $parts=@(Get-ChildItem -LiteralPath $dir -Filter 'chunk_*.txt' -File)
        $result='RESULT'; $status='CHUNK_STAGED'
        if ($parts.Count -eq $total) {
            $lockFile=Join-Path $dir 'finalize.lock'
            $lock=$null
            try {
                $lock=New-Object System.IO.FileStream -ArgumentList @($lockFile,[IO.FileMode]::OpenOrCreate,
                    [IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
                $encoded=New-Object System.Text.StringBuilder
                for ($p=0; $p -lt $total; $p++) {
                    $partFile=Join-Path $dir ('chunk_{0:D4}.txt' -f $p)
                    if (-not (Test-Path -LiteralPath $partFile)) { throw 'Missing expected part during finalize' }
                    [void]$encoded.Append([IO.File]::ReadAllText($partFile,[Text.Encoding]::ASCII))
                }
                $packed=[Convert]::FromBase64String($encoded.ToString())
                $source=New-Object System.IO.MemoryStream -ArgumentList @(,[byte[]]$packed)
                $unzipped=$null; $targetStream=$null
                try {
                    $unzipped=New-Object System.IO.Compression.GZipStream -ArgumentList @($source,[IO.Compression.CompressionMode]::Decompress)
                    $targetStream=New-Object System.IO.MemoryStream
                    $buffer=New-Object byte[] 8192
                    while (($n=$unzipped.Read($buffer,0,$buffer.Length)) -gt 0) {
                        if ($targetStream.Length + $n -gt 10485760) { throw 'Report exceeds 10MB limit' }
                        $targetStream.Write($buffer,0,$n)
                    }
                    $raw=[byte[]]$targetStream.ToArray()
                }
                finally {
                    if ($null -ne $unzipped) { $unzipped.Dispose() }
                    if ($null -ne $targetStream) { $targetStream.Dispose() }
                    $source.Dispose()
                }
                if ((Get-Sha256Hex -Bytes $raw) -cne $ExpectedDigest) {
                    throw 'Copied report SHA256 mismatch'
                }
                $destination=Join-Path $WorkRoot ('WatchGuard_Ninja_ProxyCA_Audit_{0}.txt' -f $AuditId)
                # Do not overwrite a different existing report.
                if (Test-Path -LiteralPath $destination) {
                    $existing=[IO.File]::ReadAllBytes($destination)
                    if ((Get-Sha256Hex -Bytes $existing) -cne $ExpectedDigest) {
                        throw 'Destination report exists with different SHA256'
                    }
                }
                else {
                    $temp=Join-Path $dir 'verified_report.tmp'
                    [IO.File]::WriteAllBytes($temp,$raw)
                    [IO.File]::Move($temp,$destination)
                }
                $status='VERIFIED'
            }
            catch [System.IO.IOException] {
                # Another chunk may be completing the same report concurrently.
                $status='CHUNK_STAGED'
            }
            finally { if ($null -ne $lock) { $lock.Dispose() } }
        }
        Write-Log ('COPY | Run={0} Device={1} Part={2}/{3} Status={4}' -f $AuditId,$CopyReportToNinjaDeviceId,($partNum+1),$total,$status)
    }
    catch {
        Write-Log ('COPY_ERROR | Run={0} Reason={1}' -f $AuditId,(Clean-Text $_.Exception.Message))
    }
    finally {
        $receipt='WGCOPYv1 Run={0} Device={1} State={2} SHA256={3}' -f $AuditId,$CopyReportToNinjaDeviceId,$status,$ExpectedDigest
        Write-Output ('{0} | {1}' -f $result,$receipt)
    }
}

# Worker modes run locally on targeted Ninja endpoints and need no API secrets.
if ($Mode -eq 'Probe') {
    Invoke-Probe -AuditId $RunId -ExpectedDeviceId $Arg1
}
elseif ($Mode -eq 'Copy') {
    Invoke-CopyChunk -AuditId $RunId -IndexText $Arg1 -TotalText $Arg2 `
        -ExpectedDigest $Arg3 -Fragment $Arg4
}
elseif ($Mode -eq 'Audit') {

# Controller-only functions below.
function Get-OpExe {
    $options=@("$env:ProgramFiles\1Password CLI\op.exe","$env:ProgramFiles\1Password\op.exe")
    foreach ($p in $options) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
    $cmd=Get-Command op.exe -ErrorAction SilentlyContinue
    if ($cmd) { return [string]$cmd.Source }
    throw '1Password CLI op.exe not installed on controller'
}
function Get-OpField {
    param([object]$Item,[string]$Label,[bool]$Required=$true)
    $matches=@($Item.fields | Where-Object { $_.label -eq $Label -or $_.id -eq $Label })
    if ($matches.Count -eq 0 -and -not $Required) { return '' }
    if ($matches.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$matches[0].value)) {
        throw ('Missing/ambiguous 1Password item field: {0}' -f $Label)
    }
    return ([string]$matches[0].value).Trim()
}
function Invoke-Api {
    param([string]$Url,[string]$Method='GET',[hashtable]$Headers,
          [object]$Body=$null,[int]$Timeout=60,[bool]$Retry400403=$false)
    $retry=0
    while ($retry -lt 4) {
        $retry++
        try {
            $opts=@{Uri=$Url; Method=$Method; Headers=$Headers; TimeoutSec=$Timeout;
                ErrorAction='Stop'; ContentType='application/json'}
            if ($null -ne $Body) { $opts.Body=($Body | ConvertTo-Json -Depth 12 -Compress) }
            return Invoke-RestMethod @opts
        }
        catch {
            $status=0
            try { $status=[int]$_.Exception.Response.StatusCode } catch { }
            if ($status -in @(400,403) -and $Retry400403 -and $retry -lt 2) {
                Start-Sleep -Seconds 2
                continue
            }
            if ($status -in @(401,403,404,400) -or $retry -ge 4 -or
                ($status -ne 0 -and $status -notin @(429,500,502,503,504))) {
                throw
            }
            Start-Sleep -Seconds ([Math]::Min(2*$retry,8))
        }
    }
}
function Get-WGAccessToken {
    param([string]$Audience='')
    $combined='{0}:{1}' -f $script:WGAccessId,$script:WGPassword
    $basic=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($combined))
    $form=@{grant_type='client_credentials';scope='api-access'}
    if ($Audience) { $form.audience=$Audience }
    $token=Invoke-RestMethod -Method Post -Uri $script:WGAuthUrl `
        -Headers @{Authorization="Basic $basic";Accept='application/json'} `
        -ContentType 'application/x-www-form-urlencoded' -Body $form -TimeoutSec 60
    if (-not $token.access_token) { throw 'WatchGuard did not issue a token' }
    return [string]$token.access_token
}
function Refresh-WGToken {
    if (-not $script:WGToken -or ((Get-Date)-$script:WGTokenTime).TotalMinutes -ge 40) {
        $script:WGToken=Get-WGAccessToken
        $script:WGTokenTime=Get-Date
    }
}
function Invoke-WG {
    param([string]$Path,[string]$Method='GET',[object]$Body=$null,[string]$Token='')
    $auth=$Token
    if (-not $auth) { Refresh-WGToken; $auth=$script:WGToken }
    return Invoke-Api -Url ($script:WGApiUrl+$Path) -Method $Method -Body $Body `
        -Headers @{Authorization="Bearer $auth";Accept='application/json';'WatchGuard-API-Key'=$script:WGKey} `
        -Retry400403 $true
}
function Refresh-NinjaToken {
    # Existing delegated user OAuth grant. Ninja's script/run API cannot be
    # invoked using the separate NinjaRMM client_credentials integration.
    if (-not $script:NinjaToken -or ((Get-Date)-$script:NinjaTokenTime).TotalMinutes -ge 40) {
        if ([string]::IsNullOrWhiteSpace([string]$script:NinjaRefreshToken)) {
            throw 'Delegated Ninja OAuth refresh token unavailable in controller memory'
        }
        $form=@{
            grant_type    = 'refresh_token'
            client_id     = $script:NinjaClientId
            client_secret = $script:NinjaSecret
            refresh_token = $script:NinjaRefreshToken
        }
        try {
            $token=Invoke-RestMethod -Method Post -Uri ($script:NinjaUrl+'/ws/oauth/token') `
                -ContentType 'application/x-www-form-urlencoded' -Body $form `
                -TimeoutSec 60 -ErrorAction Stop
        }
        catch {
            # Do not log a response body or request body: OAuth values are secrets.
            $httpStatus='UNAVAILABLE'
            try { $httpStatus=[string][int]$_.Exception.Response.StatusCode } catch { }
            throw ('Ninja delegated OAuth token exchange failed Grant=refresh_token HTTP={0}; check stored refresh token/app authorization if needed. Token values not logged.' -f $httpStatus)
        }
        finally {
            $form=$null
        }
        if ([string]::IsNullOrWhiteSpace([string]$token.access_token)) {
            throw 'Delegated Ninja refresh_token response contained no access token'
        }

        $replacement=[string]$token.refresh_token
        if (-not [string]::IsNullOrWhiteSpace($replacement)) {
            if ($replacement -cne $script:NinjaRefreshToken) {
                # Keep replacement in memory for this run, but do not silently
                # pretend it was persisted. Existing broker convention requires
                # a manual secure token update/reauthorization.
                $script:RefreshTokenManualUpdateRequired=$true
                Write-Log 'ACTION_REQUIRED | Delegated Ninja OAuth returned a rotated refresh token; approved 1Password token storage must be refreshed before next run. TokenValueLogged=False'
            }
            $script:NinjaRefreshToken=$replacement
        }
        $script:NinjaToken=[string]$token.access_token
        $script:NinjaTokenTime=Get-Date
        $token=$null
        Write-Log 'NINJA_OAUTH | Flow=delegated_refresh_token Principal=DelegatedOAuthUser TokenIssued=True ValuesLogged=False'
    }
}
function Invoke-Ninja {
    param([string]$Path,[string]$Method='GET',[object]$Body=$null)
    Refresh-NinjaToken
    try {
        return Invoke-Api -Url ($script:NinjaUrl+$Path) -Method $Method -Body $Body `
            -Headers @{Authorization="Bearer $($script:NinjaToken)";Accept='application/json'}
    }
    catch {
        $httpStatus='UNAVAILABLE'
        try { $httpStatus=[string][int]$_.Exception.Response.StatusCode } catch { }
        # Do not echo the URL host, response body, authorization header,
        # request parameters, or tokens into the manifest or log.
        throw ('Ninja API request failed Method={0} Path={1} HTTP={2} Auth=delegated_oauth' -f `
            $Method,(Clean-Text $Path 140),$httpStatus)
    }
}
function As-Items {
    param([object]$Response)
    if ($null -eq $Response) { return @() }
    if ($Response -is [array]) { return @($Response) }
    foreach ($field in @('items','activities','data','results','objects')) {
        if ($Response.PSObject.Properties.Name -contains $field -and
            $Response.$field -is [array]) { return @($Response.$field) }
    }
    throw 'Unexpected API collection shape; no silent partial inventory'
}
function Expand-WGTree {
    param([object[]]$Items)
    foreach ($item in @($Items)) {
        if (-not $item) { continue }
        Write-Output $item
        if ($item.PSObject.Properties.Name -contains 'childrenList') {
            $children=@($item.childrenList | Where-Object { $null -ne $_ })
            if ($children.Count) { Expand-WGTree $children }
        }
    }
}
function Get-CloudManagedAccountEligibility {
    param([string]$AccountId)
    # Only ONE WatchGuard device-details call per Subscriber; no LAN/cert queries.
    $aud=Invoke-WG -Path '/platform/authorization/v1/audiences' -Method 'POST' -Body @{accountId=$AccountId}
    if (-not $aud.audience) { throw 'No WatchGuard Subscriber audience' }
    $subscriberToken=Get-WGAccessToken -Audience ([string]$aud.audience)
    $response=Invoke-WG -Path ('/firebox/management/v1/info/{0}/devices?device_type=FB' -f $AccountId) `
        -Token $subscriberToken
    $all=@(As-Items $response)
    if ($null -ne $response.count -and [int]$response.count -ne $all.Count) {
        throw ('Incomplete WatchGuard device summary Account={0} Count={1} Items={2}' -f `
            $AccountId,$response.count,$all.Count)
    }
    $eligible=@($all | Where-Object {
        [string]$_.id -match '^FB-\d+$' -and
        [string]$_.cloud_managed -ieq 'yes' -and
        [string]$_.state -ine 'never connected'
    })
    $locallyManaged=@($all | Where-Object {
        [string]$_.id -match '^FB-\d+$' -and
        [string]$_.cloud_managed -ieq 'no'
    })
    $clusters=@($all | Where-Object { [string]$_.id -like 'FBCL-*' })
    return [PSCustomObject]@{
        Qualifies=($eligible.Count -gt 0)
        CloudManagedCount=$eligible.Count
        LocalExcluded=$locallyManaged.Count
        ClusterExcluded=$clusters.Count
    }
}
function Get-NinjaOrgDevices {
    param([int]$OrgId)
    $all=[System.Collections.Generic.List[object]]::new()
    $after=0
    do {
        $query='/v2/organization/{0}/devices?pageSize=1000' -f $OrgId
        if ($after -gt 0) { $query+=('&after={0}' -f $after) }
        $batch=@(As-Items (Invoke-Ninja -Path $query))
        foreach ($device in $batch) {
            if ([int]$device.id -le $after -or [int]$device.organizationId -ne $OrgId) {
                throw 'Ninja org-device pagination or organization ID inconsistency'
            }
            $all.Add($device)
        }
        if ($batch.Count -eq 0) { break }
        $next=[int]$batch[-1].id
        if ($next -le $after) { throw 'Device pagination cursor did not advance' }
        $after=$next
    } while ($batch.Count -ge 1000)
    return $all.ToArray()
}
function Invoke-SameScriptOnDevice {
    param([int]$DeviceId,[string]$Arguments)
    return Invoke-Ninja -Path ('/v2/device/{0}/script/run' -f $DeviceId) -Method 'POST' `
        -Body @{type='SCRIPT';id=$script:SavedScriptId;parameters=$Arguments;runAs='system'}
}
function Find-ActivityText {
    param([int]$DeviceId,[string]$Marker)
    $path='/v2/device/{0}/activities?pageSize=500' -f $DeviceId
    $response=Invoke-Ninja -Path $path
    foreach ($activity in @(As-Items $response)) {
        if ([string]$activity.activityResult -in @('FAILURE','UNSUPPORTED','UNCOMPLETED')) { continue }
        # Do not interpret input parameters or arbitrary metadata as validated stdout.
        $fields=@([string]$activity.message,[string]$activity.subject)
        if ($null -ne $activity.data) {
            foreach ($key in @('output','result','stdout','scriptOutput','message')) {
                if ($activity.data.PSObject.Properties.Name -contains $key) {
                    $fields+=([string]$activity.data.$key)
                }
            }
        }
        foreach ($field in $fields) {
            if ($field.Contains($Marker)) { return $field }
        }
    }
    return ''
}
function Decode-Info64 {
    param([string]$Encoded)
    if ($Encoded -eq 'NONE') { return '' }
    try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded)) }
    catch { return '[INVALID_BASE64]' }
}
function Get-ProbeReceipt {
    param([int]$DeviceId,[string]$AuditId)
    $prefix='WGPROBEv2 Run={0} Device={1} State=' -f $AuditId,$DeviceId
    $raw=Find-ActivityText -DeviceId $DeviceId -Marker $prefix
    if (-not $raw) { return $null }
    $pattern=[regex]::Escape($prefix) + `
        '(LOCAL_MATCH|LOCAL_MISSING|SOURCE_INVALID|SOURCE_UNAVAILABLE|LOCAL_CHECK_ERROR) Gateway=([0-9.]+|NONE) LAN=([0-9.,]+|NONE) LocationId=([0-9]+|NONE) SHA256=([A-F0-9]{64}|NONE) Thumbprint=([A-F0-9]{40}|NONE) Expires=([0-9-]+|NONE) Reason=([A-Z_]+) Subject64=([A-Za-z0-9+/=]+|NONE) Issuer64=([A-Za-z0-9+/=]+|NONE)'
    $match=[regex]::Match($raw,$pattern)
    if (-not $match.Success) { return $null }
    return [PSCustomObject]@{State=$match.Groups[1].Value;Gateway=$match.Groups[2].Value;
        LAN=$match.Groups[3].Value;LocationId=$match.Groups[4].Value;
        Fingerprint=$match.Groups[5].Value;Thumbprint=$match.Groups[6].Value;
        Expires=$match.Groups[7].Value;Reason=$match.Groups[8].Value;
        Subject=(Decode-Info64 $match.Groups[9].Value);
        Issuer=(Decode-Info64 $match.Groups[10].Value)}
}

function Test-RemoteCopyReceipt {
    param([int]$DeviceId,[string]$AuditId,[string]$Digest)
    $prefix='WGCOPYv1 Run={0} Device={1} State=VERIFIED SHA256={2}' -f $AuditId,$DeviceId,$Digest
    return [bool](Find-ActivityText -DeviceId $DeviceId -Marker $prefix)
}
function Write-HumanManifest {
    param([string]$Path,[string]$AuditId,[object[]]$Accounts,[object[]]$Locations,
          [object[]]$Endpoints,[object[]]$Issues,[string]$ReportTarget,
          [string]$AccountName)
    $lines=[Collections.Generic.List[string]]::new()
    $safeName=Clean-Text $AccountName 140
    if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName='UNRESOLVED' }
    $lines.Add(('WATCHGUARD PROXYCA CERTIFICATE AUDIT | {0} | {1}' -f $PilotWatchGuardAccountId,$safeName))
    $lines.Add(('Generated UTC: {0}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')))
    $lines.Add(('Run ID: {0}' -f $AuditId))
    $lines.Add(('WatchGuard account: {0} | Name: {1}' -f $PilotWatchGuardAccountId,$safeName))
    $lines.Add('Mode: Manual / Read-only (Ninja endpoint probes only)')
    $lines.Add(('Remote report copy target: {0}' -f $ReportTarget))
    $lines.Add('WatchGuard eligibility requires >=1 cloud-managed, non-cluster, ever-connected Firebox.')
    $lines.Add('Endpoint expected CA: live ProxyCA.cer from its own selected IPv4 gateway, not the WGC API.')
    $lines.Add('COMPLIANT: exact SHA256 of gateway ProxyCA present in LocalMachine Root, certificate in valid date range.')
    $lines.Add('NEEDS_CERT: gateway ProxyCA retrieved and valid but exact root certificate absent.')
    $lines.Add('SOURCE_UNAVAILABLE: gateway/portal/certificate source could not be verified. NOT MISSING.')
    $lines.Add('No independent WatchGuard router-identity attestation is performed by this audit.')
    $lines.Add('Locally managed-only customer accounts are excluded; remote copy receipt/status is in controller log.')
    $lines.Add('')
    $lines.Add('SUMMARY')
    $lines.Add(('  WatchGuard Subscriber accounts assessed: {0}' -f $Accounts.Count))
    $lines.Add(('  Cloud-managed eligible account matches: {0}' -f @($Accounts | Where-Object { $_.Status -eq 'MATCHED' }).Count))
    $lines.Add(('  Ninja locations in matched organizations: {0}' -f $Locations.Count))
    $lines.Add(('  Ninja endpoints: {0}' -f $Endpoints.Count))
    foreach ($status in @('OFFLINE','COMPLIANT','NEEDS_CERT')) {
        $lines.Add(('  {0}: {1}' -f $status,@($Endpoints | Where-Object { $_.Status -eq $status }).Count))
    }
    foreach ($group in @($Endpoints | Group-Object Status | Sort-Object Name)) {
        if ($group.Name -notin @('OFFLINE','COMPLIANT','NEEDS_CERT')) {
            $lines.Add(('  {0}: {1}' -f $group.Name,$group.Count))
        }
    }
    $lines.Add(('  Issues/review records: {0}' -f $Issues.Count))
    $lines.Add('')
    $lines.Add('WATCHGUARD CLOUD ELIGIBILITY / NINJA ORGANIZATION CROSSWALK')
    foreach ($a in @($Accounts | Sort-Object Name)) {
        $lines.Add(('  WG="{0}" WGC={1} | CloudManagedCount={2} LocalExcluded={3} ClusterExcluded={4}' -f `
            (Clean-Text $a.Name 130),$a.WgId,$a.CloudCount,$a.LocalExcluded,$a.ClusterExcluded))
        $lines.Add(('    Ninja="{0}" OrgId={1} | Status={2} | Reason={3}' -f `
            (Clean-Text $a.NinjaName 130),$a.NinjaId,$a.Status,(Clean-Text $a.Reason 250)))
    }
    $lines.Add('')
    $lines.Add('NINJA LOCATIONS')
    foreach ($loc in @($Locations | Sort-Object OrgName,Name)) {
        $related=@($Endpoints | Where-Object { [string]$_.OrgId -eq [string]$loc.OrgId -and
            [string]$_.LocationId -eq [string]$loc.Id })
        $hashes=@($related | Where-Object { $_.SHA256 -match '^[A-F0-9]{64}$' } |
            Select-Object -ExpandProperty SHA256 -Unique)
        $lines.Add(('  Org="{0}" OrgId={1} | Location="{2}" LocationId={3} | Endpoints={4}' -f `
            (Clean-Text $loc.OrgName 100),$loc.OrgId,(Clean-Text $loc.Name 110),$loc.Id,$related.Count))
        $lines.Add(('    Observed gateway ProxyCA SHA256: {0}' -f $(if ($hashes.Count) { $hashes -join ',' } else { 'NONE' })))
    }
    $lines.Add('')
    $lines.Add('ENDPOINT CERTIFICATE RESULTS')
    foreach ($e in @($Endpoints | Sort-Object OrgName,LocationName,DeviceName)) {
        $lines.Add(('  Org="{0}" Host="{1}" NinjaId={2} | Location="{3}"({4}) | Status={5}' -f `
            (Clean-Text $e.OrgName 85),(Clean-Text $e.DeviceName 90),$e.DeviceId,
            (Clean-Text $e.LocationName 90),$e.LocationId,$e.Status))
        $lines.Add(('    Reason={0}' -f (Clean-Text $e.Reason 220)))
        $lines.Add(('    LAN={0} | Gateway={1}' -f $e.LAN,$e.Gateway))
        $lines.Add(('    ProxyCA_SHA256={0} | SHA1_Thumbprint={1} | ExpiresUTC={2}' -f `
            $e.SHA256,$e.Thumbprint,$e.Expires))
        $lines.Add(('    Certificate_Subject={0}' -f (Clean-Text $e.Subject 400)))
        $lines.Add(('    Certificate_Issuer ={0}' -f (Clean-Text $e.Issuer 400)))
    }
    $lines.Add('')
    $lines.Add('ERRORS / REVIEW')
    if ($Issues.Count -eq 0) { $lines.Add('  None') }
    else { foreach ($issue in $Issues) { $lines.Add(('  {0}' -f (Clean-Text $issue 360))) } }
    [IO.File]::WriteAllLines($Path,$lines.ToArray(),(New-Object Text.UTF8Encoding($false)))
}
function Write-NinjaStatusGroup {
    param([string]$Status,[object[]]$Endpoints)
    $found=@($Endpoints | Where-Object { $_.Status -eq $Status } |
        Sort-Object OrgName,LocationName,DeviceName)
    $names=@($found | ForEach-Object { Clean-Text $_.DeviceName 85 })
    $machineList=if ($names.Count -gt 0) { $names -join ', ' } else { 'NONE' }
    Write-Output ('{0}: {1} | {2}' -f $Status,$found.Count,$machineList)
}
function Send-ManifestCopy {
    param([string]$Path,[string]$AuditId,[int]$Destination)
    if ($Destination -eq 0) { return 'DISABLED' }
    $recipient=Invoke-Ninja -Path ('/v2/device/{0}' -f $Destination)
    if ([int]$recipient.id -ne $Destination) { throw 'Ninja copy target ID mismatch' }
    if ([string]$recipient.nodeClass -notin @('WINDOWS_WORKSTATION','WINDOWS_SERVER')) {
        throw 'Ninja copy target is not Windows'
    }
    if ([bool]$recipient.offline) { throw 'Ninja copy target is offline' }
    $bytes=[IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -gt 10485760) { throw 'Manifest exceeds remote-copy 10MB safety cap' }
    $digest=Get-Sha256Hex $bytes
    $output=New-Object IO.MemoryStream
    try {
        $gzip=New-Object IO.Compression.GZipStream -ArgumentList @($output,[IO.Compression.CompressionMode]::Compress,$true)
        try { $gzip.Write($bytes,0,$bytes.Length) }
        finally { $gzip.Dispose() }
        $encoded=[Convert]::ToBase64String($output.ToArray())
    }
    finally { $output.Dispose() }
    $chunkSize=1600
    $count=[int][Math]::Ceiling($encoded.Length/[double]$chunkSize)
    if ($count -lt 1 -or $count -gt 600) { throw 'Manifest copy exceeds 600 Ninja parameter chunks' }
    Write-Log ('COPY_SEND | Target={0} ReportBytes={1} Chunks={2} SHA256={3}' -f $Destination,$bytes.Length,$count,$digest)
    for ($i=0; $i -lt $count; $i++) {
        $size=[Math]::Min($chunkSize,$encoded.Length-($i*$chunkSize))
        $frag=$encoded.Substring($i*$chunkSize,$size)
        $argsText='Copy {0} {1} {2} {3} {4}' -f $AuditId,$i,$count,$digest,$frag
        Invoke-SameScriptOnDevice -DeviceId $Destination -Arguments $argsText | Out-Null
    }
    $until=(Get-Date).AddSeconds(120)
    do {
        Start-Sleep -Seconds 10
        if (Test-RemoteCopyReceipt -DeviceId $Destination -AuditId $AuditId -Digest $digest) {
            Write-Log ('COPY_VERIFIED | Device={0} SHA256={1}' -f $Destination,$digest)
            return 'VERIFIED_REMOTE'
        }
    } while ((Get-Date) -lt $until)
    return 'DISPATCHED_UNVERIFIED'
}

$AuditId=[guid]::NewGuid().ToString('N')
$ManifestPath=Join-Path $WorkRoot ('WatchGuard_Ninja_ProxyCA_Audit_{0}.txt' -f $AuditId)
$AccountRows=[System.Collections.Generic.List[object]]::new()
$LocationRows=[System.Collections.Generic.List[object]]::new()
$EndpointRows=[System.Collections.Generic.List[object]]::new()
$Issues=[System.Collections.Generic.List[string]]::new()
$FinalToken='ERROR'
$CopyStatus='NOT_ATTEMPTED'
$script:WGToken=$null; $script:NinjaToken=$null
$script:NinjaRefreshToken=$null
$script:RefreshTokenManualUpdateRequired=$false
$script:WGTokenTime=[datetime]::MinValue
$script:NinjaTokenTime=[datetime]::MinValue
$script:SavedScriptId=0
$script:ResolvedWgAccountName='UNRESOLVED'
try {
    $Stage='Prepare'
    Ensure-WorkRoot
    if ([string]::IsNullOrWhiteSpace($PilotWatchGuardAccountId)) {
        throw 'Required Ninja script variable watchguardCloudAccount is missing or empty. No account selected; audit not started.'
    }
    if ($CopyReportToNinjaDeviceId -le 0) {
        throw 'Set CopyReportToNinjaDeviceId to your report-collector Ninja device ID before running this public template.'
    }
    if ($PilotWatchGuardAccountId -notmatch '^WGC-[0-9]+-[a-fA-F0-9]{20}$') {
        throw 'Invalid WatchGuard account ID. Expected WGC-1- followed by 20 hexadecimal characters.'
    }
    Write-Log ('START | Manual scoped WGC multi-location audit Run={0} PilotOrg={1} MaxProbes={2} CopyTarget={3}' -f `
        $AuditId,$PilotNinjaOrgId,$MaxProbeDevices,$CopyReportToNinjaDeviceId)
    if ($PilotNinjaOrgId -lt 0 -or $MaxProbeDevices -lt 0 -or $WaitForProbeSeconds -lt 0) {
        throw 'Invalid configuration value'
    }
    $Stage='CredentialBroker'
    $secret=[string](Ninja-Property-Get -Name 'YOUR_BROKER_TOKEN_CUSTOM_FIELD')
    if (-not $secret.Trim()) { throw 'Missing Ninja broker secure field YOUR_BROKER_TOKEN_CUSTOM_FIELD' }
    $env:OP_SERVICE_ACCOUNT_TOKEN=$secret.Trim()
    $secret=$null
    $op=Get-OpExe
    $wgJson=@(& $op item get 'YOUR_WATCHGUARD_ITEM' --vault $OnePasswordVault --format json 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0 -or -not $wgJson) { throw '1Password WatchGuard credential item read failed' }
    $ninjaJson=@(& $op item get 'YOUR_NINJA_OAUTH_ITEM' --vault $OnePasswordVault --format json 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0 -or -not $ninjaJson) {
        throw '1Password Ninja OAuth item read failed'
    }
    $refreshJson=@(& $op item get 'YOUR_NINJA_REFRESH_TOKEN_ITEM' --vault $OnePasswordVault --format json 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0 -or -not $refreshJson) {
        throw '1Password Ninja refresh-token item read failed'
    }
    $wgItem=$wgJson | ConvertFrom-Json
    $ninjaItem=$ninjaJson | ConvertFrom-Json
    $refreshItem=$refreshJson | ConvertFrom-Json
    $script:WGKey=Get-OpField $wgItem 'credential'
    $script:WGAccessId=Get-OpField $wgItem 'readOnlyAccessId'
    $script:WGPassword=Get-OpField $wgItem 'readOnlyPassword'
    $script:WGProvider=Get-OpField $wgItem 'accountID'
    $script:WGAuthUrl=(Get-OpField $wgItem 'authenticationUrl').TrimEnd('/')
    $script:WGApiUrl=(Get-OpField $wgItem 'baseApiUrl').TrimEnd('/')
    $script:NinjaUrl=(Get-OpField $ninjaItem 'consoleUrl').TrimEnd('/')
    $script:NinjaClientId=Get-OpField $ninjaItem 'clientId'
    $script:NinjaSecret=Get-OpField $ninjaItem 'clientSecret'
    $script:NinjaRefreshToken=Get-OpField $refreshItem 'refreshToken'
    $wgJson=$null; $ninjaJson=$null; $refreshJson=$null
    $wgItem=$null; $ninjaItem=$null; $refreshItem=$null
    $env:OP_SERVICE_ACCOUNT_TOKEN=$null

    $Stage='WatchGuardAccounts'
    $wgResponse=Invoke-WG -Path ('/platform/accounts/v2/accounts/{0}/children?type=0&limit=-1&includeDelegatedAccounts=true' -f $script:WGProvider)
    $allWg=@(Expand-WGTree -Items @(As-Items $wgResponse))
    $subscribers=@($allWg | Where-Object { $_.accountId -and [int]$_.type -in @(2,4) } |
        Group-Object accountId | ForEach-Object { $_.Group[0] })
    if ($subscribers.Count -eq 0) { throw 'WatchGuard returned zero Subscriber accounts' }
    $subscribers=@($subscribers | Where-Object { [string]$_.accountId -ieq $PilotWatchGuardAccountId })
    if ($subscribers.Count -ne 1) { throw ('Selected WG account must be found exactly once, Count={0} WGC={1}' -f $subscribers.Count,$PilotWatchGuardAccountId) }
    $script:ResolvedWgAccountName = Clean-Text ([string]$subscribers[0].name) 140

    # First establish WatchGuard eligibility, without downloading Firebox LANs.
    $Stage='CloudManagedAccountEligibility'
    $eligibleWg=[Collections.Generic.List[object]]::new()
    foreach ($wg in $subscribers) {
        $wgId=[string]$wg.accountId
        $wgName=[string]$wg.name
        $entry=[PSCustomObject]@{Name=$wgName;WgId=$wgId;NinjaName='';NinjaId='';
            CloudCount=0;LocalExcluded=0;ClusterExcluded=0;
            Status='PENDING_ELIGIBILITY';Reason=''}
        $AccountRows.Add($entry)
        if ([string]$wg.relationName -ieq 'Delegated' -or
            [string]$wg.relationType -ieq 'Delegated') {
            $entry.Status='EXCLUDED_DELEGATED';$entry.Reason='Delegated WatchGuard Subscriber'
            continue
        }
        try {
            $summary=Get-CloudManagedAccountEligibility -AccountId $wgId
            $entry.CloudCount=[int]$summary.CloudManagedCount
            $entry.LocalExcluded=[int]$summary.LocalExcluded
            $entry.ClusterExcluded=[int]$summary.ClusterExcluded
            if (-not $summary.Qualifies) {
                $entry.Status='EXCLUDED_NO_CLOUD_MANAGED';$entry.Reason='No eligible cloud-managed Firebox; local-only devices excluded'
                continue
            }
            $entry.Status='CLOUD_ELIGIBLE';$entry.Reason='Has cloud-managed Firebox'
            $eligibleWg.Add($wg)
            Write-Log ('WGC_ELIGIBLE | Account={0} CloudManaged={1} LocalExcluded={2} ClusterExcluded={3}' -f `
                $wgId,$entry.CloudCount,$entry.LocalExcluded,$entry.ClusterExcluded)
        }
        catch {
            $entry.Status='ELIGIBILITY_ERROR';$entry.Reason=(Clean-Text $_.Exception.Message 190)
            $Issues.Add(('WG_Eligibility Account={0} Reason={1}' -f $wgId,$entry.Reason))
        }
    }
    $Stage='NinjaOrganizations'
    if ($eligibleWg.Count -gt 0) {
        $ninjaOrgs=@(As-Items (Invoke-Ninja -Path '/v2/organizations'))
        if ($ninjaOrgs.Count -eq 0) { throw 'Ninja returned no organizations' }
        $ninjaByName=@{}
        foreach ($org in $ninjaOrgs) {
            $key=Normalize-OrgName ([string]$org.name)
            if (-not $ninjaByName.ContainsKey($key)) { $ninjaByName[$key]=@() }
            $ninjaByName[$key]+=$org
        }
        $Stage='Crosswalk'
        foreach ($wg in $eligibleWg.ToArray()) {
            $wgId=[string]$wg.accountId
            $key=Normalize-OrgName ([string]$wg.name)
            $entry=@($AccountRows.ToArray() | Where-Object { $_.WgId -ceq $wgId })[0]
            if (-not $ninjaByName.ContainsKey($key) -or @($ninjaByName[$key]).Count -ne 1) {
                $entry.Status='UNMATCHED_OR_AMBIGUOUS';$entry.Reason='No unique exact-name Ninja organization'
                $Issues.Add(('NinjaOrgMatch WGC={0} Name={1} Reason={2}' -f `
                    $wgId,(Clean-Text $wg.name 115),$entry.Reason))
                continue
            }
            $org=$ninjaByName[$key][0]
            $entry.NinjaName=[string]$org.name
            $entry.NinjaId=[string]$org.id
            if ($PilotNinjaOrgId -gt 0 -and [int]$org.id -ne $PilotNinjaOrgId) {
                $entry.Status='PILOT_ORG_MISMATCH';$entry.Reason='Pilot org ID override disagrees with discovered org'
                $Issues.Add(('PilotOrgMismatch WGC={0} Ninja={1}' -f $wgId,$org.id))
                continue
            }
            try {
                $Stage='NinjaLocations'
                $rawLocations=@(As-Items (Invoke-Ninja -Path ('/v2/organization/{0}/locations' -f [int]$org.id)))
                if ($rawLocations.Count -eq 0) { throw 'Ninja returned zero locations' }
                $locationNames=@{}
                foreach ($l in $rawLocations) {
                    $locationNames[[string]$l.id]=[string]$l.name
                    $LocationRows.Add([PSCustomObject]@{OrgName=[string]$org.name;
                        OrgId=[int]$org.id;Id=[string]$l.id;Name=[string]$l.name})
                }
                $Stage='NinjaOrgDevices'
                $devices=@(Get-NinjaOrgDevices -OrgId ([int]$org.id))
                $windowsDevices=@($devices | Where-Object {
                    [string]$_.nodeClass -in @('WINDOWS_WORKSTATION','WINDOWS_SERVER')
                })
                foreach ($device in $windowsDevices) {
                    $locId=[string]$device.locationId
                    $locName='UNMAPPED_NINJA_LOCATION'
                    if ($locationNames.ContainsKey($locId)) { $locName=$locationNames[$locId] }
                    $row=[PSCustomObject]@{OrgName=[string]$org.name;OrgId=[int]$org.id;
                        DeviceId=[int]$device.id;DeviceName=[string]$device.systemName;
                        LocationId=$locId;LocationName=$locName;Status='READY';
                        Gateway='';LAN='';SHA256='';Thumbprint='';Expires='';
                        Subject='';Issuer='';Reason='Eligible for read-only certificate probe'}
                    if (-not $locationNames.ContainsKey($locId)) {
                        $row.Status='REVIEW_NINJA_LOCATION'
                        $row.Reason='Device location ID absent from Ninja organization locations'
                    }
                    elseif ([bool]$device.offline) {
                        $row.Status='OFFLINE';$row.Reason='Device offline during manual audit'
                    }
                    $EndpointRows.Add($row)
                }
                $entry.Status='MATCHED'
                $entry.Reason=('NinjaLocations={0} NinjaDevices={1}' -f $rawLocations.Count,$windowsDevices.Count)
                Write-Log ('ACCOUNT_MATCHED | WGC={0} NinjaOrg={1} Locations={2} Endpoints={3}' -f `
                    $wgId,$org.id,$rawLocations.Count,$windowsDevices.Count)
            }
            catch {
                $entry.Status='NINJA_INVENTORY_ERROR'
                $entry.Reason=(Clean-Text $_.Exception.Message 180)
                $Issues.Add(('NinjaInventory WGC={0} Org={1} Stage={2} Reason={3}' -f `
                    $wgId,$org.id,$Stage,$entry.Reason))
            }
        }
    }
    # Inventory is now complete. Only dispatch infrastructure remains.
    if (@($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'READY' }).Count -gt 0 -or
        $CopyReportToNinjaDeviceId -gt 0) {
        $Stage='FindSameNinjaScript'
        $available=@(As-Items (Invoke-Ninja -Path '/v2/automation/scripts'))
        if ($available.Count -eq 0) { throw 'Ninja returned no saved automation scripts' }
        $approved=@($SameScriptLibraryNames | ForEach-Object { Normalize-NinjaScriptName $_ })
        if ($SavedScriptIdOverride -gt 0) {
            $same=@($available | Where-Object { [string]$_.id -eq [string]$SavedScriptIdOverride })
            if ($same.Count -ne 1 -or
                (Normalize-NinjaScriptName ([string]$same[0].name)) -notin $approved) {
                throw ('Verified script ID override {0} is not the approved saved automation' -f $SavedScriptIdOverride)
            }
        }
        else {
            $same=@($available | Where-Object {
                (Normalize-NinjaScriptName ([string]$_.name)) -in $approved
            })
        }
        if ($same.Count -ne 1 -or [int]$same[0].id -le 0) {
            throw ('Approved Ninja saved script must be unique; Matches={0}' -f $same.Count)
        }
        $script:SavedScriptId=[int]$same[0].id
        Write-Log ('SCRIPT_RESOLVED | Id={0} Name={1}' -f `
            $script:SavedScriptId,(Clean-Text $same[0].name 100))
    }
    $Stage='EndpointDispatch'
    $dispatched=0
    foreach ($row in @($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'READY' })) {
        if ($MaxProbeDevices -gt 0 -and $dispatched -ge $MaxProbeDevices) {
            $row.Status='NOT_TESTED';$row.Reason='Pilot device limit reached'
            continue
        }
        try {
            Invoke-SameScriptOnDevice -DeviceId $row.DeviceId `
                -Arguments ('Probe {0} {1}' -f $AuditId,$row.DeviceId) | Out-Null
            $row.Status='PENDING';$row.Reason='Dispatched; awaiting endpoint evidence'
            $dispatched++
        }
        catch {
            $row.Status='DISPATCH_FAILED';$row.Reason=Clean-Text $_.Exception.Message 180
            $Issues.Add(('NinjaDispatch Device={0} Reason={1}' -f $row.DeviceId,$row.Reason))
        }
    }
    Write-Log ('PILOT | WGC={0} Eligible={1} Matched={2} Locations={3} Endpoints={4} Dispatched={5}' -f `
        $PilotWatchGuardAccountId,$eligibleWg.Count,
        @($AccountRows.ToArray() | Where-Object { $_.Status -eq 'MATCHED' }).Count,
        $LocationRows.Count,$EndpointRows.Count,$dispatched)

    $Stage='ProbeResultPolling'
    $deadline=(Get-Date).AddSeconds($WaitForProbeSeconds)
    do {
        $remaining=@($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'PENDING' })
        if ($remaining.Count -eq 0) { break }
        $gotAny=$false
        foreach ($row in $remaining) {
            try {
                $receipt=Get-ProbeReceipt -DeviceId $row.DeviceId -AuditId $AuditId
                if ($receipt) {
                    $row.Status=switch ($receipt.State) {
                        'LOCAL_MATCH' { 'COMPLIANT' }
                        'LOCAL_MISSING' { 'NEEDS_CERT' }
                        'SOURCE_INVALID' { 'SOURCE_INVALID' }
                        'SOURCE_UNAVAILABLE' { 'SOURCE_UNAVAILABLE' }
                        'LOCAL_CHECK_ERROR' { 'LOCAL_CHECK_ERROR' }
                        default { 'PROBE_ERROR' }
                    };$row.Gateway=$receipt.Gateway
                    $row.LAN=$receipt.LAN
                    $row.SHA256=$receipt.Fingerprint;$row.Thumbprint=$receipt.Thumbprint
                    $row.Subject=$receipt.Subject;$row.Issuer=$receipt.Issuer
                    $row.Expires=$receipt.Expires
                    if ($receipt.LocationId -ne 'NONE' -and $receipt.LocationId -ne $row.LocationId) {
                        $row.Status='REVIEW_LOCATION_DISAGREEMENT';$row.Reason='Ninja device location ID differs from probe environment'
                    } else { $row.Reason=$receipt.Reason }
                    $gotAny=$true
                }
            }
            catch {
                # Poll failures are not certificate mismatches; keep status pending.
                Write-Log ('POLL_RETRY | NinjaDevice={0} Reason={1}' -f $row.DeviceId,(Clean-Text $_.Exception.Message 130))
            }
        }
        if ((Get-Date) -ge $deadline) { break }
        if (-not $gotAny) { Start-Sleep -Seconds 10 }
    } while ((Get-Date) -lt $deadline)
    foreach ($row in @($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'PENDING' })) {
        $row.Status='UNVERIFIED';$row.Reason='No matching completed Ninja activity returned before reporting deadline'
    }
    $FinalToken='RESULT'
    if (@($AccountRows.ToArray() | Where-Object { $_.Status -eq 'MATCHED' }).Count -eq 0 -or
        $EndpointRows.Count -eq 0) { $FinalToken='NO_ACTION' }
    if ($Issues.Count -gt 0 -or
        @($AccountRows.ToArray() | Where-Object { $_.Status -in @('ELIGIBILITY_ERROR',
            'UNMATCHED_OR_AMBIGUOUS','PILOT_ORG_MISMATCH','NINJA_INVENTORY_ERROR') }).Count -gt 0 -or
        @($EndpointRows.ToArray() | Where-Object { $_.Status -like 'REVIEW*' -or
            $_.Status -in @('DISPATCH_FAILED','PROBE_ERROR','SOURCE_UNAVAILABLE',
            'SOURCE_INVALID','LOCAL_CHECK_ERROR') }).Count -gt 0) {
        $FinalToken='ERROR'
    }

}
catch {
    $FinalToken='ERROR'
    $Issues.Add(('GLOBAL Stage={0} Reason={1}' -f $Stage,(Clean-Text $_.Exception.Message 250)))
    Write-Log ('GLOBAL_ERROR | Stage={0} Reason={1}' -f $Stage,(Clean-Text $_.Exception.Message))
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN=$null
    if ($script:RefreshTokenManualUpdateRequired) {
        $Issues.Add('ACTION_REQUIRED NinjaOAuthRefreshTokenRotated: update the approved 1Password refresh token using the existing secure broker bootstrap process before the next run. Token value NOT logged or exported.')
        $FinalToken='ERROR'
    }
    try {
        Ensure-WorkRoot
        $targetDesc=if ($CopyReportToNinjaDeviceId -gt 0) {
            'Ninja device {0}, C:\MME\CS (remote receipt required)' -f $CopyReportToNinjaDeviceId
        } else { 'Disabled' }
        Write-HumanManifest -Path $ManifestPath -AuditId $AuditId `
            -Accounts $AccountRows.ToArray() -Locations $LocationRows.ToArray() `
            -Endpoints $EndpointRows.ToArray() -Issues $Issues.ToArray() -ReportTarget $targetDesc `
            -AccountName $script:ResolvedWgAccountName
        Write-Log ('MANIFEST | Path={0} Accounts={1} Devices={2} Issues={3}' -f `
            $ManifestPath,$AccountRows.Count,$EndpointRows.Count,$Issues.Count)
        if ($CopyReportToNinjaDeviceId -gt 0 -and $script:NinjaToken -and $script:SavedScriptId -gt 0) {
            if ([string]$env:NINJA_AGENT_NODE_ID -eq [string]$CopyReportToNinjaDeviceId) {
                $CopyStatus='VERIFIED_LOCAL_ON_COPY_TARGET'
            }
            else {
                try {
                    $CopyStatus=Send-ManifestCopy -Path $ManifestPath -AuditId $AuditId `
                        -Destination $CopyReportToNinjaDeviceId
                }
                catch {
                    $CopyStatus='COPY_FAILED'
                    $Issues.Add(('CopyToReportTarget: {0}' -f (Clean-Text $_.Exception.Message 190)))
                    Write-Log ('COPY_FAILED | {0}' -f (Clean-Text $_.Exception.Message 190))
                }
            }
        }
        else { $CopyStatus='NOT_ATTEMPTED' }
        if ($CopyReportToNinjaDeviceId -gt 0 -and $CopyStatus -notin @('VERIFIED_REMOTE','VERIFIED_LOCAL_ON_COPY_TARGET')) {
            $FinalToken='ERROR'
        }
    }
    catch {
        $FinalToken='ERROR'
        Write-Log ('MANIFEST_ERROR | {0}' -f (Clean-Text $_.Exception.Message 220))
    }
    # Retain the detailed former summary ONLY in the local operational log.
    $logLine='{0} | WGC={1} Run={2} WGAccounts={3} Eligible={4} Locations={5} Endpoints={6} Compliant={7} NeedsCert={8} Offline={9} SourceUnavailable={10} Unverified={11} CopyToReportTarget={12} Issues={13} Manifest={14}' -f `
        $FinalToken,$PilotWatchGuardAccountId,$AuditId,$AccountRows.Count,
        @($AccountRows.ToArray() | Where-Object { $_.CloudCount -gt 0 }).Count,
        $LocationRows.Count,$EndpointRows.Count,
        @($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'COMPLIANT' }).Count,
        @($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'NEEDS_CERT' }).Count,
        @($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'OFFLINE' }).Count,
        @($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'SOURCE_UNAVAILABLE' }).Count,
        @($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'UNVERIFIED' }).Count,
        $CopyStatus,$Issues.Count,$ManifestPath
    $logLine+=' NinjaOAuth=DELEGATED RefreshTokenUpdateRequired={0}' -f $script:RefreshTokenManualUpdateRequired
    Write-Log $logLine

    # Ninja console: four complete status/name lines, then the required final
    # Automation Playbook token. Full technical details remain in log/manifest.
    foreach ($category in @('OFFLINE','NEEDS_CERT','COMPLIANT','UNVERIFIED')) {
        Write-NinjaStatusGroup -Status $category -Endpoints $EndpointRows.ToArray()
    }
    if ($FinalToken -eq 'ERROR') {
        $errorReason=if ($Issues.Count -gt 0) {
            Clean-Text $Issues[0] 240
        } else {
            'Incomplete audit; see operational log and manifest for unresolved statuses'
        }
        Write-Output ('ERROR | {0}' -f $errorReason)
    }
    elseif ($FinalToken -eq 'NO_ACTION') {
        Write-Output 'NO_ACTION | No matching eligible endpoints'
    }
    else {
        $unverifiedCount=@($EndpointRows.ToArray() | Where-Object { $_.Status -eq 'UNVERIFIED' }).Count
        if ($unverifiedCount -gt 0) {
            Write-Output ('RESULT | Audit completed; UNVERIFIED={0} (see manifest)' -f $unverifiedCount)
        }
        else {
            Write-Output 'RESULT | Audit complete'
        }
    }
    $script:WGPassword=$null;$script:NinjaSecret=$null
    $script:NinjaClientId=$null;$script:NinjaRefreshToken=$null
    $script:WGAccessId=$null;$script:WGKey=$null
    $script:WGToken=$null;$script:NinjaToken=$null
}
 } # End controller-only Audit mode.
else {
    Write-Output 'ERROR | Unsupported mode. Valid modes: Audit, Probe, Copy.'
}
exit 0
