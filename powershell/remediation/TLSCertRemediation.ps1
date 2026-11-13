# ============================================================================
# NAME: Device WatchGuard ProxyCA Remediation
# AUTHORED BY: MME Automation Playbook
# TYPE: Remediation
# SCOPE: Windows endpoint, device-level Ninja automation, runs as SYSTEM
# VARIABLES: Required: None | Optional: None
# OUTPUT TOKENS: RESULT / NO_ACTION / ERROR
# CUSTOM FIELDS: Reads: None | Writes: None
# LOGGING PATH: C:\MME\AutoLogs\WatchGuard_ProxyCA_Remediation.log
# DESCRIPTION: Import valid gateway ProxyCA into LocalMachine Root if exact certificate is absent; verify installation.
# ============================================================================
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$LogRoot = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogRoot 'WatchGuard_ProxyCA_Remediation.log'
$Stage = 'Initialize'
function Write-Log {
    param([string]$Message)
    try {
        if (-not (Test-Path -LiteralPath $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null }
        ('{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message) | Add-Content -LiteralPath $LogPath -Encoding UTF8
    } catch { }
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
$Final = 'ERROR | Stage=Initialize'
try {
    $Stage = 'Gateway'
    $Gateway = Get-GatewayAddress
    Write-Log ('GATEWAY | Address={0}' -f $Gateway)
    $Stage = 'CertificateDownload'
    $Certificate = Get-GatewayProxyCA -Gateway $Gateway
    $Fingerprint = Get-Sha256Hex -Bytes $Certificate.RawData
    $Thumbprint = $Certificate.Thumbprint
    Write-Log ('SOURCE | Gateway={0} SHA256={1} Thumbprint={2}' -f $Gateway,$Fingerprint,$Thumbprint)
    $Stage = 'CertificateValidity'
    if ($Certificate.NotBefore.ToUniversalTime() -gt [datetime]::UtcNow -or
        $Certificate.NotAfter.ToUniversalTime() -le [datetime]::UtcNow) {
        throw 'Gateway CA certificate is outside its validity period'
    }
    $Stage = 'LocalRootCheck'
    $Matched = $false
    foreach ($Installed in @(Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop)) {
        if ((Get-Sha256Hex -Bytes $Installed.RawData) -ceq $Fingerprint) {
            $Matched = $true
            break
        }
    }
    if ($Matched) {
        $Final = 'NO_ACTION | Gateway={0} Thumbprint={1} CertificateAlreadyPresent' -f $Gateway,$Thumbprint
    }
    else {
        $Stage = 'CertificateImport'
        $TempPath = Join-Path $env:TEMP ('WG_ProxyCA_{0}.cer' -f ([guid]::NewGuid().ToString('N')))
        try {
            [IO.File]::WriteAllBytes($TempPath,[byte[]]$Certificate.RawData)
            Import-Certificate -FilePath $TempPath -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null
        }
        finally {
            if (Test-Path -LiteralPath $TempPath) { Remove-Item -LiteralPath $TempPath -Force -ErrorAction SilentlyContinue }
        }
        $Stage = 'PostImportVerification'
        $Verified = $false
        foreach ($Installed in @(Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop)) {
            if ((Get-Sha256Hex -Bytes $Installed.RawData) -ceq $Fingerprint) {
                $Verified = $true
                break
            }
        }
        if (-not $Verified) { throw 'Certificate import completed but exact root certificate was not found' }
        $Final = 'RESULT | Gateway={0} Thumbprint={1} CertificateInstalledAndVerified' -f $Gateway,$Thumbprint
    }
}
catch {
    $Reason = ([string]$_.Exception.Message -replace '[\r\n|]+',' ').Trim()
    $Final = 'ERROR | Stage={0} Reason={1}' -f $Stage,$Reason
}
finally {
    Write-Log $Final
    Write-Output $Final
}
exit 0
