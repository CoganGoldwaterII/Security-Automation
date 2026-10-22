# ============================================================================
# NAME: WatchGuard ProxyCA Certificate - Install
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   Gateway = Automatically detected IPv4 default gateway
#   Url     = http://<Gateway>:4126/ProxyCA.cer
# OUTPUT TOKENS:
#   None; outputs diagnostic messages prefixed with [WatchGuardCert].
#   Exit 0 | Certificate already present or successfully imported
#   Exit 1 | Gateway detection, download, or validation failure
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None; console output only
# DESCRIPTION:
#   Automatically detects the default IPv4 gateway and downloads the
#   WatchGuard ProxyCA certificate from TCP port 4126.
#
#   Validates the downloaded content as an X.509 certificate and checks
#   whether the certificate already exists in the LocalMachine Root store.
#
#   Imports the certificate only when missing and removes the temporary
#   certificate file after import.
#
#   Does not require manually staged certificate files.
#   Preserves the original working gateway detection and import logic.
# ============================================================================

$ErrorActionPreference = "Stop"

function Write-Log { param([string]$m) Write-Output "[WatchGuardCert] $m" }

# ---- Detect default gateway ----
$Gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
            Sort-Object RouteMetric |
            Select-Object -First 1).NextHop

if (-not $Gateway) {
    Write-Log "ERROR: No gateway detected."
    exit 1
}

Write-Log "Gateway detected: $Gateway"

# ---- Build working WatchGuard cert URL ----
$Url = "http://$Gateway`:4126/ProxyCA.cer"
Write-Log "Downloading: $Url"

try {
    $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 60
}
catch {
    Write-Log "ERROR downloading cert: $($_.Exception.Message)"
    exit 1
}

# Guardrail: portal page instead of cert
$ct = $resp.Headers["Content-Type"]
if ($ct -and $ct -match "text/html") {
    Write-Log "ERROR: Received HTML instead of certificate."
    exit 1
}

# Get raw bytes
try {
    $bytes = [byte[]]$resp.Content
}
catch {
    $wc = New-Object System.Net.WebClient
    $bytes = $wc.DownloadData($Url)
}

# ---- Parse certificate ----
try {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($bytes)
}
catch {
    Write-Log "ERROR: Downloaded content is not a valid certificate."
    exit 1
}

Write-Log ("Thumbprint: {0}" -f $cert.Thumbprint)

# ---- Import if missing ----
$storePath = "Cert:\LocalMachine\Root"

$existing = Get-ChildItem -Path $storePath |
            Where-Object { $_.Thumbprint -eq $cert.Thumbprint }

if ($existing) {
    Write-Log "Certificate already present."
    exit 0
}

$tmp = Join-Path $env:TEMP "wg_proxyca.cer"
[IO.File]::WriteAllBytes($tmp, $cert.RawData)

Import-Certificate -FilePath $tmp -CertStoreLocation $storePath | Out-Null
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

Write-Log "Certificate imported successfully."
exit 0