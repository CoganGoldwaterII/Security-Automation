# ============================================================================
# NAME: WatchGuard ProxyCA Certificate - Install
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# EXECUTION CONTEXT:
#   SYSTEM / Elevated
# VARIABLES:
#   Gateway = Automatically detected IPv4 default gateway
#   Url     = http://<Gateway>:4126/ProxyCA.cer
# OUTPUT TOKENS:
#   None; outputs diagnostic messages prefixed with [WatchGuardCert].
#   Exit 0 | Certificate already installed or successfully imported
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
#   Detects the default IPv4 gateway and downloads the WatchGuard ProxyCA
#   certificate from http://<gateway>:4126/ProxyCA.cer.
#
#   Validates the downloaded content as an X.509 certificate and imports
#   it into the LocalMachine Trusted Root certificate store.
#
#   Skips installation when the matching certificate is already present.
#   Removes the temporary certificate file after successful import.
#
#   Requires SYSTEM or elevated administrative privileges.
# ============================================================================

$ErrorActionPreference = "Stop"

function Log { param($m) Write-Output "[WatchGuardCert] $m" }

# ---- Get default gateway ----
try {
    $Gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
                Sort-Object RouteMetric |
                Select-Object -First 1).NextHop
}
catch {
    Log "ERROR: Could not determine default gateway."
    exit 1
}

if (-not $Gateway) {
    Log "ERROR: No gateway detected."
    exit 1
}

Log "Gateway detected: $Gateway"

# ---- Build URL ----
$Url = "http://$Gateway`:4126/ProxyCA.cer"
Log "Downloading: $Url"

try {
    $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30
}
catch {
    Log "ERROR downloading cert: $($_.Exception.Message)"
    exit 1
}

if ($resp.Headers["Content-Type"] -match "text/html") {
    Log "ERROR: Firewall returned HTML instead of cert."
    exit 1
}

try {
    $bytes = [byte[]]$resp.Content
}
catch {
    $wc = New-Object System.Net.WebClient
    $bytes = $wc.DownloadData($Url)
}

# ---- Parse cert ----
try {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($bytes)
}
catch {
    Log "ERROR: Downloaded file is not a certificate."
    exit 1
}

Log "Thumbprint: $($cert.Thumbprint)"

# ---- Import if missing ----
$store = "Cert:\LocalMachine\Root"
$existing = Get-ChildItem $store |
            Where-Object Thumbprint -eq $cert.Thumbprint

if ($existing) {
    Log "Certificate already installed."
    exit 0
}

$tmp = Join-Path $env:TEMP "wg_proxyca.cer"
[IO.File]::WriteAllBytes($tmp, $cert.RawData)

Import-Certificate -FilePath $tmp -CertStoreLocation $store | Out-Null
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

Log "Certificate imported successfully."
exit 0