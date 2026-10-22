# ============================================================================
# NAME: Advanced IP Scanner - Download Utility
# AUTHORED BY: Cogan Goldwater
# TYPE: Utility / Software Download
# SCOPE: Windows endpoints / NinjaOne automation
# VARIABLES:
#   DownloadPageUri      = https://www.advanced-ip-scanner.com/download/
#   FallbackDownloadUri  = Official Advanced IP Scanner installer URL
#   DownloadRoot         = C:\MME\CS
# OUTPUT TOKENS:
#   SUCCESS | Advanced IP Scanner downloaded to C:\MME\CS
#   ERROR   | Download or validation failure
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
#   Installer downloaded directly from vendor.
# LOGGING PATH:
#   None; output written to the execution console.
# DESCRIPTION:
#   Downloads the Advanced IP Scanner installer to C:\MME\CS.
#   Creates the staging directory when necessary.
#   Removes previously staged Advanced IP Scanner downloads.
#   Attempts to discover the current installer URL from the
#   official download page, falling back to a predefined URL.
#   Enables TLS 1.2 where supported.
#   Downloads to a temporary file and validates minimum file size
#   before moving the installer to its final destination.
#   Does not install or execute the downloaded application.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'

$DownloadPageUri = 'https://www.advanced-ip-scanner.com/download/'
$FallbackDownloadUri = 'https://download.advanced-ip-scanner.com/download/files/Advanced_IP_Scanner_2.5.4594.1.exe'
$DownloadRoot = 'C:\MME\CS'

function Finish {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('SUCCESS','ERROR')]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Output "$Token | $Message"
    exit 0
}

try {
    # Must exist before any download attempt.
    if (-not (Test-Path -LiteralPath $DownloadRoot)) {
        New-Item -Path $DownloadRoot -ItemType Directory -Force | Out-Null
        Write-Output "Created directory: $DownloadRoot"
    }
    else {
        Write-Output "Directory already exists: $DownloadRoot"
    }

    # Remove prior Advanced IP Scanner downloads so only one remains after this run.
    Get-ChildItem -LiteralPath $DownloadRoot -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -like 'Advanced_IP_Scanner*.exe' -or
            $_.Name -like 'Advanced_IP_Scanner*.download'
        } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        # Continue with system defaults.
    }

    $downloadUri = $null

    try {
        $response = Invoke-WebRequest -Uri $DownloadPageUri -UseBasicParsing -MaximumRedirection 10

        $regex = 'https?://download\.advanced-ip-scanner\.com/download/files/Advanced_IP_Scanner_[^"''<>\s]+\.exe'
        $foundMatches = [regex]::Matches($response.Content, $regex)

        if ($foundMatches.Count -gt 0) {
            $downloadUri = [string]$foundMatches[0].Value
        }
    }
    catch {
        $downloadUri = $null
    }

    if ([string]::IsNullOrWhiteSpace($downloadUri)) {
        $downloadUri = $FallbackDownloadUri
    }

    $uriObj = [Uri]$downloadUri
    $fileName = Split-Path $uriObj.AbsolutePath -Leaf

    if ([string]::IsNullOrWhiteSpace($fileName) -or $fileName -notmatch '\.exe$') {
        $fileName = 'Advanced_IP_Scanner.exe'
    }

    $destinationPath = Join-Path $DownloadRoot $fileName
    $tempPath = "$destinationPath.download"

    Invoke-WebRequest -Uri $downloadUri -UseBasicParsing -MaximumRedirection 10 -OutFile $tempPath

    $downloadedItem = Get-Item -LiteralPath $tempPath

    if ($downloadedItem.Length -lt 1048576) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        throw "Downloaded file is unexpectedly small: $($downloadedItem.Length) bytes"
    }

    Move-Item -Path $tempPath -Destination $destinationPath -Force

    Finish -Token 'SUCCESS' -Message "Advanced IP Scanner downloaded to $destinationPath"
}
catch {
    Finish -Token 'ERROR' -Message $_.Exception.Message
}