# ============================================================================
# NAME: RD Gateway Certificate Install - Standalone RDG
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Server / Standalone RD Gateway / NinjaOne Automation
# VARIABLES:
#   Required: None; configuration values are defined internally
#   Internal Configuration:
#     CertSourceFolder    = C:\MME\CS
#     PfxPasswordFileName = PFX password.txt
#     ExpectedDnsName     = *.ConnectWithMME.com
#     ValidatePfxName     = True
#     PfxPasswordPlain    = Empty
#     PfxPasswordEnvVar   = MME_RDG_PFX_PASSWORD
#     LogRoot             = C:\MME\AutoLogs
#     LogPath             = C:\MME\AutoLogs\RDGatewayCertRemediation.log
# OUTPUT TOKENS:
#   RESULT | Certificate imported, bound, service restarted, and verified
#   ERROR  | Certificate import, binding, restart, or verification failed
#   Actual output uses a space after the token, not the | separator.
#   Existing exit codes: RESULT=0, ERROR=1
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: Yes
#   Files:
#     Exactly one *.pfx certificate file
#       Destination: C:\MME\CS\<certificate-filename>.pfx
#     PFX password.txt (Optional; for password-protected PFX files)
#       Destination: C:\MME\CS\PFX password.txt
#   Password may alternatively come from the configured process
#   environment variable or internal PfxPasswordPlain value.
#   Certificate and password files must not be published to GitHub.
# LOGGING PATH:
#   C:\MME\AutoLogs\RDGatewayCertRemediation.log
# DESCRIPTION:
#   Installs and binds a replacement SSL certificate on standalone
#   Windows RD Gateway servers after external evaluation gating.
#
#   Requires exactly one PFX file in C:\MME\CS. Reads and validates
#   the certificate, including private-key presence, expiration,
#   and expected DNS name when validation is enabled.
#
#   Imports the certificate into LocalMachine\My, stops TSGateway,
#   updates RDS:\GatewayServer\SSLCertificate\Thumbprint, restarts
#   TSGateway, and verifies the configured thumbprint afterward.
#
#   Does not require an RDS Connection Broker or Set-RDCertificate.
#   Does not delete existing certificates or perform rollback.
#   The existing implementation may interrupt active RD Gateway
#   connections and does not restore the prior service state.
#   Does not implement independent remediation gating.
# ============================================================================

$CertSourceFolder = "C:\MME\CS"
$PfxPasswordFileName = "PFX password.txt"

$ExpectedDnsName = "*.ConnectWithMME.com"
$ValidatePfxName = $true

$PfxPasswordPlain = ""
$PfxPasswordEnvVar = "MME_RDG_PFX_PASSWORD"

$LogRoot = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogRoot "RDGatewayCertRemediation.log"

$RDGThumbprintPath = "RDS:\GatewayServer\SSLCertificate\Thumbprint"

function Write-Log {
    param([string]$Message)

    if (-not (Test-Path $LogRoot)) {
        New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
    }

    $Line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogPath -Value $Line
}

function Get-PasswordFromFileCandidates {
    param([string]$Path)

    $Candidates = @()

    if (-not (Test-Path $Path)) {
        Write-Log "Password file not found. Path=$Path"
        return $Candidates
    }

    try {
        $RawPassword = Get-Content -Path $Path -Raw -ErrorAction Stop
        $RawPassword = $RawPassword -replace "^\uFEFF", ""

        # Candidate 1: remove trailing line breaks only.
        $NoLineBreakPassword = $RawPassword -replace "(\r?\n)+$", ""

        if (-not [string]::IsNullOrEmpty($NoLineBreakPassword)) {
            $Candidates += [pscustomobject]@{
                Password = $NoLineBreakPassword
                Mode     = "PasswordFile"
            }
        }

        # Candidate 2: trimmed copy, because document copy/paste can drag spaces in.
        $TrimmedPassword = $NoLineBreakPassword.Trim()

        if (
            -not [string]::IsNullOrEmpty($TrimmedPassword) -and
            $TrimmedPassword -ne $NoLineBreakPassword
        ) {
            $Candidates += [pscustomobject]@{
                Password = $TrimmedPassword
                Mode     = "PasswordFileTrimmed"
            }
        }

        Write-Log "Password file loaded. Path=$Path CandidateCount=$($Candidates.Count)"
        return $Candidates
    }
    catch {
        Write-Log "Failed to read password file. Path=$Path Reason=$($_.Exception.Message)"
        return $Candidates
    }
}

function Get-PfxPasswordCandidates {
    $Candidates = @()

    # Try blank/no password first.
    $Candidates += [pscustomobject]@{
        Password = ""
        Mode     = "Blank"
    }

    $PasswordFilePath = Join-Path $CertSourceFolder $PfxPasswordFileName
    $Candidates += Get-PasswordFromFileCandidates -Path $PasswordFilePath

    if (-not [string]::IsNullOrWhiteSpace($PfxPasswordPlain)) {
        $Candidates += [pscustomobject]@{
            Password = $PfxPasswordPlain
            Mode     = "ScriptVariable"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($PfxPasswordEnvVar)) {
        $EnvValue = [Environment]::GetEnvironmentVariable($PfxPasswordEnvVar, "Process")

        if (-not [string]::IsNullOrWhiteSpace($EnvValue)) {
            $Candidates += [pscustomobject]@{
                Password = $EnvValue
                Mode     = "EnvironmentVariable"
            }
        }
    }

    return $Candidates
}

function Get-CertNames {
    param($Cert)

    $Names = @()

    if ($Cert) {
        if ($Cert.Subject) {
            $Names += $Cert.Subject
        }

        try {
            foreach ($DnsName in $Cert.DnsNameList) {
                if ($DnsName.Unicode) {
                    $Names += $DnsName.Unicode
                }
                else {
                    $Names += $DnsName.ToString()
                }
            }
        }
        catch {
            # Older hosts may not expose DnsNameList cleanly.
        }

        try {
            foreach ($Extension in $Cert.Extensions) {
                if ($Extension.Oid.Value -eq "2.5.29.17") {
                    $SanText = $Extension.Format($false)

                    foreach ($Part in ($SanText -split ",\s*|\r?\n")) {
                        if ($Part -match "DNS Name=(.+)$") {
                            $Names += $Matches[1].Trim()
                        }
                    }
                }
            }
        }
        catch {
            # SAN parsing is best effort.
        }
    }

    return $Names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
}

function Test-ExpectedCertName {
    param(
        [string[]]$Names,
        [string]$ExpectedName
    )

    $ExpectedEscaped = [regex]::Escape($ExpectedName.Trim())

    foreach ($Name in $Names) {
        if ($Name -match "(?i)$ExpectedEscaped") {
            return $true
        }
    }

    return $false
}

function Read-PfxInfo {
    param(
        [string]$Path,
        [array]$PasswordCandidates
    )

    $LastError = $null

    foreach ($Candidate in $PasswordCandidates) {
        try {
            $Flags =
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable

            $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $Cert.Import($Path, $Candidate.Password, $Flags)

            return [pscustomobject]@{
                Path          = $Path
                Thumbprint    = ($Cert.Thumbprint -replace "\s", "").ToUpperInvariant()
                Subject       = $Cert.Subject
                NotAfter      = $Cert.NotAfter
                HasPrivateKey = $Cert.HasPrivateKey
                Names         = @(Get-CertNames -Cert $Cert)
                Password      = $Candidate.Password
                PasswordMode  = $Candidate.Mode
                CertObject    = $Cert
            }
        }
        catch {
            $LastError = $_.Exception.Message
        }
    }

    throw "Unable to read PFX: $Path. Last error: $LastError"
}

function Get-SinglePfxInfo {
    param(
        [string]$Folder,
        [array]$PasswordCandidates
    )

    if (-not (Test-Path $Folder)) {
        throw "Certificate source folder not found: $Folder"
    }

    $PfxFiles = @(Get-ChildItem -Path $Folder -Filter "*.pfx" -File -ErrorAction Stop)

    if ($PfxFiles.Count -eq 0) {
        throw "No .pfx files found in $Folder"
    }

    if ($PfxFiles.Count -gt 1) {
        $Names = ($PfxFiles.Name -join ",")
        throw "More than one .pfx file found in $Folder. Found=$Names"
    }

    $PfxInfo = Read-PfxInfo -Path $PfxFiles[0].FullName -PasswordCandidates $PasswordCandidates

    Write-Log "PFX checked. Path=$($PfxInfo.Path) Thumbprint=$($PfxInfo.Thumbprint) Expires=$($PfxInfo.NotAfter.ToString("yyyy-MM-dd")) HasPrivateKey=$($PfxInfo.HasPrivateKey) PasswordMode=$($PfxInfo.PasswordMode)"

    if (-not $PfxInfo.HasPrivateKey) {
        throw "PFX does not include a private key. Path=$($PfxInfo.Path)"
    }

    if ($PfxInfo.NotAfter -le (Get-Date)) {
        throw "PFX is expired. Path=$($PfxInfo.Path) Expires=$($PfxInfo.NotAfter.ToString("yyyy-MM-dd"))"
    }

    if ($ValidatePfxName) {
        $NameMatch = Test-ExpectedCertName -Names $PfxInfo.Names -ExpectedName $ExpectedDnsName

        if (-not $NameMatch) {
            throw "PFX does not match expected certificate name. Expected=$ExpectedDnsName Subject=$($PfxInfo.Subject)"
        }
    }

    return $PfxInfo
}

function Import-PfxToLocalMachineMy {
    param($PfxInfo)

    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")

    try {
        $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $Store.Add($PfxInfo.CertObject)
    }
    finally {
        $Store.Close()
    }

    $Imported = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop |
        Where-Object { ($_.Thumbprint -replace "\s", "").ToUpperInvariant() -eq $PfxInfo.Thumbprint } |
        Select-Object -First 1

    if (-not $Imported) {
        throw "PFX import verification failed. Cert not found in LocalMachine\My after import. Thumbprint=$($PfxInfo.Thumbprint)"
    }

    if (-not $Imported.HasPrivateKey) {
        throw "PFX import verification failed. Imported cert does not show private key. Thumbprint=$($PfxInfo.Thumbprint)"
    }

    return $Imported
}

function Get-RDGThumbprint {
    Import-Module RemoteDesktopServices -ErrorAction Stop

    if (-not (Test-Path $RDGThumbprintPath)) {
        return $null
    }

    $Item = Get-Item -Path $RDGThumbprintPath -ErrorAction Stop
    $Raw = $Item | Out-String

    if ($Item.CurrentValue -and $Item.CurrentValue -match "([0-9A-Fa-f]{40})") {
        return $Matches[1].ToUpperInvariant()
    }

    if ($Item.Value -and $Item.Value -match "([0-9A-Fa-f]{40})") {
        return $Matches[1].ToUpperInvariant()
    }

    if ($Raw -match "([0-9A-Fa-f]{40})") {
        return $Matches[1].ToUpperInvariant()
    }

    return $null
}

function Set-RDGThumbprint {
    param([string]$Thumbprint)

    Import-Module RemoteDesktopServices -ErrorAction Stop

    if (-not (Test-Path $RDGThumbprintPath)) {
        throw "RD Gateway SSL certificate thumbprint path not found: $RDGThumbprintPath"
    }

    Set-Item -Path $RDGThumbprintPath -Value $Thumbprint -ErrorAction Stop
}

function Restart-TSGatewayForCertBind {
    param([string]$NewThumbprint)

    Write-Log "Stopping TSGateway service before RD Gateway certificate bind."
    Stop-Service -Name TSGateway -Force -ErrorAction Stop

    try {
        Write-Log "Setting RD Gateway SSL certificate thumbprint while TSGateway is stopped. NewThumbprint=$NewThumbprint"
        Set-RDGThumbprint -Thumbprint $NewThumbprint
    }
    finally {
        Write-Log "Starting TSGateway service after RD Gateway certificate bind."
        Start-Service -Name TSGateway -ErrorAction Stop
    }

    $Service = Get-Service -Name TSGateway -ErrorAction Stop
    $Service.WaitForStatus("Running", "00:00:30")

    return $Service.Status.ToString()
}

try {
    Write-Log "Starting standalone RD Gateway certificate install."

    $Service = Get-Service -Name TSGateway -ErrorAction SilentlyContinue

    if (-not $Service) {
        $Message = "ERROR Action=Failed Reason=TSGatewayServiceNotFound"
        Write-Log $Message
        Write-Output $Message
        exit 1
    }

    $StartingServiceStatus = $Service.Status.ToString()

    $PasswordCandidates = Get-PfxPasswordCandidates
    $ReplacementPfx = Get-SinglePfxInfo -Folder $CertSourceFolder -PasswordCandidates $PasswordCandidates

    $OldThumbprint = Get-RDGThumbprint
    if ([string]::IsNullOrWhiteSpace($OldThumbprint)) {
        $OldThumbprint = "Unknown"
    }

    $ImportedCert = Import-PfxToLocalMachineMy -PfxInfo $ReplacementPfx

    Write-Log "Imported PFX to LocalMachine\My. Thumbprint=$($ReplacementPfx.Thumbprint) Subject=$($ReplacementPfx.Subject) Expires=$($ReplacementPfx.NotAfter.ToString("yyyy-MM-dd")) PasswordMode=$($ReplacementPfx.PasswordMode) OldThumbprint=$OldThumbprint StartingServiceStatus=$StartingServiceStatus"

    $PostRestartServiceStatus = Restart-TSGatewayForCertBind -NewThumbprint $ReplacementPfx.Thumbprint

    Start-Sleep -Seconds 3

    $AppliedThumbprint = Get-RDGThumbprint

    if ($AppliedThumbprint -eq $ReplacementPfx.Thumbprint) {
        $Message = "RESULT Action=Installed Role=RDGateway SourcePath=$($ReplacementPfx.Path) OldThumbprint=$OldThumbprint NewThumbprint=$($ReplacementPfx.Thumbprint) Expires=$($ReplacementPfx.NotAfter.ToString("yyyy-MM-dd")) Subject=$($ReplacementPfx.Subject) PasswordMode=$($ReplacementPfx.PasswordMode) StartingServiceStatus=$StartingServiceStatus FinalServiceStatus=$PostRestartServiceStatus Verification=Passed"
        Write-Log $Message
        Write-Output $Message
        exit 0
    }

    $Message = "ERROR Action=Failed Reason=PostInstallVerificationFailed ExpectedThumbprint=$($ReplacementPfx.Thumbprint) ActualThumbprint=$AppliedThumbprint OldThumbprint=$OldThumbprint SourcePath=$($ReplacementPfx.Path) StartingServiceStatus=$StartingServiceStatus FinalServiceStatus=$PostRestartServiceStatus"
    Write-Log $Message
    Write-Output $Message
    exit 1
}
catch {
    $Message = "ERROR standalone RD Gateway certificate install failed: $($_.Exception.Message)"
    Write-Log $Message
    Write-Output $Message
    exit 1
}
