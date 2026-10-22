# ============================================================================
# NAME: RD Gateway MME SSL Certificate Check
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows Server / RD Gateway / NinjaOne Automation
# VARIABLES:
#   Required: None; configured internally
#   Internal Configuration:
#     ExpectedDnsName  = *.ConnectWithMME.com
#     CutoffDateString = 2026-12-28
#     LogRoot          = C:\MME\AutoLogs
#     LogPath          = C:\MME\AutoLogs\RDGatewayCertCheck.log
# OUTPUT TOKENS:
#   TRIGGER   | Expected RD Gateway certificate expires before cutoff
#   NO_ACTION | RD Gateway absent, certificate not applicable/not resolved,
#             | or expected certificate expires on/after cutoff
#   ERROR     | Unexpected script failure
#   Actual output uses a space after each token (not the | separator).
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\RDGatewayCertCheck.log
# DESCRIPTION:
#   Detects RD Gateway installation, then identifies a configured/bound SSL
#   certificate and checks its expiration against December 28, 2026.
#   Certificate discovery priority:
#     1. RDS:\GatewayServer\SSLCertificate\Thumbprint
#     2. HTTP.sys SSL bindings (prefers common RD Gateway ports)
#     3. Get-RDCertificate fallback
#   Only triggers when the discovered cert matches *.ConnectWithMME.com and
#   expires before the cutoff date. Missing, nonmatching, or unverified
#   certificates currently return NO_ACTION.
#   Evaluation is read-only, logs detailed evidence, and always exits 0.
# ============================================================================

$ExpectedDnsName = "*.ConnectWithMME.com"
$CutoffDateString = "2026-12-28"

$LogRoot = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogRoot "RDGatewayCertCheck.log"

$RDGThumbprintPath = "RDS:\GatewayServer\SSLCertificate\Thumbprint"
$CommonRDGPorts = @("443", "3391", "3392")

function Write-Log {
    param([string]$Message)

    if (-not (Test-Path $LogRoot)) {
        New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
    }

    $Line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogPath -Value $Line
}

function ConvertTo-OutputSafe {
    param($Value)

    if ($null -eq $Value) {
        return "Unknown"
    }

    $Text = [string]$Value
    $Text = $Text -replace "\r?\n", " "
    $Text = $Text.Trim()

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return "Unknown"
    }

    return $Text
}

function Normalize-Thumbprint {
    param([string]$Thumbprint)

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        return $null
    }

    $Clean = ($Thumbprint -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()

    if ($Clean.Length -eq 40) {
        return $Clean
    }

    return $null
}

function Find-ThumbprintInText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $Matches = [regex]::Matches($Text, "(?i)(?:[0-9a-f]\s*){40}")

    foreach ($Match in $Matches) {
        $Thumb = Normalize-Thumbprint -Thumbprint $Match.Value

        if ($Thumb) {
            return $Thumb
        }
    }

    return $null
}

function Get-CertByThumbprint {
    param([string]$Thumbprint)

    $CleanThumbprint = Normalize-Thumbprint -Thumbprint $Thumbprint

    if (-not $CleanThumbprint) {
        return $null
    }

    return Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue |
        Where-Object { (Normalize-Thumbprint -Thumbprint $_.Thumbprint) -eq $CleanThumbprint } |
        Select-Object -First 1
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

function Get-PortFromBindingText {
    param([string]$BindingText)

    if ([string]::IsNullOrWhiteSpace($BindingText)) {
        return $null
    }

    if ($BindingText -match ":(\d+)$") {
        return $Matches[1]
    }

    return $null
}

function Get-RDGProviderThumbprint {
    try {
        Import-Module RemoteDesktopServices -ErrorAction Stop

        if (-not (Test-Path $RDGThumbprintPath)) {
            Write-Log "RDS provider path not found: $RDGThumbprintPath"
            return $null
        }

        $Item = Get-Item -Path $RDGThumbprintPath -ErrorAction Stop

        foreach ($Value in @($Item.CurrentValue, $Item.Value)) {
            $Thumb = Normalize-Thumbprint -Thumbprint $Value

            if ($Thumb) {
                return $Thumb
            }
        }

        $Raw = $Item | Out-String
        $RawThumb = Find-ThumbprintInText -Text $Raw

        if ($RawThumb) {
            return $RawThumb
        }
    }
    catch {
        Write-Log "RDS provider thumbprint lookup failed: $($_.Exception.Message)"
    }

    return $null
}

function Get-HttpSysSslBindings {
    $Results = @()

    try {
        $NetshOutput = & netsh http show sslcert 2>$null
        $CurrentBinding = $null

        foreach ($Line in $NetshOutput) {
            if ($Line -match "^\s*(IP:port|Hostname:port)\s*:\s*(.+)$") {
                $CurrentBinding = $Matches[2].Trim()
                continue
            }

            if ($Line -match "Certificate Hash\s*:\s*([0-9A-Fa-f ]{40,})") {
                $Thumb = Normalize-Thumbprint -Thumbprint $Matches[1]

                if ($Thumb) {
                    $Results += [pscustomobject]@{
                        Binding    = $CurrentBinding
                        Port       = Get-PortFromBindingText -BindingText $CurrentBinding
                        Thumbprint = $Thumb
                    }
                }
            }
        }
    }
    catch {
        Write-Log "HTTP.sys SSL binding lookup failed: $($_.Exception.Message)"
    }

    return $Results
}

function Get-RDCertificateThumbprint {
    try {
        Import-Module RemoteDesktop -ErrorAction SilentlyContinue

        if (-not (Get-Command Get-RDCertificate -ErrorAction SilentlyContinue)) {
            return $null
        }

        $RDCert = Get-RDCertificate -Role RDGateway -ErrorAction Stop | Select-Object -First 1

        if (-not $RDCert) {
            return $null
        }

        foreach ($PropertyName in @("Thumbprint", "CertificateHash", "Hash", "CertHash")) {
            if ($RDCert.PSObject.Properties.Name -contains $PropertyName) {
                $Thumb = Normalize-Thumbprint -Thumbprint $RDCert.$PropertyName

                if ($Thumb) {
                    return $Thumb
                }
            }
        }

        $Raw = $RDCert | Out-String
        $RawThumb = Find-ThumbprintInText -Text $Raw

        if ($RawThumb) {
            return $RawThumb
        }
    }
    catch {
        Write-Log "Get-RDCertificate lookup failed: $($_.Exception.Message)"
    }

    return $null
}

function New-CertDataObject {
    $Data = [ordered]@{
        Source        = "None"
        Thumbprint    = $null
        Cert          = $null
        Names         = @()
        NotAfter      = $null
        Subject       = "Unknown"
        HasPrivateKey = "Unknown"
        Bindings      = @()
        Ports         = @()
    }

    return [pscustomobject]$Data
}

function New-CertDataFromCert {
    param(
        [string]$Source,
        [string]$Thumbprint,
        $Cert,
        [object[]]$Bindings
    )

    $Data = New-CertDataObject

    $Data.Source = $Source
    $Data.Thumbprint = $Thumbprint
    $Data.Cert = $Cert
    $Data.Names = @(Get-CertNames -Cert $Cert)
    $Data.NotAfter = $Cert.NotAfter
    $Data.Subject = $Cert.Subject
    $Data.HasPrivateKey = $Cert.HasPrivateKey

    if ($Bindings) {
        $Data.Bindings = @($Bindings.Binding | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        $Data.Ports = @($Bindings.Port | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    }

    return $Data
}

function Get-ActiveRDGCertData {
    $EmptyData = New-CertDataObject
    $HttpBindings = @(Get-HttpSysSslBindings)

    # 1. Primary source for standalone RD Gateway.
    $ProviderThumb = Get-RDGProviderThumbprint

    if ($ProviderThumb) {
        $ProviderCert = Get-CertByThumbprint -Thumbprint $ProviderThumb

        if ($ProviderCert) {
            $ProviderBindings = @($HttpBindings | Where-Object { $_.Thumbprint -eq $ProviderThumb })
            return New-CertDataFromCert -Source "RDSProvider" -Thumbprint $ProviderThumb -Cert $ProviderCert -Bindings $ProviderBindings
        }
        else {
            Write-Log "RDS provider thumbprint found but cert was not found in LocalMachine\My. Thumbprint=$ProviderThumb"
        }
    }

    # 2. HTTP.sys fallback.
    # Prefer bound certs matching expected name on common RDG ports.
    $HttpCandidates = @()

    foreach ($Binding in $HttpBindings) {
        $BindingCert = Get-CertByThumbprint -Thumbprint $Binding.Thumbprint

        if (-not $BindingCert) {
            continue
        }

        $Names = @(Get-CertNames -Cert $BindingCert)
        $NameMatch = Test-ExpectedCertName -Names $Names -ExpectedName $ExpectedDnsName

        if ($NameMatch) {
            $HttpCandidates += [pscustomobject]@{
                Binding    = $Binding.Binding
                Port       = $Binding.Port
                Thumbprint = $Binding.Thumbprint
                Cert       = $BindingCert
            }
        }
    }

    if ($HttpCandidates.Count -gt 0) {
        $GroupedCandidates = @()

        foreach ($Group in ($HttpCandidates | Group-Object Thumbprint)) {
            $GroupItems = @($Group.Group)
            $Cert = $GroupItems[0].Cert
            $Ports = @($GroupItems.Port | Where-Object { $_ } | Select-Object -Unique)

            $Score = 9

            if ($Ports -contains "443") {
                $Score = 0
            }
            elseif (($Ports | Where-Object { $CommonRDGPorts -contains $_ }).Count -gt 0) {
                $Score = 1
            }

            $GroupedCandidates += [pscustomobject]@{
                Thumbprint = $Group.Name
                Cert       = $Cert
                Bindings   = $GroupItems
                Score      = $Score
                NotAfter   = $Cert.NotAfter
            }
        }

        $Selected = $GroupedCandidates |
            Sort-Object @{ Expression = "Score"; Ascending = $true }, @{ Expression = "NotAfter"; Descending = $true } |
            Select-Object -First 1

        if ($Selected) {
            return New-CertDataFromCert -Source "HTTP.sys" -Thumbprint $Selected.Thumbprint -Cert $Selected.Cert -Bindings $Selected.Bindings
        }
    }

    # 3. Last fallback for full RDS deployment-style boxes.
    $RDThumb = Get-RDCertificateThumbprint

    if ($RDThumb) {
        $RDCert = Get-CertByThumbprint -Thumbprint $RDThumb

        if ($RDCert) {
            $RDBindings = @($HttpBindings | Where-Object { $_.Thumbprint -eq $RDThumb })
            return New-CertDataFromCert -Source "Get-RDCertificate" -Thumbprint $RDThumb -Cert $RDCert -Bindings $RDBindings
        }
        else {
            Write-Log "Get-RDCertificate thumbprint found but cert was not found in LocalMachine\My. Thumbprint=$RDThumb"
        }
    }

    return $EmptyData
}

function Test-RDGatewayInstalled {
    $RoleInstalled = $false
    $FeatureState = "Unknown"
    $ServiceStatus = "NotFound"

    try {
        $Feature = Get-WindowsFeature -Name RDS-Gateway -ErrorAction SilentlyContinue

        if ($Feature) {
            $FeatureState = $Feature.InstallState.ToString()

            if ($Feature.InstallState -eq "Installed") {
                $RoleInstalled = $true
            }
        }
    }
    catch {
        Write-Log "Get-WindowsFeature check failed: $($_.Exception.Message)"
    }

    $Service = Get-Service -Name TSGateway -ErrorAction SilentlyContinue

    if ($Service) {
        $RoleInstalled = $true
        $ServiceStatus = $Service.Status.ToString()
    }

    return [pscustomobject]@{
        Installed     = $RoleInstalled
        FeatureState  = $FeatureState
        ServiceStatus = $ServiceStatus
    }
}

try {
    Write-Log "Starting RD Gateway MME certificate expiration check."

    $CutoffDate = [datetime]::ParseExact($CutoffDateString, "yyyy-MM-dd", $null)
    $RDGState = Test-RDGatewayInstalled

    if (-not $RDGState.Installed) {
        $Message = "NO_ACTION RDGatewayInstalled=False FeatureState=$($RDGState.FeatureState) ServiceStatus=$($RDGState.ServiceStatus) Reason=RDGatewayNotInstalled"
        Write-Log $Message
        Write-Output $Message
        exit 0
    }

    $CertData = Get-ActiveRDGCertData

    if (-not $CertData.Thumbprint -or -not $CertData.Cert) {
        $Message = "NO_ACTION RDGatewayInstalled=True CertFound=False ExpectedCert=$ExpectedDnsName Source=$($CertData.Source) SslPorts=Unknown SslBindings=Unknown Reason=NoRDGatewayCertificateFound"
        Write-Log $Message
        Write-Output $Message
        exit 0
    }

    $CertMatch = Test-ExpectedCertName -Names $CertData.Names -ExpectedName $ExpectedDnsName

    $Expires = "Unknown"
    if ($CertData.NotAfter) {
        $Expires = $CertData.NotAfter.ToString("yyyy-MM-dd")
    }

    $SslPorts = "Unknown"
    if ($CertData.Ports.Count -gt 0) {
        $SslPorts = ($CertData.Ports -join ",")
    }

    $SslBindings = "Unknown"
    if ($CertData.Bindings.Count -gt 0) {
        $SslBindings = ($CertData.Bindings -join ",")
    }

    $Subject = ConvertTo-OutputSafe -Value $CertData.Subject
    $HasPrivateKey = ConvertTo-OutputSafe -Value $CertData.HasPrivateKey

    if (-not $CertMatch) {
        $Message = "NO_ACTION RDGatewayInstalled=True CertFound=True CertMatch=False ExpectedCert=$ExpectedDnsName Source=$($CertData.Source) Thumbprint=$($CertData.Thumbprint) Expires=$Expires Cutoff=$CutoffDateString SslPorts=$SslPorts SslBindings=$SslBindings HasPrivateKey=$HasPrivateKey Subject=$Subject Reason=RDGatewayCertIsNotExpectedMMEWildcard"
        Write-Log $Message
        Write-Output $Message
        exit 0
    }

    if (-not $CertData.NotAfter) {
        $Message = "NO_ACTION RDGatewayInstalled=True CertFound=True CertMatch=True ExpectedCert=$ExpectedDnsName Source=$($CertData.Source) Thumbprint=$($CertData.Thumbprint) Expires=Unknown Cutoff=$CutoffDateString SslPorts=$SslPorts SslBindings=$SslBindings HasPrivateKey=$HasPrivateKey Subject=$Subject Reason=UnableToValidateExpiration"
        Write-Log $Message
        Write-Output $Message
        exit 0
    }

    if ($CertData.NotAfter.Date -lt $CutoffDate.Date) {
        $Message = "TRIGGER RDGatewayInstalled=True CertFound=True CertMatch=True ExpectedCert=$ExpectedDnsName Source=$($CertData.Source) Thumbprint=$($CertData.Thumbprint) Expires=$Expires Cutoff=$CutoffDateString SslPorts=$SslPorts SslBindings=$SslBindings HasPrivateKey=$HasPrivateKey Subject=$Subject Reason=CertExpiresBeforeCutoff"
        Write-Log $Message
        Write-Output $Message
        exit 0
    }

    $Message = "NO_ACTION RDGatewayInstalled=True CertFound=True CertMatch=True ExpectedCert=$ExpectedDnsName Source=$($CertData.Source) Thumbprint=$($CertData.Thumbprint) Expires=$Expires Cutoff=$CutoffDateString SslPorts=$SslPorts SslBindings=$SslBindings HasPrivateKey=$HasPrivateKey Subject=$Subject Reason=CertExpiresOnOrAfterCutoff"
    Write-Log $Message
    Write-Output $Message
    exit 0
}
catch {
    $Message = "ERROR RD Gateway MME certificate expiration check failed: $($_.Exception.Message)"
    Write-Log $Message
    Write-Output $Message
    exit 0
}
