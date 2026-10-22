# ============================================================================
# NAME: Microsoft 365 Apps for Business Eval and Install
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation + Remediation
# SCOPE: Windows Workstations and Servers / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#   Internal Configuration:
#     ProductId       = O365BusinessRetail
#     TargetProductId = O365BusinessRetail
#     TargetName      = Microsoft 365 Apps for business - en-us
#     Channel         = Current
#     LanguageId      = en-us
#     DelayMinutes    = 10
#
# OUTPUT TOKENS:
#   NO_ACTION | Microsoft 365 Apps for business detected
#   RESULT    | Microsoft 365 Apps for business installed successfully
#   ERROR     | Installation failed or post-install detection failed
#
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#   Downloads Office Deployment Tool during execution.
#
# LOGGING PATH:
#   C:\MME\AutoLogs\M365Business_Install.log
#
# STAGING PATH:
#   C:\MME\CS\Office365
#
# GENERATED FILES:
#   C:\MME\CS\Office365\officedeploymenttool.exe
#   C:\MME\CS\Office365\setup.exe
#   C:\MME\CS\Office365\install-office365.xml
#
# DESCRIPTION:
#   Evaluates Windows endpoints for Microsoft 365 Apps for business.
#
#   Detection sources:
#     - Office Click-to-Run ProductReleaseIds
#     - Installed application uninstall registry entries
#     - Known Office executable paths
#
#   The existing decision logic uses the Click-to-Run product ID
#   as the authoritative installation indicator.
#
#   When the product ID is detected, returns NO_ACTION.
#
#   When not detected:
#     - Waits 10 minutes
#     - Downloads the Microsoft Office Deployment Tool
#     - Extracts the deployment tool
#     - Generates the Office configuration XML
#     - Installs O365BusinessRetail, 64-bit, Current Channel, en-us
#     - Uses silent installation with EULA acceptance
#     - Requests automatic activation
#     - Includes RemoveMSI to remove MSI-based Office installations
#     - Rechecks the Click-to-Run product ID following installation
#
#   Reports RESULT when post-install detection succeeds.
#   Reports ERROR when installation or verification fails.
#
#   EXISTING BEHAVIOR:
#   Uses Write-Host for output and does not explicitly exit 0.
#   Does not implement separate TRIGGER-based evaluation gating.
#   Downloads deployment files at runtime; no Ninja file transfer needed.
#
#   WARNING:
#   RemoveMSI may uninstall existing MSI-based Office products.
#   No functional changes have been made during standardization.
# ============================================================================

$ErrorActionPreference = "Stop"

$BasePath     = "C:\MME\CS\Office365"
$LogRoot      = "C:\MME\AutoLogs"
$LogPath      = Join-Path $LogRoot "M365Business_Install.log"

$ProductId       = "O365BusinessRetail"
$TargetProductId = "O365BusinessRetail"
$TargetName      = "Microsoft 365 Apps for business - en-us"

$Channel      = "Current"
$LanguageId   = "en-us"
$DelayMinutes = 10

$OdtUrl    = "https://download.microsoft.com/download/6c1eeb25-cf8b-41d9-8d0d-cc1dbc032140/officedeploymenttool_20026-20112.exe"
$OdtExe    = Join-Path $BasePath "officedeploymenttool.exe"
$SetupExe  = Join-Path $BasePath "setup.exe"
$ConfigXml = Join-Path $BasePath "install-office365.xml"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null

function Write-Log {
    param([string]$Message)

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
    Write-Host $Message
}

function Test-M365BusinessInstalled {
    $PrimaryHit = $false
    $SecondaryHit = $false
    $Evidence = @()

    # Primary check: Office Click-to-Run ProductReleaseIds
    $CtrPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"

    if (Test-Path $CtrPath) {
        $Ctr = Get-ItemProperty -Path $CtrPath -ErrorAction SilentlyContinue
        $ProductReleaseIds = $Ctr.ProductReleaseIds
        $ClientVersion = $Ctr.ClientVersionToReport
        $InstallPath = $Ctr.InstallationPath

        if ($ProductReleaseIds -match $TargetProductId) {
            $PrimaryHit = $true
            $Evidence += "Primary: ProductReleaseIds=$ProductReleaseIds; Version=$ClientVersion; InstallPath=$InstallPath"
        }
        else {
            $Evidence += "PrimaryMiss: ProductReleaseIds=$ProductReleaseIds"
        }
    }
    else {
        $Evidence += "PrimaryMiss: Click-to-Run configuration key not found"
    }

    # Secondary check A: Programs & Features display name
    $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($Path in $UninstallPaths) {
        $Matches = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $TargetName }

        foreach ($Match in $Matches) {
            $SecondaryHit = $true
            $Evidence += "Secondary: DisplayName=$($Match.DisplayName); Version=$($Match.DisplayVersion)"
        }
    }

    # Secondary check B: Office executable presence
    $OfficeExePaths = @(
        "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
        "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
    )

    foreach ($OfficeExe in $OfficeExePaths) {
        if (Test-Path $OfficeExe) {
            $SecondaryHit = $true
            $Evidence += "Secondary: Found $OfficeExe"
        }
    }

    return [PSCustomObject]@{
        Installed = ($PrimaryHit -or ($SecondaryHit -and $PrimaryHit))
        PrimaryHit = $PrimaryHit
        SecondaryHit = $SecondaryHit
        Evidence = ($Evidence -join " | ")
    }
}

try {
    Write-Log "Starting Microsoft 365 Apps for business evaluation."

    $Eval = Test-M365BusinessInstalled

    if ($Eval.PrimaryHit) {
        Write-Log "NO_ACTION | Microsoft 365 Apps for business detected. $($Eval.Evidence)"
        return
    }

    Write-Log "Microsoft 365 Apps for business not detected. $($Eval.Evidence)"
    Write-Log "Waiting $DelayMinutes minutes before install."
    Start-Sleep -Seconds ($DelayMinutes * 60)

    Write-Log "Starting Microsoft 365 Apps for business install."

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Log "Downloading Office Deployment Tool."
    Invoke-WebRequest -Uri $OdtUrl -OutFile $OdtExe -UseBasicParsing

    if (!(Test-Path $OdtExe)) {
        throw "ODT download failed. File not found: $OdtExe"
    }

    Write-Log "Extracting Office Deployment Tool."
    $ExtractArgs = "/quiet /extract:`"$BasePath`""
    $Extract = Start-Process -FilePath $OdtExe -ArgumentList $ExtractArgs -Wait -PassThru

    if ($Extract.ExitCode -ne 0) {
        throw "ODT extraction failed. ExitCode=$($Extract.ExitCode)"
    }

    if (!(Test-Path $SetupExe)) {
        throw "setup.exe not found after extraction: $SetupExe"
    }

    Write-Log "Writing Office install XML."

    $XmlContent = @"
<Configuration>
  <Add OfficeClientEdition="64" Channel="$Channel">
    <Product ID="$ProductId">
      <Language ID="$LanguageId" />
    </Product>
  </Add>
  <RemoveMSI />
  <Display Level="None" AcceptEULA="TRUE" />
  <Property Name="AUTOACTIVATE" Value="1" />
</Configuration>
"@

    Set-Content -Path $ConfigXml -Value $XmlContent -Encoding UTF8 -Force

    if (!(Test-Path $ConfigXml)) {
        throw "Config XML was not created: $ConfigXml"
    }

    Write-Log "Launching Office install."
    $InstallArgs = "/configure `"$ConfigXml`""
    $Install = Start-Process -FilePath $SetupExe -ArgumentList $InstallArgs -Wait -PassThru

    if ($Install.ExitCode -ne 0) {
        throw "Office install failed. ExitCode=$($Install.ExitCode)"
    }

    Write-Log "Re-checking Microsoft 365 Apps for business after install."
    $PostEval = Test-M365BusinessInstalled

    if ($PostEval.PrimaryHit) {
        Write-Log "RESULT | Microsoft 365 Apps for business installed successfully. $($PostEval.Evidence)"
    }
    else {
        Write-Log "ERROR | Install completed, but Microsoft 365 Apps for business was not detected afterward. $($PostEval.Evidence)"
    }
}
catch {
    Write-Log "ERROR | $($_.Exception.Message)"
}