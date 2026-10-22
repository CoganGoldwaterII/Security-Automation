# ============================================================================
# NAME: Qualys Cloud Agent - Install
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   folder        = C:\Temp
#   installerUrl  = Installer download URL (must be configured)
#   installerPath = C:\Temp\QualysCloudAgent.exe
#   installArgs   = Qualys customer/activation identifiers and service URL
# OUTPUT TOKENS:
#   None; outputs installation progress messages.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
#   Installer downloaded from configured URL
# LOGGING PATH:
#   None; console output only
# DESCRIPTION:
#   Downloads the Qualys Cloud Agent installer to C:\Temp and executes
#   installation using the configured Customer ID, Activation ID, and
#   Qualys Web Service URI.
#
#   Customer ID and Activation ID must be configured before execution.
#   Activation ID must be changed for each client as appropriate.
#
#   This public version contains placeholders for sensitive identifiers
#   and the original installer download URL.
#
#   Original installation logic preserved.
# ============================================================================

# Set variables
$folder = "C:\Temp"
$installerUrl = "https://YOUR-INSTALLER-URL/QualysCloudAgent.exe"
$installerPath = "$folder\QualysCloudAgent.exe"
$installArgs = 'CustomerId={YOUR_CUSTOMER_ID} ActivationId={YOUR_ACTIVATION_ID} WebServiceUri=https://qagpublic.qg3.apps.qualys.com/CloudAgent/'

# Create temp folder if it doesn't exist
if (-not (Test-Path -Path $folder)) {
    New-Item -ItemType Directory -Path $folder | Out-Null
}

# Download the Qualys installer
Write-Host "Downloading latest Qualys installer..."
Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing

# Install the Qualys agent
Write-Host "Installing Qualys agent..."
Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$installerPath`" $installArgs" -Wait -NoNewWindow

# Note: YOU MUST CHANGE THE ACTIVATION ID PER CLIENT