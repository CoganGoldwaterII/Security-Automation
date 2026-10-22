# ============================================================================
# NAME: OpenVPN Community - Update Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogPath       = C:\MME\AutoLogs\OpenVPN_Update.log
#   DownloadDir   = C:\MME\CS
#   InstallerPath = C:\MME\CS\OpenVPN.msi
#   DownloadURL   = Official OpenVPN Community 2.6.10 MSI URL
# OUTPUT TOKENS:
#   None; script does not emit standardized result tokens.
# CUSTOM FIELDS:
#   Reads: remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: No
#   Files: None
#   MSI downloaded directly from OpenVPN.
# LOGGING PATH:
#   C:\MME\AutoLogs\OpenVPN_Update.log
# DESCRIPTION:
#   Downloads the specified OpenVPN Community MSI to the local staging
#   directory and performs a silent installation or upgrade.
#   Uses MSI reinstall properties to refresh installed components.
#   Updates the NinjaOne remediation ledger after successful installation.
#   Targets OpenVPN Community version 2.6.10.
#   Exits 0 on success and 1 on failure.
# ============================================================================

$ErrorActionPreference = 'Stop'

# --- GLOBALS ---
$LogPath = "C:\MME\AutoLogs\OpenVPN_Update.log"
$DownloadDir = "C:\MME\CS"
$InstallerPath = "$DownloadDir\OpenVPN.msi"
$DownloadURL = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.10-I001-amd64.msi"

# --- LOG FUNCTION ---
function Write-Log {
    param ($Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogPath -Value "$Timestamp | $Message"
}

# --- LEDGER FUNCTION ---
function Update-Ledger {
    param ($Message)

    $Date = Get-Date -Format "yyyy-MM-dd"

    try {
        $Existing = ninja-property-get remediationSummary
        if (-not $Existing) { $Existing = "" }

        # sanitize existing
        $Clean = ($Existing -split "`n" | Where-Object { $_.Trim() -ne "" })

        $NewEntry = "$Date | $Message"

        if ($Clean -notcontains $NewEntry) {
            $Updated = ($Clean + $NewEntry) -join "`n"
            ninja-property-set remediationSummary "$Updated"
        }

        ninja-property-set lastRemediationDate (Get-Date -Format "o")
    }
    catch {
        Write-Log "Ledger update failed: $_"
    }
}

# --- START ---
try {
    Write-Log "===== OpenVPN Update START ====="

    # Ensure directories
    if (-not (Test-Path $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    }

    if (-not (Test-Path "C:\MME\AutoLogs")) {
        New-Item -ItemType Directory -Path "C:\MME\AutoLogs" -Force | Out-Null
    }

    # --- DOWNLOAD ---
    Write-Log "Downloading installer..."
    Start-BitsTransfer -Source $DownloadURL -Destination $InstallerPath -ErrorAction Stop

    if (-not (Test-Path $InstallerPath)) {
        throw "Download failed"
    }

    Write-Log "Download complete"

    # --- INSTALL / UPGRADE ---
    Write-Log "Running MSI upgrade..."

    $Process = Start-Process "msiexec.exe" `
        -ArgumentList "/i `"$InstallerPath`" /qn /norestart REINSTALL=ALL REINSTALLMODE=vomus" `
        -Wait -PassThru

    if ($Process.ExitCode -ne 0) {
        throw "MSI failed with exit code $($Process.ExitCode)"
    }

    Write-Log "Upgrade completed successfully"

    # --- LEDGER ---
    Update-Ledger "OpenVPN Community Updated"

    Write-Log "===== OpenVPN Update COMPLETE ====="
    exit 0
}
catch {
    Write-Log "ERROR: $_"
    exit 1
}