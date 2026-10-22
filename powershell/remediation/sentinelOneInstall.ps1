# ============================================================================
# NAME: SentinelOne Silent Install (MSI)
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   SiteToken     = SentinelOne site enrollment token (must be configured)
#   InstallerPath = C:\Temp\SentinelOne.msi
#   LogPath       = C:\Temp\S1Install.log
#   TimeoutSec    = 600
# OUTPUT TOKENS:
#   None; outputs installation progress and diagnostic messages.
#   Exit 0 | SentinelAgent service detected
#   Exit 1 | Installer missing or SentinelAgent service not detected
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: Yes
#   Destination: C:\Temp
#   Files:
#     SentinelOne.msi
# LOGGING PATH:
#   C:\Temp\S1Install.log
# DESCRIPTION:
#   Silently installs the SentinelOne Windows agent using a staged MSI
#   and the configured SentinelOne site enrollment token.
#
#   Runs msiexec with a 600-second timeout and terminates the installer
#   process if the timeout is exceeded.
#
#   Waits 45 seconds after installation before checking for the
#   SentinelAgent service to verify installation.
#
#   Requires a valid site enrollment token and staged MSI.
#
# SECURITY NOTES:
#   The site enrollment token must be configured before execution.
#   Do not publish actual enrollment tokens in source control.
# ============================================================================

# SentinelOne Silent Install (MSI) - Ninja-safe with timeout
# Installs: C:\Temp\SentinelOne.msi
# Logs:     C:\Temp\S1Install.log

$SiteToken     = "YOUR_SENTINELONE_SITE_TOKEN"
$InstallerPath = "C:\Temp\SentinelOne.msi"
$LogPath       = "C:\Temp\S1Install.log"
$TimeoutSec    = 600   # 10 minutes

Write-Output "=== SentinelOne Install Script Starting ==="
Write-Output "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

if (!(Test-Path $InstallerPath)) {
    Write-Error "Installer not found: $InstallerPath"
    exit 1
}

# Build arguments
$Arguments = "/i `"$InstallerPath`" SITE_TOKEN=$SiteToken /qn /norestart /l*v `"$LogPath`""
Write-Output "Starting msiexec..."

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -PassThru

# Wait with timeout
$elapsed = 0
while (-not $process.HasExited -and $elapsed -lt $TimeoutSec) {
    Start-Sleep -Seconds 5
    $elapsed += 5
}

if (-not $process.HasExited) {
    Write-Warning "msiexec exceeded timeout ($TimeoutSec seconds). Killing process."
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
}

if ($process.HasExited) {
    Write-Output "msiexec exit code: $($process.ExitCode)"
}

# Give SentinelOne time to register
Start-Sleep -Seconds 45

# Verify install
$svc = Get-Service -Name "SentinelAgent" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Output "SentinelAgent service detected. Status: $($svc.Status)"
    Write-Output "=== SentinelOne Install Completed Successfully ==="
    exit 0
}

Write-Error "SentinelAgent service not detected. Check log: $LogPath"
exit 1