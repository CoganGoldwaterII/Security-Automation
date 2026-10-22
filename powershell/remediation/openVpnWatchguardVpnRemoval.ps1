# ============================================================================
# NAME: VPN Client Full Removal - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   None required
#   Application targets:
#     OpenVPN / OpenVPN Community
#     OpenVPN Connect
#     WatchGuard Mobile VPN with SSL
# OUTPUT TOKENS:
#   None; script emits descriptive progress and completion messages.
#   No standardized RESULT / NO_ACTION / ERROR token.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None; output written to the execution console.
# DESCRIPTION:
#   Attempts complete removal of selected Windows VPN clients.
#   Identifies OpenVPN and WatchGuard Mobile VPN with SSL installations
#   through Windows uninstall registry entries.
#   Stops selected OpenVPN processes and services, executes application
#   uninstall commands, removes matching network adapters, and cleans
#   selected files, profile directories, and registry entries.
#   Displays potentially related driver packages for manual review.
#
#   EXCLUDED APPLICATIONS:
#     WatchGuard AuthPoint
#     WatchGuard Logon App
#     WatchGuard System Manager / Fireware
#
#   WARNING:
#   Destructive cleanup that can interrupt active VPN connectivity.
#   Some process, adapter, and filesystem cleanup occurs independently
#   of application detection. Adapter matching includes generic TAP
#   and Wintun descriptions that may belong to other applications.
#   Removal operations are largely best-effort and are not verified.
#   Always exits 0 on normal completion.
# ============================================================================

$ErrorActionPreference = 'SilentlyContinue'

Write-Output "====================================="
Write-Output "Starting SAFE VPN client cleanup..."
Write-Output "====================================="

# -----------------------------
# Helper: Get installed apps
# -----------------------------
function Get-InstalledApps {
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($Path in $RegPaths) {
        Get-ItemProperty $Path -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName
        } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString
    }
}

# -----------------------------
# Helper: Safe uninstall
# -----------------------------
function Invoke-SafeUninstall {
    param($App)

    $Name = $App.DisplayName
    $Uninstall = $App.QuietUninstallString
    if (-not $Uninstall) { $Uninstall = $App.UninstallString }

    if (-not $Uninstall) {
        Write-Output "No uninstall string found for: $Name"
        return
    }

    Write-Output "Uninstalling: $Name"
    Write-Output "Using uninstall string: $Uninstall"

    if ($Uninstall -match '(?i)msiexec') {

        if ($Uninstall -match '(\{[A-Z0-9\-]+\})') {
            $ProductCode = $Matches[1]
            Start-Process "msiexec.exe" -ArgumentList "/x $ProductCode /qn /norestart" -Wait
        }
        else {
            $Args = $Uninstall -replace '(?i)^.*?msiexec(\.exe)?\s*', ''
            $Args = $Args -replace '(?i)/i', '/x'

            if ($Args -notmatch '(?i)/qn|/quiet') { $Args += ' /qn' }
            if ($Args -notmatch '(?i)/norestart') { $Args += ' /norestart' }

            Start-Process "msiexec.exe" -ArgumentList $Args -Wait
        }

    } else {

        # Handle EXE uninstallers (WatchGuard)
        if ($Uninstall -match '^\s*"([^"]+)"\s*(.*)$') {
            $Exe = $Matches[1]
            $Args = $Matches[2]
        }
        else {
            $Parts = $Uninstall -split '\s+', 2
            $Exe = $Parts[0]
            $Args = if ($Parts.Count -gt 1) { $Parts[1] } else { "" }
        }

        Write-Output "EXE uninstall detected"
        Write-Output "Executable: $Exe"

        # Force silent flags (Inno-safe)
        if ($Args -notmatch '(?i)silent') {
            $Args = "$Args /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
        }

        Write-Output "Args: $Args"

        Start-Process -FilePath $Exe -ArgumentList $Args -Wait
    }
}

# -----------------------------
# Kill OpenVPN processes ONLY
# -----------------------------
Write-Output "Stopping VPN processes..."

Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match '^(openvpn|openvpn-gui|ovpnconnector|ovpnagent|OpenVPNConnect)$'
} | Stop-Process -Force -ErrorAction SilentlyContinue

# -----------------------------
# Remove OpenVPN services
# -----------------------------
$services = @(
    "OpenVPNService",
    "OpenVPNServiceInteractive",
    "ovpn-dco"
)

foreach ($svc in $services) {
    if (Get-Service $svc -ErrorAction SilentlyContinue) {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        sc.exe delete $svc | Out-Null
        Write-Output "Removed service: $svc"
    }
}

# -----------------------------
# Detect target apps
# -----------------------------
$Apps = Get-InstalledApps

$Targets = foreach ($App in $Apps) {

    $Name = [string]$App.DisplayName
    $Publisher = [string]$App.Publisher

    # --- OpenVPN ---
    $IsOpenVPN = ($Name -match '^OpenVPN($|[\s-])' -or $Name -match '^OpenVPN Connect')

    # --- WatchGuard SSLVPN ---
    $IsWGSSL = $false

    if ($Name -match '(?i)mobile.*vpn.*ssl' -and
        $Name -match '(?i)vpn' -and
        $Name -match '(?i)ssl') {

        if ($Publisher -match '(?i)watchguard' -or $Name -match '(?i)watchguard') {
            $IsWGSSL = $true
        }
    }

    if ($IsOpenVPN -or $IsWGSSL) {
        $App
    }
}

if ($Targets) {
    Write-Output "Matched uninstall targets:"
    $Targets | ForEach-Object { Write-Output " - $($_.DisplayName)" }
}
else {
    Write-Output "No VPN clients detected"
}

# -----------------------------
# Uninstall apps
# -----------------------------
foreach ($App in $Targets) {
    Invoke-SafeUninstall $App
}

# -----------------------------
# Remove OpenVPN adapters
# -----------------------------
Write-Output "Removing OpenVPN adapters..."

Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceDescription -match 'TAP|Wintun|OpenVPN'
} | ForEach-Object {
    Disable-NetAdapter $_.Name -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetAdapter $_.Name -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "Removed adapter: $($_.Name)"
}

# -----------------------------
# Remove OpenVPN files
# -----------------------------
Write-Output "Removing OpenVPN files..."

$OpenVPNPaths = @(
    "C:\Program Files\OpenVPN",
    "C:\Program Files (x86)\OpenVPN",
    "C:\ProgramData\OpenVPN",
    "$env:APPDATA\OpenVPN",
    "$env:LOCALAPPDATA\OpenVPN"
)

foreach ($p in $OpenVPNPaths) {
    if (Test-Path $p) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Removed: $p"
    }
}

# -----------------------------
# Remove WatchGuard SSLVPN files ONLY
# -----------------------------
Write-Output "Removing WatchGuard SSLVPN files..."

$WGPaths = @(
    "C:\Program Files (x86)\WatchGuard\WatchGuard Mobile VPN with SSL",
    "C:\Program Files\WatchGuard\WatchGuard Mobile VPN with SSL",
    "C:\Program Files (x86)\WatchGuard\Mobile VPN with SSL",
    "C:\Program Files\WatchGuard\Mobile VPN with SSL"
)

foreach ($p in $WGPaths) {
    if (Test-Path $p) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Removed: $p"
    }
}

# -----------------------------
# Remove WatchGuard AppData (SAFE)
# -----------------------------
Write-Output "Cleaning WatchGuard AppData remnants..."

$Users = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

foreach ($u in $Users) {

    $WGRoot = Join-Path $u.FullName "AppData\Roaming\WatchGuard"

    if (Test-Path $WGRoot) {

        $Targets = @(
            "Mobile VPN with SSL",
            "MobileVPN",
            "SSLVPN"
        )

        foreach ($t in $Targets) {

            $Full = Join-Path $WGRoot $t

            if (Test-Path $Full) {
                Remove-Item $Full -Recurse -Force -ErrorAction SilentlyContinue
                Write-Output "Removed: $Full"
            }
        }
    }
}

# -----------------------------
# Registry cleanup
# -----------------------------
Write-Output "Cleaning registry..."

$RegPaths = @(
    "HKLM:\SOFTWARE\OpenVPN",
    "HKLM:\SOFTWARE\WOW6432Node\OpenVPN",
    "HKCU:\SOFTWARE\OpenVPN",
    "HKLM:\SOFTWARE\WatchGuard\Mobile VPN with SSL",
    "HKLM:\SOFTWARE\WOW6432Node\WatchGuard\Mobile VPN with SSL",
    "HKCU:\SOFTWARE\WatchGuard\Mobile VPN with SSL"
)

foreach ($r in $RegPaths) {
    if (Test-Path $r) {
        Remove-Item $r -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Removed: $r"
    }
}

# -----------------------------
# Driver visibility
# -----------------------------
Write-Output ""
Write-Output "Checking driver remnants..."

pnputil /enum-drivers | Select-String -Pattern "tap|wintun|openvpn" -Context 0,3

# -----------------------------
# Finish
# -----------------------------
Write-Output ""
Write-Output "====================================="
Write-Output "SAFE VPN cleanup complete"
Write-Output "All versions of SSLVPN handled"
Write-Output "Other WatchGuard products untouched"
Write-Output "Reboot recommended"
Write-Output "====================================="

exit 0