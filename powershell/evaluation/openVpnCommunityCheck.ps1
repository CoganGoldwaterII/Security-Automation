# ============================================================================
# NAME: OpenVPN Community Edition - Version Check
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   DownloadURL   = Official OpenVPN Community MSI URL
#   TargetVersion = Extracted from installer filename (2.6.10)
# OUTPUT TOKENS:
#   TRIGGER   | OpenVPN absent, outdated, or version unavailable
#   NO_ACTION | OpenVPN installed at or above target version
#   ERROR     | Evaluation exception
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None
# DESCRIPTION:
#   Evaluates OpenVPN Community Edition installations using Windows
#   uninstall registry entries.
#   Extracts the target version from the configured MSI download URL.
#   Excludes OpenVPN Connect from application detection.
#   Triggers remediation when OpenVPN Community Edition is missing,
#   its installed version cannot be determined, or it is outdated.
#   Emits NO_ACTION when the highest installed version meets or
#   exceeds the configured target.
#   Exits 0 for evaluation results and 1 on caught exceptions.
# ============================================================================

$ErrorActionPreference = 'Stop'

try {
    # --- CONFIG ---
    $DownloadURL = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.10-I001-amd64.msi"

    # --- EXTRACT TARGET VERSION FROM URL ---
    $FileName = Split-Path $DownloadURL -Leaf

    if ($FileName -match '^OpenVPN-([^-]+)-') {
        $TargetVersion = $Matches[1]
    } else {
        Write-Output "TRIGGER"
        exit 0
    }

    # --- SEARCH REGISTRY FOR INSTALLED APPS ---
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $CommunityApps = foreach ($Path in $RegPaths) {
        Get-ItemProperty $Path -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -and
            $_.DisplayName -match '^OpenVPN($|[\s-])' -and
            $_.DisplayName -notmatch 'Connect'
        }
    }

    # --- NOT INSTALLED ---
    if (-not $CommunityApps) {
        Write-Output "TRIGGER"
        exit 0
    }

    # --- GET HIGHEST INSTALLED VERSION ---
    $InstalledVersionRaw = ($CommunityApps |
        Where-Object { $_.DisplayVersion } |
        Sort-Object { [version]($_.DisplayVersion -replace '[^0-9\.].*','') } -Descending |
        Select-Object -First 1
    ).DisplayVersion

    if (-not $InstalledVersionRaw) {
        Write-Output "TRIGGER"
        exit 0
    }

    $InstalledVersion = ($InstalledVersionRaw -replace '[^0-9\.].*','')

    # --- COMPARE VERSIONS ---
    if ([version]$InstalledVersion -lt [version]$TargetVersion) {
        Write-Output "TRIGGER"
        exit 0
    }

    # --- CURRENT ---
    Write-Output "NO_ACTION"
    exit 0
}
catch {
    # Only true failure should land here
    Write-Output "ERROR"
    exit 1
}