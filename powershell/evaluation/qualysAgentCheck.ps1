# ============================================================================
# NAME: Qualys Cloud Agent - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   QualysPattern = (?i)qualys
# OUTPUT TOKENS:
#   TRIGGER   | Qualys not installed
#   NO_ACTION | Qualys installed
#   ERROR     | Not emitted by this script
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None; console output only
# DESCRIPTION:
#   Searches Windows uninstall registry locations for installed Qualys
#   products using a case-insensitive display name match.
#
#   Checks 32-bit, 64-bit, and user uninstall registry locations.
#
#   Reports NO_ACTION when a matching Qualys product is detected,
#   including its display name and installed version.
#
#   Reports TRIGGER when no matching Qualys product is found.
#
#   Always exits with code 0 for NinjaOne automation compatibility.
# ============================================================================

$QualysPattern = '(?i)qualys'

$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "Registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "Registry::HKEY_USERS\*\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$qualysHits = @()

foreach ($path in $registryPaths) {
    Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        ForEach-Object {
            $dn = $_.DisplayName
            $dv = $_.DisplayVersion

            if ($dn -match $QualysPattern) {
                $qualysHits += [pscustomobject]@{
                    DisplayName    = $dn
                    DisplayVersion = $dv
                    RegPath        = $path
                }
            }
        }
}

# Qualys present -> healthy
if ($qualysHits.Count -gt 0) {
    $details = ($qualysHits | ForEach-Object {
        "'$($_.DisplayName)' v$($_.DisplayVersion)"
    }) -join "; "

    Write-Output "NO_ACTION | Qualys installed ($details)"
    exit 0
}

# Qualys missing -> trigger install/remediation
Write-Output "TRIGGER | Qualys not installed"
exit 0