# ============================================================================
# NAME: Set IPv4 MTU to 1500
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   None; script exits 0 without reporting remediation status.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# LOGGING PATH:
#   None
# DESCRIPTION:
#   Identifies active physical network adapters and sets their IPv4 MTU
#   to 1500 bytes.
#
#   Suppresses individual adapter errors and confirmation prompts.
#   Does not modify inactive or non-physical network adapters.
#   Always exits with code 0.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"

$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }

foreach ($adapter in $adapters) {
    Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -NlMtuBytes 1500 -Confirm:$false -ErrorAction SilentlyContinue
}

exit 0
