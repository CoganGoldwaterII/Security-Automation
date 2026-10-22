# ============================================================================
# NAME: Windows Wake-on-LAN NIC Baseline - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir  = C:\MME\AutoLogs
#   LogFile = C:\MME\AutoLogs\WOL_Windows_NIC_Baseline.log
# OUTPUT TOKENS:
#   RESULT    | Wake-on-LAN baseline changes applied
#   NO_ACTION | No changes required
#   RESULT    | ERROR (remediation failure)
# CUSTOM FIELDS:
#   Reads: None
#   Writes: wakeonlanEnabled (TRUE)
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\WOL_Windows_NIC_Baseline.log
# DESCRIPTION:
#   Configures Windows power settings and physical Ethernet adapters
#   to support Wake-on-LAN functionality.
#   Disables hibernation and Fast Startup, applies supported NIC
#   advanced properties, and enables device wake permissions.
#   Records unsupported adapter properties in the execution log.
#   Sets the NinjaOne wakeonlanEnabled device field to TRUE.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "WOL_Windows_NIC_Baseline.log"

# ---------------- HELPERS ----------------
function Ensure-Dir($p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}
function Log($m) {
    Ensure-Dir $LogDir
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [WOL-WinNIC] $m"
}

function Set-NinjaField($name, $value) {
    # Best-effort: do not fail remediation if not running under Ninja / cmdlet missing
    try {
        if (Get-Command ninja-property-set -ErrorAction SilentlyContinue) {
            ninja-property-set $name "$value"
            Log "Ninja field set: $name = $value"
        } else {
            Log "Ninja field set skipped (ninja-property-set not found): $name"
        }
    } catch {
        Log "WARN: Failed setting Ninja field '$name' (ignored): $($_.Exception.Message)"
    }
}

function Finish($out) {
    # ALWAYS stamp the custom field TRUE (per requirement)
    Set-NinjaField "wakeonlanEnabled" "TRUE"

    Log "FINAL: $out"
    Write-Output $out
    exit 0
}

function Is-PhysicalEthernet($na) {
    $desc = "$($na.InterfaceDescription)"
    $name = "$($na.Name)"
    if ($desc -match "TAP|Virtual|VMware|Hyper-V|Bluetooth|Loopback|WAN Miniport|Wi-Fi|Wireless|VPN") { return $false }
    if ($name -match "TAP|Virtual|VMware|Hyper-V|Bluetooth|Loopback|Wi-Fi|Wireless|VPN") { return $false }
    return $true
}

# ---------------- START ----------------
try {
    Ensure-Dir $LogDir
    Log "============================================================"
    Log "Starting Windows WOL baseline (disable hibernate + NIC tuning)..."

    $changed = @()
    $notes   = @()

    # ---- 1) Disable Hibernate (and therefore Fast Startup) ----
    Log "Running: powercfg /hibernate off"
    & powercfg /hibernate off | Out-Null

    $aText = (& powercfg /a 2>&1 | Out-String)
    Log "powercfg /a output:`n$aText"

    # Keep your existing verification logic intact
    if ($aText -match "Fast Startup\s+Hibernation is not available" -and
        $aText -match "Hibernation has not been enabled") {
        $changed += "Hibernate/FastStartup enforced OFF"
        Log "Hibernate + Fast Startup verified OFF via powercfg /a."
    } else {
        throw "Hibernate/Fast Startup not confirmed OFF. Review powercfg /a output."
    }

    # ---- 2) NIC Advanced Property Baseline ----
    $desiredProps = @(
        @{ Pattern = "^Wake on Magic Packet$";       Desired = "Enabled"  },
        @{ Pattern = "^Wake on pattern match$";      Desired = "Disabled" },
        @{ Pattern = "^Shutdown Wake-On-Lan$";       Desired = "Enabled"  }, # may not exist on Intel/Realtek depending on driver
        @{ Pattern = "^System Idle Power Saver$";    Desired = "Disabled" },
        @{ Pattern = "^Ultra Low Power Mode$";       Desired = "Disabled" },
        @{ Pattern = "^Reduce Speed On Power Down$"; Desired = "Disabled" }
    )

    $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { Is-PhysicalEthernet $_ }
    if (!$adapters -or $adapters.Count -eq 0) {
        Finish "RESULT | Updated: $($changed -join '; ') | Notes: No physical Ethernet adapters found"
    }

    foreach ($a in $adapters) {
        Log "------------------------------------------------------------"
        Log "Adapter: $($a.Name) | $($a.InterfaceDescription)"

        $props = Get-NetAdapterAdvancedProperty -Name $a.Name -ErrorAction Stop

        foreach ($dp in $desiredProps) {
            $pattern = $dp.Pattern
            $want    = $dp.Desired

            $m = $props | Where-Object { $_.DisplayName -match $pattern } | Select-Object -First 1
            if (-not $m) {
                Log "NOT_SUPPORTED: '$pattern' not found on '$($a.Name)'"
                $notes += "$($a.Name): missing '$pattern'"
                continue
            }

            $current = [string]$m.DisplayValue
            Log "PROP: '$($m.DisplayName)' Current='$current' Desired='$want'"

            if ($current -eq $want) { continue }

            Set-NetAdapterAdvancedProperty -Name $a.Name -DisplayName $m.DisplayName -DisplayValue $want -NoRestart -ErrorAction Stop
            $changed += "$($a.Name): $($m.DisplayName) '$current' -> '$want'"
            Log "UPDATED: $($m.DisplayName) '$current' -> '$want'"
        }

        # Best-effort: ensure adapter is allowed to wake
        try {
            & powercfg -deviceenablewake "$($a.InterfaceDescription)" | Out-Null
            Log "powercfg: enabled wake for '$($a.InterfaceDescription)' (best-effort)"
        } catch {
            Log "WARN: powercfg enablewake failed: $($_.Exception.Message)"
            $notes += "$($a.Name): powercfg enablewake failed"
        }
    }

    if ($changed.Count -gt 0) {
        $msg = "Updated: " + ($changed -join "; ")
        if ($notes.Count -gt 0) { $msg += " | Notes: " + ($notes -join "; ") }
        Finish "RESULT | $msg"
    } else {
        $msg = "No changes required"
        if ($notes.Count -gt 0) { $msg += " | Notes: " + ($notes -join "; ") }
        Finish "NO_ACTION | $msg"
    }
}
catch {
    Log "ERROR: $($_.Exception.Message)"
    Finish "RESULT | ERROR ($($_.Exception.Message))"
}