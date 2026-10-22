# ============================================================================
# NAME: Dell BIOS Provider + SMBIOS Verification + WOL Baseline
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Dell Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir        = C:\MME\AutoLogs
#   DoCsvExport   = $true
#   DoFuzzySearch = $false
#   Settings      = Dell BIOS power management baseline
# OUTPUT TOKENS:
#   RESULT    | Updated BIOS settings
#   NO_ACTION | All targeted settings already compliant
#   RESULT    | ERROR (remediation failure)
#   INFO      | SMBIOS discovery and optional CSV export
#   RUN_MARKER | SMBIOS_MENU | START / END
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\Dell_PowerBaseline.log
# CSV EXPORT:
#   C:\MME\CS\DellSMBIOS_Menu_<timestamp>.csv
# DESCRIPTION:
#   Prepares PowerShell module dependencies and installs DellBIOSProvider
#   when missing. Imports the module and verifies the DellSMBIOS PSDrive.
#   Probes Wake-on-LAN attributes and optionally exports the SMBIOS tree.
#   Enforces five Dell BIOS power management settings using strict
#   PossibleValues validation and post-change readback verification.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

# ---------------- CONFIG ----------------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "Dell_PowerBaseline.log"

# Set to $true only when you want a full SMBIOS CSV dump (can be slow on some boxes)
$DoCsvExport = $true

# Set to $true to do a fuzzy search of the SMBIOS tree (can be slow)
$DoFuzzySearch = $false

# Canonical enforced baseline (per your current orders)
$Settings = @(
    @{ Path="DellSMBIOS:\PowerManagement\WakeOnLan";     Desired="LanOnly";  Name="WakeOnLan" },
    @{ Path="DellSMBIOS:\PowerManagement\DeepSleepCtrl"; Desired="Disabled"; Name="DeepSleepCtrl" },
    @{ Path="DellSMBIOS:\PowerManagement\AcPwrRcvry";    Desired="On";       Name="AcPwrRcvry" },
    @{ Path="DellSMBIOS:\PowerManagement\BlockSleep";    Desired="Disabled"; Name="BlockSleep" },
    @{ Path="DellSMBIOS:\PowerManagement\UsbWake";       Desired="Disabled"; Name="UsbWake" }
)

# ---------------- HELPERS ----------------
function Ensure-Dir([string]$p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Log([string]$m) {
    Ensure-Dir $LogDir
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [DellPowerBaseline] $m"
}

function Finish([string]$out) {
    Log "FINAL: $out"
    Write-Output $out
    exit 0
}

function Ensure-Tls12 {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
}

function Ensure-DellBiosProviderInstalled {
    Ensure-Tls12

    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Log "NuGet provider missing; installing..."
        Install-PackageProvider -Name NuGet -Force -Scope AllUsers -Confirm:$false | Out-Null
        Log "NuGet provider installed."
    } else {
        Log "NuGet provider already present."
    }

    if (-not (Get-Module -ListAvailable -Name PowerShellGet)) {
        Log "PowerShellGet not found; attempting install (best-effort)..."
        Install-Module -Name PowerShellGet -Scope AllUsers -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }

    $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if ($repo -and $repo.InstallationPolicy -ne "Trusted") {
        Log "Trusting PSGallery..."
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }

    if (-not (Get-Module -ListAvailable -Name DellBIOSProvider)) {
        Log "DellBIOSProvider missing; installing..."
        Install-Module -Name DellBIOSProvider -Scope AllUsers -Force -Confirm:$false
        Log "DellBIOSProvider installed."
    } else {
        Log "DellBIOSProvider already installed."
    }
}

function Ensure-DellSmbiosDrive {
    Import-Module DellBIOSProvider -Force
    Log "DellBIOSProvider imported."

    $drive = Get-PSDrive -Name DellSMBIOS -ErrorAction SilentlyContinue
    if (-not $drive) {
        Log "DellSMBIOS PSDrive not present; attempting to create..."
        try {
            New-PSDrive -Name DellSMBIOS -PSProvider DellBIOSProvider -Root "\" -ErrorAction Stop | Out-Null
        } catch {
            throw "DellSMBIOS PSDrive could not be created: $($_.Exception.Message)"
        }
        $drive = Get-PSDrive -Name DellSMBIOS -ErrorAction SilentlyContinue
        if (-not $drive) {
            throw "DellSMBIOS drive still not found after creation attempt."
        }
    }

    Log ("DriveRoot=" + $drive.Root)
    Log ("Provider=" + $drive.Provider.Name)
}

function Targeted-WolProbe {
    Write-Output "RUN_MARKER | SMBIOS_MENU | START"
    Log "TargetedProbe: Wake-on-LAN"

    $wolCandidates = @(
        "DellSMBIOS:\PowerManagement\WakeOnLan",
        "DellSMBIOS:\PowerManagement\WakeOnLAN",
        "DellSMBIOS:\PowerManagement\WakeOnWlan"
    )

    $foundAny = $false
    foreach ($p in $wolCandidates) {
        $item = Get-Item -Path $p -ErrorAction SilentlyContinue
        if ($item) {
            $foundAny = $true
            Write-Output ("INFO | Found: " + $p)
            Write-Output ("INFO | Attribute=" + $item.Attribute)
            Write-Output ("INFO | CurrentValue=" + $item.CurrentValue)
            Write-Output ("INFO | PossibleValues=" + ($item.PossibleValues -join ","))
            Log ("Found: $p | Current=" + $item.CurrentValue + " | Possible=" + ($item.PossibleValues -join ","))
        }
    }

    if (-not $foundAny) {
        Write-Output "INFO | TargetedProbe: NO_WOL_PATHS_FOUND"
        Log "TargetedProbe: NO_WOL_PATHS_FOUND"
    }

    if ($DoFuzzySearch) {
        Write-Output "INFO | LiveSearch (wake|wol|lan|nic|pxe):"
        Log "LiveSearch enabled."

        $hits = Get-ChildItem "DellSMBIOS:\" -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.PSPath -match 'wake|wol|lan|nic|pxe') -or
                ($_.PSObject.Properties.Name -contains 'Attribute' -and $_.Attribute -match 'wake|wol|lan|nic|pxe')
            } |
            Select-Object PSPath, Attribute, CurrentValue, PossibleValues

        if (-not $hits -or $hits.Count -eq 0) {
            Write-Output "INFO | LiveSearch: NO_MATCHES"
            Log "LiveSearch: NO_MATCHES"
        } else {
            $hits | ForEach-Object {
                Write-Output ("  - {0} | {1} | {2} | {3}" -f $_.PSPath, $_.Attribute, $_.CurrentValue, $_.PossibleValues)
            }
            Log ("LiveSearch: " + $hits.Count + " matches")
        }
    } else {
        Write-Output "INFO | LiveSearch: SKIPPED"
        Log "LiveSearch skipped."
    }

    if ($DoCsvExport) {
        $exportDir = "C:\MME\CS"
        if (-not (Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }

        $csv = Join-Path $exportDir ("DellSMBIOS_Menu_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

        Get-ChildItem "DellSMBIOS:\" -Recurse -ErrorAction SilentlyContinue |
            Select-Object PSPath, Name, Attribute, CurrentValue, PossibleValues |
            Export-Csv $csv -NoTypeInformation

        Write-Output ("INFO | CSV=" + $csv)
        Log ("CSV exported: " + $csv)
    } else {
        Write-Output "INFO | CSV: SKIPPED"
        Log "CSV export skipped."
    }

    Write-Output "RUN_MARKER | SMBIOS_MENU | END"
}

# ---------------- MAIN ----------------
try {
    Ensure-Dir $LogDir
    Log "============================================================"
    Log "Starting ALL-IN-ONE Dell BIOSProvider + SMBIOS verify + baseline..."

    Ensure-DellBiosProviderInstalled
    Ensure-DellSmbiosDrive

    # Menu probe + optional export
    Targeted-WolProbe

    # Enforce baseline (STRICT)
    $changed = @()
    $already = @()

    foreach ($s in $Settings) {
        $p       = $s.Path
        $desired = $s.Desired
        $name    = $s.Name

        Log "------------------------------------------------------------"
        Log "Processing ${name}"
        Log "Path: $p"
        Log "Desired: $desired"

        $item = Get-Item -Path $p -ErrorAction Stop
        $current  = [string]$item.CurrentValue
        $possible = @($item.PossibleValues)

        Log "${name} CurrentValue: $current"
        Log "${name} PossibleValues: $($possible -join ',')"

        if ($possible.Count -eq 0) {
            throw "${name} has no PossibleValues exposed at '$p'."
        }
        if ($possible -notcontains $desired) {
            throw "${name} desired '$desired' invalid. Allowed: $($possible -join ',')"
        }

        if ($current -eq $desired) {
            Log "${name} already compliant."
            $already += "${name} already $desired"
            continue
        }

        Log "Setting ${name}: '$current' -> '$desired'"
        Set-Item -Path $p -Value $desired -ErrorAction Stop

        $verify = [string](Get-Item -Path $p -ErrorAction Stop).CurrentValue
        Log "${name} Verify readback: $verify"

        if ($verify -ne $desired) {
            throw "${name} set attempted ($current -> $desired) but verify returned '$verify'"
        }

        Log "${name} updated successfully."
        $changed += "${name} $current -> $verify"
    }

    if ($changed.Count -gt 0) {
        Finish ("RESULT | Updated: " + ($changed -join "; "))
    } else {
        Finish ("NO_ACTION | " + ($already -join "; "))
    }
}
catch {
    Log "ERROR: $($_.Exception.Message)"
    Finish ("RESULT | ERROR ($($_.Exception.Message))")
}