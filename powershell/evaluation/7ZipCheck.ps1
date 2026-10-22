# ============================================================================
# NAME: 7-Zip Version Check - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LogDir               = C:\MME\AutoLogs
#   LogFile              = C:\MME\AutoLogs\7Zip_Eval.log
#   SevenZipDownloadPage = https://www.7-zip.org/download.html
# OUTPUT TOKENS:
#   TRIGGER   | Outdated 7-Zip
#   NO_ACTION | 7-Zip not installed
#   NO_ACTION | 7-Zip current
#   NO_ACTION | ERROR (evaluation failure)
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\7Zip_Eval.log
# DESCRIPTION:
#   Detects the installed 7-Zip version using executable metadata
#   or Windows uninstall registry entries.
#   Retrieves the latest stable version from the official 7-Zip
#   download page and compares installed and available versions.
#   Triggers remediation when the installed version is outdated.
#   Reports NO_ACTION when absent, current, or evaluation fails.
#   Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

# -------- CONFIG --------
$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "7Zip_Eval.log"
$SevenZipDownloadPage = "https://www.7-zip.org/download.html"

# -------- HELPERS --------
function Ensure-Dir([string]$Path) {
    if (!(Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Write-Log([string]$Message) {
    Ensure-Dir $LogDir
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [7ZipEval] $Message"
}

function Finish([string]$Output) {
    Write-Log "FINAL: $Output"
    Write-Output $Output
    exit 0
}

function Convert-7ZipDigitsToVersion([string]$digits4) {
    # e.g., "2409" => "24.09"
    if ($digits4 -notmatch '^\d{4}$') { return $null }
    $maj = [int]$digits4.Substring(0,2)
    $min = [int]$digits4.Substring(2,2)
    return ("{0}.{1:D2}" -f $maj, $min)
}

function Get-Latest7ZipVersion {
    Write-Log "Fetching latest 7-Zip version from: $SevenZipDownloadPage"
    $html = Invoke-WebRequest -Uri $SevenZipDownloadPage -UseBasicParsing -TimeoutSec 30
    $content = $html.Content

    # Prefer x64 MSI pattern like: 7z2409-x64.msi (sometimes .exe only; handle both)
    $m = [regex]::Match($content, '7z(?<ver>\d{4})-x64\.msi', 'IgnoreCase')
    if (!$m.Success) {
        $m = [regex]::Match($content, '7z(?<ver>\d{4})-x64\.exe', 'IgnoreCase')
    }
    if (!$m.Success) { throw "Could not parse latest 7-Zip version from download page." }

    $digits = $m.Groups['ver'].Value
    $ver = Convert-7ZipDigitsToVersion $digits
    if (!$ver) { throw "Parsed digits '$digits' but failed to convert to version." }

    Write-Log "Latest 7-Zip parsed: $ver (digits=$digits)"
    return $ver
}

function Get-Installed7ZipVersion {
    # First try actual binary
    $exe = "C:\Program Files\7-Zip\7z.exe"
    if (Test-Path $exe) {
        try {
            $fv = (Get-Item $exe).VersionInfo.FileVersion
            if ($fv) {
                # file version may be like "24.09" or "24.09.00.0"; normalize to Major.Minor
                $parts = $fv -split '\.'
                if ($parts.Count -ge 2) {
                    $norm = ("{0}.{1:D2}" -f [int]$parts[0], [int]$parts[1])
                    Write-Log "Installed 7-Zip from file: $norm (raw=$fv)"
                    return $norm
                }
            }
        } catch {
            Write-Log "File version read failed: $($_.Exception.Message)"
        }
    }

    # Fallback: uninstall registry
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($p in $paths) {
        $items = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match '^7-Zip\b' -and $_.DisplayVersion }
        foreach ($i in $items) {
            $dv = $i.DisplayVersion.Trim()
            # Normalize like "24.09" or "24.09 (x64 edition)" just in case
            $m = [regex]::Match($dv, '(\d+)\.(\d+)')
            if ($m.Success) {
                $norm = ("{0}.{1:D2}" -f [int]$m.Groups[1].Value, [int]$m.Groups[2].Value)
                Write-Log "Installed 7-Zip from registry: $norm (raw=$dv)"
                return $norm
            }
        }
    }

    return $null
}

function Compare-Version([string]$a, [string]$b) {
    # returns -1 if a<b, 0 if equal, 1 if a>b
    return ([version]$a).CompareTo([version]$b)
}

# -------- MAIN --------
try {
    Write-Log "============================================"
    Write-Log "Starting 7-Zip evaluation..."

    $installed = Get-Installed7ZipVersion
    if (-not $installed) {
        Finish "NO_ACTION | 7-Zip not installed"
    }

    $latest = Get-Latest7ZipVersion

    $cmp = Compare-Version $installed $latest
    if ($cmp -lt 0) {
        Finish "TRIGGER | Outdated 7-Zip ($installed < $latest)"
    } else {
        Finish "NO_ACTION | 7-Zip current ($installed)"
    }
}
catch {
    $msg = $_.Exception.Message
    Write-Log "ERROR: $msg"
    Finish "NO_ACTION | ERROR (7-Zip eval failed: $msg)"
}